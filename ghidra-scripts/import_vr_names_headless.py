#!/usr/bin/env python3
"""Apply VR Address Library names to a VR program in a Ghidra project, headlessly.

WHY THIS EXISTS
---------------
BethesdaGhidraScripts names Fallout 4 VR functions by porting byte signatures from a flat
Fallout 4 build, and its porter anchors only at AE (1.11.191) or NG (1.10.984). A VR-only
setup therefore gets types but almost no names, and staging the *current* Steam flat build
(1.11.221) does not help: measured, a 221 -> VR port matched 1 function out of 12,240,
because those two branches share essentially no byte-identical bodies.

But the names already exist, precomputed, in alandtse's VR address library --
`vr_address_tools/fallout_vr_address_library/fo4_database.csv` maps
`id, fo4, vr, status, name` for 93,858 entries, every one carrying both a VR address and a
demangled C++ name. 46,348 of them are status >= 3. No flat binary is needed at all.

The repo's other importer (ImportAddressLibrary.py) does this from Ghidra's Script Manager,
but declares `@runtime Jython`, which on Ghidra 12.x is an optional extension a human has to
install through the GUI. This one runs under pyghidra instead, so an agent can apply the
names unattended as part of setup.

USAGE
-----
  python import_vr_names_headless.py \
      --project-dir  C:\\repos\\BethesdaGhidraScripts\\ghidraprojects\\BethesdaGhidraScripts \
      --project-name BethesdaGhidraScripts \
      --program      /f4/vr/Fallout4VR.exe.unpacked.exe \
      --csv          C:\\repos\\vr_address_tools\\fallout_vr_address_library\\fo4_database.csv \
      [--min-status 3] [--dry-run]

Only functions still carrying Ghidra's `FUN_`/`sub_` placeholder are renamed, and anything
already USER_DEFINED or IMPORTED is left alone -- so this composes with the RTTI vtable walk
rather than fighting it, in either order.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys

# Vtable-slot placeholders the RTTI walk leaves behind: 'Func42', 'Actor::Func42'.
_SLOT_RE = re.compile(r'^(?:.*::)?Func\d+$')


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--project-dir', required=True,
                   help='Directory CONTAINING the .gpr (note: the .gpr lives one level '
                        'below ghidraprojects\\, in <project-name>\\)')
    p.add_argument('--project-name', required=True)
    p.add_argument('--program', required=True,
                   help='Program path inside the project, e.g. /f4/vr/Fallout4VR.exe.unpacked.exe')
    p.add_argument('--csv', required=True, help='fo4_database.csv (or Skyrim database.csv)')
    p.add_argument('--min-status', type=int, default=3,
                   help='Confidence floor; the library uses 2/3/4 and 3+ is the high-confidence '
                        'tier the repo has always applied (default: 3)')
    p.add_argument('--dry-run', action='store_true',
                   help='Report what would be applied; change nothing')
    p.add_argument('--replace-slot-names', action='store_true',
                   help="Also overwrite vtable-slot placeholders like 'Func42' or "
                        "'Actor::Func42' that the RTTI walk leaves behind. A real signature "
                        "from the address library beats a slot number, so this is worth "
                        "setting when the improve pass has already run on this program.")
    return p.parse_args()


def load_rows(path, min_status):
    """Return [(vr_address:int, name:str)] for usable, high-enough-confidence rows."""
    out, skipped_status, skipped_blank, bad = [], 0, 0, 0
    with open(path, newline='', encoding='utf-8', errors='replace') as fh:
        reader = csv.DictReader(fh)
        missing = {'vr', 'status', 'name'} - set(reader.fieldnames or ())
        if missing:
            raise SystemExit(
                f'ERROR: {path} lacks column(s) {sorted(missing)}; got {reader.fieldnames}')
        for row in reader:
            name = (row.get('name') or '').strip().strip('"')
            vr = (row.get('vr') or '').strip()
            if not name or not vr:
                skipped_blank += 1
                continue
            try:
                if int(row['status']) < min_status:
                    skipped_status += 1
                    continue
            except (TypeError, ValueError):
                skipped_status += 1
                continue
            try:
                out.append((int(vr, 16) if vr.lower().startswith('0x') else int(vr, 16), name))
            except ValueError:
                bad += 1
    return out, skipped_status, skipped_blank, bad


def main():
    args = parse_args()

    rows, skipped_status, skipped_blank, bad = load_rows(args.csv, args.min_status)
    print(f'CSV            : {args.csv}')
    print(f'  usable rows  : {len(rows):,}  (status >= {args.min_status})')
    print(f'  below status : {skipped_status:,}')
    print(f'  blank name/vr: {skipped_blank:,}')
    if bad:
        print(f'  unparseable  : {bad:,}')
    if not rows:
        raise SystemExit('ERROR: nothing to apply.')

    import pyghidra
    pyghidra.start()
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang  # noqa: F401  (pyghidra installs the java import hook)

    monitor = ConsoleTaskMonitor()
    print(f'\nOpening project: {args.project_dir} / {args.project_name}')
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        target = None

        def walk(folder, prefix=''):
            nonlocal target
            for f in folder.getFiles():
                full = prefix + '/' + f.getName()
                if full == args.program:
                    target = (full, f)
            for sub in folder.getFolders():
                walk(sub, prefix + '/' + sub.getName())

        walk(root)
        if target is None:
            print(f'ERROR: program {args.program!r} not found in project. Available:')

            def show(folder, prefix=''):
                for f in folder.getFiles():
                    print('   ', prefix + '/' + f.getName())
                for sub in folder.getFolders():
                    show(sub, prefix + '/' + sub.getName())

            show(root)
            sys.exit(1)

        path, df = target
        print(f'Program        : {path}')
        consumer = java.lang.Object()
        prog = df.getDomainObject(consumer, True, False, monitor)
        try:
            # The CSV stores absolute VAs for the default image base. Ghidra may have rebased,
            # so translate through the address factory rather than assuming they line up.
            af = prog.getAddressFactory().getDefaultAddressSpace()
            fm = prog.getFunctionManager()

            stats = {'renamed': 0, 'already_named': 0, 'no_func': 0, 'errored': 0,
                     'replaced_slot': 0}
            if args.dry_run:
                for va, _name in rows:
                    if fm.getFunctionAt(af.getAddress(va)) is None:
                        stats['no_func'] += 1
                    else:
                        stats['renamed'] += 1
                print(f"\n--dry-run: would consider {stats['renamed']:,} functions; "
                      f"{stats['no_func']:,} addresses have no function.")
                return

            tx = prog.startTransaction('VR address library name import')
            commit = False
            try:
                for va, name in rows:
                    try:
                        f = fm.getFunctionAt(af.getAddress(va))
                        if f is None:
                            stats['no_func'] += 1
                            continue
                        # Never clobber a human's work or an earlier importer's.
                        if f.getSymbol().getSource() in (SourceType.USER_DEFINED,
                                                         SourceType.IMPORTED):
                            stats['already_named'] += 1
                            continue
                        curr = f.getName()
                        if not (curr.startswith('FUN_') or curr.startswith('sub_')
                                or (args.replace_slot_names and _SLOT_RE.match(curr))):
                            stats['already_named'] += 1
                            continue
                        if _SLOT_RE.match(curr):
                            stats['replaced_slot'] += 1
                        f.setName(name, SourceType.IMPORTED)
                        stats['renamed'] += 1
                    except Exception:
                        # Most often DuplicateNameException; skip the one symbol rather
                        # than voiding the whole transaction.
                        stats['errored'] += 1
                commit = True
            finally:
                prog.endTransaction(tx, commit)

            print(f"\nrenamed={stats['renamed']:,}  already_named={stats['already_named']:,}  "
                  f"no_func={stats['no_func']:,}  errored={stats['errored']:,}")
            if stats['renamed']:
                prog.save('VR address library name import', monitor)
                print('saved.')
            else:
                print('nothing applied; not saving.')
        finally:
            prog.release(consumer)


if __name__ == '__main__':
    main()
