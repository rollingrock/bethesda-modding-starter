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

The CSV's addresses are absolute VAs against the binary's default image base, so they are
translated by the delta between that base and the one the program is actually at before
anything is looked up. A program still at the default base is unaffected; a rebased one is
handled instead of being silently misapplied to whatever happens to sit at the stale address.

EXIT CODES
----------
Follows the convention the numbered setup scripts use: `0` means the state you asked for now
holds, `1` means it does not.

  0   names were applied and saved, OR every address that resolved to a function already
      carried a real name. That second case is an idempotent re-run and it is a success:
      `already_named` is the whole point of not clobbering earlier work.
  1   the run achieved nothing and had nothing to work with -- no usable CSV rows, the
      program was not found in the project, or not one CSV address resolved to a function
      in it.

That last case used to print `nothing applied; not saving.` and exit 0, which is
indistinguishable from the harmless re-run above. It is not harmless: it is what you get when
this runs before `35-ghidra-analysis.ps1` has created any functions, or against the wrong
program in the project, and an agent gating on the exit code walked straight past it with one
console line in an unattended log as the only evidence.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys

# Vtable-slot placeholders the RTTI walk leaves behind: 'Func42', 'Actor::Func42'.
#
# NOT matched, and left that way on purpose: the SECONDARY-vtable form 'Actor::Func42_v1' that
# BethesdaGhidraScripts emits when a class has more than one vtable
# (scripts/core/ghidra_import_gen.py:1898-1901 builds sec_suffix = '_v<n>', :1925 appends it).
# Those stay already_named even with --replace-slot-names, so replaced_slot=0 does not by
# itself prove no placeholder was in reach -- it can also mean every hit was a secondary slot.
# Widening this regex is a behaviour change (it would start overwriting names this script has
# never touched), not a reporting one, so it is documented here rather than done.
_SLOT_RE = re.compile(r'^(?:.*::)?Func\d+$')

# The image base every address in these CSVs was computed against. Both databases store
# ABSOLUTE VAs, not RVAs, so they are only meaningful relative to a base -- and that base is
# stated here rather than inferred from the rows, because inferring it (rounding the minimum
# address down, say) would just relocate the bug into a heuristic that also cannot be checked.
#
# Measured over the two corpora this script accepts: fo4_database.csv's 93,858 `vr` addresses
# span 0x140001060 - 0x14689E1A8, and skyrim_vr_address_library/database.csv's 17,786 span
# 0x140107430 - 0x1436F2F58. Both sit above 0x140000000, which is where the MSVC x64 link
# puts the preferred base of Fallout4VR.exe and SkyrimVR.exe alike.
CSV_IMAGE_BASE = 0x140000000


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


def main() -> int:
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
            # The CSV stores absolute VAs computed for the binary's DEFAULT image base
            # (CSV_IMAGE_BASE above). Ghidra keeps whatever base the importer recorded, but a
            # program can be moved off it -- Memory Map > Set Image Base, or a dump imported at
            # another base -- and after that every VA in the CSV is off by the delta.
            #
            # An earlier version of this comment claimed the address factory performed that
            # translation. It does not, and never did: AddressSpace.getAddress(va) builds an
            # address at exactly the raw offset handed to it and consults no image base at all.
            # So the delta is computed here, explicitly, and applied to every lookup.
            #
            # Getting this wrong is not a quiet miss. Most stale VAs would land in the middle of
            # some instruction and inflate no_func harmlessly, but at this corpus size a few
            # hundred land exactly on an unrelated function's entry point -- and those get a
            # confidently wrong C++ signature applied with SourceType.IMPORTED, counted in
            # `renamed`, and committed by prog.save(). A run reading `renamed=612 no_func=45,700
            # ... saved.` is the shape that damage takes.
            #
            # On a program at the expected base the delta is 0 and every lookup is byte-for-byte
            # what it was before this fix. On a rebased one the whole corpus shifts together, so
            # if the base is somehow still wrong the failure is total rather than partial --
            # which the exit-1 case at the bottom of this function then reports.
            image_base = int(prog.getImageBase().getOffset())
            base_delta = image_base - CSV_IMAGE_BASE
            af = prog.getAddressFactory().getDefaultAddressSpace()
            fm = prog.getFunctionManager()
            if base_delta:
                print(f'Image base     : 0x{image_base:X}  (CSV assumes 0x{CSV_IMAGE_BASE:X}; '
                      f'translating every address by {base_delta:+#x})')
            else:
                print(f'Image base     : 0x{image_base:X}  (the base the CSV assumes)')

            def addr_for(va):
                """One CSV VA as an address in THIS program, through the image-base delta."""
                return af.getAddress(va + base_delta)

            stats = {'renamed': 0, 'already_named': 0, 'no_func': 0, 'errored': 0,
                     'replaced_slot': 0}
            if args.dry_run:
                for va, _name in rows:
                    if fm.getFunctionAt(addr_for(va)) is None:
                        stats['no_func'] += 1
                    else:
                        stats['renamed'] += 1
                print(f"\n--dry-run: would consider {stats['renamed']:,} functions; "
                      f"{stats['no_func']:,} addresses have no function.")
                # A dry run cannot rename anything, so the one thing it CAN establish is
                # whether the CSV's addresses and this program's functions line up at all.
                # Zero hits out of tens of thousands of rows is not a preview of a no-op
                # re-run, it is a preview of a run that would achieve nothing -- so it exits
                # 1 like the real run does, which is what makes --dry-run usable as a
                # pre-flight gate instead of a line in a log nobody reads.
                if not stats['renamed']:
                    print(f'ERROR: not one of the {len(rows):,} CSV addresses resolves to a '
                          'function in this program; nothing would be applied.')
                    return 1
                return 0

            tx = prog.startTransaction('VR address library name import')
            commit = False
            try:
                for va, name in rows:
                    try:
                        f = fm.getFunctionAt(addr_for(va))
                        if f is None:
                            stats['no_func'] += 1
                            continue
                        # Never clobber a human's work or an earlier importer's.
                        #
                        # ORDERING HAZARD, left as it is on purpose: this check runs BEFORE the
                        # slot-name gate below, so a 'Func42' placeholder whose symbol carries
                        # SourceType.IMPORTED is counted as already_named and
                        # --replace-slot-names can never reach it. That set is empty in this
                        # pipeline, which is why the order is safe today: BethesdaGhidraScripts
                        # writes 'Func<n>' names only from its UNNAMED-vtable walk, with
                        # SourceType.ANALYSIS (scripts/core/ghidra_import_gen.py:1959), and
                        # ANALYSIS falls through to the gate. Its named-class walk does use
                        # IMPORTED (:1826) but writes real header-derived member names there,
                        # never slot numbers. If a future BGS change starts stamping slot names
                        # as IMPORTED, they will silently stay 'Func42' forever while being
                        # reported as already_named -- move the slot gate above this check then,
                        # rather than rediscovering it as a bug.
                        if f.getSymbol().getSource() in (SourceType.USER_DEFINED,
                                                         SourceType.IMPORTED):
                            stats['already_named'] += 1
                            continue
                        curr = f.getName()
                        if not (curr.startswith('FUN_') or curr.startswith('sub_')
                                or (args.replace_slot_names and _SLOT_RE.match(curr))):
                            stats['already_named'] += 1
                            continue
                        f.setName(name, SourceType.IMPORTED)
                        stats['renamed'] += 1
                        # Counted AFTER the rename lands, not before it is attempted. setName
                        # raises on this corpus (DuplicateNameException, most often) and that
                        # row goes to `errored` -- a replaced_slot incremented ahead of the
                        # call would make the summary line below report a slot replacement
                        # that never happened. replaced_slot is printed as a subset of
                        # renamed, so it has to actually be one.
                        if _SLOT_RE.match(curr):
                            stats['replaced_slot'] += 1
                    except Exception:
                        # Most often DuplicateNameException; skip the one symbol rather
                        # than voiding the whole transaction.
                        stats['errored'] += 1
                commit = True
            finally:
                prog.endTransaction(tx, commit)

            print(f"\nrenamed={stats['renamed']:,}  already_named={stats['already_named']:,}  "
                  f"no_func={stats['no_func']:,}  errored={stats['errored']:,}")
            # replaced_slot was counted from the start but never printed, which made
            # --replace-slot-names an unobservable flag: its renames folded into `renamed` and
            # a run with the flag looked identical in shape to a run without it. It is a SUBSET
            # of renamed rather than a fifth bucket, so it gets its own line -- putting it in
            # the summary line above would read as a partition and would also break whatever
            # already greps that line.
            print(f"  of those renames, {stats['replaced_slot']:,} overwrote a vtable-slot "
                  "placeholder (--replace-slot-names "
                  f"{'on' if args.replace_slot_names else 'off'})")
            if args.replace_slot_names and not stats['replaced_slot']:
                print('  --replace-slot-names changed nothing: no CSV address landed on a '
                      "function still named 'Func<n>'. Either the RTTI vtable walk (BGS menu 9) "
                      'has not run on this program yet, or it has and the address library has '
                      'no row for any of the slots it left behind.')

            if stats['renamed']:
                prog.save('VR address library name import', monitor)
                print('saved.')
                return 0

            # Nothing was applied -- and that is two completely different outcomes that used to
            # share one console line and one exit code.
            #
            # already_named > 0 means the addresses DID resolve to functions and every one of
            # them already carried a real name. That is this script run twice, and it is the
            # success it looks like: not clobbering earlier work is the whole design.
            #
            # already_named == 0 means not one of the CSV's addresses resolved to a function at
            # all. Nothing was skipped for being done already, because nothing was ever there.
            # That is total failure -- the program has no functions yet, or it is the wrong
            # program -- and it must not hand back the same 0 as the re-run above, because the
            # agent that gates on the exit code proceeds through setup on it.
            if stats['already_named']:
                print('nothing applied; not saving. Every address that resolved to a function '
                      'already carried a real name -- an idempotent re-run, not a failure.')
                return 0
            print('nothing applied; not saving.')
            print(f"ERROR: not one of the {len(rows):,} CSV addresses resolved to a function in "
                  f"this program (no_func={stats['no_func']:,}, errored={stats['errored']:,}). "
                  f"Check that Ghidra's analysis has actually run on {path} and created "
                  "functions, and that this is the program the CSV describes.")
            return 1
        finally:
            prog.release(consumer)


if __name__ == '__main__':
    # main() returns the exit code rather than falling off the end. Reaching the last line of
    # a Python script is not evidence that it did anything, and this one is invoked unattended.
    sys.exit(main())
