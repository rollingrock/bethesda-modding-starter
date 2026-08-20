# Import Skyrim Address Library into Ghidra
# Applies function names and labels from the VR Address Library database
#
# @author ghidra_tool_dev
# @category SkyrimVR
# @menupath Tools.Skyrim VR.Import Address Library
# @runtime Jython

"""
Skyrim VR Address Library Importer for Ghidra

This script imports function names and symbols from the Skyrim VR Address Library
(database.csv) into the current Ghidra program.

Usage:
1. Open SkyrimVR.exe in Ghidra and run auto-analysis
2. Run this script from the Script Manager (Window -> Script Manager)
3. Select the database.csv file when prompted (or use default)
4. Wait for import to complete

The script will:
- Create labels at known addresses
- Create function definitions where appropriate
- Apply namespaces based on class names (e.g., Actor::StealAlarm -> Actor namespace)
- Track statistics on successful/failed imports

WHAT THE SUMMARY IS ALLOWED TO SAY
----------------------------------
A counter here counts what was APPLIED to the program, never what was attempted. That is not
a style preference: this pack's other importer once counted what VALIDATED rather than what
applied and reported a clean run while 2,027 writes had silently failed. The same shape was
live in this script in three places -- an unvalidated CSV whose every row was skipped
uncounted, a cancelled run, and a swallowed namespace failure -- all three of which ended at
the same unconditional 'Address Library Import Complete' banner and 'Import Complete!' popup.

So: the header is validated before a transaction is opened, every reason a row is not
imported has its own counter, the six per-entry outcomes add up to the number of entries the
loop actually reached, and the words 'Complete' and 'Import Complete!' appear only for a run
that ran to the end of the CSV and applied at least one symbol.
"""

import csv
import re
import os
import sys

from ghidra.program.model.symbol import SourceType, SymbolType, Namespace
from ghidra.program.model.listing import Function
from ghidra.app.cmd.function import CreateFunctionCmd


# The address library's confidence tier. Both games' CSVs use 2/3/4, and 3+ is the
# high-confidence tier this repo has always applied -- 46,348 of fo4_database.csv's 93,858
# rows clear it. Named rather than inlined so the census, the loop and every message that
# quotes the floor cannot drift apart.
MIN_STATUS = 3

# The three columns this script reads. Every real address-library CSV is
# `id,<flat address>,vr,status,name`, so a file missing any of them is not one -- and the
# damage a missing column does is silent: csv.DictReader hands back rows whose keys simply do
# not exist, row.get() defaults them to ''/'0', and every row then dies at the status test.
# A HEADERLESS file is worse still, because DictReader eats the first data row as the header,
# so no key exists for any of fo4_database.csv's remaining 93,857 rows -- and before this
# check the run ended on 'Total entries: 0 ... Errors: 0' under an 'Import Complete!' popup.
REQUIRED_COLUMNS = ('vr', 'status', 'name')

# How many namespace failures to quote in the summary before collapsing to a count. Same
# reasoning as apply_prototypes.py printing its first 5 apply failures: a bare number tells
# you something broke, a handful of examples tells you WHICH class name collided.
NS_FAILURE_EXAMPLES = 8


def parse_address(program, addr_str):
    """Convert hex string to Ghidra Address"""
    try:
        if addr_str.startswith('0x') or addr_str.startswith('0X'):
            addr_str = addr_str[2:]
        addr_long = long(addr_str, 16)
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_long)
    except:
        return None


def sanitize_symbol_name(name):
    """
    Sanitize a symbol name for Ghidra.
    Removes/replaces invalid characters.
    Called AFTER namespace splitting, so no :: expected.
    """
    if not name:
        return None

    # Strip any file reference metadata (e.g., "FuncName src/file.h:99")
    # These appear after a space followed by what looks like a path
    space_idx = name.find(' ')
    if space_idx > 0:
        remainder = name[space_idx+1:]
        # Check if remainder looks like a file path or source reference
        if '/' in remainder or '\\' in remainder or '.h' in remainder or '.cpp' in remainder:
            name = name[:space_idx]

    # Strip trailing line number references like ":99"
    colon_idx = name.rfind(':')
    if colon_idx > 0:
        after_colon = name[colon_idx+1:]
        if after_colon.isdigit():
            name = name[:colon_idx]

    # Replace characters invalid in Ghidra symbols
    # Valid: letters, digits, underscore
    # Invalid: spaces, slashes, colons, etc.
    invalid_chars = ' /\\:;,<>[]{}()!@#$%^&*+=|\'"`~-'
    for ch in invalid_chars:
        if ch in name:
            name = name.replace(ch, '_')

    # Clean up any double underscores
    while '__' in name:
        name = name.replace('__', '_')

    # Strip leading/trailing underscores
    name = name.strip('_')

    # Ensure name starts with letter or underscore
    if name and not (name[0].isalpha() or name[0] == '_'):
        name = '_' + name

    return name if name else None


def parse_name(raw_name):
    """
    Parse a function name like:
      'RE::TESForm::GetFormEditorID'
      'void Actor::StealAlarm(TESObjectREFR* a_ref, ...)'
      'BGSDefaultObjectManager* BGSDefaultObjectManager::GetSingleton()'

    Returns: (namespace_parts, function_name, is_function)
    """
    name = raw_name.strip()

    # First, strip any trailing file reference metadata
    # e.g., "AttackDistanceBase src/Hook_AttackStart.h:99"
    space_parts = name.split(' ')
    if len(space_parts) > 1:
        # Check if last part looks like a file reference
        last = space_parts[-1]
        if '/' in last or '\\' in last or '.h:' in last or '.cpp:' in last:
            # Remove the file reference part
            name = ' '.join(space_parts[:-1])

    # Remove RE:: prefix if present (CommonLib convention)
    if name.startswith('RE::'):
        name = name[4:]

    # Check if this looks like a function signature (has parentheses)
    is_function = '(' in name

    # Extract just the name part, handling return types
    # Pattern: "ReturnType ClassName::FuncName(...)" or just "ClassName::FuncName(...)"
    func_match = re.match(r'^(?:[^(]+?\s+)?([A-Za-z_][\w:]*)\s*\(', name)
    if func_match:
        name = func_match.group(1)
    else:
        # No parentheses, just take the whole thing
        paren_idx = name.find('(')
        if paren_idx > 0:
            name = name[:paren_idx].strip()

    # Split by :: to get namespace and function name
    parts = name.split('::')
    if len(parts) >= 2:
        namespace_parts = parts[:-1]
        func_name = parts[-1]
    else:
        namespace_parts = []
        func_name = parts[0] if parts else name

    func_name = func_name.strip()

    return namespace_parts, func_name, is_function


def classify_row(row):
    """Decide what one CSV row is, without touching the program.

    Returns (vr_string, name_string, verdict), where verdict is one of:

        'ok'            usable: has an address, has a name, status >= MIN_STATUS
        'below_status'  confidence below MIN_STATUS, or a status that is not a number
        'blank'         no vr address, or no name

    Both the pre-import census and the import loop call this, so the numbers printed before
    the run and the counters printed after it cannot be measuring different things -- which
    is the entire point of counting skips. Previously the loop's skip test
    ('status < 3 or not vr_addr or not name') incremented no counter at all, so a CSV that
    produced nothing but skips was indistinguishable in the summary from a CSV that
    contained nothing.

    A status that will not parse as an integer is reported as below the floor rather than as
    an error: a non-numeric status is not evidence of confidence, and this is what
    import_vr_names_headless.py does with the same data (its load_rows counts a TypeError or
    ValueError from int(row['status']) as skipped_status).
    """
    vr = (row.get('vr') or '').strip()
    name = (row.get('name') or '').strip()
    if not vr or not name:
        return vr, name, 'blank'
    try:
        status = int(row.get('status'))
    except (TypeError, ValueError):
        return vr, name, 'below_status'
    if status < MIN_STATUS:
        return vr, name, 'below_status'
    return vr, name, 'ok'


def scan_csv(csv_path):
    """Read the whole CSV once, before anything is written, and census it.

    Returns (census, error). `error` is None when the file is usable and a human-readable
    explanation otherwise; `census` is a dict of

        rows          data rows DictReader produced
        eligible      rows classify_row() calls 'ok'
        below_status  rows below MIN_STATUS (or with an unparseable status)
        blank         rows with no vr address or no name
        fieldnames    the header DictReader actually saw

    WHY THIS RUNS FIRST, AND WHY IT DOES NOT RAISE
    ----------------------------------------------
    The headless sibling in this directory validates reader.fieldnames and SystemExits on a
    missing column, then aborts again if no row is usable. This script needs both guards for
    the same reason -- it is driven by askFile, so the file it gets is whatever the user
    picked -- but it is a GUI script, so a SystemExit would surface as a Jython stack trace
    in the console rather than as something the person clicking Import can read. Hence an
    error string the caller turns into a popup, and a hard stop BEFORE
    startTransaction(): a run that never opens a transaction cannot half-write the program.

    The extra pass costs one read of the file (~93,858 rows, a fraction of a second) and
    replaces the old 'sum(1 for _ in f) - 1' line count, which was also wrong for any CSV
    with an embedded newline in a quoted field.
    """
    census = {'rows': 0, 'eligible': 0, 'below_status': 0, 'blank': 0, 'fieldnames': None}
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            census['fieldnames'] = fieldnames
            if not fieldnames:
                return census, "'{}' is empty -- no header row at all.".format(csv_path)

            missing = [c for c in REQUIRED_COLUMNS if c not in fieldnames]
            if missing:
                return census, (
                    "'{}' is missing the column(s) {} this script reads.\n\n"
                    "Header found: {}\n\n"
                    "An address library CSV looks like 'id,fo4,vr,status,name'. If that "
                    "header line is what you see above as data, the file has no header row "
                    "and its first entry was consumed as one.".format(
                        csv_path, ', '.join(missing), ', '.join(fieldnames)))

            for row in reader:
                census['rows'] += 1
                verdict = classify_row(row)[2]
                if verdict == 'ok':
                    census['eligible'] += 1
                elif verdict == 'below_status':
                    census['below_status'] += 1
                else:
                    census['blank'] += 1
    except:
        # Bare except: under Jython a Java IOException coming back through the file object
        # is not reliably caught by 'except Exception'.
        return census, "could not read '{}': {}".format(csv_path, sys.exc_info()[1])

    return census, None


def same_namespace(a, b):
    """True when two Namespace objects are the same namespace.

    Compared by symbol ID rather than with '!=', which on two Java objects Ghidra handed
    back at different moments is an identity test. A false 'the namespace differs' here is
    exactly how an entry got counted as 'updated' when nothing about it had changed.
    """
    if a is None or b is None:
        return a is b
    try:
        return a.getID() == b.getID()
    except:
        return a == b


def get_or_create_namespace(program, namespace_parts):
    """Get or create nested namespace/class.

    Returns (namespace, ok). When `ok` is False the requested namespace does NOT exist and
    `namespace` is the deepest ancestor that does -- usually global.

    WHY THE FLAG EXISTS: this used to swallow both failures with a bare 'except: pass' and
    return the parent as if it were the namespace that had been asked for. The caller cannot
    tell the difference by inspecting the returned object, so one collision -- createClass
    raises when the name is already held by a non-namespace symbol, which is ordinary Ghidra
    behaviour, not a hypothetical -- quietly dumped every 'Actor::*' entry into the global
    namespace while the summary counted each one as a successful import.
    """
    if not namespace_parts:
        return program.getGlobalNamespace(), True

    symbol_table = program.getSymbolTable()
    current_ns = program.getGlobalNamespace()

    for part in namespace_parts:
        # Look for existing namespace
        existing = symbol_table.getNamespace(part, current_ns)
        if existing:
            current_ns = existing
        else:
            # Create new class namespace (most Skyrim symbols are class members)
            try:
                current_ns = symbol_table.createClass(
                    current_ns, part, SourceType.IMPORTED)
            except:
                try:
                    current_ns = symbol_table.createNameSpace(
                        current_ns, part, SourceType.IMPORTED)
                except:
                    # Everything below this part is unreachable too, so stop here and hand
                    # back the fallback parent MARKED as a fallback.
                    return current_ns, False

    return current_ns, True


def try_set_namespace(setter, namespace, label_name, address, stats, ns_notes):
    """Call one of Ghidra's namespace setters, counting the failure instead of hiding it.

    `setter` is the bound method -- Function.setParentNamespace or Symbol.setNamespace.
    Returns True only when the namespace was actually assigned.

    All three call sites for this were 'try: ... except: pass' followed unconditionally by a
    success counter, so a DuplicateNameException or CircularDependencyException left the
    symbol sitting in the global namespace and the run still reported it as imported.
    """
    try:
        setter(namespace)
        return True
    except:
        # Bare except on purpose: these setters throw Java exceptions (DuplicateName,
        # CircularDependency, InvalidInput) and under Jython those are not reliably caught
        # by 'except Exception'.
        stats['namespace_failed'] += 1
        if ns_notes is not None and len(ns_notes) < NS_FAILURE_EXAMPLES:
            ns_notes.append("{} at {}: {}".format(
                label_name, address, sys.exc_info()[1]))
        return False


def import_entry(program, address, namespace_parts, label_name, is_function, stats,
                 create_funcs=True, overwrite=False, ns_notes=None):
    """Import a single address library entry.

    Every path out of here increments EXACTLY ONE of labels/functions/updated/skipped/
    unchanged/errors, so those six add up to the number of entries handed in. run() checks
    that arithmetic and complains if it ever stops holding.

    'namespace_failed' is a SEPARATE axis and deliberately not part of that sum: the symbol
    still exists, it is just not where the CSV said it belongs, so it is reported alongside
    the outcome rather than folded into it. The one case where a namespace failure decides
    the outcome is an entry whose ONLY intended change was the namespace -- that one is
    'unchanged', because nothing about the program differs afterwards and calling it
    'updated' is the precise defect this counter was added to stop.
    """
    symbol_table = program.getSymbolTable()
    function_manager = program.getFunctionManager()

    try:
        # Check for existing non-default symbol (preserve USER_DEFINED and ANALYSIS).
        #
        # This runs BEFORE the namespace is resolved, where it used to run after. Two
        # reasons, both about the report telling the truth: a skipped entry should not
        # leave an empty class namespace behind as though it had been imported, and
        # 'namespace_failed' must count only entries this run actually tried to import --
        # otherwise a re-run with overwrite off, which skips everything, would report
        # thousands of namespace failures for entries it never touched.
        existing_symbols = list(symbol_table.getSymbols(address))
        for sym in existing_symbols:
            src = sym.getSource()
            if (src == SourceType.USER_DEFINED or src == SourceType.ANALYSIS) and not overwrite:
                stats['skipped'] += 1
                return

        namespace, ns_ok = get_or_create_namespace(program, namespace_parts)
        if not ns_ok:
            stats['namespace_failed'] += 1
            if ns_notes is not None and len(ns_notes) < NS_FAILURE_EXAMPLES:
                ns_notes.append("{} at {}: cannot create namespace '{}'".format(
                    label_name, address, '::'.join(namespace_parts)))

        # When the requested namespace could not be created, `namespace` is an ANCESTOR of
        # it, so assigning it to an EXISTING symbol would be a regression rather than a
        # no-op: on a re-run it would move an already correctly-namespaced symbol back down
        # into global. New symbols still get created under the fallback parent (a named
        # symbol in the wrong namespace beats FUN_140a1b2c0), and the count above is what
        # makes that visible.
        ns_assignable = ns_ok

        # Check for existing function
        existing_func = function_manager.getFunctionAt(address)

        if is_function and create_funcs:
            if existing_func:
                # Update existing function name if different
                name_differs = existing_func.getName() != label_name
                ns_differs = ns_assignable and not same_namespace(
                    existing_func.getParentNamespace(), namespace)
                if not name_differs and not ns_differs:
                    # Nothing left to do -- unless the reason there is nothing left to do is
                    # that the namespace could not be created, which is not agreement.
                    stats['skipped' if ns_ok else 'unchanged'] += 1
                    return
                changed = False
                if name_differs:
                    existing_func.setName(label_name, SourceType.IMPORTED)
                    changed = True
                if ns_differs and try_set_namespace(existing_func.setParentNamespace,
                                                   namespace, label_name, address,
                                                   stats, ns_notes):
                    changed = True
                stats['updated' if changed else 'unchanged'] += 1
            else:
                # Try to create function
                cmd = CreateFunctionCmd(address)
                if cmd.applyTo(program):
                    new_func = function_manager.getFunctionAt(address)
                    if new_func:
                        new_func.setName(label_name, SourceType.IMPORTED)
                        if ns_assignable:
                            try_set_namespace(new_func.setParentNamespace, namespace,
                                              label_name, address, stats, ns_notes)
                        stats['functions'] += 1
                    else:
                        # Fallback to label
                        symbol_table.createLabel(address, label_name, namespace, SourceType.IMPORTED)
                        stats['labels'] += 1
                else:
                    # Couldn't create function, make label
                    symbol_table.createLabel(address, label_name, namespace, SourceType.IMPORTED)
                    stats['labels'] += 1
        else:
            # Just create label
            primary = symbol_table.getPrimarySymbol(address)
            if primary and primary.getSource() != SourceType.DEFAULT:
                if overwrite:
                    name_differs = primary.getName() != label_name
                    ns_differs = ns_assignable and not same_namespace(
                        primary.getParentNamespace(), namespace)
                    changed = False
                    if name_differs:
                        primary.setName(label_name, SourceType.IMPORTED)
                        changed = True
                    if ns_differs and try_set_namespace(primary.setNamespace, namespace,
                                                        label_name, address, stats, ns_notes):
                        changed = True
                    stats['updated' if changed else 'unchanged'] += 1
                else:
                    stats['skipped'] += 1
            else:
                symbol_table.createLabel(address, label_name, namespace, SourceType.IMPORTED)
                stats['labels'] += 1

    except:
        # BARE except, not 'except Exception'. Verified against the Jython 2.7.3 that Ghidra
        # 11.2 ships (Ghidra/Features/Jython/lib/jython-standalone-2.7.3.jar): a Java
        # throwable raised inside Jython is NOT matched by 'except Exception' -- only a bare
        # except (or 'except java.lang.Throwable') catches it. And every write this function
        # performs raises a CHECKED Java exception, per the interfaces in SoftwareModeling.jar:
        #
        #   SymbolTable.createLabel(..) throws InvalidInputException
        #   Symbol.setName(..)          throws DuplicateNameException, InvalidInputException
        #   FunctionDB.setParentNamespace(..) throws DuplicateName/InvalidInput/CircularDependency
        #
        # So with the narrow clause this handler was dead for every failure Ghidra actually
        # raises: a single DuplicateNameException on entry 3 of 46,348 escaped run()'s
        # handler too, aborted the whole import, left the transaction OPEN, and printed no
        # summary at all. 'one bad entry should not abort 46,000' only holds with a bare
        # except here.
        stats['errors'] += 1


def run():
    """Main script entry point"""

    # Check program is open
    if currentProgram is None:
        popup("No program is open. Please open SkyrimVR.exe first.")
        return

    # Default CSV path
    default_path = r"C:\repos\vr_address_tools\skyrim_vr_address_library\database.csv"

    # Get CSV file path
    if os.path.exists(default_path):
        use_default = askYesNo("Address Library",
            "Use default database.csv?\n\n" + default_path)
        if use_default:
            csv_path = default_path
        else:
            csv_file = askFile("Select Address Library CSV", "Import")
            if csv_file is None:
                return
            csv_path = csv_file.getAbsolutePath()
    else:
        csv_file = askFile("Select Address Library CSV", "Import")
        if csv_file is None:
            return
        csv_path = csv_file.getAbsolutePath()

    # Validate and census the CSV BEFORE asking anything else and before opening a
    # transaction. A file that cannot produce a single import must fail here, where nothing
    # has been written and the message can name the actual problem -- not at the end, where
    # the only report was a summary of zeroes under an 'Import Complete!' popup.
    census, error = scan_csv(csv_path)
    if error:
        printerr("Address Library import ABORTED: " + error)
        popup("Address Library import ABORTED\n\n" + error +
              "\n\nNothing was imported.")
        return

    println("CSV: {}".format(csv_path))
    println("  data rows                : {}".format(census['rows']))
    println("  usable (status >= {})     : {}".format(MIN_STATUS, census['eligible']))
    println("  below status {}           : {}".format(MIN_STATUS, census['below_status']))
    println("  blank vr address or name : {}".format(census['blank']))

    if census['eligible'] == 0:
        # Same guard as import_vr_names_headless.py's 'ERROR: nothing to apply.' -- the
        # header parsed, so this is a real address-library-shaped file, but not one row in
        # it clears the confidence floor or carries both an address and a name. There is
        # nothing to import, and 'nothing to import' is not a successful import.
        message = ("'{}' has {} data rows and NONE of them are usable:\n"
                   "  {} below status {}\n"
                   "  {} with a blank vr address or name\n\n"
                   "Nothing was imported. Check that this is a VR address library CSV for "
                   "the right game -- the 'vr' column must hold the VR address, and only "
                   "status >= {} entries are applied.").format(
                       csv_path, census['rows'], census['below_status'], MIN_STATUS,
                       census['blank'], MIN_STATUS)
        printerr("Address Library import ABORTED: nothing usable in " + csv_path)
        popup("Address Library import ABORTED\n\n" + message)
        return

    # Options
    create_functions = askYesNo("Import Options",
        "Create function definitions?\n\n(Recommended: Yes)")

    overwrite = askYesNo("Import Options",
        "Overwrite existing labels?\n\n(Recommended: No)")

    println("Importing {} entries from Address Library...".format(census['eligible']))
    monitor.setMaximum(census['rows'])
    monitor.setProgress(0)

    # Statistics.
    #
    # 'total' is eligible entries the loop REACHED, which is what makes a cancelled run
    # legible: census['eligible'] - stats['total'] is how much of the file never got looked
    # at. skipped_status/skipped_blank exist because the old skip test incremented nothing,
    # so a CSV whose every row was skipped and a CSV that imported cleanly printed the same
    # zeroes. 'unchanged' and 'namespace_failed' are the two ways an entry can be touched
    # without anything about the program actually changing.
    stats = {
        'total': 0,
        'labels': 0,
        'functions': 0,
        'updated': 0,
        'skipped': 0,
        'unchanged': 0,
        'invalid': 0,
        'errors': 0,
        'skipped_status': 0,
        'skipped_blank': 0,
        'namespace_failed': 0
    }
    ns_notes = []
    cancelled = False
    rows_read = 0

    # Start transaction
    tx = currentProgram.startTransaction("Import Address Library")
    # Tracks whether `tx` is still open. The success path ends the transaction and then keeps
    # running (summary, namespace notes, popup) INSIDE the same try, so without this flag an
    # exception raised after that point would call endTransaction on an already-closed id and
    # replace the real error with an IllegalStateException from Ghidra.
    tx_open = True
    commit_interval = 500  # Commit every 500 entries to avoid huge transactions

    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            processed = 0

            for i, row in enumerate(reader):
                if monitor.isCancelled():
                    cancelled = True
                    println("Import cancelled by user at CSV row {} of {}".format(
                        rows_read, census['rows']))
                    break

                monitor.setProgress(i)
                rows_read = i + 1

                # Skip low confidence or empty entries -- counted, one counter per reason,
                # so the summary can distinguish 'this CSV had nothing to give' from 'this
                # CSV was fine and the import did nothing'.
                vr_addr, name, verdict = classify_row(row)
                if verdict == 'below_status':
                    stats['skipped_status'] += 1
                    continue
                if verdict == 'blank':
                    stats['skipped_blank'] += 1
                    continue

                stats['total'] += 1

                # Parse address
                address = parse_address(currentProgram, vr_addr)
                if address is None:
                    stats['invalid'] += 1
                    continue

                # Parse name
                namespace_parts, label_name, is_function = parse_name(name)
                if not label_name:
                    stats['errors'] += 1
                    continue

                # Sanitize the label name for Ghidra
                label_name = sanitize_symbol_name(label_name)
                if not label_name:
                    stats['errors'] += 1
                    continue

                # Also sanitize namespace parts
                namespace_parts = [sanitize_symbol_name(p) for p in namespace_parts]
                namespace_parts = [p for p in namespace_parts if p]  # Remove None/empty

                # Import
                import_entry(currentProgram, address, namespace_parts, label_name,
                            is_function, stats, create_functions, overwrite, ns_notes)

                processed += 1

                # Periodic transaction commit to avoid memory issues
                if processed % commit_interval == 0:
                    currentProgram.endTransaction(tx, True)
                    println("Committed {} entries (Labels: {}, Functions: {}, Errors: {})".format(
                        processed, stats['labels'], stats['functions'], stats['errors']))
                    tx = currentProgram.startTransaction("Import Address Library (batch {})".format(processed))

                # Progress update
                if i % 100 == 0:
                    monitor.setMessage("Processed {} entries...".format(i))

        # COMMIT, including after a cancel, and say so below.
        #
        # This is a deliberate choice, not the default falling through. The loop commits
        # every 500 entries (commit_interval), so by the time anyone can click Cancel the
        # earlier batches are already committed and unreachable from here -- rolling this
        # last transaction back would discard up to 499 entries the user watched being
        # applied while leaving the thousands before them in the program. The run is partial
        # either way; a rollback would only move the boundary and make it less predictable.
        # So the partial import stands, and the report has to tell the user it stands:
        # silently committing a partial import is defensible only if they are told.
        currentProgram.endTransaction(tx, True)
        tx_open = False

        applied = stats['labels'] + stats['functions'] + stats['updated']

        # The banner reports OBSERVED state. 'Complete' is earned by reaching the end of the
        # CSV and applying at least one symbol; anything else says what actually happened.
        #
        # 'nothing to do' is separated from 'failed' on purpose. Running this script twice is
        # normal -- the second run skips every entry because the symbols are already there --
        # and calling that a failure would teach the reader to ignore the word. Neither one
        # is allowed to say 'Complete'.
        if cancelled:
            outcome = 'cancelled'
            headline = "Address Library Import CANCELLED - PARTIAL"
        elif applied == 0 and stats['total'] and stats['skipped'] == stats['total']:
            outcome = 'nothing_to_do'
            headline = "Address Library Import: NOTHING TO DO - all entries already present"
        elif applied == 0:
            outcome = 'failed'
            headline = "Address Library Import FAILED - NOTHING WAS IMPORTED"
        else:
            outcome = 'complete'
            headline = "Address Library Import Complete"

        # Summary
        println("")
        println("=" * 50)
        println(headline)
        println("=" * 50)
        println("CSV rows read: {} of {}".format(rows_read, census['rows']))
        println("  Skipped, below status {}: {}".format(MIN_STATUS, stats['skipped_status']))
        println("  Skipped, blank vr/name: {}".format(stats['skipped_blank']))
        println("Eligible entries reached: {} of {}".format(stats['total'], census['eligible']))
        println("  Labels created: {}".format(stats['labels']))
        println("  Functions created: {}".format(stats['functions']))
        println("  Updated: {}".format(stats['updated']))
        println("  Skipped (existing): {}".format(stats['skipped']))
        println("  Unchanged (nothing applied): {}".format(stats['unchanged']))
        println("  Invalid addresses: {}".format(stats['invalid']))
        println("  Errors: {}".format(stats['errors']))
        println("APPLIED (labels + functions + updated): {}".format(applied))

        # The six per-entry outcomes must account for every eligible entry the loop reached.
        # If they ever stop doing that, some path is either double-counting or returning
        # without counting -- which is exactly how this script came to report zeroes as a
        # success -- so it is checked rather than assumed.
        accounted = (stats['labels'] + stats['functions'] + stats['updated'] +
                     stats['skipped'] + stats['unchanged'] + stats['invalid'] +
                     stats['errors'])
        if accounted != stats['total']:
            printerr("BUG in this script: {} entries were imported but {} outcomes were "
                     "counted. The numbers above do not add up and should not be "
                     "trusted.".format(stats['total'], accounted))

        if stats['namespace_failed']:
            # Not folded into the counts above: these symbols exist, they are just not in
            # the namespace the CSV asked for (a 'Actor::' member sitting flat in global,
            # indistinguishable from a free function). Silence here is what made thousands
            # of them look like clean imports.
            println("")
            println("Namespace NOT applied: {} entr{} -- the class namespace could not be "
                    "created or assigned, so the symbol is in a parent namespace (usually "
                    "global) instead.".format(
                        stats['namespace_failed'],
                        'y' if stats['namespace_failed'] == 1 else 'ies'))
            for note in ns_notes:
                println("    {}".format(note))
            if stats['namespace_failed'] > len(ns_notes):
                println("    ... and {} more".format(stats['namespace_failed'] - len(ns_notes)))

        if cancelled:
            println("")
            println("Cancelled at CSV row {} of {}: {} eligible entries were never "
                    "reached.".format(rows_read, census['rows'],
                                      census['eligible'] - stats['total']))
            println("What had been applied is COMMITTED, not rolled back -- each {}-entry "
                    "batch was its own transaction, so undoing the whole import means one "
                    "Undo per batch. Re-running the script finishes the job instead: "
                    "existing symbols are preserved unless you answer Yes to "
                    "overwrite.".format(commit_interval))
        println("=" * 50)

        ns_line = ""
        if stats['namespace_failed']:
            ns_line = "\nNamespace NOT applied: {}".format(stats['namespace_failed'])

        # The popup is the last thing a GUI user sees and the only thing they are guaranteed
        # to read, so it carries the verdict, not just the two numbers that look best.
        if outcome == 'cancelled':
            popup("Import CANCELLED - PARTIAL\n\n"
                  "Stopped at CSV row {} of {}.\n"
                  "{} of {} eligible entries were never reached.\n\n"
                  "Applied so far, and COMMITTED (not rolled back):\n"
                  "  Labels: {}\n  Functions: {}\n  Updated: {}{}\n\n"
                  "Re-run the script to finish the import.\n"
                  "See console for the full breakdown.".format(
                      rows_read, census['rows'],
                      census['eligible'] - stats['total'], census['eligible'],
                      stats['labels'], stats['functions'], stats['updated'], ns_line))
        elif outcome == 'nothing_to_do':
            popup("Nothing to do\n\n"
                  "All {} eligible entries already exist in this program, so no symbol was "
                  "applied.{}\n\n"
                  "If you expected changes, answer Yes to 'Overwrite existing labels?' or "
                  "check you picked the CSV for this game.".format(stats['total'], ns_line))
        elif outcome == 'failed':
            popup("Import FAILED - NOTHING WAS IMPORTED\n\n"
                  "{} eligible entries were processed and no symbol was applied:\n"
                  "  Skipped (existing): {}\n"
                  "  Unchanged (nothing applied): {}\n"
                  "  Invalid addresses: {}\n"
                  "  Errors: {}{}\n\n"
                  "See console for the full breakdown.".format(
                      stats['total'], stats['skipped'], stats['unchanged'],
                      stats['invalid'], stats['errors'], ns_line))
        else:
            popup("Import Complete!\n\n"
                  "Labels: {}\nFunctions: {}\nUpdated: {}{}\n\n"
                  "See console for details.".format(
                      stats['labels'], stats['functions'], stats['updated'], ns_line))

    except:
        # BARE except for the same reason as import_entry's, and it matters more here: with
        # 'except Exception' this entire block was unreachable for any Java throwable, so a
        # failure from Ghidra killed the script with a raw Jython traceback, no popup, and --
        # worst of all -- an OPEN transaction left on the program.
        e = sys.exc_info()[1]

        # Rolls back the CURRENT batch only: every earlier commit_interval batch is already
        # committed, so the program is left partially imported. Say that, rather than
        # letting 'Import failed' imply nothing was written.
        if tx_open:
            currentProgram.endTransaction(tx, False)
            batch_note = ("The current batch was rolled back, but {} symbols applied in "
                          "earlier {}-entry batches are already COMMITTED -- the program is "
                          "partially imported.".format(
                              stats['labels'] + stats['functions'] + stats['updated'],
                              commit_interval))
        else:
            # The import itself finished and committed; this failed while REPORTING it.
            batch_note = ("The import itself had already been COMMITTED -- this failed while "
                          "printing the summary, so the program is fine but the numbers "
                          "above are incomplete.")

        printerr("Import FAILED at CSV row {} of {}: {}".format(
            rows_read, census['rows'], e))
        printerr(batch_note)
        try:
            import traceback
            traceback.print_exc()
        except:
            # Never let a failure to PRINT the traceback swallow the popup below, which is
            # the only thing a GUI user is guaranteed to see.
            pass
        popup("Import FAILED\n\n"
              "Stopped at CSV row {} of {}:\n{}\n\n{}\n\n"
              "See console for the stack trace.".format(
                  rows_read, census['rows'], e, batch_note))


# Run the script
run()
