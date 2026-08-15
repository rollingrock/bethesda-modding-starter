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
"""

import csv
import re
import os

from ghidra.program.model.symbol import SourceType, SymbolType, Namespace
from ghidra.program.model.listing import Function
from ghidra.app.cmd.function import CreateFunctionCmd


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


def get_or_create_namespace(program, namespace_parts):
    """Get or create nested namespace/class"""
    if not namespace_parts:
        return program.getGlobalNamespace()

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
                    pass  # Keep current if we can't create

    return current_ns


def import_entry(program, address, namespace_parts, label_name, is_function, stats, create_funcs=True, overwrite=False):
    """Import a single address library entry"""
    symbol_table = program.getSymbolTable()
    function_manager = program.getFunctionManager()

    try:
        namespace = get_or_create_namespace(program, namespace_parts)

        # Check for existing non-default symbol (preserve USER_DEFINED and ANALYSIS)
        existing_symbols = list(symbol_table.getSymbols(address))
        for sym in existing_symbols:
            src = sym.getSource()
            if (src == SourceType.USER_DEFINED or src == SourceType.ANALYSIS) and not overwrite:
                stats['skipped'] += 1
                return

        # Check for existing function
        existing_func = function_manager.getFunctionAt(address)

        if is_function and create_funcs:
            if existing_func:
                # Update existing function name if different
                if existing_func.getName() != label_name or existing_func.getParentNamespace() != namespace:
                    existing_func.setName(label_name, SourceType.IMPORTED)
                    try:
                        existing_func.setParentNamespace(namespace)
                    except:
                        pass
                    stats['updated'] += 1
                else:
                    stats['skipped'] += 1
            else:
                # Try to create function
                cmd = CreateFunctionCmd(address)
                if cmd.applyTo(program):
                    new_func = function_manager.getFunctionAt(address)
                    if new_func:
                        new_func.setName(label_name, SourceType.IMPORTED)
                        try:
                            new_func.setParentNamespace(namespace)
                        except:
                            pass
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
                    primary.setName(label_name, SourceType.IMPORTED)
                    try:
                        primary.setNamespace(namespace)
                    except:
                        pass
                    stats['updated'] += 1
                else:
                    stats['skipped'] += 1
            else:
                symbol_table.createLabel(address, label_name, namespace, SourceType.IMPORTED)
                stats['labels'] += 1

    except Exception as e:
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

    # Options
    create_functions = askYesNo("Import Options",
        "Create function definitions?\n\n(Recommended: Yes)")

    overwrite = askYesNo("Import Options",
        "Overwrite existing labels?\n\n(Recommended: No)")

    # Count lines for progress
    with open(csv_path, 'r') as f:
        total_lines = sum(1 for _ in f) - 1

    println("Importing {} entries from Address Library...".format(total_lines))
    monitor.setMaximum(total_lines)
    monitor.setProgress(0)

    # Statistics
    stats = {
        'total': 0,
        'labels': 0,
        'functions': 0,
        'updated': 0,
        'skipped': 0,
        'invalid': 0,
        'errors': 0
    }

    # Start transaction
    tx = currentProgram.startTransaction("Import Address Library")
    commit_interval = 500  # Commit every 500 entries to avoid huge transactions

    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            processed = 0

            for i, row in enumerate(reader):
                if monitor.isCancelled():
                    println("Import cancelled by user")
                    break

                monitor.setProgress(i)

                # Parse row
                try:
                    vr_addr = row.get('vr', '')
                    status = int(row.get('status', '0'))
                    name = row.get('name', '')
                except:
                    stats['errors'] += 1
                    continue

                # Skip low confidence or empty entries
                if status < 3 or not vr_addr or not name:
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
                            is_function, stats, create_functions, overwrite)

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

        currentProgram.endTransaction(tx, True)

        # Summary
        println("")
        println("=" * 50)
        println("Address Library Import Complete")
        println("=" * 50)
        println("Total entries: {}".format(stats['total']))
        println("Labels created: {}".format(stats['labels']))
        println("Functions created: {}".format(stats['functions']))
        println("Updated: {}".format(stats['updated']))
        println("Skipped (existing): {}".format(stats['skipped']))
        println("Invalid addresses: {}".format(stats['invalid']))
        println("Errors: {}".format(stats['errors']))
        println("=" * 50)

        popup("Import Complete!\n\n" +
              "Labels: {}\nFunctions: {}\n\nSee console for details.".format(
                  stats['labels'], stats['functions']))

    except Exception as e:
        currentProgram.endTransaction(tx, False)
        printerr("Import failed: " + str(e))
        import traceback
        traceback.print_exc()


# Run the script
run()
