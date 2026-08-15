# Ghidra scripts

## ImportAddressLibrary.py

Bulk-imports function names/labels from a VR Address Library CSV into the current Ghidra
program (~17K names for Skyrim VR). Works on **both** games' CSVs — the script reads the
`vr`, `status` and `name` columns, which are common to:

- Skyrim VR: `vr_address_tools/skyrim_vr_address_library/database.csv`
- Fallout 4 VR: `vr_address_tools/fallout_vr_address_library/fo4_database.csv`
  (much smaller coverage — hundreds of names, not tens of thousands)

It prompts for the CSV (the built-in default points at the Skyrim path under `C:\repos`).
Only entries with `status >= 3` (high confidence) are applied.

### Requirements

- **The Jython extension.** Ghidra 12.x ships Jython as an *optional* extension and these
  scripts declare `@runtime Jython`. Install it once via `File > Install Extensions`
  (it's bundled with the Ghidra distribution) and restart — otherwise the Script Manager
  refuses to run the script.
- Run it from the Script Manager (`Window > Script Manager`) with your game program open
  **after auto-analysis has completed**.

### Tip for agents

Anything shaped "for each X in the program, tell me Y" should be a single
`run_script_inline` call through the Ghidra MCP bridge (full Ghidra Java, runs
in-process) rather than N round-trip tool calls. See `docs/GHIDRA_WORKFLOW.md`.
