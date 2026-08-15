# Ghidra scripts

> **Superseded for real work by [BethesdaGhidraScripts](https://github.com/1001Bits/BethesdaGhidraScripts)**
> (cloned by `setup/20-repos.ps1`), which automates types + vtable layouts + function
> signatures + address-library names for every supported game, headlessly — see
> `../docs/GHIDRA_WORKFLOW.md`. The script below remains as a minimal names-only fallback.

## ImportAddressLibrary.py (fallback)

Bulk-imports function names/labels from a VR Address Library CSV into the current Ghidra
program. Works on **both** games' CSVs — the script reads the `vr`, `status` and `name`
columns, which are common to:

- Skyrim VR: `vr_address_tools/skyrim_vr_address_library/database.csv` (~17K names)
- Fallout 4 VR: `vr_address_tools/fallout_vr_address_library/fo4_database.csv`
  (much smaller coverage)

It prompts for the CSV (the built-in default points at the Skyrim path under `C:\repos`).
Only entries with `status >= 3` (high confidence) are applied.

### Requirements

- **The Jython extension.** Ghidra 12.x ships Jython as an *optional* extension and this
  script declares `@runtime Jython`. Install it once via `File > Install Extensions`
  (it's bundled with the Ghidra distribution) and restart — otherwise the Script Manager
  refuses to run the script.
- Run it from the Script Manager (`Window > Script Manager`) with your game program open
  **after auto-analysis has completed**.

### Tip for agents

Anything shaped "for each X in the program, tell me Y" should be a single
`run_script_inline` call through the Ghidra MCP bridge (full Ghidra Java, runs
in-process) rather than N round-trip tool calls. See `docs/GHIDRA_WORKFLOW.md`.
