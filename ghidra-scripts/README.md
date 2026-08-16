# Ghidra scripts

> BethesdaGhidraScripts (cloned by `setup/20-repos.ps1`) automates types + vtable layouts +
> function signatures headlessly and is the main pipeline — see `../docs/GHIDRA_WORKFLOW.md`.
> But it is **not** a superset of what is here. For **Fallout 4 VR specifically** it has no
> address-library function symbols at all and names VR by porting byte signatures from a flat
> build, so a VR-only machine gets almost nothing from it. The address-library import below is
> not a fallback in that case — it is the primary source of real VR function names.
>
> Measured on F4VR 1.2.72, no flat Fallout 4 staged:
>
> | Step | Named functions (of 216,891) |
> |---|---|
> | BGS option 7 alone | 13 (0.0%) — then rolled back by its own check |
> | + BGS option 9 (RTTI vtable walk) | 34,507 (15.9%) — but as `Func42` slot placeholders |
> | + `import_vr_names_headless.py` | **60,427 (27.9%)**, of which **26,355 real C++ signatures** |
>
> The two sources are near-disjoint (only 1 collision across 26,411 applies), so run both.

## ImportAddressLibrary.py (fallback)

Bulk-imports function names/labels from a VR Address Library CSV into the current Ghidra
program. Works on **both** games' CSVs — the script reads the `vr`, `status` and `name`
columns, which are common to:

- Skyrim VR: `vr_address_tools/skyrim_vr_address_library/database.csv` (~17K names)
- Fallout 4 VR: `vr_address_tools/fallout_vr_address_library/fo4_database.csv` —
  **93,858 rows, every one carrying both a VR address and a demangled C++ signature;
  46,348 of them at `status >= 3`.** (An earlier version of this file called F4VR coverage
  "much smaller". Measured, it is the single best source of VR function names there is, and
  it needs no flat Fallout 4 binary — see `import_vr_names_headless.py` below.)

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
