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

## `apply_prototypes.py` — turn the signature in a NAME into an applied prototype

The name import above sets names only, so the decompiler still shows
`(undefined4 *param_1, longlong param_2, ...)` even though the name says
`Allocate(NiPoint3&,TESObjectCELL*,TESWorldSpace*,float,float)`. This parses those names
and applies them with `/set_function_prototype`. It talks HTTP to the **headless** MCP
server (`setup/36-ghidra-mcp.ps1 -Start`); no pyghidra, no GUI.

```powershell
python apply_prototypes.py fetch                       # ~20 s
python apply_prototypes.py probe --only-resolvable     # SLOW, resumable (see below)
python apply_prototypes.py report                      # tiers + writes plan.json
python apply_prototypes.py apply                       # DRY RUN: validates, writes nothing
python apply_prototypes.py apply --tier 1 --apply      # commits
```

**Back up the project first.** This writes to a database that took hours to build. Every
applied change is journalled to `.proto-cache/journal.jsonl`.

### Measured on F4VR (2026-08-16)

25,867 functions carry a signature in their name. After probing all of them:

| | |
|---|---|
| **Tier 1** — every argument typed | **9,437** |
| **Tier 2** — some arguments `void *` | **3,671** |
| Tier 3 — skipped | 12,759 |
| &nbsp;&nbsp;ambiguous this-ness | 6,032 |
| &nbsp;&nbsp;no argument type resolves | 5,571 |
| &nbsp;&nbsp;inferred arity exceeds args+1 | 1,155 |

**13,108 prototypes planned; all 13,108 validated by Ghidra's own parser, 0 rejected.**
Of those, 4,176 get a typed `this`, 8,689 get `void * this` (the class type does not exist),
and 243 are free functions with no `this` at all.

`void * this` is still worth having: it marks the this-pointer so every *other* parameter
lands in the right position, which is where most of the value is. It just gives no field
access on `this` itself.

The probe costs ~350 ms/function — the decompiler, not HTTP — so about 100 minutes for the
full corpus on this machine. It is resumable, and `--from-plan` re-probes only what a plan
already contains.

### Why it is more than a string substitution

A demangled C++ name is missing two things, and both will bite:

- **No `this`.** Prepending one when the method is static shifts every parameter by one —
  strictly worse than leaving the function alone. Nothing in the source data records
  static vs instance (the address-library CSV is `id,fo4,vr,status,name`; BGS's PDB
  publics corpus is already demangled with no access specifiers). The only local signal is
  Ghidra's decompiler arity, which can undercount but never overcount, so `inferred ==
  args+1` proves a `this` and `inferred == args` is genuinely ambiguous. Measured on 150
  functions: **67% decisive, 26% ambiguous**. The ambiguous ones are skipped, not guessed.
- **No return type.** Emitting `void` would destroy the decompiler's own inference, so
  every prototype returns `undefined8` — Ghidra's honest "unknown 8 bytes".

### Most of the type inventory is unusable, which is the real limit

The program reports ~45,700 data types, but that number is misleading:
**32,182 have template arguments in their name and 27,813 of those are 1-byte stubs.**
`NiPointer`, `BSTSmartPointer`, `CArgs` and `StreamRequest` are all 1 byte. Pointing a
parameter at one makes the decompiler confidently misreport field offsets — worse than
leaving it undefined. Worse still, bare leaf names are ambiguous: **four unrelated types
in this program are called `Entry`.**

So resolution is strict by default — a type must match verbatim and not be a stub.
Measured across all 25,867 signature-carrying functions:

| | args |
|---|---|
| exact type match | 14,194 |
| builtin (int/float/bool/...) | 10,443 |
| recovered by normalising `RE::` | 241 |
| **unresolved** | **22,429** |

Unresolved parameters become `void *` in Tier 2 rather than a wrong struct. `--loose`
relaxes this to accept a template's base name; it is off by default for the reasons above.

The `RE::` normalisation is worth explaining because it looks like a bigger win than it is.
Ghidra stores template arguments with the namespace (`NiPointer<RE::TESObjectREFR>`, 8 bytes,
a real layout) while the pipeline's names omit it (`NiPointer<TESObjectREFR>`). Canonicalising
both sides is a normalisation rather than a guess, so it is trusted like an exact match — but
measured, it recovers only **241 of 47,363 tokens (0.5%)**.

**The remaining gap is not an import gap.** Checked against CommonLibF4's headers directly:
of the 19 most frequent unresolved tokens, **14 exist in neither the program's type manager
nor CommonLibF4's source** — `hkQsTransformf`, `hkbContext`, `hkaSkeleton`,
`hkbBehaviorGraph`, `BSScrapArray`, `BSTScatterTableEntry`, `BGSProcessContext` and so on.
Zero were "in the headers but not imported". So BGS's type import is complete with respect to
CommonLibF4, and closing this gap means **authoring type definitions that do not exist
anywhere yet** — a real project, not a re-run of the importer.

### Gotcha found the hard way

`/decompile_function?functions=` **silently caps a batch at 20**. Ask for 25 and exactly 20
come back, tail dropped, no error, nothing in the endpoint's description. The probe phase
detects short responses and re-fetches the remainder individually, so a future change to
the cap costs speed rather than coverage.

### Tip for agents

Anything shaped "for each X in the program, tell me Y" should be a single
`run_script_inline` call through the Ghidra MCP bridge (full Ghidra Java, runs
in-process) rather than N round-trip tool calls. See `docs/GHIDRA_WORKFLOW.md`.
