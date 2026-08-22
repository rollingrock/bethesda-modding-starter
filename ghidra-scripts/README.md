# Ghidra scripts

> BethesdaGhidraScripts (cloned by `setup/20-repos.ps1`) automates types + vtable layouts +
> function signatures headlessly and is the main pipeline — see `../docs/GHIDRA_WORKFLOW.md`.
> But it is **not** a superset of what is here. For **Fallout 4 VR specifically** it has no
> address-library function symbols at all and names VR by porting byte signatures from a flat
> build, so a VR-only machine gets almost nothing from it. The address-library import is not a
> fallback in that case — it is the primary source of real VR function names.
>
> Measured 2026-08-16 on F4VR 1.2.72, no flat Fallout 4 staged. The denominator moves as
> analysis runs — BGS's improve pass alone creates ~16,000 functions
> (`setup\35-ghidra-analysis.ps1` records 201,005 → 216,903 across it) — so a function count
> quoted elsewhere in this pack is not this one.
>
> | Step | Named functions (of 216,891) |
> |---|---|
> | BGS option 7 alone | 13 (0.0%) — then rolled back by its own check |
> | + BGS option 9 (RTTI vtable walk) | 34,507 (15.9%) — but as `Func42` slot placeholders |
> | + `import_vr_names_headless.py` | **60,427 (27.9%)**, of which **26,355 real C++ signatures** |
>
> The two sources are near-disjoint (only 1 collision across 26,411 applies), so run both.

## `import_vr_names_headless.py` — the names, unattended

Applies a VR Address Library CSV to a program inside a Ghidra project under pyghidra. No GUI,
no Jython extension, no flat Fallout 4 binary, so an agent can run it unattended. Its
arguments, its image-base handling and its exit codes are in the script's own docstring —
`--help` prints it.

Where it goes in the sequence:

- **After `setup\35-ghidra-analysis.ps1` has created functions.** This renames functions that
  already exist; it creates none. Run it first and every CSV address lands on nothing — which
  is the case it now exits **1** on, rather than the 0 an agent walks straight past.
- **After the RTTI vtable walk (BGS menu 9), if you want `--replace-slot-names`.** Before that
  walk there are no `Func42` placeholders to replace and the flag changes nothing; the script
  says so in its summary rather than leaving you to infer it from a zero.
- **`--dry-run` is a usable pre-flight gate**, not just a preview: it exits 1 on the same
  "not one CSV address resolved to a function" condition the real run does, so a script can
  gate on it before committing to the real one.

## `ImportAddressLibrary.py` — the Script Manager fallback (Jython)

The same CSVs, from Ghidra's GUI, for a machine where pyghidra is not available. It reads the
`vr`, `status` and `name` columns, which both games' databases carry:

- Skyrim VR: `vr_address_tools/skyrim_vr_address_library/database.csv` (~17K names)
- Fallout 4 VR: `vr_address_tools/fallout_vr_address_library/fo4_database.csv` — **93,858 rows,
  every one carrying a VR address and a demangled C++ name; 46,348 at `status >= 3`, of which
  29,580 carry an argument list** (counted off the CSV, 2026-08-22). The other rows name
  vtables, RTTI objects and static instances — real symbols, but nothing `apply_prototypes.py`
  can parse a signature out of. An earlier version of this file called F4VR coverage "much
  smaller". Measured, it is the single best source of VR function names there is, and it needs
  no flat Fallout 4 binary.

Two things it needs:

- **The Jython extension.** Ghidra 12.x ships Jython as an *optional* extension and this
  script declares `@runtime Jython`. Install it once via `File > Install Extensions`
  (it's bundled with the Ghidra distribution) and restart — otherwise the Script Manager
  refuses to run the script.
- **Your game program open, after auto-analysis has completed.** Note that unlike the headless
  importer this one will *create* a function at an address that has none, if you answer Yes to
  its "Create function definitions?" prompt.

And one thing it costs you, which is not obvious from the summary it prints:

> **It strips the signature.** `parse_name` cuts each name at the first `(` and keeps namespace
> + leaf, and the symbol sanitiser would replace `(`, `&`, `*` and `,` anyway — so
> `Allocate(NiPoint3&,TESObjectCELL*,...)` lands on the function as `Allocate`.
> `apply_prototypes.py` below skips any name without a `(`, so a program named **only** by this
> script produces zero candidates: `probing 0 of 0 candidates`, `plan written … (0 prototypes)`,
> and no console line explains why. If you want prototypes, the names have to come from
> `import_vr_names_headless.py` or from the BGS pipeline.

## `apply_prototypes.py` — turn the signature in a NAME into an applied prototype

The pipeline's names — and `import_vr_names_headless.py`'s — carry the full signature but set
names only, so the decompiler still shows `(undefined4 *param_1, longlong param_2, ...)` even
though the name says `Allocate(NiPoint3&,TESObjectCELL*,TESWorldSpace*,float,float)`. This
parses those names and applies them with `/set_function_prototype`. It talks HTTP to the
**headless** MCP server (`setup\36-ghidra-mcp.ps1 -Start`); no pyghidra, no GUI.

```powershell
python apply_prototypes.py fetch                       # ~20 s
python apply_prototypes.py probe --only-resolvable     # SLOW, resumable (see below)
python apply_prototypes.py report                      # tiers + writes plan.json
python apply_prototypes.py apply                       # DRY RUN: validates, writes nothing
python apply_prototypes.py apply --tier 1 --apply      # commits
```

The remaining flags are in the script's docstring and `--help`.

**Back up the project first.** This writes to a database that took hours to build. Every
outcome of an `--apply` run — applied, rejected on apply, invalid, error on validate, stale
row, unknown — is journalled to `.proto-cache/journal.jsonl` and flushed per line, because that
file is the only record of what reached the database. A dry run journals nothing.

**A plan is bound to the program it was built from**, and `apply` refuses one built against a
different program — including a dry run, since a validation report about the wrong program is
worse than none. The server serves whatever `36-ghidra-mcp.ps1` last loaded, and
`/set_function_prototype` takes an *address*: a plan applied to the wrong program writes 13,108
prototypes at addresses that mean something else there, and the server reports every one of
them as applied.

**After a failure, the two recoveries are not the same one.** `--retry-failed` re-applies only
what the journal *records* as not applied — the recovery after fixing a type mapping or a
this-detection rule. It deliberately does not pick up rows that appear in no journal line at
all, which is exactly what an interrupted run leaves behind; a plain `apply --apply` sweeps
those up (re-applying a row that already succeeded is idempotent, it just costs ~250 ms).

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

**13,108 prototypes planned; all 13,108 validated by Ghidra's own parser, 0 rejected at
validation.** Of those, 4,176 get a typed `this`, 8,689 get `void * this` (the class type does
not exist), and 243 are free functions with no `this` at all.

**Validating is not applying, and that gap is 15.5% wide.** The two endpoints resolve types by
different paths: on the same 13,108-row plan, `/validate_function_prototype` answered
`valid` for **2,027 prototypes that `/set_function_prototype` then rejected** with "Can't
resolve datatype". **1,904 of those 2,027 were `bool` or `bool *`** — the very type Ghidra's own
decompiler infers — because importing CommonLibF4 created a second definition of it, so the
program holds both `/bool` and `/CommonLibF4/bool` and the parser refuses to guess between
them. `report` now composes those types as unambiguous equivalents instead (`bool` →
`undefined1`, which leaves the decompiler free to recover bool-ness itself), `apply` counts
what *applied* rather than what validated, and every rejection is journalled with its reason.
Read the APPLIED line, not the validated one.

`void * this` is still worth having: it marks the this-pointer so every *other* parameter
lands in the right position, which is where most of the value is. It just gives no field
access on `this` itself.

The probe costs ~350 ms/function on this machine — the decompiler, not HTTP — which is ~150
minutes for all 25,867. It is resumable and safe to interrupt, and it prints that estimate for
whatever subset it is about to probe; `--from-plan` narrows it to the addresses a plan already
contains.

### Why it is more than a string substitution

A demangled C++ name is missing two things, and both will bite:

- **No `this`.** Prepending one when the method is static shifts every parameter by one —
  strictly worse than leaving the function alone. Nothing in the source data records
  static vs instance (the address-library CSV is `id,fo4,vr,status,name`; BGS's PDB
  publics corpus is already demangled with no access specifiers). The only local signal is
  Ghidra's decompiler arity, which can undercount but never overcount, so `inferred ==
  args+1` proves a `this` and `inferred == args` is genuinely ambiguous. Measured on 150
  functions: **67% decisive, 26% ambiguous**. The ambiguous ones are skipped, not guessed.
- **No return type.** Emitting `void` would destroy the decompiler's own inference — and so
  would a hardcoded `undefined8`, which is what this script used to write. Applying a prototype
  *replaces* the return type, so functions Ghidra had already worked out as `bool`,
  `longlong *` or `undefined1 *` were being downgraded to "unknown 8 bytes" wholesale. The
  probe now reads the current return type out of the decompiled signature and puts it back
  unchanged; `undefined8` appears only where the decompiler offered nothing to preserve.

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
