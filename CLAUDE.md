# Agent bootstrap runbook

You are setting up (or working inside) a Bethesda modding + reverse-engineering environment.
This file is written for you, the agent. Execute phases in order; each has a **gate** — do not
advance past a failing gate, fix it. Everything is idempotent; re-running a phase is safe.

Conventions on this machine after setup: source repos under `C:\repos`, tools under
`C:\tools`. Both are parameters of the scripts if the user wants different roots — ask before
diverging from the defaults.

## Phase 0 — orient

1. Ask the user which layers they want now: **dev** (build plugins), **RE** (Ghidra/x64dbg),
   **devbench** (in-game instrumentation). Dev alone is fine; RE can come later.
2. Ask which game(s) they target first (F4VR / F4 / Skyrim / Starfield) and whether they use
   MO2 (and its path) — you need this for deploy wiring.
3. `winget --version` must work. If not, stop and have the user install "App Installer".
4. Shell: every script here is **Windows PowerShell 5.1**-clean, so you can run them from the
   stock Windows shell (which is also what Claude Code uses on Windows) — you do not need
   pwsh 7 first. That constraint is not cosmetic: `00-prereqs.ps1` is what *installs* pwsh 7,
   so if it needed pwsh 7 the runbook could never start. If you edit a script, keep it 5.1-safe
   — no `?:` ternary, no `??` — and save it as UTF-8 **with BOM**. Without a BOM, 5.1 decodes
   the file as CP1252 and an em dash (`—`) becomes `â€”`, whose last character is U+201D, which
   PowerShell treats as a quote; the file then fails to parse with a misleading error pointing
   at some unrelated line. CI enforces both rules (`.github/workflows/ps-compat.yml`).

## Phase 1 — toolchain

```powershell
.\setup\00-prereqs.ps1          # needs elevation if anything is missing
.\setup\10-vcpkg.ps1
```

**Gate:** `.\setup\00-prereqs.ps1 -CheckOnly` all present, and `10-vcpkg.ps1 -CheckOnly`
passes. Freshly installed tools need a **new terminal** for PATH — if a command is missing
right after install, restart the shell before debugging anything else.

Known trap this phase exists for: `VCPKG_ROOT` **and** `VCPKG_INSTALLATION_ROOT` must both be
set (different files in the build chain read different names).

## Phase 2 — repos

```powershell
.\setup\20-repos.ps1            # add -SkipAddressTools to defer the ~300 MB CSV clone
```

**Gate:** `C:\repos\CommonLibF4\.git` exists.

## Phase 3 — first plugin build (the real proof)

```powershell
.\New-Plugin.ps1 -Name <name> -Game F4VR [-Mo2Path <mo2 mod folder>]
cd C:\repos\<name>
cmake --preset windows-vcpkg-vr           # or vr-mo2 if -Mo2Path was given
cmake --build buildvr --config Release
```

First configure restores ~13 vcpkg ports and compiles CommonLibF4 — several minutes; that is
normal. **Gate:** `buildvr/Release/<name>.dll` exists.

This gate proves VS + C++23, CMake, vcpkg, git submodules and the whole chain at once —
everything after it is additive.

**One DLL, three runtimes.** The submodule is [alandtse/CommonLibF4](https://github.com/alandtse/CommonLibF4),
which dispatches at runtime: `ENABLE_FALLOUT_F4`/`_NG`/`_VR` are all ON by default, so a
single build serves pre-NG Fallout 4, the Next-Gen update **and** Fallout 4 VR, choosing via
`REL::Module` at load time. There is no `FALLOUTVR` define to set. `BUILD_FALLOUTVR` only
picks the deploy target and build directory (`buildvr/` vs `build/`). Gate your own
runtime-specific code on `REL::Module::IsVR()` / `IsNG()` / `IsF4()`, not on a compile-time
macro.

**Visual Studio version:** `windows-vcpkg-vr` takes whatever VS is installed. VS2022 and
VS2026 are both verified to build the full chain; `vs2019`/`vs2022`/`vs2026` presets exist if
you need to pin one. (Historical note, in case you meet it in an old checkout: the previous
submodule — rollingrock/CommonLibF4 — could not compile on MSVC 14.5x, because
`hkVector4f& GetNormalized()` returned a reference to a local and C++23's P2266 makes a
returned local an rvalue, giving ~14 `C2440` errors in `RE/Havok/hkVector4.h`. alandtse's
fork fixed that in `ba22620`.)

To test in game: the DLL+PDB go in the mod's `F4SE/Plugins/` (automatic with the `vr-mo2`
preset); copy the TOML from `Data/F4SE/Plugins/` next to it by hand. The game needs F4SEVR
and the [VR Address Library](https://www.nexusmods.com/fallout4/mods/64879) installed. Check
`Documents\My Games\Fallout4VR\F4SE\<name>.log` for the load banner.

## Phase 4 — Ghidra: analysis database + MCP (RE layer)

Two halves. First the **enriched analysis database** via BethesdaGhidraScripts (types,
vtables, signatures, address-library names — automated; this is what makes decompiles
readable), then the **MCP bridge** so you can drive Ghidra from sessions.

1. Ask the user which game EXE(s) to analyze and stage them:
   `C:\repos\BethesdaGhidraScripts\exes\<game>\<ver>\<Game>.exe` (paths in its README —
   the EXEs come from the user's game installs; you cannot download them).
2. ```powershell
   .\setup\35-ghidra-analysis.ps1 -CheckOnly       # what's staged, what's still needed
   .\setup\35-ghidra-analysis.ps1                  # runs it; -OnlyGame f4 to scope
   ```
   **You can run this yourself — do not hand it back to the user.** BGS ships an interactive
   menu, but the items this needs (1 prereqs, 2 submodules, 7 full rebuild) each run straight
   through without prompting, and 7 discovers every staged binary on its own, so the script
   drives them by feeding menu keys on stdin. Prompts only appear in the other submenus and on
   failure-retry; `run.py` treats EOF as quit.

   `-CheckOnly` answers "does Ghidra need to run for this game?" instantly and changes
   nothing — exit 0 means nothing to do, exit 2 means work is pending. Use it before
   committing to a run.

   **Use run.py's subcommands, not the menu.** `python run.py setup` (menu 1+2), `build`
   (menu 7), `all`, `clean` are documented under "Non-interactive mode" and need no stdin at
   all. Only the improve pass (menu 9) has no subcommand. `run clean` before rebuilding if the
   project records a different importer stage, or stale names survive.

   **Export the symbols when the analysis is done** — `scripts/core/symbol_export.py` is
   scriptable (menu 10 wraps it) and is what makes Phase 5 work: it emits a `.dd64` x64dbg
   database, a `.map`, and a `.symbols.json` with prototypes. Measured on F4VR: 60,615
   functions, 60,671 x64dbg labels. Without it the analysis stays locked inside Ghidra.
   `35-ghidra-analysis.ps1` runs it into `<bgs>\symbols\<game>-<ver>\`.

   **The improvement drivers do nothing for F4VR** — measured, not assumed.
   `string_anchored_rename` renamed 0 (release build, no self-identifying debug strings),
   `console_harvest` found no command table, `settings_harvest` 0 candidates,
   `pe_unwind_enrich` and `registration_harvest` changed nothing. Named-function count was
   byte-identical before and after all five. They are documented as being for "where CommonLib
   is thin (newer builds, Starfield, FNV)" — F4VR's gap is a *naming-source* gap, not a type
   gap. Worth trying on Starfield; do not spend time on them for Fallout 4 VR.
   Their multi-program runner `discover_combined.py` is also broken on Windows: it calls
   `getExecutablePath()` raw instead of the `_program_executable_path()` normalizer that sits
   beside it, so Ghidra's `/C:/...` form becomes `C:\C:\...` and every program fails identity
   verification. `apply_enrichment_to_user_project.py` (one driver, one program) is correct.

   Option 7's auto-analysis takes **hours per binary** — start it detached (or overnight) and
   do not interrupt it. Scope with `-OnlyGame <skyrim|f4|starfield|fnv>`; the other staged
   binaries are moved aside for the run and restored afterwards.

   **The improve pass (menu 9) is not optional on VR — it is where the names come from.**
   BGS has no address-library function symbols for Fallout 4 VR (`Total symbols ... VR: 0`):
   VR and OG use ID namespaces CommonLibF4 does not reference, so option 7 alone imports ~37k
   struct types, names **13** functions, and its own `>=100 named functions` check then rejects
   and rolls that apply back. Menu 9 fixes this without any extra binary — it re-applies the
   true-VR importer and then walks RTTI vtables **in the VR binary itself**. Measured on F4VR
   1.2.72 with nothing else staged: 12,150 vtables discovered, **13 → 34,507 named functions**
   of 216,903 (+34,494), and the changes are *saved*, not rolled back. `35-ghidra-analysis.ps1`
   runs it automatically after option 7 (`-SkipImprove` opts out).

   **Which flat build you stage matters, and 1.11.221 is not the one for VR.** Measured here:

   | Staged | Result |
   |---|---|
   | `f4\vr` only | VR: 13 named by option 7 (rolled back) → **34,507** after the improve pass |
   | `+ f4\221` | 221 itself: **31,040 scoped `Class::Fn`** names. VR: **no change** |

   The auto-run porter (`run_bytesig_port.py`) anchors only at AE or NG — literally
   `for cand in ("ae", "ng")` — so a 221 binary never triggers it. Forcing the other porter
   (`bytesig_port_combined.py --source 221`, which BGS documents as "the richest PDB pool")
   ported **1 function out of 12,240**: exact 32-byte pass matched once, the masked 48-byte
   retry matched nothing. 1.11.221 and VR 1.2.72 are too far apart to share function bodies.
   BGS ships vtable-slot shift maps for `vr_to_ae` and `vr_to_ng` and none for 221, which is
   the same conclusion from the other direction.

   So: stage **`exes\f4\ae\Fallout4.exe` (1.11.191)** or **`\ng\` (1.10.984)** if you want real
   CommonLib names on VR. `exes\f4\221\` is still worth staging — it is what unlocks the
   38k-record PDB-publics corpus and it names the flat binary well — but it does nothing for
   VR. Without an AE/NG binary the RTTI walk's ~34.5k is the realistic ceiling for F4VR.

   Two traps that make the corpus look absent when it is not:
   - **`PDB publics: 0 loaded`** — the corpus is identity-bound by SHA-256 to one exact
     `Fallout4.exe`. It is skipped silently unless that binary is staged.
   - **Git mangles the corpus on Windows.** `f4_221_pdb_publics.txt` is a byte-exact artifact
     with no `.gitattributes` protection, so `core.autocrlf=true` (the Git-for-Windows default)
     rewrites its line endings on checkout and its hash stops matching — the validator then
     raises `ValueError: F4 221 PDB-public dump changed after binding` and kills the whole run
     with a traceback. Fix by converting it back to LF (3,939,250 → 3,901,215 bytes, sha256
     `ab927b7d…`) and pinning it with `-text` in `.git/info/attributes`.
   - **clang is resolved as a bare `clang` on PATH**, but BGS installs it to `tools\llvm\bin`.
     Menu 1 mutates PATH only inside its own process, so every later run prints
     `Clang: not installed` and **silently skips script generation** — the run then imports
     binaries and ports nothing, with no error. `35-ghidra-analysis.ps1` puts it on PATH.

   **Do not treat the `.gpr` as proof of success.** Ghidra creates the project and imports the
   binary *before* enrichment runs, and `run.py` exits 0 even when verification fails and rolls
   back — so a failed run still leaves a several-hundred-MB project behind. The script reads
   run.py's report and records its verdict in `.analysis-verified.json`; that file, not the
   project directory, is what `-CheckOnly` trusts.
3. ```powershell
   .\setup\30-ghidra.ps1   # builds the MCP extension against BGS's managed Ghidra
   ```
4. Manual once-per-machine (the script prints it): open Ghidra (BGS menu 6), confirm the
   GhidraMCP extension is enabled, `Tools > GhidraMCP > Start MCP Server`.

Give the project's Claude sessions access by copying `mcp\mcp.template.json` to the project as
`.mcp.json` (the scaffolder already does this for new plugins).

**Gate:** with Ghidra running + server started, an MCP session can `list_instances()` →
`connect_instance(...)` → `decompile_function` on a function **and see CommonLib names/types
in the output** (not just `FUN_*`). **Read `docs/GHIDRA_WORKFLOW.md` before real RE work —
especially the connect ritual; skipping it makes the toolset look broken or, worse, reads the
wrong binary.**

Bonus once analysis is done: BGS menu option 10 exports symbols for **x64dbg** (live
debugging with real names) and can build a synthetic PDB.

## Phase 5 — x64dbg + MCP (live debugging)

```powershell
.\setup\40-x64dbg.ps1
```

**Gate:** launching `C:\tools\x64dbg\x96dbg.exe` → x64 → log shows
`[MCP] x64dbg MCP Server started on 127.0.0.1:27042`. For MO2-managed games: launch the game
through MO2 first, then **attach** x64dbg to the process.

## Phase 6 — devbench (in-game instrumentation)

Read `docs/DEVBENCH.md`, build the `fallout4` preset from `C:\repos\devbench`, deploy via
`FalloutPluginTargets`, load a save, then:

```powershell
irm http://127.0.0.1:8930/api/health     # 8931 for VR
```

**Gate:** health answers with the right game identity. NOTE (2026-08-15): this is a young
fork — the Fallout target has never been live-tested; a failure here is findings, not user
error. Report what happened to the user (and ideally upstream as an issue on
rollingrock/devbench).

## Final verification

```powershell
.\setup\90-verify.ps1 -BuildTest
```

All PASS (vr_address_tools may be an intentional skip) = the machine is at parity.

## Standing rules for work in this environment

- **Trampoline:** one `F4SE::AllocTrampoline(N)` per plugin, in `F4SEPlugin_Load`, before any
  hook; never per-hook (per-hook allocation frees earlier stubs on F4SEVR and crashes). 14
  bytes per `write_call<5>` hook.
- **New source files must be added to `cmake/sourcelist.cmake`** (headers to
  `headerlist.cmake`) — the lists are manual; forgetting is a silent no-build.
- **Settings over constants:** expose tunables via the template's TOML settings framework
  rather than hardcoding, so users (and you, live) can tune without a rebuild.
- **Ghidra sessions start with the connect ritual** (`docs/GHIDRA_WORKFLOW.md`). Labels are
  hints; code bytes are ground truth.
- **Instrumentation must represent failure states** — NaN/Inf as explicit values, never
  silently coerced (see `docs/DEVBENCH.md` for why this rule exists).
- Prefer building against the pinned/vendored versions in this pack; upgrade deliberately,
  one component at a time, with the verifier run after.
