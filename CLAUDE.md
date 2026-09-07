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
   stock Windows shell (which is also what Claude Code uses on Windows). Nothing here installs
   pwsh 7 and nothing here needs it — `00-prereqs.ps1` lists PowerShell 7 under "Not required,
   deliberately" for exactly that reason: a runbook whose first script needed pwsh 7 could
   never start on the machine it targets. If you edit a script, keep it 5.1-safe — no `?:`
   ternary, no `??` — and save it as UTF-8 **with BOM**. Without a BOM, 5.1 decodes the file as
   CP1252 and an em dash (`—`) becomes `â€”`, whose last character is U+201D, which PowerShell
   treats as a quote; the file then fails to parse with a misleading error pointing at some
   unrelated line. CI enforces both rules (`.github/workflows/ps-compat.yml`).
5. **One home per fact.** A script's own header is authoritative for its flags, its sizes, its
   paths and its exit codes. This file and the READMEs carry what only they can know — the
   sequence, the gates, the traps, and measurements with the date they were taken — and stop
   restating what a script already owns. When you change a script, grep the docs for the old
   claim and *delete* it rather than restate it: a fact that lives in one place cannot drift.
   This is not tidiness. A doc that confidently states something false is worse than one that
   says nothing, because a reader trusts it over a directory listing — this pack shipped a
   documented symbols path that pointed at two different wrong places, and a "300 MB" clone the
   script itself calls 1.1 GB.

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

What this phase delivers is *both env vars pointing at one healthy vcpkg* — not a vcpkg at
`C:\repos\vcpkg` specifically. If this machine already has a bootstrapped clone and
`VCPKG_ROOT` names it, `10-vcpkg.ps1` adopts that root in place and says so, rather than
cloning a second copy and repointing a machine-wide variable other projects resolve through.
Pass `-VcpkgDir` only when you actually want a particular location; an explicit one always
wins over adoption.

**Exit codes.** `0` = the state you asked for now holds. `1` = a real failure. `2` = nothing
failed, but the state is not the one you asked for — work pending, or up-but-degraded. Only
four scripts speak the third one: `20-repos.ps1`, `30-ghidra.ps1`, `35-ghidra-analysis.ps1` and
`36-ghidra-mcp.ps1`. Three of them say what their own `2` means at the top of the file;
`30-ghidra.ps1` does not — its only explanation is the refusal it prints (Phase 4, step 3).
**`00-prereqs.ps1` and `10-vcpkg.ps1` answer 0/1 only** — their `-CheckOnly` reports "there is
something to install" as `1`, so a caller that reads 1 as broken will misread a fresh machine.
A script exits `0` only when it has *verified* the outcome, never merely because its last line
ran, so gate on the exit code — and read the message before re-running, because `1` is often a
refusal rather than a flake.

**Every gate below is a script, not a file test.** A path existing proves something was
created, never that it works: `python.exe` on a stock Windows box is a Store stub that exits
9009, a `.git` directory says nothing about which fork it came from, and a venv launcher
outlives the interpreter it points at. The `-CheckOnly` paths run the tool the way its real
consumer does.

## Phase 2 — repos

```powershell
.\setup\20-repos.ps1
```

`-SkipAddressTools` defers the address-library clone, which is the big one; `-Only <names>`
narrows the table to the repos you name. Both work in either mode, and the script's header
carries the table, the sizes and which fork each row pins.

**Gate:** `.\setup\20-repos.ps1 -CheckOnly` exits 0. A `.git` directory is not the gate: it
proves something was cloned, not that it came from the URL this pack pins, and a wrong-fork or
wrong-branch clone would otherwise stay blessed forever. Exit 2 covers both reasons this gate
can be unmet, and they want opposite responses: a repo that is simply **absent** is cleared by
running the script without `-CheckOnly`, while a directory holding a **different repository** is
reported and left exactly where it is — nothing is cloned into it and nothing is deleted, and no
re-run clears it until a human moves it. Read which one it printed before acting.

## Phase 3 — first plugin build (the real proof)

```powershell
.\New-Plugin.ps1 -Name <name> -Game F4VR [-Mo2Path <mo2 mod folder>]
cd C:\repos\<name>
cmake --preset windows-vcpkg-vr           # or vr-mo2 if -Mo2Path was given
cmake --build buildvr --config Release
```

First configure restores ~13 vcpkg ports and compiles CommonLibF4 — several minutes; that is
normal.

**Gate:** `buildvr/Release/<token>.dll` exists, where `<token>` is `-Name` lowercased with
every `-` turned into `_`. That transform is not cosmetic and it is the whole reason this gate
is worth stating: `New-Plugin.ps1` renames the project, the DLL, the TOML and the log file
after the token, so `-Name my-cool-mod` produces `my_cool_mod.dll` and a gate copied literally
from `<name>` never matches. `90-verify.ps1` computes the same transform for its own
`-BuildTest` row.

This gate proves VS + C++23, CMake, vcpkg, git submodules and the whole chain at once —
everything after it is additive.

**One DLL, three runtimes.** The submodule is [alandtse/CommonLibF4](https://github.com/alandtse/CommonLibF4),
which dispatches at runtime: `ENABLE_FALLOUT_F4`/`_NG`/`_VR` are all ON by default, so a
single build serves pre-NG Fallout 4, the Next-Gen update **and** Fallout 4 VR, choosing via
`REL::Module` at load time. There is no `FALLOUTVR` define to set. `BUILD_FALLOUTVR` only
chooses which install a deploy *would* target; the hidden `vr`/`flat` presets that set it also
choose the build directory (`buildvr/` vs `build/`). Gate your own runtime-specific code on
`REL::Module::IsVR()` / `IsNG()` / `IsF4()`, not on a compile-time macro.

**One DLL, but TWO plugin handshakes — and flat Fallout 4 no longer speaks the old one.**
F4SE 0.7.0 replaced `F4SEPlugin_Query` with a declarative `F4SEPlugin_Version` record, and by
0.7.9 (the build for Fallout 4 1.11.240) the old entry point is simply gone: the string
`F4SEPlugin_Query` does not occur anywhere in `f4se_1_11_240.dll`. F4SEVR 1.2.72 is the mirror
image — it resolves `Query` and `Load` and has never heard of `F4SEPlugin_Version`. So the
template exports **both**, and each extender ignores the one it does not look for. Export only
`Query` and the plugin is refused before a line of its code runs, with the one log line that
says so and nothing else:

```
plugin <name>.dll (00000000  00000000) no version data 0 (handle 0)
```

The record sets `addressIndependence` and `structureIndependence` to `(1<<1)|(1<<2)` directly
rather than calling `UsesAddressLibrary()`, because CommonLibF4's helper hardcodes `1<<1` —
the 1.10.980-era address library — and a plugin offering only that bit is not claiming the
Anniversary (1.11.137+) library a 1.11 runtime wants. `compatibleVersions` is left empty,
meaning "any runtime", which is right for an address-library plugin; if yours reads struct
**fields** you have only verified on one build, pin them with `CompatibleVersions({...})` and
let F4SE refuse you elsewhere instead of reading garbage.

**Neither default preset deploys anything.** `COPY_BUILD` is FALSE unless you ask for it, and
`windows-vcpkg-vr` / `windows-vcpkg` do not ask — a plain build leaves the DLL in its build
directory and copies it nowhere. Deploying is a separate decision with two mechanisms:
`MO2_INSTALL_PATH` (what `-Mo2Path` writes into `CMakeUserPresets.json` as the `vr-mo2`
preset), or `COPY_BUILD` plus `FalloutVRPath`/`Fallout4Path`. Both now fail at *configure* when
the target path is wrong, rather than building green into a tree nothing reads.

**`-Mo2Path` is checked before anything is copied, and it throws.** Pass the mod's own folder
(`<mo2>\mods\<yourmod>`), not the mods root, and the mods root above it must already exist —
that directory is MO2's, and if it is missing the path is not pointing at an MO2 install. The
mod folder itself not existing is fine; the first deploy creates it. Do not retry the throw,
fix the path: MO2 > Settings > Paths shows the mods folder it really uses, and an
instance-mode MO2 keeps it under `%LOCALAPPDATA%\ModOrganizer\<game>\mods`.

**Visual Studio version:** `windows-vcpkg-vr` takes whatever VS is installed. VS2022 and
VS2026 are both verified to build the full chain; `vs2026-windows-vcpkg-vr`,
`vs2022-windows-vcpkg-vr` and `vs2022-windows-vcpkg` pin a generator if you need one; there is
no vs2019 preset. (Historical note, in case you meet it in an old checkout: the previous
submodule — rollingrock/CommonLibF4 — could not compile on MSVC 14.5x, because
`hkVector4f& GetNormalized()` returned a reference to a local and C++23's P2266 makes a
returned local an rvalue, giving ~14 `C2440` errors in `RE/Havok/hkVector4.h`. alandtse's
fork fixed that in `ba22620`.)

To test in game: the DLL+PDB go in the mod's `F4SE/Plugins/` (automatic with the `vr-mo2`
preset); copy the TOML from `Data/F4SE/Plugins/` next to it by hand. The game needs F4SEVR
and the [VR Address Library](https://www.nexusmods.com/fallout4/mods/64879) installed. Check
`Documents\My Games\Fallout4VR\F4SE\<token>.log` for the load banner — same token as the DLL,
so a hyphenated `-Name` logs to the underscored file and not to the one you typed.

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
   menu, but nothing this phase needs a human for: `run.py` has real subcommands for the main
   path, and option 7 discovers every staged binary on its own. Prompts appear only in the
   other submenus and on failure-retry, and `run.py` treats EOF as quit.

   `-CheckOnly` answers "does Ghidra need to run for this game?" instantly — exit 0 means
   nothing to do, exit 2 means work is pending. Use it before committing to a run. It changes
   exactly one thing, deliberately: game binaries stranded under `.exes-held` by an interrupted
   `-OnlyGame` run are moved back before the staging scan reads `exes\`, because otherwise
   `-CheckOnly` would report "nothing to do" for a game whose un-redownloadable binary it had
   just declined to reclaim.

   **Use run.py's subcommands, not the menu** — and this script already does. `python run.py
   setup` (menu 1+2), `build` (menu 7), `all` and `clean` are documented under "Non-interactive
   mode" and need no stdin at all; only the improve pass (menu 9) has no subcommand, and it is
   the one place `35-ghidra-analysis.ps1` still feeds menu keys. `run clean` before rebuilding
   if the project records a different importer stage, or stale names survive.

   **The export is part of this step, not a later one.** `35-ghidra-analysis.ps1` runs
   `scripts/core/symbol_export.py` itself (BGS menu 10 wraps the same code behind prompts) and
   gates its own exit code on it: a run that analyzed but did not export exits **1**, not 2,
   because "analyzed, no symbols" is a state that otherwise reads as success and strands Phase
   5. It emits a `.dd64` x64dbg database, a `.map`, and a `.symbols.json` with prototypes;
   without it the analysis stays locked inside Ghidra. Measured on F4VR (2026-08-16): 60,615
   functions, 60,671 x64dbg labels.

   **Where the symbols landed is recorded, not derivable.** Read `entries[].exportDir` in
   `<bgs>\.analysis-verified.json` — the script prints it at the end of a run and
   `40-x64dbg.ps1` reads it. Do not reconstruct that path by hand; this file used to state two
   different wrong ones, and the directory on a machine that exported before the field existed
   does not match today's layout either.

   `-SkipExport` opts out. If an export goes missing later, **re-run this script — it does the
   export alone, minutes rather than the hours menu 7 costs**, because the recorded analysis is
   still good. That fast path exists so nobody reaches for `-Force` (a full re-analysis) to
   recover a step measured in minutes.

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
   1.2.72 with nothing else staged: 12,150 vtables discovered, **13 → 34,507 named functions**,
   and the changes are *saved*, not rolled back. (`35-ghidra-analysis.ps1`'s own comment at that
   step carries the counts with their denominators; the denominator moves as analysis discovers
   more functions, so do not compare it against the end-to-end table below.)
   `35-ghidra-analysis.ps1` runs the pass automatically after option 7 (`-SkipImprove` opts out).

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
   .\setup\30-ghidra.ps1                 # builds + deploys the MCP extension and the bridge
   .\setup\36-ghidra-mcp.ps1 -Start `
       -Program /f4/vr/Fallout4VR.exe.unpacked.exe `
       -WriteMcpConfigTo <your-plugin-dir>
   ```
   **No GUI and no clicks — run both yourself.** `36-ghidra-mcp.ps1`'s header carries the
   measured bringup (endpoint and tool counts, with the Ghidra and ghidra-mcp versions they
   were taken against) and its full flag list; `-Status` and `-Stop` manage the server.

   **`30-ghidra.ps1` refuses (exit 2) while a JVM is running from that Ghidra install** —
   including a pyghidra process, so this fires exactly when step 2 is still going. It is not a
   flake and retrying will not clear it: `gradlew deploy`'s `stopGhidra` task would force-kill
   an in-flight analysis and leave a stale project lock. Wait for step 2, or take the extension
   jar without the GUI deploy with `-HeadlessOnly`, which the headless server does not need
   anything from. Do not gate-loop on exit 0 here.

   **The build uses Gradle, not Maven.** `gradlew.bat` bootstraps itself and reads the Ghidra
   jars straight out of the install, so the JDK is the only prerequisite. This is not a
   preference: **there is no `Apache.Maven` package in winget**, so the old Maven-based
   instructions could never complete on a fresh Windows machine.

   **Headless is invisible to `list_instances()` — this is expected, not a fault.** Discovery
   probes `/mcp/instance_info`, which only the GUI plugin registers (`ServerManager.java`,
   `GhidraMCPPlugin.java`); the headless server does not serve it, so the scan returns
   nothing. It does serve `/mcp/schema`, so the bridge's TCP fallback connects anyway — which
   is why the generated `.mcp.json` pins `GHIDRA_MCP_URL=http://127.0.0.1:8089`. **Do not
   start the connect ritual with `list_instances()` on a headless server and conclude the
   toolset is broken.** (README also documents a `/server_status` endpoint for headless;
   `server_status` appears nowhere in the Java and returns 404.)

   That pin is why **`-Port` has to be passed everywhere or nowhere.** It is what goes into
   `GHIDRA_MCP_URL`, and discovery cannot correct a wrong one — a `.mcp.json` generated for one
   port against a server listening on another is an agent session with no Ghidra tools in it
   and nothing anywhere saying why. The PID and load records are per-port too, so `-Stop` on
   the wrong port cannot find the server it is aimed at.

   Use the GUI path instead only when you want to *look* at the disassembly. Note that
   `patchGhidraUserConfig`, which makes the plugin auto-load, can only edit `FrontEndTool.xml`
   if it already exists — and it does not until the Ghidra GUI has run once. So on a fresh
   machine the first GUI launch has no MCP server; launch Ghidra once, re-run
   `30-ghidra.ps1`, and it will auto-start from then on.

**Gate:** `36-ghidra-mcp.ps1 -Status` **exits 0** — which now means all three of a live
connection, a non-zero tool count, and a loaded program *whenever one was asked for*, rather
than just the connection. That last qualifier is load-bearing: a bare `-Start`, and the
locked-project path that deliberately starts with no project, both record that no program was
requested, and `-Status` passes them. **So exit 0 is not by itself proof there is a program to
decompile.** An agent that needs one must `-Stop` and `-Start -Program <path>`. Then an MCP
session can `decompile_function` and see **real names** rather than `FUN_*`.
**Read `docs/GHIDRA_WORKFLOW.md` before real RE work.**

**Exit 2 from `-Start` means "up, but not what you asked for" — read it, don't retry it.** The
server is running and serving its full toolset; something about the *requested* state does not
hold. Four ways to get it, and each wants a different response:

- **The project was locked**, so your `-Program` was dropped and the server came up empty. The
  holder is named in the output. Wait for it, or work against the loaded-nothing server. Never
  delete a lock that is held.
- **The `-Program` you named failed to load** — a path that is not in the project, or a
  `LockException`. Ghidra prints the failure and carries on, so the server is healthy and empty
  and every tool call answers "No program loaded". Check the path against the layout the
  pipeline imported into (`/f4/vr/Fallout4VR.exe.unpacked.exe`), not against the filesystem.
- **A different program is loaded** than the one you named. `-Stop` first, then `-Start` again.
- **The `.mcp.json` already there points somewhere else** — a different port or a different
  bridge. The difference is printed. Reconcile it, point `-WriteMcpConfigTo` elsewhere, or pass
  `-Force`, which **regenerates** that file from this pack's two servers rather than merging:
  any other MCP server you had added to it is gone.

A caller that gates on `-eq 0` treats 1 and 2 alike and is right to. Only ask which it was when
you need "it is up, just not loaded" to be actionable. Either way the JVM is running and still
has to be stopped.

**`-Stop` exiting 1 is a refusal, not a flake — do not retry-loop it.** It declines in exactly
two cases, and both mean stopping would destroy something: `/save_all_programs` failed, so
every rename and retype made through the MCP tools since the last save is still only in the
JVM; or something is serving the port but no PID record proves this checkout started it. Read
which one it printed. The first is usually a busy server — wait for the long decompile or
analysis to finish and run `-Stop` again. Re-run with `-Force` only when you accept the stated
cost (lost edits, or a stale project `.lock` the next run has to clear). `-Force` with no PID
record still only asks over HTTP; it never kills a process it cannot identify.

Measured end to end on F4VR (2026-08-16), so you know what "done" looks like:

| | |
|---|---|
| functions | 227,212 |
| named (not `FUN_*`) | 61,136 (26.9%) |
| fully-scoped `Class::Method(args)` | 25,883 |
| data types loaded | 45,696, of which 44,738 under `/CommonLibF4/` |
| ...but with a real layout (>1 byte) | far fewer — see below |

**Names yes, prototypes no — do not expect typed decompiles.** The function *name* carries
the full signature
(`BGSAIWorldLocationPointRadius::Allocate(NiPoint3&,TESObjectCELL*,TESWorldSpace*,float,float)`),
but the applied prototype is still `undefined4 *param_1, longlong param_2, ...`, because the
bulk of these names come from the VR address-library import, which sets names only.
`ghidra-scripts/apply_prototypes.py` closes that gap — read its README before using it.

**Do not read "44,738 types" as 44,738 usable types.** 32,182 of them carry template
arguments and **27,813 of those are 1-byte stubs** — `NiPointer`, `BSTSmartPointer`, `CArgs`
and `StreamRequest` included. Applying a 1-byte stub to a parameter is worse than leaving it
`undefined`: the decompiler then reports field offsets that are confidently wrong. Bare leaf
names are worse still — **four unrelated types in this program are called `Entry`**. The
resolution table — measured across all 25,867 signature-carrying functions, and split by match
kind so the `RE::`-normalised row is not miscounted as unresolved — is in
`ghidra-scripts/README.md`; it belongs next to the resolver that produced it.

So the honest ceiling on "make the decompiles typed" is roughly half the parameters. The
unresolved half clusters tightly — Havok (`hkbInternal`, `hkQsTransformf`, `hkaSkeleton`) and
Bethesda containers — and **that is not an import gap**: of the 19 most frequent unresolved
tokens, 14 exist in neither the program's type manager nor CommonLibF4's headers, and none
were present-in-headers-but-not-imported. BGS's type import is complete with respect to
CommonLibF4. Raising the ceiling means authoring type definitions that do not exist yet, not
re-running the importer.

A Ghidra project is single-writer. If the enrichment pipeline (or a GUI, or another agent)
holds the lock, `36-ghidra-mcp.ps1` says who has it and starts with no project rather than
failing deep inside Ghidra. **Never delete a `.lock` while its holder is alive.**

BGS menu option 10 wraps the same `symbol_export.py` step 2 already ran, and can also build a
synthetic PDB. You do not need it for Phase 5 — this pack's path is 35's own export.

## Phase 5 — x64dbg + MCP (live debugging)

```powershell
.\setup\40-x64dbg.ps1
```

Runs unattended, and does one of two different things depending on what is already at
`-InstallDir`. On a machine with no x64dbg it installs a **pack-managed** one: the snapshot,
then the pinned MCP plugin into both `x64\plugins\x64dbg_mcp.dp64` and
`x32\plugins\x64dbg_mcp.dp32`. Against an x64dbg that was already there it **adopts** it —
fetches no snapshot, flattens nothing, and writes only those two plugin files, because that
directory holds the user's settings, databases and other plugins.

What decides which is `<InstallDir>\.starter-pack-install.json`, the receipt the script writes
after watching an install finish. It is also the only record of **which** MCP release the
`.dp64` came from, since every release ships that file under the same name — so deleting the
receipt is the way to force the plugin to be fetched again after a pin bump. Deleting it does
not re-fetch the x64dbg snapshot.

**Load the symbols Phase 4 exported — that is the entire point.** They are a `.dd64` in exactly
x64dbg's own format (`{"labels":[{module,address,manual,text}]}`, RVAs against
`fallout4vr.exe`); measured on F4VR (2026-08-16), **60,671 labels** carrying real C++ signatures
like `BGSAIWorldLocation::LoadLocation(BGSLoadFormBuffer*)` rather than `sub_1250`. Without
them you are debugging raw addresses. The file is plain JSON, not gzipped — x64dbg reads both.
`40-x64dbg.ps1` finds them itself, by reading `exportDir` out of `.analysis-verified.json` and
falling back to `<BgsRoot>\symbols`, and it prints which of the two it used. If your repos are
not under `C:\repos`, pass `-BgsRoot`/`-Root` rather than believing "run 35 first" over a
finished Phase 4.

**Never probe the npm server with `--version` or `--help`.** It ignores them, starts the stdio
MCP server, and logs `Timeout: none (waits indefinitely)` — the call hangs until something
kills it. The pin has one home — `$script:X64dbgMcpServerPin` in `setup\_common.ps1`, which
both the release tag `40-x64dbg.ps1` fetches and the npm spec written into `.mcp.json` derive
from — so read it there rather than from any generated file. A successful start prints
`[x64dbg-mcp] Server started (23 tools), plugin expected at 127.0.0.1:27042`.

**Gate:** launching `x96dbg.exe` from the `-InstallDir` you used (default `C:\tools\x64dbg`;
the script prints the real path) → x64 → log shows
`[MCP] x64dbg MCP Server started on 127.0.0.1:27042`. For MO2-managed games: launch the game
through MO2 first, then **attach** x64dbg to the process. (This last step needs the game, so
it is the one part of Phase 5 an agent cannot self-verify.)

## Phase 6 — devbench (in-game instrumentation)

Read `docs/DEVBENCH.md`, build the `fallout4` preset from `C:\repos\devbench`, deploy via
`FalloutPluginTargets`, then:

```powershell
irm http://127.0.0.1:8930/api/health     # 8931 for VR
```

**Gate:** health answers `ok:true` with the right game identity, and `frame` rises between two
calls (that is what separates "rendering" from "stuck at init").

**You can run this yourself — a VR game does not need a headset.** SteamVR's null driver
presents a synthetic HMD, so the game initialises, loads F4SE plugins and renders frames with
nothing plugged in. It is how Phase 6 was verified on this machine:

```powershell
& C:\repos\modlist-agent\core\tools\steamvr-null.ps1 -Enable
& "C:\Modding\mo2_fo4vr_gen\ModOrganizer.exe" -p Default "moshortcut://:F4SEVR"
# ... test against 127.0.0.1:8931 ...
& C:\repos\modlist-agent\core\tools\steamvr-null.ps1 -Disable
```

**`-Disable` on every path, including failure.** The setting is GLOBAL: left enabled it forces
the null HMD even when a real headset is plugged in. Close SteamVR before toggling — the
script refuses while `vrserver`/`vrmonitor` run, because the change would be both ignored and
overwritten on exit. Expect the first-ever headless launch to be eaten by SteamVR room setup.

Launch **through MO2**, never from Steam: the mods only exist inside MO2's virtual filesystem,
so a Steam launch is silently vanilla. MO2 executable titles must not contain spaces —
`moshortcut://` arguments get whitespace-split by callers.

Verified live on FO4VR 1.2.72 (2026-08-16): every tool in the catalogue answered;
`rendertarget list` returns 95 targets at 3024x1680 R11G11B10_FLOAT; `measure` reports 135 fps
/ p99 18.2 ms. The catalogue has grown since — devbench added a Fallout `menu` tool on
2026-08-17 — so take the current list from `docs/DEVBENCH.md`, not from that run. Two things
that cost real time to learn:

- **The server binds at `kPostLoad`, not `kGameDataReady`.** On F4SEVR that message arrives
  ~7 s late and on some installs never — a server bound to it never starts at all.
- **A save is needed for the TOOLS, not for the server.** At the main menu anything needing a
  main-thread task returns a 504 saying the frame counter has not advanced. That is the
  instrument being honest; load a save before calling `inspect`/`console`/`rendertarget`.

## Final verification

```powershell
.\setup\90-verify.ps1 -BuildTest
```

No `FAIL` row = the machine is at parity. Every row is `Area` / `Check` / `OK` / `Detail` —
those four field names are the machine-readable contract, and `OK` carries the state, not a
boolean. `FAIL` is the only state that gates the exit code; the other four are information,
not alarm:

| `OK` | |
|---|---|
| `PASS` | checked, and it held |
| `FAIL` | checked, and it did not — the only state that exits 1 |
| `skip` | does not apply to *this* machine on purpose (`-SkipAddressTools`, `-HeadlessOnly`, an analysis nobody has spent the hours on yet) |
| `pending` | work is outstanding but nothing is broken — the exit-2 answer the `-CheckOnly` gates give |
| `idle` | an optional service simply is not running right now |

Read `Detail` before acting on any row: it carries what was actually observed — which `python`
was found, which JVM `gradlew` will use, which jar is missing — not a restatement of the check.

`-Json` emits the same rows as a JSON array, which is what an agent should consume; a
`Format-Table` render moves its column boundaries with the terminal width. `-Fast` drops the
delegated `-CheckOnly` gate rows, the only rows that spawn a process rather than reading state.
(`-BuildTest` spawns three of its own — that is the point of it, and it is opt-in.)

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
- **A change to the setup scripts must keep `tests\run-all.ps1` green.** Its three fixtures pin
  fixes whose failure mode destroys something the user cannot get back — an unrelated process
  force-killed, a directory of local work deleted, hours of build state declared ready when it
  is not — so a red there is never cosmetic. CI runs it (`ps-compat.yml`, the `contract-tests`
  job) alongside the 5.1 parse and BOM lints, an end-to-end scaffold+build on two runner images
  (`e2e-build.yml`), the Phase 4 bringup (`ghidra-bringup.yml`) and the same bringup against
  Ghidra's latest release (`ghidra-drift.yml`).
- **When you change a script, grep the docs for what it used to claim.** The script header owns
  its own flags, sizes, paths and exit codes; this file and the READMEs own the sequence, the
  gates, the traps and dated measurements. Anything restated in both places drifts, and the doc
  is the copy that loses.
- **Never destroy what you cannot prove you created.** Before any `Remove-Item -Recurse`,
  `Stop-Process`, or `Move-Item -Force` against something a user could own, the script must hold
  local evidence that the pack made it: a pre-existence flag captured before the operation, an
  identity-carrying record (pid *and* process name *and* start time, not a bare pid), or a
  successful save. Absent that evidence the correct action is to leave it alone and say so —
  a directory deleted, a process killed, or hours of unsaved database edits lost are not
  recoverable by re-running the script, and every one of these was a real defect here, not a
  hypothetical. The same rule applies in the restore direction: never `-Force` a file back over
  one that reappeared while it was held.
