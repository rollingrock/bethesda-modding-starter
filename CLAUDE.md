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
cmake --preset vs2022-windows-vcpkg-vr    # or vr-mo2 if -Mo2Path was given
cmake --build buildvr --config Release
```

First configure restores ~13 vcpkg ports and compiles CommonLibF4 — several minutes; that is
normal. **Gate:** `buildvr/Release/<name>.dll` exists. This gate proves VS2022+C++23, CMake,
vcpkg, git submodules and the whole chain at once — everything after it is additive.

To test in game: the DLL+PDB go in the mod's `F4SE/Plugins/` (automatic with the `vr-mo2`
preset); copy the TOML from `Data/F4SE/Plugins/` next to it by hand. The game needs F4SEVR
and the [VR Address Library](https://www.nexusmods.com/fallout4/mods/64879) installed. Check
`Documents\My Games\Fallout4VR\F4SE\<name>.log` for the load banner.

## Phase 4 — Ghidra + MCP (RE layer)

```powershell
.\setup\30-ghidra.ps1
```

Then the once-per-machine manual part (the script prints it): start Ghidra, confirm the
GhidraMCP extension is enabled, import the game EXE, run auto-analysis (**hours** — schedule
it overnight; do not interrupt), then `Tools > GhidraMCP > Start MCP Server`.

Give the project's Claude sessions access by copying `mcp\mcp.template.json` to the project as
`.mcp.json` (the scaffolder already does this for new plugins).

**Gate:** with Ghidra running + server started, an MCP session can `list_instances()` →
`connect_instance(...)` → `decompile_function` on some function. **Read
`docs/GHIDRA_WORKFLOW.md` before real RE work — especially the connect ritual; skipping it
makes the toolset look broken or, worse, reads the wrong binary.**

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
