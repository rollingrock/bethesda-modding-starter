# bethesda-modding-starter

A one-stop bootstrap for Bethesda script-extender plugin development (Fallout 4 flat/VR,
Skyrim, Starfield) **plus** the reverse-engineering tooling to work at the engine level
(Ghidra + MCP, x64dbg + MCP, in-game devbench) — the environment behind rollingrock's
FO4VR mods, packaged so a new machine gets there in about an hour instead of months.

Built to be driven by a coding agent: clone this repo, open
[Claude Code](https://claude.com/claude-code) in it, and say **"read CLAUDE.md and set this
machine up"**. Everything also works by hand — the setup scripts are ordinary PowerShell.

## What you get

- **`setup/`** — numbered, idempotent install scripts: the winget toolchain, vcpkg (both env
  var names the build chain reads), the source repos, Ghidra + [GhidraMCP](https://github.com/bethington/ghidra-mcp),
  x64dbg + [MCP plugin](https://github.com/bromoket/x64dbg_mcp), and an end-to-end verifier.
  Each script's own header is the authority on its flags, its sizes and its paths; `CLAUDE.md`
  carries the order, the gates and the traps.
- **`New-Plugin.ps1`** — scaffold a ready-to-build plugin repo in one command:
  ```powershell
  .\New-Plugin.ps1 -Name my-cool-mod -Game F4VR -Mo2Path "C:\MO2\Fallout4VR\mods\my-cool-mod"
  cd C:\repos\my-cool-mod
  cmake --preset vr-mo2
  cmake --build buildvr --config Release   # my_cool_mod.dll+PDB land in the MO2 folder
  ```
  `-Mo2Path` is the mod's **own** folder, and the `mods` root above it has to exist already:
  the scaffolder refuses a path MO2 does not use, and so does the build's configure step,
  because `cmake -E make_directory` deep-creates whatever it is handed — a typo used to build
  green into a tree no MO2 instance reads.
  The F4VR template carries the fixes that cost real crashes to learn (single trampoline
  allocation, MO2 deploy, TOML settings framework) and builds clean at `/W4 /WX`.
- **`docs/`** — the per-game stack matrix (which CommonLib/address library per game), the
  Ghidra MCP workflow, and the devbench guide.
- **`mcp/mcp.template.json`** — a reference copy of the `.mcp.json` that gives a project's
  Claude sessions Ghidra + x64dbg tools. The real one is generated, never copied: the
  scaffolder writes one into every new repo, and `36-ghidra-mcp.ps1 -WriteMcpConfigTo <dir>`
  writes one into a project that already exists — both carrying this machine's real bridge
  path, which a copied template cannot know.
- **`ghidra-scripts/`** — the VR naming and prototype scripts: `import_vr_names_headless.py`
  (address-library names applied unattended under pyghidra — for Fallout 4 VR this is the
  primary source of real function names, not a fallback), `apply_prototypes.py` (turns those
  signature-carrying names into applied prototypes over the MCP server), and
  `ImportAddressLibrary.py` (the Jython GUI fallback).

## Quick start (fresh machine)

```powershell
git clone https://github.com/rollingrock/bethesda-modding-starter.git C:\repos\bethesda-modding-starter
cd C:\repos\bethesda-modding-starter
# elevated PowerShell for installs:
.\setup\00-prereqs.ps1        # toolchain via winget
.\setup\10-vcpkg.ps1          # vcpkg + BOTH env vars the chain reads
.\setup\20-repos.ps1          # CommonLibs, devbench, ghidra-mcp, BethesdaGhidraScripts,
                              #   modlist-agent, VR address libraries
.\setup\35-ghidra-analysis.ps1     # the enriched analysis database (hours; -CheckOnly first)
.\setup\30-ghidra.ps1         # GhidraMCP extension + bridge, built for YOUR Ghidra version
.\setup\36-ghidra-mcp.ps1 -Start   # headless MCP server — no GUI, no clicks
.\setup\40-x64dbg.ps1         # x64dbg + MCP plugin (version-pinned)
.\setup\90-verify.ps1 -BuildTest   # proves it: scaffolds and builds a real plugin
```

**`35` runs before `30`, and that order is not cosmetic.** `30-ghidra.ps1` builds the MCP
extension for a Ghidra install that already exists, and throws when there is none. On a fresh
machine that install is the one BethesdaGhidraScripts manages, and `35-ghidra-analysis.ps1` is
what creates it. `35` in turn needs your own game binaries staged as
`C:\repos\BethesdaGhidraScripts\exes\<game>\<ver>\<Game>.exe` — they come out of your game
installs and cannot be downloaded. With none staged, `35` exits 0 having done nothing at all,
and `30` then throws for want of a Ghidra install.

Games/dev only? `00`, `10`, `20 -SkipAddressTools`, then `New-Plugin.ps1`. The RE layer
(`35`, `30`, `36`, `40`) is independent and can come later; `35` is the long pole, hours per
binary. `CLAUDE.md` carries the full phase order, each phase's gate, and the traps.

## Credits

This is community-built infrastructure all the way down: alandtse (CommonLib VR forks,
address libraries, devbench), the F4SE/SKSE/SFSE teams, Ryan-rsm-McKenzie and the CommonLib
lineage, meh321 (address libraries), bethington (ghidra-mcp), bromoket (x64dbg_mcp),
powerof3, shad0wshayd3, and many more.
