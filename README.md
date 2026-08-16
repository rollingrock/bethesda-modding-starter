# bethesda-modding-starter

A one-stop bootstrap for Bethesda script-extender plugin development (Fallout 4 flat/VR,
Skyrim, Starfield) **plus** the reverse-engineering tooling to work at the engine level
(Ghidra + MCP, x64dbg + MCP, in-game devbench) — the environment behind rollingrock's
FO4VR mods, packaged so a new machine gets there in about an hour instead of months.

Built to be driven by a coding agent: clone this repo, open
[Claude Code](https://claude.com/claude-code) in it, and say **"read CLAUDE.md and set this
machine up"**. Everything also works by hand — the setup scripts are ordinary PowerShell.

## What you get

- **`setup/`** — numbered, idempotent install scripts: toolchain (VS2022/CMake/vcpkg/JDK/
  Node), source repos, Ghidra + [GhidraMCP](https://github.com/bethington/ghidra-mcp),
  x64dbg + [MCP plugin](https://github.com/bromoket/x64dbg_mcp), and an end-to-end verifier.
- **`New-Plugin.ps1`** — scaffold a ready-to-build plugin repo in one command:
  ```powershell
  .\New-Plugin.ps1 -Name my-cool-mod -Game F4VR -Mo2Path "C:\MO2\Fallout4VR\mods\my-cool-mod"
  cd C:\repos\my-cool-mod
  cmake --preset vr-mo2
  cmake --build buildvr --config Release   # DLL+PDB auto-deploy into the MO2 folder
  ```
  The F4VR template carries the fixes that cost real crashes to learn (single trampoline
  allocation, MO2 deploy, TOML settings framework) and builds clean at `/W4 /WX`.
- **`docs/`** — the per-game stack matrix (which CommonLib/address library per game), the
  Ghidra MCP workflow, and the devbench guide.
- **`mcp/mcp.template.json`** — drop-in `.mcp.json` giving any project's Claude sessions
  Ghidra + x64dbg access (the scaffolder installs it automatically;
  `36-ghidra-mcp.ps1 -WriteMcpConfigTo <dir>` generates it with paths resolved).
- **`ghidra-scripts/`** — bulk address-library name import for Ghidra.

## Quick start (fresh machine)

```powershell
git clone https://github.com/rollingrock/bethesda-modding-starter.git C:\repos\bethesda-modding-starter
cd C:\repos\bethesda-modding-starter
# elevated PowerShell for installs:
.\setup\00-prereqs.ps1        # toolchain via winget
.\setup\10-vcpkg.ps1          # vcpkg + BOTH env vars the chain reads
.\setup\20-repos.ps1          # CommonLibs, devbench, ghidra-mcp, address libraries
.\setup\30-ghidra.ps1         # GhidraMCP extension + bridge, built for YOUR Ghidra version
.\setup\35-ghidra-analysis.ps1     # the enriched analysis database (hours; -CheckOnly first)
.\setup\36-ghidra-mcp.ps1 -Start   # headless MCP server — no GUI, no clicks
.\setup\40-x64dbg.ps1         # x64dbg + MCP plugin (version-pinned)
.\setup\90-verify.ps1 -BuildTest   # proves it: scaffolds and builds a real plugin
```

Games/dev only? `00`, `10`, `20 -SkipAddressTools`, then `New-Plugin.ps1`. The RE layer
(`30`, `40`) is independent and can come later.

## Credits

This is community-built infrastructure all the way down: alandtse (CommonLib VR forks,
address libraries, devbench), the F4SE/SKSE/SFSE teams, Ryan-rsm-McKenzie and the CommonLib
lineage, meh321 (address libraries), bethington (ghidra-mcp), bromoket (x64dbg_mcp),
powerof3, shad0wshayd3, and many more.
