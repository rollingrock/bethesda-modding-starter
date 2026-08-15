<#
.SYNOPSIS
    Clone the source repos the modding + RE workflow builds on.

.DESCRIPTION
    Everything is cloned over HTTPS (no SSH key setup required). Idempotent — existing
    clones are left alone (a message notes they exist; no pull is forced).

    What and why:
      CommonLibF4        rollingrock/CommonLibF4 — NG-style: one lib builds flat F4 AND F4VR.
                         Plugin repos consume it as a submodule; this standalone clone is for
                         reading/searching the headers and for the CommonLibF4Path fallback.
      commonlibsf        libxse/commonlibsf — Starfield CommonLib (xmake-based).
      vr_address_tools   alandtse/vr_address_tools + the two VR address-library submodules
                         (Skyrim VR + Fallout 4 VR offset CSVs). LARGE (~300 MB of CSV/JSON).
      devbench           rollingrock/devbench, branch feat/multigame-core — in-game query
                         server (MCP+REST on loopback) for Skyrim (SKSE/xmake) and
                         Fallout 4 / FO4VR (F4SE/CMake). See docs/DEVBENCH.md.
      ghidra-mcp         bethington/ghidra-mcp — Ghidra MCP bridge + extension source.
                         Installed by setup/30-ghidra.ps1.
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\repos',
    [switch]$SkipAddressTools   # skip the ~300 MB vr_address_tools clone
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }

$repos = @(
    @{ Name = 'CommonLibF4';  Url = 'https://github.com/rollingrock/CommonLibF4.git';   Args = @() }
    @{ Name = 'commonlibsf';  Url = 'https://github.com/libxse/commonlibsf.git';        Args = @('--recurse-submodules') }
    @{ Name = 'devbench';     Url = 'https://github.com/rollingrock/devbench.git';      Args = @('--branch', 'feat/multigame-core', '--recurse-submodules') }
    @{ Name = 'ghidra-mcp';   Url = 'https://github.com/bethington/ghidra-mcp.git';     Args = @() }
)
if (-not $SkipAddressTools) {
    $repos += @{ Name = 'vr_address_tools'; Url = 'https://github.com/alandtse/vr_address_tools.git'; Args = @('--recurse-submodules') }
}

foreach ($r in $repos) {
    $dest = Join-Path $Root $r.Name
    if (Test-Path (Join-Path $dest '.git')) {
        Write-Host "exists: $dest"
        continue
    }
    Write-Host "cloning $($r.Url) -> $dest"
    git clone @($r.Args) $r.Url $dest
    if ($LASTEXITCODE -ne 0) { throw "clone failed: $($r.Url)" }
}

Write-Host ''
Write-Host 'Done. Plugin projects get CommonLib as a submodule automatically via New-Plugin.ps1;'
Write-Host 'these clones are for browsing, devbench, and the RE tooling.'
