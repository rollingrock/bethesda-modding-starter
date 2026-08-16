<#
.SYNOPSIS
    Clone the source repos the modding + RE workflow builds on.

.DESCRIPTION
    Everything is cloned over HTTPS (no SSH key setup required). Idempotent — existing
    clones are left alone (a message notes they exist; no pull is forced).

    What and why:
      CommonLibF4        alandtse/CommonLibF4 — NG-style with runtime dispatch: ENABLE_FALLOUT_F4
                         /_NG/_VR default ON, so ONE DLL serves pre-NG Fallout 4, the Next-Gen
                         update and Fallout 4 VR, choosing at load time via REL::Module.
                         Plugin repos consume it as a submodule; this standalone clone is for
                         reading/searching the headers and for the CommonLibF4Path fallback.
      commonlibsf        libxse/commonlibsf — Starfield CommonLib (xmake-based).
      vr_address_tools   alandtse/vr_address_tools + the two VR address-library submodules
                         (Skyrim VR + Fallout 4 VR offset CSVs). LARGE (~1.1 GB cloned).
      devbench           rollingrock/devbench, branch feat/multigame-core — in-game query
                         server (MCP+REST on loopback) for Skyrim (SKSE/xmake) and
                         Fallout 4 / FO4VR (F4SE/CMake). See docs/DEVBENCH.md.
      ghidra-mcp         bethington/ghidra-mcp — Ghidra MCP bridge + extension source.
                         Installed by setup/30-ghidra.ps1.
      BethesdaGhidraScripts
                         1001Bits/BethesdaGhidraScripts — THE Ghidra enrichment pipeline:
                         auto-imports CommonLib types, vtable layouts, function signatures
                         and address-library names for Skyrim SE/AE/VR, Fallout 4 (all
                         builds + VR), Starfield and FNV; true-VR struct layouts; symbol
                         export to JSON/.map/x64dbg/synthetic PDB. Manages its own pinned
                         Ghidra under tools/ghidra. Cloned WITHOUT submodules — its own
                         menu option 2 restores the reviewed submodule revisions.
                         (alandtse/BethesdaGhidraScripts is an actively developed sibling
                         fork; the two have diverged — see docs/GHIDRA_WORKFLOW.md.)
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\repos',
    [switch]$SkipAddressTools   # skip the ~1.1 GB vr_address_tools clone
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }

$repos = @(
    @{ Name = 'CommonLibF4';  Url = 'https://github.com/alandtse/CommonLibF4.git';      Args = @() }
    @{ Name = 'commonlibsf';  Url = 'https://github.com/libxse/commonlibsf.git';        Args = @('--recurse-submodules') }
    @{ Name = 'devbench';     Url = 'https://github.com/rollingrock/devbench.git';      Args = @('--branch', 'feat/multigame-core', '--recurse-submodules') }
    @{ Name = 'ghidra-mcp';   Url = 'https://github.com/bethington/ghidra-mcp.git';     Args = @() }
    @{ Name = 'BethesdaGhidraScripts'; Url = 'https://github.com/1001Bits/BethesdaGhidraScripts.git'; Args = @() }
)
if (-not $SkipAddressTools) {
    $repos += @{ Name = 'vr_address_tools'; Url = 'https://github.com/alandtse/vr_address_tools.git'; Args = @('--recurse-submodules') }
}

$failed = @()
foreach ($r in $repos) {
    $dest = Join-Path $Root $r.Name
    if (Test-Path (Join-Path $dest '.git')) {
        Write-Host "exists: $dest"
        continue
    }
    Write-Host "cloning $($r.Url) -> $dest"
    # git reports progress on stderr. Under Windows PowerShell 5.1 that becomes an ErrorRecord
    # whenever the caller merges streams (2>&1), and $ErrorActionPreference='Stop' would then
    # abort before the exit-code check below could clean up the partial clone.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    git clone @($r.Args) $r.Url $dest
    $ErrorActionPreference = $prevEap
    if ($LASTEXITCODE -ne 0) {
        # Remove the partial clone: a half-cloned repo would pass the exists-check on
        # re-run and hide the failure. Keep going — one bad repo must not block the rest.
        if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
        $failed += $r.Url
        Write-Warning "clone failed (cleaned up partial dir): $($r.Url)"
    }
}
if ($failed) {
    Write-Host ''
    Write-Warning "FAILED clones: $($failed -join ', ') — re-run this script after fixing connectivity/URLs."
    exit 1
}

Write-Host ''
Write-Host 'Done. Plugin projects get CommonLib as a submodule automatically via New-Plugin.ps1;'
Write-Host 'these clones are for browsing, devbench, and the RE tooling.'
