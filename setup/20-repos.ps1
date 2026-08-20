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
      devbench           rollingrock/devbench (main) — in-game query server (MCP+REST on
                         loopback) for Skyrim (SKSE/xmake) and Fallout 4 / FO4VR
                         (F4SE/CMake). See docs/DEVBENCH.md.
      modlist-agent      rollingrock/modlist-agent — reproducible MO2 instance builder, and
                         the SteamVR null-driver toggle Phase 6 uses to run a VR game with
                         no headset attached.
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
    # devbench: MAIN, not feat/multigame-core. That branch stopped at 82cbdb2 and is missing
    # df37963, which moves the Fallout server's startup from kGameDataReady to kPostLoad --
    # without it the server never starts on F4SEVR and :8931 is simply closed. Cloning the
    # branch handed a fresh machine the broken build while the docs said Phase 6 worked.
    @{ Name = 'devbench';     Url = 'https://github.com/rollingrock/devbench.git';      Args = @('--recurse-submodules') }
    @{ Name = 'ghidra-mcp';   Url = 'https://github.com/bethington/ghidra-mcp.git';     Args = @() }
    @{ Name = 'BethesdaGhidraScripts'; Url = 'https://github.com/1001Bits/BethesdaGhidraScripts.git'; Args = @() }
    # modlist-agent: builds the MO2 instance Phase 6 runs against, and ships
    # core/tools/steamvr-null.ps1 -- the SteamVR null driver toggle that lets a VR game boot
    # and load its plugins with no headset attached. That is what makes Phase 6 something an
    # agent can run rather than hand back to the user. CLAUDE.md references it by path.
    @{ Name = 'modlist-agent'; Url = 'https://github.com/rollingrock/modlist-agent.git'; Args = @() }
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
    # Provenance for the failure cleanup below -- never destroy what this script cannot prove
    # it created. Only a $dest that did NOT exist a moment ago can be a partial clone of ours.
    # git refuses to clone into an existing non-empty directory ("destination path ... already
    # exists and is not an empty directory") WITHOUT touching a byte of its contents, so on
    # that failure everything under $dest is the user's: a GitHub "Download ZIP" extract, a
    # snapshot with .git deliberately removed (either sails past the .git check at line 69),
    # or an unrelated working folder that merely shares a repo name. Deleting it cost the user
    # months of local modifications and reported nothing but a transient clone failure.
    $existedBefore = Test-Path $dest
    # git reports progress on stderr. Under Windows PowerShell 5.1 that becomes an ErrorRecord
    # whenever the caller merges streams (2>&1), and $ErrorActionPreference='Stop' would then
    # abort before the exit-code check below could clean up the partial clone.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    git clone @($r.Args) $r.Url $dest
    $ErrorActionPreference = $prevEap
    if ($LASTEXITCODE -ne 0) {
        $failed += $r.Url
        if ($existedBefore) {
            # A separate event from a partial clone, so it gets a separate message: git
            # declined to write into a directory that was already on disk. One message for
            # both cases actively misleads -- it told the user their data was "partial" and
            # that removing it was cleanup. Either way the directory is the user's and this
            # branch never deletes; only the wording differs.
            if (Test-Path (Join-Path $dest '.git')) {
                # git ACCEPTS an existing EMPTY directory, so a dir the user pre-created can
                # still get a clone started in it that dies later -- a --recurse-submodules
                # fetch failure (commonlibsf, devbench, vr_address_tools) leaves a complete
                # .git and a checked-out top level behind. We must not delete it, but it must
                # not pass silently either: the .git test at line 69 would print "exists" on
                # the next run and count this broken tree as a finished clone.
                Write-Warning "clone failed: $($r.Url) -- an INCOMPLETE clone was left inside the pre-existing directory $dest. Not deleting it (this script did not create that directory). Remove or move it aside yourself before re-running, or the next run will see its .git and skip it as already cloned."
            }
            else {
                Write-Warning "clone failed: $($r.Url) -- pre-existing non-repo directory left untouched at $dest; move it aside yourself, then re-run."
            }
        }
        else {
            # Remove the partial clone: a half-cloned repo would pass the exists-check on
            # re-run and hide the failure. Keep going — one bad repo must not block the rest.
            if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
            Write-Warning "clone failed (cleaned up partial dir): $($r.Url)"
        }
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

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
