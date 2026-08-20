<#
.SYNOPSIS
    Clone the source repos the modding + RE workflow builds on.

.DESCRIPTION
    Everything is cloned over HTTPS (no SSH key setup required). Idempotent — an existing
    clone is left alone (no pull is forced), but only once its origin has been checked against
    the URL pinned below. A .git in a directory of the right NAME is not evidence it holds the
    repo this pack wants; a clone of a different repository is reported and left exactly where
    it is -- never cloned over, never deleted.

    -CheckOnly reports each repo's identity and clones nothing.

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
    [switch]$SkipAddressTools,  # skip the ~1.1 GB vr_address_tools clone

    # Report what each repo IS; clone nothing. Exit 0 = every wanted repo is present and came
    # from the pinned URL, 2 = work is pending (something is missing or is a different repo),
    # 1 = a real failure (git itself does not run, so no identity question can be answered).
    # Same vocabulary 35-ghidra-analysis.ps1 documents, so an agent gates on both the same way.
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"

# This was the ONE tool-using script here that never dot-sourced _common.ps1 and never called
# Sync-Path, and it runs git. A shell that started before winget installed Git carries a PATH
# without it: `git clone` below then resolves to nothing, and because the clone deliberately
# runs inside an $ErrorActionPreference='Continue' window the CommandNotFound error is
# non-terminating, $LASTEXITCODE is left untouched by a command that never ran, `$null -ne 0`
# is true, and EVERY repo is reported as a failed clone on a machine whose only problem is a
# stale PATH. Sync-Path rebuilds $env:Path from the registry so a just-installed git is visible
# in THIS process.
Sync-Path

# Ask the capability question once, by running the tool (see the probe layer in _common.ps1):
# Get-Command finding git.exe is not the same claim as git working. Asking here converts the
# stale-PATH failure above into one accurate message instead of six wrong ones, and it has to
# precede the identity checks as well, because Test-RepoIdentity cannot distinguish "this is
# the wrong fork" from "git could not be asked". -MinMajor 2 is not a feature floor -- every
# git since 2005 clears it -- it just refuses to accept a git that exits 0 while printing no
# version at all.
$gitProbe = Test-CmdRuns -Name 'git' -ProbeArgs @('--version') -MinMajor 2
if ($gitProbe.Status -ne 'OK') {
    Write-ProbeResult $gitProbe
    Write-Warning 'git does not run, so nothing here can be cloned or identified. Fix git first (setup\00-prereqs.ps1), then re-run.'
    exit 1
}

# -CheckOnly writes nothing at all, and -Root is part of "nothing": creating C:\repos in order
# to report that it is empty changes the very machine the caller asked about. Missing repos are
# reported as pending either way, which is the honest answer.
if (-not $CheckOnly -and -not (Test-Path $Root)) { New-Item -ItemType Directory -Force $Root | Out-Null }

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

# ---- -CheckOnly: the same table, the same predicate, nothing written ----
# One loop over the table above, so the answer this reports and the decision the clone loop
# below makes can never drift apart -- they are the same call to Test-RepoIdentity. Answering
# "is phase 2 done?" used to require re-implementing the .git test somewhere else (90-verify
# has its own copy, and it does not even list BethesdaGhidraScripts), and the weakest copy is
# what a caller ends up trusting.
if ($CheckOnly) {
    Write-Host "Repo identity under $Root (nothing will be cloned):"
    $pending = 0
    foreach ($r in $repos) {
        $id = Test-RepoIdentity -Path (Join-Path $Root $r.Name) -Url $r.Url
        Write-ProbeResult $id
        if ("$($id.Status)" -ne 'OK') { $pending++ }
    }
    if ($SkipAddressTools) {
        # Reported, but NOT pending: the caller asked for this repo to be skipped, and calling
        # a declined repo "work pending" is how a healthy machine ends up permanently non-zero.
        # Silence would be worse than either -- a reader would take it for present.
        Write-Host '  skip vr_address_tools     -SkipAddressTools was passed: not checked, not counted as pending.'
    }
    Write-Host ''
    if ($pending -gt 0) {
        Write-Host "  $pending repo(s) missing, or cloned from a URL this pack does not pin."
        Write-Host '  Re-run without -CheckOnly to clone what is absent. A URL mismatch is yours to'
        Write-Host '  resolve: this script will not touch a clone it cannot prove it created.'
        exit 2
    }
    Write-Host '  All wanted repos are present and came from the pinned URLs.'
    exit 0
}

$failed = @()
$mismatched = @()
foreach ($r in $repos) {
    $dest = Join-Path $Root $r.Name
    # A .git under $dest was the entire skip decision, and it blesses the WRONG repository
    # forever: "exists: <dest>", exit 0, on this run and every run after it. That is not
    # hypothetical for this table. alandtse/BethesdaGhidraScripts is an actively developed
    # sibling of the 1001Bits fork pinned above, the two have diverged, and both put a .git in
    # a directory named BethesdaGhidraScripts -- 30-ghidra.ps1 would then build against
    # whatever tools\ghidra the other fork manages while docs/GHIDRA_WORKFLOW.md sends the user
    # to a menu option it does not have. The same blind spot is why the devbench branch fix
    # above (main, not feat/multigame-core) only ever reached machines with no clone yet: a
    # machine already carrying the broken one was told it was done. Only origin tells them
    # apart, so ask origin.
    if (Test-Path (Join-Path $dest '.git')) {
        $id = Test-RepoIdentity -Path $dest -Url $r.Url
        if ("$($id.Status)" -eq 'OK') {
            Write-Host "exists: $dest ($($id.Detail))"
            continue
        }
        # Say what is wrong -- the probe's Detail names the origin found AND the URL pinned --
        # then leave it alone and keep going. Not cloned over (git would refuse anyway) and
        # above all not deleted: this script just gained a rule against destroying what it
        # cannot prove it created, and a clone of another fork is still the user's directory,
        # possibly with the local work they care about in it. Which one they want is their
        # call, not this script's.
        Write-ProbeResult $id
        $mismatched += $dest
        continue
    }
    Write-Host "cloning $($r.Url) -> $dest"
    # Provenance for the failure cleanup below -- never destroy what this script cannot prove
    # it created. Only a $dest that did NOT exist a moment ago can be a partial clone of ours.
    # git refuses to clone into an existing non-empty directory ("destination path ... already
    # exists and is not an empty directory") WITHOUT touching a byte of its contents, so on
    # that failure everything under $dest is the user's: a GitHub "Download ZIP" extract, a
    # snapshot with .git deliberately removed (either sails past the .git check above),
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
                # not pass silently either: the .git test at the top of this loop finds a
                # matching origin in that stump and would print "exists" on the next run,
                # counting this broken tree as a finished clone.
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
if ($mismatched) {
    Write-Host ''
    Write-Warning ("NOT the pinned repository: " + ($mismatched -join ', ') + " -- left untouched (nothing cloned into them, nothing deleted). The usual cause is the other fork; a mirror or an SSH rewrite of the same repo looks the same from here and this script will not guess between them. Move the directory aside and re-run, or repoint its origin at the URL named above.")
}
if ($failed) {
    Write-Host ''
    Write-Warning "FAILED clones: $($failed -join ', ') — re-run this script after fixing connectivity/URLs."
    exit 1
}
if ($mismatched) {
    # Work is pending that only the user can decide -- exit 2, the -CheckOnly vocabulary, and
    # deliberately not 0: exiting 0 here would tell an agent phase 2 is finished while the repo
    # every later phase builds against is the wrong one, which is precisely the failure the
    # identity check exists to stop. Not 1 either: nothing failed, and re-running changes
    # nothing until a human moves that directory.
    exit 2
}

Write-Host ''
Write-Host 'Done. Plugin projects get CommonLib as a submodule automatically via New-Plugin.ps1;'
Write-Host 'these clones are for browsing, devbench, and the RE tooling.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
