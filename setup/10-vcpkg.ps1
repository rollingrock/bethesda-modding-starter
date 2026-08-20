<#
.SYNOPSIS
    Clone + bootstrap vcpkg and set the environment variables the build chain reads.

.DESCRIPTION
    THE TRAP THIS SCRIPT EXISTS FOR: the plugin templates read TWO different names for
    the same thing — CMakeLists.txt reads VCPKG_ROOT, CMakePresets.json reads
    VCPKG_INSTALLATION_ROOT. Both must be set or configure fails confusingly.
    Idempotent; safe to re-run.
#>
[CmdletBinding()]
param(
    [string]$VcpkgDir = 'C:\repos\vcpkg',
    [switch]$CheckOnly,
    # Clone + bootstrap only; do not write persistent env vars (sandbox/CI runs).
    [switch]$NoEnv
)

$ErrorActionPreference = 'Stop'

# Test-VcpkgUsable -- the one definition of "this vcpkg works" -- lives here. It matters that
# it is ONE definition: -CheckOnly, the do-path below and 90-verify each used to answer that
# question with their own weaker test, and a gate is only ever as strong as its weakest copy.
. "$PSScriptRoot\_common.ps1"

# What Phase 1 has to deliver is "both env vars point at ONE HEALTHY vcpkg", not "a vcpkg
# exists at C:\repos\vcpkg". Judging only against $VcpkgDir punished a machine that was
# already correct: a working clone at, say, D:\dev\vcpkg with VCPKG_ROOT pointing at it got
# "MISSING/WRONG: user env VCPKG_ROOT" and exit 1 from -CheckOnly -- a false alarm about a
# CORRECT setup -- and on a real run got a second multi-GB clone plus User-scope VCPKG_ROOT
# and VCPKG_INSTALLATION_ROOT overwritten to the new root, which silently retargets every
# other project on the machine that resolves vcpkg through those names.
# So when the caller did NOT name a location, adopt the vcpkg this machine already points at,
# provided it satisfies the contract: a .git (it is a clone, so the staleness block can update
# it) AND a vcpkg.exe (it is bootstrapped). Nothing downstream is special-cased -- the
# staleness block, the bootstrap check and the env loop all run unchanged against the adopted
# root, so an adopted vcpkg is still fetched, fast-forwarded and re-bootstrapped like any
# other. An explicit -VcpkgDir always wins, which is what keeps the CI calls -- they always
# pass one -- on exactly the clone they asked for rather than on the runner's preinstalled one.
if (-not $PSBoundParameters.ContainsKey('VcpkgDir')) {
    $adopted = $null
    # VCPKG_ROOT wins the tiebreak when the two names disagree, and the env loop below then
    # aligns VCPKG_INSTALLATION_ROOT to whatever root is chosen here. Per name this is the
    # same lookup the env loop does: User scope first, then Machine.
    foreach ($probe in 'VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT') {
        $candidate = [Environment]::GetEnvironmentVariable($probe, 'User')
        if (-not $candidate) { $candidate = [Environment]::GetEnvironmentVariable($probe, 'Machine') }
        if (-not $candidate) { continue }
        # These values come from the registry, not from us, and Test-Path THROWS
        # ("Illegal characters in path") rather than returning false on a value containing
        # a | or a " -- which under $ErrorActionPreference='Stop' would abort the whole
        # script over an env var it was about to replace anyway. A value we cannot probe is
        # simply not adoptable.
        $healthy = $false
        try {
            $healthy = (Test-Path (Join-Path $candidate '.git')) -and
                       (Test-Path (Join-Path $candidate 'vcpkg.exe'))
        }
        catch { $healthy = $false }
        if ($healthy) { $adopted = $candidate; break }
    }
    if ($adopted) {
        Write-Host "Adopting existing vcpkg at $adopted"
        $VcpkgDir = $adopted
    }
}

# git and bootstrap-vcpkg.bat both write progress to stderr. Under Windows PowerShell 5.1 that
# becomes an ErrorRecord whenever the caller merges streams (2>&1), which $ErrorActionPreference
# ='Stop' would turn into a spurious abort. Run natives with 'Continue' and judge them by their
# exit code, which is the only trustworthy signal.
#
# This deliberately SHADOWS _common.ps1's same-named helper, which takes -Exe/-Arguments: the
# two calls below wrap a scriptblock instead, because one of them is `git clone <url> <dir>`
# and the other a .bat with a switch. It works because this definition runs AFTER the
# dot-source above, so every call in this file binds to this signature. Move the dot-source
# below this point and the scriptblocks would silently bind to the library's -Arguments.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][scriptblock]$Body)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Body } finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)" }
}


$ok = $true
if (-not (Test-Path (Join-Path $VcpkgDir '.git'))) {
    if ($CheckOnly) { Write-Host "MISSING: vcpkg clone at $VcpkgDir"; $ok = $false }
    else {
        Invoke-Native 'git clone vcpkg' { git clone https://github.com/microsoft/vcpkg.git $VcpkgDir }
    }
}

# Bootstrap BEFORE anything asks whether this vcpkg works, because the readiness predicate
# below answers that by RUNNING vcpkg.exe: on a clone this script just made there would be
# nothing to run, and the repair would go hunting for staleness in a checkout that is one
# minute old. The -CheckOnly half of this test is gone on purpose -- `Test-Path vcpkg.exe` is
# a weaker copy of a question Test-VcpkgUsable answers by executing the tool, and an exe built
# from an older checkout is present on disk and still fails every configure with
# "vcpkg-tools.json: document schema version 2 is not supported by this version of vcpkg".
# Two copies of one contract is how the gate ends up softer than the thing it gates.
if (-not $CheckOnly -and (Test-Path $VcpkgDir) -and -not (Test-Path (Join-Path $VcpkgDir 'vcpkg.exe'))) {
    Invoke-Native 'bootstrap-vcpkg' { & (Join-Path $VcpkgDir 'bootstrap-vcpkg.bat') -disableMetrics }
}

# THE READINESS QUESTION, asked identically by -CheckOnly and by the real run.
# It used to be arithmetic -- `git rev-list --count 'HEAD..@{u}'` with its stderr sent to
# $null -- and that arithmetic cannot answer it. On a detached HEAD (what `git checkout
# <release-tag>` leaves behind, which is how Microsoft's own install instructions once told
# people to pin vcpkg, and what `git clone --branch <tag>` produces) rev-list exits 128, the
# count comes back EMPTY, the "behind" test is false, and control fell through to
# 'vcpkg is up to date.' -> 'vcpkg ready.' -> exit 0 over a clone that cannot resolve the
# template's manifest at all. Where origin is a FORK, fetch and rev-list both succeed and
# "up to date" means up to date with the wrong repository. And the whole block sat behind
# `elseif (-not $CheckOnly)`, so `10-vcpkg.ps1 -CheckOnly` -- what CLAUDE.md calls the Phase 1
# gate -- was physically incapable of observing the one failure the comment below says this
# script exists to prevent: "passes the gate" and "can build the template" were decoupled.
# Test-VcpkgUsable asks what actually decides a build: does vcpkg.exe RUN, and is the
# builtin-baseline commit that templates\f4sevr-plugin\vcpkg.json pins both present in this
# clone AND checked out -- fetched objects alone do not help, because vcpkg reads port
# versions out of the working tree. That is true or false however the clone got there --
# branch, tag, detached HEAD or fork -- so both modes ask it, and both are gated on the same
# answer. It is the LIBRARY's definition, deliberately: a local copy here would drift from
# the one 90-verify will consume, and a gate is only as strong as its weakest copy.
$usable = $null
if (Test-Path (Join-Path $VcpkgDir '.git')) {
    $usable = Test-VcpkgUsable -VcpkgDir $VcpkgDir
}

# THE REPAIR. What it does is unchanged; what changed is who asks for it -- the predicate
# above, rather than rev-list arithmetic that mistook "I could not measure this" for "nothing
# to do". A clone that already carries the pinned baseline is now left completely alone: this
# script has no business fetching into, or fast-forwarding, a working clone nobody asked it to
# change.
# An EXISTING clone goes stale, and a stale vcpkg breaks manifests two different ways:
#   1. The pinned `builtin-baseline` commit isn't present at all ->
#      "failed to `git show` versions/baseline.json ... exists on disk, but not in <sha>"
#   2. The commit IS present but the CHECKED-OUT versions/ database predates the versions
#      that baseline names -> "no version database entry for spdlog at 1.17.0"
# Both read like a corrupt checkout rather than an old one. Fetching alone only fixes (1),
# because vcpkg looks port versions up in the working tree -- so fast-forward as well.
# Safe for pinned manifests: a newer tree is a superset of version entries, and each
# project still resolves against its own builtin-baseline.
if ($usable -and $usable.Status -ne 'OK' -and -not $CheckOnly) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    git -C $VcpkgDir fetch origin --quiet
    $fetchRc = $LASTEXITCODE
    $dirty = (git -C $VcpkgDir status --porcelain)
    $behind = (git -C $VcpkgDir rev-list --count 'HEAD..@{u}' 2>$null)
    $ErrorActionPreference = $prev

    if ($fetchRc -ne 0) {
        Write-Warning "vcpkg fetch failed (exit $fetchRc); a manifest pinning a newer baseline may not configure."
    }
    elseif ($dirty) {
        Write-Warning "vcpkg checkout at $VcpkgDir has local changes; leaving it alone. If a build reports a missing version database entry, update it by hand."
    }
    elseif ($behind -and [int]$behind -gt 0) {
        Write-Host "vcpkg is $behind commits behind; fast-forwarding (pinned baselines are unaffected) ..."
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        git -C $VcpkgDir merge --ff-only '@{u}' --quiet
        $ffRc = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($ffRc -ne 0) { Write-Warning "vcpkg fast-forward failed (exit $ffRc); update $VcpkgDir by hand." }
        else {
            # The repo and the vcpkg.exe built from it are versioned together. Advancing the
            # checkout without re-bootstrapping leaves an old tool against new scripts, which
            # fails every configure with "vcpkg-tools.json: document schema version 2 is not
            # supported by this version of vcpkg" -- a message that says nothing about the
            # tool being stale. Rebuild it whenever the checkout moved.
            Write-Host 'Re-bootstrapping vcpkg.exe to match the updated checkout ...'
            Invoke-Native 'bootstrap-vcpkg (post-update)' {
                & (Join-Path $VcpkgDir 'bootstrap-vcpkg.bat') -disableMetrics
            }
        }
    }
    else {
        # This is where 'vcpkg is up to date.' used to be printed, and that claim is the whole
        # of this defect. Reaching here now means the predicate said the clone is NOT usable
        # and nothing was fast-forwarded, so there is nothing to celebrate -- only a state to
        # name. $behind is EMPTY when rev-list could not answer at all (detached HEAD, tag
        # checkout, or a branch with no upstream: it exits 128 with its stderr discarded) and
        # '0' when the checkout really is level with its upstream.
        # The fetch above may still have been enough on its own, because it brings the pinned
        # baseline COMMIT into the object database -- failure (1). What no fetch can do is
        # advance the CHECKED-OUT versions/ tree, which is failure (2). Neither this branch nor
        # the two above get to decide that: the postcondition below re-runs the tool.
        if ("$behind".Trim()) {
            Write-Warning "vcpkg at $VcpkgDir is level with its upstream and still not usable; fetched, but there was nothing to fast-forward."
        }
        else {
            Write-Warning "vcpkg at $VcpkgDir is not on a branch tracking origin (detached HEAD, tag checkout, or no upstream), so nothing could be fast-forwarded and this clone stays pinned where you put it. If a build then reports 'no version database entry for <port> at <version>', its versions/ database predates the manifest baseline: check out a branch that tracks origin (git -C $VcpkgDir checkout master), or pin the manifest's builtin-baseline to a commit this checkout contains."
        }
    }

    # POSTCONDITION. The do-path has to finish by PROVING the state it was asked to produce,
    # not by reaching the end of its own code: "fetch returned 0 and merge returned 0" is a
    # report about two commands, not about whether this vcpkg can resolve the manifest. Same
    # predicate and same four-property answer that -CheckOnly gets, so a repair that did not
    # take fails the run on exactly the evidence a check run would have shown. It has to be the
    # CLONE predicate, not the shared one: the fetch two branches up puts the baseline commit in
    # the object database whether or not anything was fast-forwarded, so the object test alone
    # would report OK for the detached-HEAD and refused-dirty cases purely because the repair
    # touched the object store -- the postcondition would be passing itself.
    $usable = Test-VcpkgUsable -VcpkgDir $VcpkgDir
}

# The one place either mode announces the answer, so a check run and a real run cannot disagree
# about what "ready" means. Write-ProbeResult prints the exact command underneath a FAIL,
# because the first thing anyone does with "vcpkg is not usable" is try to reproduce it by
# hand. A clone that is unusable and could not be repaired FAILS here -- which is precisely
# what the 'vcpkg is up to date.' path never did.
if ($usable) {
    Write-ProbeResult -Result $usable
    if ($usable.Status -ne 'OK') {
        $ok = $false
        if ($CheckOnly) {
            Write-Host "  Re-run this script without -CheckOnly to repair it: it bootstraps a clone that has no vcpkg.exe, and fetches origin and fast-forwards one whose checkout is behind."
        }
        else {
            Write-Host "  The repair ran and this clone is still not usable. Fast-forward $VcpkgDir onto origin by hand (it may be pinned to a tag, or origin may be a fork), then re-run bootstrap-vcpkg.bat -disableMetrics."
        }
    }
}

if ($NoEnv) {
    Write-Host 'NoEnv: skipping persistent env var setup.'
    # Leaving by `return` skipped the explicit `exit 0` at the bottom of the file, so this
    # path fell off the end of the script and $LASTEXITCODE kept whatever the last native
    # command left behind. On a fully SUCCESSFUL run against a detached-HEAD or tag-pinned
    # clone that is `git rev-list --count HEAD..@{u}`, which exits 128 with its stderr
    # suppressed -- so a caller gating on the exit code reported a failure that never
    # happened. Exit explicitly instead. A miss found above still has to win, because skipping
    # the env work is not permission to call an incomplete vcpkg ready -- and that is no longer
    # only a -CheckOnly concern: the readiness predicate can now report a clone the repair
    # could not make usable, on the very path (-NoEnv, used by CI) whose next step is a
    # configure that would fail on the baseline it was never told about.
    if (-not $ok) { exit 1 }
    exit 0
}

foreach ($name in 'VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT') {
    # Accept an existing value at either persisted scope (some machines set these Machine-wide).
    $current = [Environment]::GetEnvironmentVariable($name, 'User')
    if (-not $current) { $current = [Environment]::GetEnvironmentVariable($name, 'Machine') }
    if ($current -ne $VcpkgDir) {
        if ($CheckOnly) { Write-Host "MISSING/WRONG: user env $name (is: '$current', want: '$VcpkgDir')"; $ok = $false }
        else {
            [Environment]::SetEnvironmentVariable($name, $VcpkgDir, 'User')
            Set-Item "env:$name" $VcpkgDir
            # Say what is being replaced. Overwriting a machine-wide VCPKG_ROOT retargets
            # every other project that resolves vcpkg through it, and a bare "Set user env
            # VCPKG_ROOT = ..." gave the user nothing to put back if that was not wanted.
            $was = ''
            if ($current) { $was = " (was: '$current')" }
            Write-Host "Set user env $name = $VcpkgDir$was"
        }
    }
    else {
        # The registry already agrees, but the PROCESS copy may not -- this shell may have
        # started before the value was persisted, or with a stale one. Without this the
        # closing "this one was updated in-place" message below is a lie on every re-run,
        # and a cmake configure launched from this same shell still reads the old root.
        Set-Item "env:$name" $current
        Write-Host "OK: $name = $current"
    }
}

# Manifest-mode projects pick their own triplet; this is just a sane default.
$trip = [Environment]::GetEnvironmentVariable('VCPKG_DEFAULT_TRIPLET', 'User')
if (-not $trip) {
    if (-not $CheckOnly) {
        [Environment]::SetEnvironmentVariable('VCPKG_DEFAULT_TRIPLET', 'x64-windows', 'User')
        Write-Host 'Set user env VCPKG_DEFAULT_TRIPLET = x64-windows'
    }
}

# No longer -CheckOnly's gate alone. A real run that could not make this clone usable must not
# reach the line below: 'vcpkg ready.' is the sentence a stale, tag-pinned or forked clone used
# to get on its way to exit 0, and it is the last thing anyone reads before blaming CMake for
# "no version database entry for spdlog at 1.17.0". The env vars above have still been pointed
# at $VcpkgDir -- that half of the job did succeed; what failed is the clone they name.
if (-not $ok) { exit 1 }
Write-Host 'vcpkg ready. NOTE: env vars set at User scope — new terminals see them; this one was updated in-place.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
