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
elseif (-not $CheckOnly) {
    # An EXISTING clone goes stale, and a stale vcpkg breaks manifests two different ways:
    #   1. The pinned `builtin-baseline` commit isn't present at all ->
    #      "failed to `git show` versions/baseline.json ... exists on disk, but not in <sha>"
    #   2. The commit IS present but the CHECKED-OUT versions/ database predates the versions
    #      that baseline names -> "no version database entry for spdlog at 1.17.0"
    # Both read like a corrupt checkout rather than an old one. Fetching alone only fixes (1),
    # because vcpkg looks port versions up in the working tree -- so fast-forward as well.
    # Safe for pinned manifests: a newer tree is a superset of version entries, and each
    # project still resolves against its own builtin-baseline.
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
    else { Write-Host 'vcpkg is up to date.' }
}
if ((Test-Path $VcpkgDir) -and -not (Test-Path (Join-Path $VcpkgDir 'vcpkg.exe'))) {
    if ($CheckOnly) { Write-Host 'MISSING: vcpkg.exe (bootstrap not run)'; $ok = $false }
    else { Invoke-Native 'bootstrap-vcpkg' { & (Join-Path $VcpkgDir 'bootstrap-vcpkg.bat') -disableMetrics } }
}

if ($NoEnv) {
    Write-Host 'NoEnv: skipping persistent env var setup.'
    # Leaving by `return` skipped the explicit `exit 0` at the bottom of the file, so this
    # path fell off the end of the script and $LASTEXITCODE kept whatever the last native
    # command left behind. On a fully SUCCESSFUL run against a detached-HEAD or tag-pinned
    # clone that is `git rev-list --count HEAD..@{u}`, which exits 128 with its stderr
    # suppressed -- so a caller gating on the exit code reported a failure that never
    # happened. Exit explicitly instead. A -CheckOnly miss found above still has to win,
    # because skipping the env work is not permission to call an incomplete vcpkg ready.
    if ($CheckOnly -and -not $ok) { exit 1 }
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

if ($CheckOnly -and -not $ok) { exit 1 }
Write-Host 'vcpkg ready. NOTE: env vars set at User scope — new terminals see them; this one was updated in-place.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
