<#
.SYNOPSIS
    A vcpkg clone that cannot resolve the template's baseline must not be called usable.

.DESCRIPTION
    setup\10-vcpkg.ps1 used to decide staleness with `git rev-list --count 'HEAD..@{u}'` and its
    stderr sent to $null. That arithmetic cannot answer the question. On a detached HEAD -- what
    `git checkout <release-tag>` leaves behind, which is how Microsoft's own instructions once
    told people to pin vcpkg -- rev-list exits 128, the count comes back EMPTY, the "behind" test
    is false, and control fell through to "vcpkg is up to date." over a clone that cannot resolve
    the template's manifest at all. The user then spends the evening blaming CMake for
    "no version database entry for spdlog at 1.17.0".

    The message is gone, so this fixture does not look for a message. It tests the PREDICATE that
    replaced it -- Test-VcpkgUsable in setup\_common.ps1, dot-sourced here and called directly --
    because the message is the half that drifted and the predicate is the contract. Three things
    have to be true together for a clone to be usable:

      1. vcpkg.exe RUNS. Present on disk is not the same claim: an exe built from an older
         checkout sits there and fails every configure with "vcpkg-tools.json: document schema
         version 2 is not supported by this version of vcpkg".
      2. The template's pinned builtin-baseline commit is PRESENT in the clone. Without it,
         configure fails with "failed to git show versions/baseline.json ... exists on disk, but
         not in <sha>", which reads like a corrupt checkout rather than an old one.
      3. That commit is an ANCESTOR OF HEAD. Having the object is not enough: git fetch puts it
         in the object database while vcpkg resolves port versions out of the WORKING TREE, so a
         clone that fetched but was never advanced holds the commit and still fails every
         configure. This is also what keeps the predicate honest as 10-vcpkg.ps1's postcondition,
         since the repair fetches -- an object-only test would pass on a tree the repair never
         touched.

    Each of the three is given a scratch git repo built to fail exactly it, and one repo built to
    satisfy all three. vcpkg.exe is a compiled console stub, not the real 100 MB tool: the
    predicate asks whether it runs and exits 0, so a stub answers that question honestly, and a
    fixture that had to bootstrap vcpkg would take minutes and need the network.

    LAST TWO ASSERTIONS, id 5 and a different defect in the same file: `-NoEnv` used to leave the
    script by `return`, which skips the trailing `exit 0`, so a fully successful run left the
    caller holding whatever the last native command had put in $LASTEXITCODE -- measured 128 from
    the suppressed rev-list on a tag-pinned clone, which every caller gating on that value reads
    as a hard failure. The usable clone below is checked out DETACHED for that reason: it is the
    shape that produced the 128. Both directions are pinned, because "always exit 0" is not the
    fix either -- an unusable clone must still leave 1 on the -NoEnv path, which is the path CI
    uses and whose next step is a configure.

    The -NoEnv runs need a pack tree rather than a bare script: Test-VcpkgUsable reads its
    baseline from <pack>\templates\f4sevr-plugin\vcpkg.json, and no scratch repo can contain the
    real pinned sha. So the real manifest is copied with its builtin-baseline rewritten to a
    commit these scratch repos do have. Nothing outside the scratch tree is written, and -NoEnv
    means no persisted environment variable is touched.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$script:failures = New-Object System.Collections.Generic.List[string]

# The library under test, dot-sourced. _common.ps1 has no side effects at load time by design,
# which is what makes calling one predicate out of it a cheap thing for a fixture to do.
. (Join-Path $repoRoot 'setup\_common.ps1')

function Assert-That {
    param([bool]$Condition, [string]$What)
    if ($Condition) { Write-Host "    ok   $What" }
    else {
        Write-Host "    FAIL $What"
        $script:failures.Add($What)
    }
}

function Assert-Probe {
    param($Result, [string]$WantStatus, [string]$What)
    $got = "$($Result.Status)"
    if ($got -eq $WantStatus) { Write-Host "    ok   $What" }
    else {
        Write-Host "    FAIL $What -- got $got, wanted $WantStatus"
        Write-Host "         detail: $($Result.Detail)"
        $script:failures.Add($What)
    }
}

function Invoke-GitOrThrow {
    param([string]$Dir, [string[]]$GitArgs)
    # Same 5.1 dance the setup scripts use: a native command's stderr becomes ErrorRecords, and
    # git narrates on stderr even when it succeeds (the detached-HEAD advice below is the
    # example this fixture actually trips over). Judge it by the exit code only.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & git -C $Dir @GitArgs 2>&1
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    $text = (@($out) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    if ($rc -ne 0) { throw "git -C $Dir $($GitArgs -join ' ') exited $rc : $text" }
    return $text.Trim()
}

# A console exe that prints a version line and exits 0, which is the entire question
# Test-VcpkgUsable asks of vcpkg.exe. -ExitCode 3 gives the other half: an exe that is present
# and does not work.
function New-VcpkgStub {
    param([string]$Dir, [int]$ExitCode = 0)
    $exe = Join-Path $Dir 'vcpkg.exe'
    $src = 'public class VcpkgStub { public static int Main(string[] a) {' +
           ' System.Console.WriteLine("vcpkg package management program version 2099-01-01-stub");' +
           " return $ExitCode; } }"
    Add-Type -TypeDefinition $src -OutputAssembly $exe -OutputType ConsoleApplication
    if (-not (Test-Path $exe)) { throw "could not compile the vcpkg.exe stub into $Dir" }
    return $exe
}

function New-ScratchRepo {
    param([string]$Dir)
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & git init -q $Dir 2>&1 | Out-Null
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0) { throw "git init $Dir exited $rc" }
    # Committing needs an identity, and a runner (or a developer using a per-repo identity) has
    # no global one. Set it locally so this fixture never reads, and never needs, the machine's.
    Invoke-GitOrThrow $Dir @('config', 'user.email', 'fixture@bethesda-modding-starter.invalid') | Out-Null
    Invoke-GitOrThrow $Dir @('config', 'user.name', 'starter pack fixture') | Out-Null
}

function Add-ScratchCommit {
    param([string]$Dir, [string]$FileName)
    # A guid in the blob, which is the only thing here that guarantees the sha is unique. A
    # commit sha is a hash of the tree, the parents, and the author/committer identity and
    # SECOND -- so two of these repos, built from the same file name and content with the same
    # message inside the same second, came out with the SAME first commit. Measured: the
    # "clone that does not contain the baseline commit at all" repo contained it, the predicate
    # correctly answered OK, and the -NoEnv exit-1 assertion failed on a run where nothing was
    # wrong with the code under test. Two fixtures in one file passed or failed on a race
    # against the clock, which is exactly the flake this suite must not ship.
    $body = "$FileName in $Dir" + [Environment]::NewLine + [guid]::NewGuid().ToString()
    [IO.File]::WriteAllText((Join-Path $Dir $FileName), $body, (New-Object System.Text.UTF8Encoding($false)))
    Invoke-GitOrThrow $Dir @('add', '-A') | Out-Null
    Invoke-GitOrThrow $Dir @('commit', '-q', '-m', "add $FileName") | Out-Null
    return (Invoke-GitOrThrow $Dir @('rev-parse', 'HEAD'))
}

$scratch = Join-Path $env:TEMP ('spk-fixture-vcpkg-' + [guid]::NewGuid().ToString('n').Substring(0, 8))

try {
    # Nothing below has a remote, so nothing below can reach the network. This makes that
    # structural rather than incidental: any transport git is asked for is refused outright.
    $env:GIT_ALLOW_PROTOCOL = 'file'

    New-Item -ItemType Directory -Force $scratch | Out-Null
    Write-Host "Scratch tree $scratch"

    # ---- the clone that satisfies all three conditions, pinned the way a real one is pinned:
    # DETACHED at a commit, with no upstream to measure anything against.
    $good = Join-Path $scratch 'usable'
    New-ScratchRepo $good
    $goodBaseline = Add-ScratchCommit $good 'ports.txt'
    $goodHead = Add-ScratchCommit $good 'versions.txt'
    Invoke-GitOrThrow $good @('checkout', '-q', $goodHead) | Out-Null
    New-VcpkgStub $good | Out-Null

    # ---- a clone holding the baseline commit that is NOT an ancestor of its HEAD: the object is
    # in the database (a fetch landed it) and the working tree was never advanced onto it.
    $stale = Join-Path $scratch 'fetched-not-advanced'
    New-ScratchRepo $stale
    $staleHead = Add-ScratchCommit $stale 'ports.txt'
    Invoke-GitOrThrow $stale @('checkout', '-q', '-b', 'upstream-later') | Out-Null
    $staleAhead = Add-ScratchCommit $stale 'versions.txt'
    Invoke-GitOrThrow $stale @('checkout', '-q', $staleHead) | Out-Null
    New-VcpkgStub $stale | Out-Null

    # ---- a bootstrapped clone whose vcpkg.exe is present and does not work
    $broken = Join-Path $scratch 'broken-exe'
    New-ScratchRepo $broken
    $brokenBaseline = Add-ScratchCommit $broken 'ports.txt'
    New-VcpkgStub $broken -ExitCode 3 | Out-Null

    # ---- a clone that was never bootstrapped at all
    $unbootstrapped = Join-Path $scratch 'never-bootstrapped'
    New-ScratchRepo $unbootstrapped
    $unbootBaseline = Add-ScratchCommit $unbootstrapped 'ports.txt'

    Write-Host ''
    Write-Host '  Test-VcpkgUsable, called directly:'
    Assert-Probe (Test-VcpkgUsable -VcpkgDir $good -BaselineSha $goodBaseline) 'OK' `
        'a bootstrapped clone whose HEAD descends from the baseline is usable'
    Assert-Probe (Test-VcpkgUsable -VcpkgDir $stale -BaselineSha $staleAhead) 'FAIL' `
        'a clone holding the baseline that is NOT an ancestor of HEAD is not usable'
    Assert-Probe (Test-VcpkgUsable -VcpkgDir $stale -BaselineSha $goodHead) 'FAIL' `
        'a clone that does not contain the baseline commit at all is not usable'
    Assert-Probe (Test-VcpkgUsable -VcpkgDir $broken -BaselineSha $brokenBaseline) 'FAIL' `
        'a clone whose vcpkg.exe exits non-zero is not usable, however current the checkout'
    Assert-Probe (Test-VcpkgUsable -VcpkgDir $unbootstrapped -BaselineSha $unbootBaseline) 'FAIL' `
        'a clone that was never bootstrapped is not usable'

    # ---- the -NoEnv exit code, both directions
    $pack = Join-Path $scratch 'pack'
    New-Item -ItemType Directory -Force (Join-Path $pack 'setup') | Out-Null
    New-Item -ItemType Directory -Force (Join-Path $pack 'templates\f4sevr-plugin') | Out-Null
    Copy-Item (Join-Path $repoRoot 'setup\10-vcpkg.ps1') (Join-Path $pack 'setup')
    Copy-Item (Join-Path $repoRoot 'setup\_common.ps1') (Join-Path $pack 'setup')

    $manifestSrc = Join-Path $repoRoot 'templates\f4sevr-plugin\vcpkg.json'
    $manifestDst = Join-Path $pack 'templates\f4sevr-plugin\vcpkg.json'
    $manifestText = [IO.File]::ReadAllText($manifestSrc)
    # ${1} and ${2}, never $1 and $2. A git sha is 40 hex characters and 10 of the 16 possible
    # first characters are DIGITS, so '$1' + '48063dee...' reads to .NET as a reference to
    # capture group 148063 -- which does not exist, so the whole token is left literal and the
    # replacement swallows the '"builtin-baseline": "' the group was holding. Measured: that
    # produced a vcpkg.json ConvertFrom-Json rejects, Test-VcpkgUsable then reported "baseline
    # NOT checked" and passed the clone on vcpkg.exe alone, and the -NoEnv assertions below
    # would have gone green on a fixture that tested nothing -- on roughly ten runs in sixteen,
    # decided by whichever sha git happened to produce. The braces end the group number.
    $rewritten = $manifestText -replace '("builtin-baseline"\s*:\s*")[0-9a-fA-F]+(")', ('${1}' + $goodBaseline + '${2}')
    [IO.File]::WriteAllText($manifestDst, $rewritten, (New-Object System.Text.UTF8Encoding($false)))

    # The real manifest is copied rather than invented so the shape under test stays the shipped
    # one -- which means this fixture breaks if builtin-baseline is ever spelled differently.
    # It must break LOUDLY: a rewrite that quietly did nothing leaves the predicate reporting
    # "baseline NOT checked", and both -NoEnv runs below would then pass for the wrong reason.
    # So read back what was actually written and hold it to the sha this fixture chose.
    $wroteBaseline = ''
    try { $wroteBaseline = "$((([IO.File]::ReadAllText($manifestDst)) | ConvertFrom-Json).'builtin-baseline')" }
    catch { $wroteBaseline = "unparseable: $($_.Exception.Message)" }
    Assert-That ($wroteBaseline -eq $goodBaseline) "the scratch manifest pins the fixture's own baseline (got '$wroteBaseline')"
    $packVcpkg = Join-Path $pack 'setup\10-vcpkg.ps1'

    Write-Host ''
    Write-Host '  10-vcpkg.ps1 -NoEnv, as a caller sees it:'
    # Invoked IN PROCESS with &, deliberately not through powershell.exe -File, because the
    # contract is about the CALLER's $LASTEXITCODE and only an in-process call can observe it.
    # Measured against a copy of 10-vcpkg.ps1 with the old `return` put back: a script that ends
    # by falling off the end makes powershell.exe -File exit 0 whatever $LASTEXITCODE held, so
    # the out-of-process version of this assertion went GREEN on the bug it exists to catch. In
    # process, `exit 0` sets $LASTEXITCODE to 0 while `return` leaves standing whatever the last
    # native command inside the script put there -- 128 from the suppressed
    # `git rev-list --count HEAD..@{u}` on the tag-pinned clone below, which is the id-5 defect
    # exactly. `exit` in an &-invoked script ends that script and not this one, so the fixture
    # keeps running and gets to read the code.
    #
    # The sentinel is the second net, for a `return` taken before any native command ran at all:
    # nothing in the script would then overwrite it, and 42 is as wrong an answer as 128.
    $global:LASTEXITCODE = 42
    & $packVcpkg -NoEnv -VcpkgDir $good
    $rcGood = $LASTEXITCODE
    Assert-That ($rcGood -eq 0) "-NoEnv over a usable, tag-pinned clone leaves the caller `$LASTEXITCODE 0 (got $rcGood)"

    $global:LASTEXITCODE = 42
    & $packVcpkg -NoEnv -VcpkgDir $stale
    $rcStale = $LASTEXITCODE
    Assert-That ($rcStale -eq 1) "-NoEnv over a clone the repair could not fix leaves the caller `$LASTEXITCODE 1 (got $rcStale)"
}
catch {
    Write-Host "    FAIL threw: $($_.Exception.Message)"
    $script:failures.Add("threw: $($_.Exception.Message)")
}
finally {
    Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failures.Count) {
    Write-Host "$($script:failures.Count) assertion(s) failed:"
    foreach ($f in $script:failures) { Write-Host "  - $f" }
    Write-Host '"Usable" means vcpkg.exe runs AND the pinned builtin-baseline is present AND it is'
    Write-Host 'an ancestor of HEAD. Weakening any one of the three restores a gate that passes a'
    Write-Host 'clone no build on this machine can configure against.'
    exit 1
}
Write-Host 'Test-VcpkgUsable holds all three conditions, and -NoEnv reports both outcomes honestly.'

exit 0
