<#
.SYNOPSIS
    Run every dirty-state regression fixture in tests\ and fail if any of them fails.

.DESCRIPTION
    Three fixtures, one class. Each pins a fix whose failure mode destroys something the user
    cannot get back -- an unrelated process force-killed, a directory of local work deleted, or
    hours of build state declared ready when it is not. They collapse no findings on their own;
    they exist so that class cannot come back quietly, and they were written AFTER the fixes
    landed so they encode the contracts that now hold rather than the bugs that used to.

    They are deliberately cheap, offline and deterministic. Nothing here stands up a fake HTTP
    server or matches a transcript: a flaky test is worse than no test, because it teaches
    people to ignore red, and red is the only thing these three have to say.

    EVERY FIXTURE RUNS IN ITS OWN CHILD powershell.exe. That is isolation this suite needs, not
    tidiness:
      * Test-PreExistingCloneDir.ps1 sets GIT_ALLOW_PROTOCOL so that 20-repos.ps1's six clones
        fail in 0.7 s instead of pulling repos off GitHub (vr_address_tools alone is ~1.1 GB).
        Leaked into a later fixture, every git call it makes then fails for a reason that has
        nothing to do with what it is testing -- a red that means nothing.
      * every setup script dot-sources _common.ps1 and calls Sync-Path, which REPLACES this
        process's $env:Path with one rebuilt from the registry.
      * a fixture ends in `exit N`; dot-sourcing one would end this harness with it, and the
        fixtures after it would never run at all.

    Windows PowerShell 5.1 is resolved BY PATH rather than inherited. The setup scripts have to
    survive 5.1 -- that is the whole subject of .github\workflows\ps-compat.yml -- so a suite
    that happened to be started from pwsh 7 must still exercise them under the shell a fresh
    machine actually has.

.PARAMETER Name
    Substring filter, for working on one fixture: -Name vcpkg runs Test-VcpkgBaselinePredicate
    alone. The floor below is measured against the unfiltered set, so a filter cannot be
    mistaken for an empty suite.

.EXAMPLE
    .\tests\run-all.ps1
.EXAMPLE
    .\tests\run-all.ps1 -Name pid
#>
[CmdletBinding()]
param(
    [string]$Name = ''
)

$ErrorActionPreference = 'Stop'

# Resolved from %SystemRoot% rather than taken from Get-Process, so this is 5.1 even when the
# harness itself is not. -ExecutionPolicy Bypass because -File is refused outright on a machine
# left at the Restricted default, and "the policy blocked it" would be reported here as a
# failing fixture.
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $psExe)) { $psExe = 'powershell.exe' }

$all = @(Get-ChildItem -Path $PSScriptRoot -Filter 'Test-*.ps1' -File | Sort-Object Name)

# A suite that finds nothing and prints a success line is the defect ps-compat.yml already
# guards against with its inline-PS block floor: a check that passes because it checked
# nothing. Three fixtures ship here, so three is the floor -- deleting one has to turn this
# red, and adding a fourth is the change that raises the number.
if ($all.Count -lt 3) {
    Write-Host "Only $($all.Count) fixture(s) matched Test-*.ps1 under $PSScriptRoot; this suite ships three."
    Write-Host 'Either one was deleted or the glob has stopped finding them. Lowering the floor'
    Write-Host 'instead just restores a suite that runs nothing.'
    exit 1
}

$tests = $all
if ($Name) {
    $tests = @($all | Where-Object { $_.Name -like "*$Name*" })
    if ($tests.Count -eq 0) {
        Write-Host "-Name '$Name' matched none of: $(($all | ForEach-Object { $_.Name }) -join ', ')"
        exit 1
    }
}

Write-Host "Running $($tests.Count) fixture(s) under $psExe"
$failed = @()
foreach ($t in $tests) {
    Write-Host ''
    Write-Host "=== $($t.Name) ==="
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $psExe -NoProfile -ExecutionPolicy Bypass -File $t.FullName
    $rc = $LASTEXITCODE
    $sw.Stop()
    if ($rc -eq 0) {
        Write-Host ("PASS {0} ({1:N1}s)" -f $t.Name, $sw.Elapsed.TotalSeconds)
    }
    else {
        Write-Host ("FAIL {0} -- exit $rc ({1:N1}s)" -f $t.Name, $sw.Elapsed.TotalSeconds)
        $failed += $t.Name
    }
}

Write-Host ''
if ($failed.Count) {
    Write-Host "$($failed.Count) of $($tests.Count) fixture(s) failed: $($failed -join ', ')"
    Write-Host 'Each one pins a destructive-class fix. Read what it asserted before changing it:'
    Write-Host 'the fixture is the contract, and a fixture edited to agree with new behaviour'
    Write-Host 'proves nothing about the behaviour it was written to stop.'
    exit 1
}
Write-Host "All $($tests.Count) fixture(s) passed."

exit 0
