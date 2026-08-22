<#
.SYNOPSIS
    A directory setup\20-repos.ps1 did not create must survive a failed clone.

.DESCRIPTION
    The clone loop used to end every failure with one line:

        if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
        Write-Warning "clone failed (cleaned up partial dir): $($r.Url)"

    That is correct for a half-written clone this script started, and catastrophic for anything
    else -- and the two are indistinguishable at that point unless somebody looked BEFORE the
    clone. git refuses to clone into an existing non-empty directory ("destination path ...
    already exists and is not an empty directory") WITHOUT touching a byte of its contents, so
    on that failure everything under $dest is the user's: a GitHub "Download ZIP" extract, a
    snapshot with .git deliberately removed, or an unrelated working folder that merely shares a
    repo name. The user lost it to a message that called the deletion cleanup, and the only
    other thing printed was a transient clone failure.

    The fix records $existedBefore before running git, and never deletes on the true branch.
    This fixture is the outside proof: a sentinel file in a non-git directory at a clone
    destination, a run that fails every clone, and the sentinel still there afterwards with the
    same bytes in it.

    HOW THE CLONE IS MADE TO FAIL, and why it is not a network timeout: this fixture sets
    GIT_ALLOW_PROTOCOL=file, so git rejects every https URL in the table at once with "fatal:
    transport 'https' not allowed". No DNS, no sockets, no ~1.1 GB vr_address_tools clone, and
    the same answer on a runner with no egress as on a developer's machine -- measured at 0.7 s
    for the whole six-repo table. A deliberately bad URL was the other option and is worse here:
    the URLs are pinned inside the script, so faking one would mean editing a copy of it, and
    then the fixture would no longer be testing the script that ships.

    The destination the sentinel sits in is the pre-existing NON-EMPTY case on purpose. git
    declines that one outright, which is the branch where the deletion used to happen. The
    pre-existing EMPTY case is deliberately not pinned: git may or may not remove a directory it
    found empty, so an assertion about it would be a coin-flip, and a flaky fixture is worse
    than none.

    -Root points at a scratch tree, so nothing here can touch C:\repos. 20-repos.ps1 writes
    nothing outside -Root, which is why this one runs the checkout's own script rather than a
    copy.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
$script:failures = New-Object System.Collections.Generic.List[string]

function Assert-That {
    param([bool]$Condition, [string]$What)
    if ($Condition) { Write-Host "    ok   $What" }
    else {
        Write-Host "    FAIL $What"
        $script:failures.Add($What)
    }
}

$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $psExe)) { $psExe = 'powershell.exe' }

# The destination has to be a name the script actually tries to clone, and that name lives in a
# table inside it. Assert it is still there rather than trusting it: drop CommonLibF4 from that
# table and this fixture would stop exercising the clone loop entirely, keep passing (nothing
# would touch the sentinel either), and quietly stop defending anything. A fixture that passes
# for the wrong reason is the failure mode this whole suite exists to avoid.
$reposScript = Join-Path $repoRoot 'setup\20-repos.ps1'
$repoName = 'CommonLibF4'

$scratch = Join-Path $env:TEMP ('spk-fixture-clone-' + [guid]::NewGuid().ToString('n').Substring(0, 8))
$root = Join-Path $scratch 'repos'
$dest = Join-Path $root $repoName
$sentinel = Join-Path $dest 'DO-NOT-DELETE.txt'
$sentinelText = 'Months of local modifications. 20-repos.ps1 did not create this directory.'

try {
    $scriptText = [IO.File]::ReadAllText($reposScript)
    Assert-That ($scriptText -match "Name\s*=\s*'$repoName'") "20-repos.ps1 still clones '$repoName' (this fixture aims at that destination)"

    New-Item -ItemType Directory -Force (Join-Path $dest 'include') | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($sentinel, $sentinelText, $utf8)
    [IO.File]::WriteAllText((Join-Path $dest 'include\mine.h'), '#pragma once', $utf8)

    # No .git anywhere under $dest: that is what makes this the interesting case. The identity
    # check at the top of the clone loop only fires on a directory that HAS one, so a ZIP
    # extract or a de-gitted snapshot falls straight through to the clone -- and to the cleanup
    # that used to follow it.
    Assert-That (-not (Test-Path (Join-Path $dest '.git'))) 'the pre-existing directory is not a git clone'

    Write-Host "Scratch root $root"
    # Set for THIS process, inherited by the child. run-all.ps1 runs every fixture in its own
    # powershell.exe precisely so this cannot follow the suite into the next one.
    $env:GIT_ALLOW_PROTOCOL = 'file'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # Merge the child's streams and keep them. 20-repos.ps1 reports failures through
    # Write-Warning, which is stderr on the child, and the "did it get that far" assertion below
    # needs the transcript. EAP Continue around it for the usual 5.1 reason: with 2>&1 those
    # warnings arrive as ErrorRecords and 'Stop' would abort this fixture on the child's normal
    # output.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $captured = @(& $psExe -NoProfile -ExecutionPolicy Bypass -File $reposScript -Root $root -SkipAddressTools 2>&1 |
        ForEach-Object { [string]$_ })
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    $sw.Stop()
    foreach ($line in $captured) { Write-Host "  | $line" }
    Write-Host ("  20-repos.ps1 exited $rc after {0:N1}s" -f $sw.Elapsed.TotalSeconds)
    $transcript = $captured -join [Environment]::NewLine

    # THE RUN HAS TO HAVE REACHED THIS DESTINATION. Everything else here is an assertion that
    # something did NOT happen, and those are all satisfied for free by a run that never got
    # started: measured, a 20-repos.ps1 edited into a state where it did not even PARSE exited 1
    # with the sentinel untouched and every other assertion below green -- a fixture reporting
    # that a deletion it never gave the script a chance to perform did not happen. The script
    # prints the destination immediately before handing it to git, so requiring that line is
    # what separates "did not delete it" from "never ran". A path, not prose, so the coupling is
    # to something this fixture already had to know.
    # .Contains, not -like: a scratch path is data, and -like would read any [ ] in it as a
    # character class and quietly stop matching.
    Assert-That ("$transcript".Contains($dest)) "20-repos.ps1 actually reached the clone of $repoName (its own progress line names $dest)"

    Assert-That (Test-Path $dest) "the pre-existing directory $repoName still exists"
    Assert-That (Test-Path $sentinel) 'the sentinel file survived the failed clone'
    $after = ''
    if (Test-Path $sentinel) { $after = [IO.File]::ReadAllText($sentinel) }
    Assert-That ($after -eq $sentinelText) 'the sentinel file still holds exactly what was written'
    Assert-That (Test-Path (Join-Path $dest 'include\mine.h')) 'the rest of the directory tree survived too'
    # Nothing was cloned into it either. git declined the destination outright, so a .git here
    # would mean this fixture stopped testing what it thinks it tests.
    Assert-That (-not (Test-Path (Join-Path $dest '.git'))) 'nothing was cloned into it'
    # The failure has to have been REPORTED. Deleting nothing is only half the contract; the
    # other half is that the run does not exit 0 over a repo it never obtained, which is what
    # sends an agent on to a phase that cannot work.
    Assert-That ($rc -eq 1) "the run reported failed clones (exit 1, got $rc)"
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
    Write-Host 'setup\20-repos.ps1 must never destroy a directory it cannot prove it created.'
    Write-Host 'The provenance flag is $existedBefore, captured before git clone runs.'
    exit 1
}
Write-Host 'A pre-existing directory at a clone destination survived a failed clone intact.'

exit 0
