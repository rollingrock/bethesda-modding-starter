<#
.SYNOPSIS
    A stale PID record must never get an innocent process force-killed.

.DESCRIPTION
    setup\36-ghidra-mcp.ps1 has two force-kill sites -- the -Stop terminate and the -Start
    "alive but not answering" cleanup -- and both resolve their victim through Get-ServerPid.
    Nothing cleans the PID record on boot, so a number left behind by a crash or a reboot
    outlives the server, and Windows recycles PIDs aggressively: days later that same number
    can be the user's MO2 or their editor. Get-ServerPid is the ONE check standing between
    Stop-Process -Force and a stranger's process, so this fixture holds it to its contract from
    the outside, with a real live process pointed at by a real record on disk.

    THREE records, all of which must be refused, because they fail the identity test in three
    different places:

      1. setup\.ghidra-headless.pid holding a bare integer. This is the LEGACY shape -- what
         older versions of this script wrote -- and it identifies nothing: no process name, no
         start time, no port. The current script recognises it, acts on it never, and deletes
         it. It is pinned here because it is the shape most likely to be lying around on a
         machine that has been through several versions of this pack, and because "we still
         understand the old file" is exactly the kind of sentence someone later turns back into
         "so we can still use it".

      2. setup\.ghidra-headless.<port>.pid holding well-formed JSON whose `name` does not match
         the live process. This is the record a server on this port really would have written,
         against a PID that now belongs to something else entirely.

      3. The same, with the right `name` and a `startedUtc` an hour off. This is the sharpest
         one: the start time is the tie-breaker PID reuse cannot fake, because the recycled
         process necessarily started later than the one that was recorded. A check that
         compared only pid and name would pass this record and kill the wrong java.

    Each case asserts three things: the sacrificial process is still alive AND still ours, the
    record was discarded from disk, and -Stop exited 0 (the state you asked for -- no server on
    this port -- does hold).

    The script is run from a COPY under the TEMP directory because $stateDir is $PSScriptRoot:
    the PID record lands next to the script that reads it. Running the checkout's own copy would
    write these deliberately-poisoned records into setup\, where a later real -Stop could read
    one -- a test that leaves the bug it is testing for behind it.

    -Port is an ephemeral port this fixture proves is closed first. The -Stop path probes
    /check_connection before it will claim anything is down, and pointing that probe at 8089
    would have it answer a real headless server on the developer's machine.
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

# The same identity test the script itself applies, used here for the opposite purpose: to
# refuse to claim anything about a process that is no longer provably the one we started. If
# the PID were recycled between the -Stop run and this check, "still alive" would be a lie in
# our favour -- the fixture would report the process survived when what survived is somebody
# else's program with the same number.
function Test-SacrificialStillOurs {
    $live = Get-Process -Id $script:sacPid -ErrorAction SilentlyContinue
    if (-not $live) { return $false }
    if ($live.ProcessName -ne $script:sacName) { return $false }
    return ([Math]::Abs(($live.StartTime - $script:sacStart).TotalSeconds) -le 2)
}

function Test-PortQuiet {
    param([int]$TcpPort)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect('127.0.0.1', $TcpPort)
        $client.Close()
        return $false
    }
    catch { return $true }
    finally { $client.Dispose() }
}

$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $psExe)) { $psExe = 'powershell.exe' }

$scratch = Join-Path $env:TEMP ('spk-fixture-pid-' + [guid]::NewGuid().ToString('n').Substring(0, 8))
$scratchSetup = Join-Path $scratch 'setup'
$script:sacPid = 0
$sacrificial = $null

try {
    New-Item -ItemType Directory -Force $scratchSetup | Out-Null
    Copy-Item (Join-Path $repoRoot 'setup\36-ghidra-mcp.ps1') $scratchSetup
    Copy-Item (Join-Path $repoRoot 'setup\_common.ps1') $scratchSetup
    $target = Join-Path $scratchSetup '36-ghidra-mcp.ps1'

    # Ask the OS for a free port and give it straight back, rather than picking a number and
    # hoping. 8089 is the default and 8090..8104 are what the bridge's discovery scan walks, so
    # a hard-coded "surely nothing is on this one" is exactly how a fixture ends up talking to
    # the developer's live server.
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()

    $legacyRecord = Join-Path $scratchSetup '.ghidra-headless.pid'
    $portRecord = Join-Path $scratchSetup ".ghidra-headless.$port.pid"

    Write-Host "Scratch tree $scratch, port $port"
    Assert-That (Test-PortQuiet $port) "port $port is closed before the fixture starts"

    # A process whose only job is to be a tempting target: it is not java, it is not a server,
    # and nothing in this pack has any business ending it.
    $sacrificial = Start-Process -FilePath $psExe `
        -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 300' -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    if ($sacrificial.HasExited) {
        throw "the sacrificial process exited immediately (code $($sacrificial.ExitCode)); nothing can be asserted about it"
    }
    $script:sacPid = $sacrificial.Id
    $script:sacName = $sacrificial.ProcessName
    $script:sacStart = $sacrificial.StartTime
    Write-Host "Sacrificial process: PID $script:sacPid ($script:sacName), started $($script:sacStart.ToUniversalTime().ToString('o'))"
    Assert-That (Test-SacrificialStillOurs) 'the sacrificial process is ours before any case runs'

    $utc = $script:sacStart.ToUniversalTime()
    $cases = @(
        @{
            Label  = 'legacy bare-integer record (pre-port-scoped)'
            File   = $legacyRecord
            Body   = "$script:sacPid"
        }
        @{
            Label  = 'port-scoped JSON record, name does not match the live process'
            File   = $portRecord
            Body   = ([pscustomobject]@{
                    pid        = $script:sacPid
                    name       = 'java'
                    startedUtc = $utc.ToString('o')
                } | ConvertTo-Json)
        }
        @{
            Label  = 'port-scoped JSON record, right name, startedUtc an hour off (a recycled PID)'
            File   = $portRecord
            Body   = ([pscustomobject]@{
                    pid        = $script:sacPid
                    name       = $script:sacName
                    startedUtc = $utc.AddHours(-1).ToString('o')
                } | ConvertTo-Json)
        }
    )

    foreach ($case in $cases) {
        Write-Host ''
        Write-Host "  case: $($case.Label)"
        # [IO.File] rather than Set-Content: this writes UTF-8 with no BOM in one call on 5.1,
        # which is what the script's Get-Content -Raw | ConvertFrom-Json reads cleanly.
        [IO.File]::WriteAllText($case.File, $case.Body, (New-Object System.Text.UTF8Encoding($false)))

        & $psExe -NoProfile -ExecutionPolicy Bypass -File $target -Stop -Port $port
        $rc = $LASTEXITCODE

        Assert-That (Test-SacrificialStillOurs) "PID $script:sacPid survived -Stop and is still our process"
        Assert-That (-not (Test-Path $case.File)) "the record was discarded from disk ($(Split-Path $case.File -Leaf))"
        Assert-That ($rc -eq 0) "-Stop exited 0 with no server on port $port (got $rc)"
    }
}
catch {
    Write-Host "    FAIL threw: $($_.Exception.Message)"
    $script:failures.Add("threw: $($_.Exception.Message)")
}
finally {
    # Only ever end a process we can still prove is ours -- the fixture must not commit the
    # defect it exists to catch.
    if ($script:sacPid -gt 0 -and (Test-SacrificialStillOurs)) {
        Stop-Process -Id $script:sacPid -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -Recurse -Force $scratch -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failures.Count) {
    Write-Host "$($script:failures.Count) assertion(s) failed:"
    foreach ($f in $script:failures) { Write-Host "  - $f" }
    Write-Host 'A PID record this pack cannot prove describes its own java server must be discarded'
    Write-Host 'UNKILLED. Fail safe, never fail open: see Get-ServerPid in setup\36-ghidra-mcp.ps1.'
    exit 1
}
Write-Host 'Stale PID records are refused: the innocent process survived all three.'

exit 0
