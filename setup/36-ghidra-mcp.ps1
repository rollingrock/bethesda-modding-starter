<#
.SYNOPSIS
    Start / stop / inspect the GhidraMCP HEADLESS server, and write .mcp.json for it.

.DESCRIPTION
    This is the whole of Phase 4 with no human in it. No Ghidra GUI, no
    "File > Install Extensions", no "Tools > GhidraMCP > Start MCP Server", no clicks.

    Measured on a clean run (Ghidra 12.0.4, ghidra-mcp 7.0.0):
      * server up and answering /check_connection in ~5 s
      * 226 REST endpoints registered
      * the MCP bridge pulls /mcp/schema and registers 225 tools against it

    KNOWN GAP -- worth understanding before you debug the wrong thing. The bridge's
    instance DISCOVERY (list_instances(), the 8089..8104 port scan) probes
    /mcp/instance_info, and that endpoint is registered only by the GUI plugin
    (ServerManager.java / GhidraMCPPlugin.java). The headless server does not serve it,
    so list_instances() returns [] and connect_instance() has nothing to match. That does
    NOT block us: the bridge's TCP fallback reads GHIDRA_MCP_URL (default
    http://127.0.0.1:8089), fetches /mcp/schema directly, and auto-connects. So .mcp.json
    below pins GHIDRA_MCP_URL and the tools come up without discovery.
    (README also documents a /server_status endpoint for headless; `server_status` appears
    nowhere in the Java source and returns 404. Don't rely on it.)

.PARAMETER Project
    Ghidra project to open -- a .gpr path or the directory containing one. Defaults to
    BethesdaGhidraScripts' project, i.e. the database the enrichment pipeline built.

.PARAMETER Program
    Program inside the project to load, e.g. /f4/vr/Fallout4VR.exe.unpacked.exe.

.EXAMPLE
    .\36-ghidra-mcp.ps1 -Start -Program /f4/vr/Fallout4VR.exe.unpacked.exe
.EXAMPLE
    .\36-ghidra-mcp.ps1 -Status
.EXAMPLE
    .\36-ghidra-mcp.ps1 -Stop
#>
[CmdletBinding(DefaultParameterSetName = 'Start')]
param(
    [Parameter(ParameterSetName = 'Start')][switch]$Start,
    [Parameter(ParameterSetName = 'Stop')][switch]$Stop,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,

    [string]$Root = 'C:\repos',
    [int]$Port = 8089,
    [string]$Project = '',
    [string]$Program = '',
    # Import a loose binary instead of opening a project. Auto-analysis runs on import,
    # so this is for small targets (a plugin DLL); a game EXE belongs in the pipeline.
    [string]$File = '',
    # Write .mcp.json into this directory so an agent working there gets the tools.
    [string]$WriteMcpConfigTo = '',
    [int]$TimeoutSec = 180,
    # Go through with a shutdown -Stop would otherwise refuse: one where /save_all_programs
    # failed (you accept losing whatever the MCP tools changed since the last save, plus a
    # stale project .lock), or one where something is serving the port but no PID record here
    # proves we started it (we still only ask it to exit over HTTP -- see the -Stop path).
    # Deliberately outside the parameter sets, like -Root and -Port, so it applies to any mode.
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"
Sync-Path

$stateDir = $PSScriptRoot
# The PID record is scoped to the PORT it describes. One shared file could only ever describe
# one server, so -Port made it ambiguous in the single direction that matters: with one
# record, `-Stop -Port 8099` resolved the record of the server actually running on 8089,
# addressed save and exit to a port nothing was listening on (both fail quietly), and then
# force-killed that JVM -- a kill with no save, which is the exact trade the -Stop path
# otherwise refuses to make. Put the port in the name and the question cannot be asked
# wrongly: each server owns its own record, and a port with no server has none to misread.
$pidFile = Join-Path $stateDir ".ghidra-headless.$Port.pid"
# Older versions wrote one unsuffixed file holding a bare integer. It identifies nothing --
# no process name, no start time, no port -- so nothing may ever act on it. Drop it rather
# than leave a number lying around for a later run to trust. A server started by that older
# script keeps running and simply becomes unmanaged: -Stop finds it by probing the port and
# says so, instead of killing a process it cannot identify.
$legacyPidFile = Join-Path $stateDir '.ghidra-headless.pid'
if (Test-Path $legacyPidFile) {
    Write-Host "Discarding pre-port-scoped PID record $legacyPidFile (a bare number cannot identify a process)."
    Remove-Item $legacyPidFile -Force -ErrorAction SilentlyContinue
}
$outLog = Join-Path $stateDir '.ghidra-headless.out.log'
$errLog = Join-Path $stateDir '.ghidra-headless.err.log'
$manifestPath = Join-Path $stateDir '.ghidra-mcp-build.json'
$baseUrl = "http://127.0.0.1:$Port"

function Get-Manifest {
    if (-not (Test-Path $manifestPath)) {
        throw "No $manifestPath - run setup\30-ghidra.ps1 first (it builds the jar and the classpath argfile)."
    }
    Get-Content $manifestPath -Raw | ConvertFrom-Json
}

function Invoke-Endpoint([string]$path, [int]$timeoutSec = 5) {
    try {
        $r = Invoke-WebRequest "$baseUrl$path" -UseBasicParsing -TimeoutSec $timeoutSec
        [pscustomobject]@{ Ok = $true; Status = $r.StatusCode; Body = $r.Content }
    }
    catch {
        [pscustomobject]@{ Ok = $false; Status = 0; Body = $_.Exception.Message }
    }
}

# /mcp/schema answers {"tools":[...],"count":N} -- NOT the {"data":...} envelope other
# endpoints use. Prefer the server's own count and fall back to measuring the array.
function Get-ToolCount {
    $resp = Invoke-Endpoint '/mcp/schema' 30
    if (-not $resp.Ok) { return -1 }
    try {
        $j = $resp.Body | ConvertFrom-Json
        if ($null -ne $j.count) { return [int]$j.count }
        return @($j.tools).Count
    }
    catch { return -1 }
}

# The PID file records IDENTITY -- pid, process name and start time -- not just a number,
# and this function refuses to hand back a process it cannot prove is the java server this
# checkout started. Nothing cleans the record on boot, so a number left behind by
# a crash or a reboot outlives the server, and Windows recycles PIDs aggressively: days
# later that same number can be the user's MO2 or their editor. Both force-kill sites in
# this file (the -Stop terminate and the -Start "alive but not answering" cleanup) resolve
# their victim through here, so this one check is what keeps either of them from killing a
# stranger's process and reporting it as routine cleanup.
#
# A record counts only if the PID is live AND the process name still matches AND the start
# time agrees to within a couple of seconds. Everything else is discarded UNKILLED: a legacy
# plain-integer pid file (what older versions of this script wrote) carries no identity at
# all and can never be proven ours, and a StartTime we are not allowed to read belongs to a
# process owned by somebody else -- by definition not our child. Fail safe, never fail open.
function Get-ServerPid {
    if (-not (Test-Path $pidFile)) { return $null }
    $ours = $null
    try {
        # ConvertFrom-Json turns a legacy '14332' file into a bare integer with no .pid /
        # .name / .startedUtc, so it falls out here and is removed rather than trusted.
        $rec = (Get-Content $pidFile -Raw) | ConvertFrom-Json
        $recPid = 0
        if ([int]::TryParse([string]$rec.pid, [ref]$recPid) -and $recPid -gt 0 -and $rec.name -and $rec.startedUtc) {
            $live = Get-Process -Id $recPid -ErrorAction SilentlyContinue
            if ($live -and $live.ProcessName -eq [string]$rec.name) {
                # Start time is the tie-breaker PID reuse cannot fake: the recycled process
                # necessarily started later than the one we recorded. Reading it throws on a
                # process we may not inspect, and the catch below turns that into "not ours".
                $recorded = [datetime]::Parse([string]$rec.startedUtc, [Globalization.CultureInfo]::InvariantCulture)
                $delta = ($live.StartTime.ToUniversalTime() - $recorded.ToUniversalTime()).TotalSeconds
                if ([Math]::Abs($delta) -le 2) { $ours = $live }
            }
        }
    }
    catch { $ours = $null }
    # Unreadable, legacy, or identifying someone else: drop the record so no later run
    # inherits the ambiguity and mistakes it for a server it can kill.
    if (-not $ours) { Remove-Item $pidFile -ErrorAction SilentlyContinue }
    return $ours
}

# --------------------------------------------------------------------------- Stop
if ($Stop) {
    $p = Get-ServerPid
    if (-not $p) {
        # The PID record is per-checkout state under $PSScriptRoot: 'git clean -fdx' deletes
        # it, a second clone never had it, and a reboot leaves it identifying nothing. Its
        # absence is therefore NOT evidence that the server is down -- so ask the port before
        # claiming that, or we report a successful stop while the JVM keeps serving $baseUrl
        # and keeps the project lock that 35-ghidra-analysis.ps1 then trips over.
        $conn = Invoke-Endpoint '/check_connection'
        if (-not $conn.Ok) {
            Write-Host "Headless server is not running (no PID of ours recorded, nothing answering on $baseUrl)."
            exit 0
        }
        Write-Host "Something IS serving $baseUrl, but nothing here proves that we started it:"
        Write-Host "  $($conn.Body.Trim())"
        if (-not $Force) {
            Write-Host '  Leaving it alone. It may be a Ghidra GUI, or a headless server started from'
            Write-Host '  another checkout that still holds its own PID record.'
            Write-Host '  Stop it from the checkout that started it, or run:'
            Write-Host '    .\setup\36-ghidra-mcp.ps1 -Stop -Force   # save + /exit_ghidra over HTTP'
            exit 1
        }
        Write-Host '  -Force: asking it to save and exit over HTTP. Nothing is force-killed on this'
        Write-Host '  path -- with no PID record we cannot prove which process to kill, and a wrong'
        Write-Host '  Stop-Process would take out whatever inherited that PID.'
    }
    else {
        Write-Host "Stopping headless server (PID $($p.Id)) ..."
    }
    # Save first: a killed JVM leaves the project locked, and a stale .lock blocks every
    # later run (including the enrichment pipeline's). Then shut down over HTTP --
    # CloseMainWindow() is useless here because the JVM runs windowless.
    $save = Invoke-Endpoint '/save_all_programs' 300
    if (-not $save.Ok) {
        # Discarding this result is how hours of work vanish: everything an agent renamed,
        # retyped or commented through the MCP tools lives in the JVM until this call lands,
        # and the save is the entire reason the terminate below is survivable. A timeout (busy
        # decompiler, wedged JVM) or an error means NOTHING was written -- so it must not be
        # followed by a kill and a printed "Stopped."
        Write-Host "  /save_all_programs FAILED: $($save.Body)"
        if (-not $Force) {
            Write-Host '  UNSAVED DATABASE WORK MAY BE LOST -- leaving the server running.'
            Write-Host '  Re-run -Stop once the JVM finishes what it is busy with (a long analysis or'
            Write-Host '  decompile can hold the save past its 300 s timeout). If you accept losing'
            Write-Host '  every change made since the last successful save, plus a stale project .lock'
            Write-Host '  the next run has to clear, re-run with -Force.'
            exit 1
        }
        Write-Host '  -Force: shutting down anyway. Changes made since the last successful save are'
        Write-Host '  being discarded, and the project may be left holding a stale .lock.'
    }
    $exit = Invoke-Endpoint '/exit_ghidra' 15
    if (-not $exit.Ok) {
        if ($p) { Write-Host "  /exit_ghidra did not answer ($($exit.Body)); will terminate." }
        else { Write-Host "  /exit_ghidra did not answer ($($exit.Body))." }
    }
    if (-not $p) {
        # -Force against a server we cannot claim: HTTP is the only lever we are willing to
        # pull, so judge the outcome by whether the port went quiet rather than by announcing
        # a kill we never performed. /exit_ghidra answers BEFORE the JVM is down -- it has to,
        # or the response could never be sent -- and a real Ghidra closing a loaded project
        # takes seconds. Poll for the same 20 s the managed path below gives WaitForExit,
        # rather than calling a shutdown in progress a failure after one impatient probe.
        $gone = $false
        $quietBy = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $quietBy) {
            Start-Sleep -Seconds 1
            if (-not (Invoke-Endpoint '/check_connection').Ok) { $gone = $true; break }
        }
        if (-not $gone) {
            Write-Host "Still serving $baseUrl. Stop it from the checkout that started it, or end that process yourself."
            exit 1
        }
        Write-Host "Stopped over HTTP ($baseUrl no longer answers)."
        exit 0
    }
    if (-not $p.WaitForExit(20000)) {
        Write-Host '  still alive after 20 s; terminating.'
        # Safe here precisely because Get-ServerPid refused to return anything it could not
        # prove: this is still the same java process, started at the same instant, that this
        # checkout launched. Without that proof this line is how a recycled PID gets an
        # unrelated program killed.
        $p | Stop-Process -Force
    }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
    Write-Host 'Stopped.'
    exit 0
}

# --------------------------------------------------------------------------- Status
if ($Status) {
    $p = Get-ServerPid
    $conn = Invoke-Endpoint '/check_connection'
    $rows = [System.Collections.Generic.List[object]]::new()
    $rows.Add([pscustomobject]@{ Check = 'process'; Result = $(if ($p) { "running (PID $($p.Id))" } else { 'not running' }) })
    $rows.Add([pscustomobject]@{ Check = 'check_connection'; Result = $(if ($conn.Ok) { $conn.Body.Trim() } else { "unreachable: $($conn.Body)" }) })
    if ($conn.Ok) {
        $rows.Add([pscustomobject]@{ Check = 'mcp tools'; Result = "$(Get-ToolCount) exposed via /mcp/schema" })
        $meta = Invoke-Endpoint '/get_metadata' 30
        $rows.Add([pscustomobject]@{ Check = 'program'; Result = $(if ($meta.Ok) { ($meta.Body -replace '\s+', ' ').Substring(0, [Math]::Min(160, ($meta.Body -replace '\s+', ' ').Length)) } else { 'n/a' }) })
    }
    $rows | Format-Table -AutoSize
    exit $(if ($conn.Ok) { 0 } else { 1 })
}

# --------------------------------------------------------------------------- Start
$manifest = Get-Manifest
if (-not (Test-Path $manifest.headlessCpFile)) {
    throw "Classpath argfile $($manifest.headlessCpFile) is missing - re-run setup\30-ghidra.ps1."
}

$existing = Get-ServerPid
if ($existing) {
    $conn = Invoke-Endpoint '/check_connection'
    if ($conn.Ok) {
        Write-Host "Already running (PID $($existing.Id)): $($conn.Body.Trim())"
        Write-Host 'Use -Stop first if you need to change the loaded project or program.'
        exit 0
    }
    # Get-ServerPid hands back a process only when the name and start time still match the
    # record we wrote at launch, so this is provably OUR java server gone deaf -- not some
    # unrelated program that inherited a recycled PID. That proof is what makes the force
    # below acceptable; without it this line kills whatever the number now points at.
    Write-Host "PID $($existing.Id) is our java server but is not answering on $baseUrl; stopping it."
    # Say the cost out loud. It is deaf, so there is no /save_all_programs to run first:
    # whatever the MCP tools changed since its last save dies with it and the project may be
    # left holding a stale .lock. -Stop refuses that trade without -Force; -Start has to make
    # it, because a wedged server is exactly what is standing between you and a working one.
    Write-Host '  It is not answering, so it cannot be asked to save first - changes made through'
    Write-Host '  the MCP tools since its last save are lost, and it may leave a stale project .lock.'
    $existing | Stop-Process -Force
    Remove-Item $pidFile -ErrorAction SilentlyContinue
}
if ((Invoke-Endpoint '/check_connection').Ok) {
    throw "Something is already serving $baseUrl but we did not start it. Use -Port to pick another port, or stop that process first."
}

if ($File) {
    if (-not (Test-Path $File)) { throw "-File '$File' does not exist." }
    $File = (Resolve-Path $File).Path
    $Project = ''
    $Program = ''
}
elseif (-not $Project) {
    $Project = Join-Path $Root 'BethesdaGhidraScripts\ghidraprojects\BethesdaGhidraScripts'
}

# A Ghidra project is single-writer. If the enrichment pipeline (or a GUI, or another
# agent) holds it, opening it here fails deep inside Ghidra with a confusing error --
# and forcing it risks the database. Detect it up front and say who has it.
if ($Project) {
    $projDir = if ($Project.EndsWith('.gpr')) { Split-Path $Project -Parent } else { $Project }

    # Ground truth is the OS handle on <name>.lock~, not the presence of <name>.lock and not
    # a scan for java.exe. See Test-GhidraProjectLocked: pyghidra runs the JVM inside
    # python.exe, so the pipeline can hold a project while no java process exists at all.
    if (Test-GhidraProjectLocked -ProjectDir $projDir) {
        Write-Host 'WARNING: the project is LOCKED by another process right now.'
        $who = Get-GhidraHolderDescription
        if ($who) { Write-Host "         holder: $who" }
        else { Write-Host '         (holder not identified - it may be a pyghidra/python process)' }
        Write-Host '         Starting the server WITHOUT a project. Re-run once it is free.'
        Write-Host '         Never delete the lock while it is held - that is how databases get corrupted.'
        $Project = ''
        $Program = ''
    }
    else {
        # Not held. A leftover <name>.lock from a crash still makes Ghidra throw
        # "LockException: Unable to lock project!", and leaving it needs a human to delete a
        # file nothing owns -- exactly the manual step this script exists to remove.
        $lock = Get-ChildItem $projDir -Filter '*.lock' -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike '*.lock~' } | Select-Object -First 1
        if ($lock) {
            $lockHost = (Get-Content $lock.FullName -ErrorAction SilentlyContinue |
                Where-Object { $_ -match '^Hostname=(.+)$' } | ForEach-Object { $Matches[1].Trim() } |
                Select-Object -First 1)
            if ($lockHost -and $lockHost -ne $env:COMPUTERNAME) {
                Write-Host "WARNING: $($lock.Name) was taken by host '$lockHost', not this machine"
                Write-Host "         ($env:COMPUTERNAME) - a shared project may be in use elsewhere."
                Write-Host '         Leaving it alone and starting WITHOUT a project.'
                $Project = ''
                $Program = ''
            }
            else {
                Write-Host "Breaking a stale lock: $($lock.Name) (nothing holds .lock~, host '$lockHost' is this machine)."
                Remove-Item $lock.FullName -Force
            }
        }
    }
}

$javaArgs = @(
    "-Dghidra.home=$($manifest.ghidraHome)",
    # Its own application name => its own user-settings dir (%APPDATA%\ghidramcp\...),
    # so the headless server never fights the GUI profile over preferences.
    '-Dapplication.name=GhidraMCP',
    "@$($manifest.headlessCpFile)",
    $manifest.headlessClass,
    '--port', "$Port",
    # Loopback only. The server exposes 226 endpoints that read and WRITE the database;
    # binding 0.0.0.0 would publish that to the network.
    '--bind', '127.0.0.1'
)
if ($File) { $javaArgs += @('--file', $File) }
if ($Project) { $javaArgs += @('--project', $Project) }
if ($Program) { $javaArgs += @('--program', $Program) }

# run_script_inline is gated by an env var read by the Ghidra JVM. 30-ghidra.ps1 persists it
# at User scope; mirror it into THIS process so the child inherits it without a new terminal.
$allowScripts = [Environment]::GetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', 'User')
if ($allowScripts -eq '1') {
    $env:GHIDRA_MCP_ALLOW_SCRIPTS = '1'
    # Costs a few hundred ms of OSGi/Felix startup in headless -- say so, so the slower
    # boot does not look like a hang.
    Write-Host 'run_script_inline enabled (GHIDRA_MCP_ALLOW_SCRIPTS=1); adds OSGi init to startup.'
}

Write-Host "Starting headless GhidraMCP on $baseUrl ..."
if ($File) { Write-Host "  file:    $File" }
if ($Project) { Write-Host "  project: $Project" }
if ($Program) { Write-Host "  program: $Program" }
Remove-Item $outLog, $errLog -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath 'java' -ArgumentList $javaArgs -WorkingDirectory $manifest.ghidraHome `
    -PassThru -WindowStyle Hidden -RedirectStandardOutput $outLog -RedirectStandardError $errLog
# Record WHO we started, not just a number: Get-ServerPid will not let Stop-Process touch a
# process whose name and start time do not still match these, which is what keeps a recycled
# PID from being force-killed later. Read both properties defensively -- if java rejected its
# arguments the process may already have exited, and ProcessName and StartTime both throw on
# a dead process; the poll loop below reports that case properly with the java exit code and
# the logs, so a property getter must not abort the script first. The fallbacks stay honest:
# we launched java, microseconds ago, so both are still true of the process we just spawned.
$procName = 'java'
$procStart = (Get-Date).ToUniversalTime()
try { $procName = $proc.ProcessName; $procStart = $proc.StartTime.ToUniversalTime() } catch { }
# ASCII by construction (a number, a process name, an ISO-8601 timestamp), and written with
# an explicit encoding because the repo's encoding lint expects one.
[pscustomobject]@{
    pid        = $proc.Id
    name       = $procName
    startedUtc = $procStart.ToString('o')
} | ConvertTo-Json | Set-Content $pidFile -Encoding ascii

$deadline = (Get-Date).AddSeconds($TimeoutSec)
$conn = $null
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) {
        Write-Host "java exited with code $($proc.ExitCode) before the server came up."
        Write-Host '--- stdout ---'; Get-Content $outLog -Tail 30 -ErrorAction SilentlyContinue
        Write-Host '--- stderr ---'; Get-Content $errLog -Tail 30 -ErrorAction SilentlyContinue
        Remove-Item $pidFile -ErrorAction SilentlyContinue
        exit 1
    }
    $conn = Invoke-Endpoint '/check_connection' 3
    if ($conn.Ok) { break }
    Start-Sleep -Milliseconds 1000
}
if (-not $conn.Ok) {
    Write-Host "Server did not answer on $baseUrl within $TimeoutSec s."
    # The HTTP listener is opened AFTER the initial load, so a slow import looks exactly
    # like a hang. Say so, rather than letting it read as a failure.
    if ($File -or $Program) { Write-Host 'It loads the program BEFORE opening the port; a large binary may just need -TimeoutSec higher.' }
    Write-Host '--- stdout ---'; Get-Content $outLog -Tail 30 -ErrorAction SilentlyContinue
    Write-Host '--- stderr ---'; Get-Content $errLog -Tail 30 -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "Up: $($conn.Body.Trim())  (PID $($proc.Id))"

# Judge the load by the server's own answer, not by the absence of a crash: --project and
# --program failures are printed and then IGNORED, so the server comes up healthy with
# nothing loaded and every later tool call returns "No program loaded."
$toolCount = Get-ToolCount
Write-Host "MCP tools exposed: $toolCount"
if ($toolCount -lt 1) {
    Write-Host 'The server is up but exposes no tools - the bridge would connect and register nothing.'
    exit 1
}

if ($Program -or $File) {
    $wanted = if ($File) { $File } else { $Program }
    $meta = Invoke-Endpoint '/get_metadata' 120
    if (-not $meta.Ok -or $meta.Body -match 'No program loaded') {
        Write-Host "FAILED to load '$wanted'."
        Get-Content $outLog -Tail 20 -ErrorAction SilentlyContinue | Where-Object { $_ -match 'Failed|Error|error' }
        Write-Host 'The server is still running with no program.'
        # NOT /list_project_files -- headless answers "Project listing requires GUI mode
        # (PluginTool not available)". Same GUI-only family as /mcp/instance_info.
        Write-Host 'A "LockException: Unable to lock project" above means something still holds it.'
        Write-Host 'For the program path, use the folder layout the pipeline imported into, e.g.'
        Write-Host '  /f4/vr/Fallout4VR.exe.unpacked.exe'
        exit 1
    }
    $flat = ($meta.Body -replace '\s+', ' ')
    Write-Host "Loaded: $($flat.Substring(0,[Math]::Min(240,$flat.Length)))"
}

# --------------------------------------------------------------------------- .mcp.json
if ($WriteMcpConfigTo) {
    if (-not (Test-Path $WriteMcpConfigTo)) { throw "-WriteMcpConfigTo '$WriteMcpConfigTo' does not exist." }
    $target = Join-Path $WriteMcpConfigTo '.mcp.json'
    $cfg = [ordered]@{
        mcpServers = [ordered]@{
            ghidra = [ordered]@{
                type    = 'stdio'
                command = $manifest.bridgeExe
                args    = @()
                env     = [ordered]@{
                    PYTHONIOENCODING = 'utf-8'
                    # Required: headless serves no /mcp/instance_info, so the bridge's
                    # discovery scan finds nothing. This pins the TCP fallback instead.
                    GHIDRA_MCP_URL   = $baseUrl
                }
            }
        }
    }
    if (Test-Path $target) {
        Write-Host "NOTE: $target already exists - leaving it alone. Merge this in yourself:"
        $cfg | ConvertTo-Json -Depth 6
    }
    else {
        $cfg | ConvertTo-Json -Depth 6 | Set-Content $target -Encoding UTF8
        Write-Host "Wrote $target - restart your agent session there to pick up the ghidra tools."
    }
}

Write-Host ''
Write-Host "Stop it with: .\setup\36-ghidra-mcp.ps1 -Stop"

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
