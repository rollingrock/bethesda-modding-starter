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
    [int]$TimeoutSec = 180
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"
Sync-Path

$stateDir = $PSScriptRoot
$pidFile = Join-Path $stateDir '.ghidra-headless.pid'
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

function Get-ServerPid {
    if (-not (Test-Path $pidFile)) { return $null }
    $id = (Get-Content $pidFile -Raw).Trim()
    if (-not $id) { return $null }
    $p = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue
    if ($p) { return $p } else { return $null }
}

# --------------------------------------------------------------------------- Stop
if ($Stop) {
    $p = Get-ServerPid
    if (-not $p) {
        Write-Host 'Headless server is not running (no live PID recorded).'
        Remove-Item $pidFile -ErrorAction SilentlyContinue
        exit 0
    }
    Write-Host "Stopping headless server (PID $($p.Id)) ..."
    # Save first: a killed JVM leaves the project locked, and a stale .lock blocks every
    # later run (including the enrichment pipeline's). Then shut down over HTTP --
    # CloseMainWindow() is useless here because the JVM runs windowless.
    $null = Invoke-Endpoint '/save_all_programs' 300
    $exit = Invoke-Endpoint '/exit_ghidra' 15
    if (-not $exit.Ok) { Write-Host "  /exit_ghidra did not answer ($($exit.Body)); will terminate." }
    if (-not $p.WaitForExit(20000)) {
        Write-Host '  still alive after 20 s; terminating.'
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
    Write-Host "PID $($existing.Id) is alive but not answering on $baseUrl; stopping it."
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
    $lock = Get-ChildItem $projDir -Filter '*.lock' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($lock) {
        $holder = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and ($_.CommandLine -match 'ghidra|pyghidra|bgs-analyze') } |
            Select-Object -First 1
        Write-Host "WARNING: $($lock.Name) exists - the project is held by another process."
        if ($holder) { Write-Host "         likely holder: PID $($holder.ProcessId)  $($holder.CommandLine)" }
        Write-Host '         Starting the server WITHOUT a project. Re-run once it is free.'
        Write-Host '         (Do not delete the lock while that process is alive - it will corrupt the database.)'
        $Project = ''
        $Program = ''
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
$proc.Id | Set-Content $pidFile -Encoding ascii

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
        Write-Host 'The server is still running with no program. List what the project actually holds:'
        Write-Host "  Invoke-RestMethod $baseUrl/list_project_files"
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
