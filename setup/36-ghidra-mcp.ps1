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

    EXIT CODES. Agents and CI gate on these, so each one means exactly one thing, and 0 is
    the narrow one: it asserts the state you ASKED FOR now holds, not that this script
    reached its last line.
      0  The server is up, it exposes its MCP toolset, it is holding the program you named,
         and any .mcp.json you asked for describes THIS server.
      1  You have no usable server. Nothing came up, something refused (a project lock this
         script will not break, a -Stop that would have thrown away unsaved database work),
         or what did come up exposes no MCP tools at all - the bridge would connect to it
         and register nothing.
      2  The server is up and exposing its tools, but the state is NOT the one you asked
         for: no program where you asked for one (a locked project, or a --program Ghidra
         printed a failure for and then ignored), a different program than the one you
         named, or a .mcp.json already on disk that points somewhere else. Everything is
         running and usable for whatever IS loaded - and the JVM still has to be stopped -
         which is why this is deliberately not 1. A caller that gates on `-eq 0` treats 1
         and 2 alike and is right to; only a caller that wants to say "it is up, just not
         loaded" has to tell them apart.

.PARAMETER Project
    Ghidra project to open -- a .gpr path or the directory containing one. Defaults to
    BethesdaGhidraScripts' project, i.e. the database the enrichment pipeline built.

.PARAMETER Program
    Program inside the project to load, e.g. /f4/vr/Fallout4VR.exe.unpacked.exe.

.PARAMETER WriteMcpConfigTo
    Directory to write .mcp.json into, so an agent session started there gets the tools.
    The file carries BOTH servers - ghidra and x64dbg - because it is built by
    New-McpConfigObject in setup\_common.ps1, which is the one definition of that file's
    shape; this script used to build its own inline with the x64dbg server missing.

    If a .mcp.json is already there this COMPARES the two and prints what differs. That is
    not an edge case: New-Plugin.ps1 scaffolds a .mcp.json into every project, so the
    documented Phase 4 command always lands on an existing file, and the old behaviour
    (print the JSON, say "merge this in yourself", exit 0) meant the interesting half was
    never even looked at. A file describing a different server is a real failure - a stale
    port pin is how an agent session ends up talking to nothing - so a difference exits 2.
    -Force replaces the file instead.

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
    # On -Start it means one more thing: replace a .mcp.json that already exists and describes
    # a different server. That is refused by default because the file belongs to the project
    # you pointed at, not to us -- it may carry MCP servers nothing here knows about, and the
    # replacement is REGENERATED from this pack's two servers, not merged with them.
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
# What the server on this port was told to LOAD, recorded beside the PID record and scoped to
# the same port. -Status needs it to tell apart two states that look identical over HTTP: a
# server started with no program ON PURPOSE (a bare -Start, or the locked-project path below,
# which deliberately starts without a project) and a server that was asked for a program and
# does not have it. /get_metadata answers "No program loaded" to both, so with nothing recorded
# -Status could only ever pass a useless server or fail a healthy one -- and it chose to pass.
# A SEPARATE file from the PID record on purpose: that record answers "which process is
# provably ours" and is the single check standing between both force-kill sites and a stranger's
# process, so it is not a place to hang new fields on.
# Nothing has to clean this one up. Get-LoadRecord hands it back only while its pid and start
# time still match the live process Get-ServerPid proved is ours, so a record left behind by a
# stopped server describes nothing and is ignored; the next -Start on this port overwrites it.
$loadFile = Join-Path $stateDir ".ghidra-headless.$Port.load.json"
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

# The load record -Start writes the moment it launches the JVM, handed back ONLY while it still
# describes the live server. Pass the process Get-ServerPid already proved is ours: the record
# repeats that process's pid and start time, so a file left over from an earlier server on this
# port -- nothing deletes it on -Stop, and it must not need to -- fails to match and is ignored
# rather than answering for a server it knows nothing about. Same fail-safe rule as the PID
# record: anything we cannot prove is current is treated as absent.
function Get-LoadRecord {
    [CmdletBinding()]
    param($Server)
    if (-not $Server) { return $null }
    if (-not (Test-Path $loadFile)) { return $null }
    try {
        $rec = (Get-Content $loadFile -Raw) | ConvertFrom-Json
        $recPid = 0
        if (-not ([int]::TryParse([string]$rec.pid, [ref]$recPid))) { return $null }
        if ($recPid -ne $Server.Id) { return $null }
        $recorded = [datetime]::Parse([string]$rec.startedUtc, [Globalization.CultureInfo]::InvariantCulture)
        $delta = ($Server.StartTime.ToUniversalTime() - $recorded.ToUniversalTime()).TotalSeconds
        if ([Math]::Abs($delta) -gt 2) { return $null }
        return $rec
    }
    catch { return $null }
}

# /get_metadata answers a FLAT object -- program_name, executable_path, function_count and the
# rest -- or {"error":"No program loaded."}; it is not the {"data":...} envelope some other
# endpoints use. Read program_name out of it, and return '' rather than guessing when the body
# will not parse: an unreadable answer must never be turned into "the wrong program is loaded",
# because the caller acts on that by exiting 2 against a server that may be perfectly right.
function Get-MetadataProgramName([string]$body) {
    if (-not $body) { return '' }
    try {
        $j = $body | ConvertFrom-Json
        return "$($j.program_name)".Trim()
    }
    catch { return '' }
}

# The leaf of what the caller asked to load, which is the only thing comparable to what the
# server reports. A -Program is a path INSIDE the Ghidra project (/f4/vr/Fallout4VR.exe.unpacked.exe)
# and a -File is a path on disk, while program_name is just the name Ghidra gave the program --
# so the folder halves have nothing in common and only the last segment can be held up against
# it. Split on both separators: the project path uses forward slashes, the disk path backslashes.
function Get-RequestedProgramLeaf([string]$request) {
    if (-not $request) { return '' }
    $flat = ($request -replace '\\', '/').TrimEnd('/')
    if (-not $flat) { return '' }
    return $flat.Split('/')[-1]
}

# --------------------------------------------------------------- .mcp.json (write or compare)
# Returns $true when the file on disk now describes THIS server, $false when it does not and we
# refused to overwrite it -- the caller turns that into the exit code, because "I ran the config
# branch" is not the same claim as "the config the agent will load points here".
#
# The caller has already checked that $Directory exists (that check runs before the JVM starts,
# so a typo cannot leave a server running behind a failed run).
function Write-McpConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Directory,
        [string]$BridgeExe = ''
    )

    # Pinned to a provider path before anything writes to it. The write below goes through
    # [IO.File], which is .NET and resolves a relative path against the PROCESS working
    # directory -- a thing Set-Location and Push-Location never change -- so a relative
    # -WriteMcpConfigTo would be compared in one directory and written in another. Same
    # reasoning as New-Plugin.ps1's $target; when the path is already absolute this is a no-op.
    $target = Join-Path ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory)) '.mcp.json'
    # ONE definition of this file's shape, in _common.ps1, consumed by every writer. There used
    # to be two that disagreed in both directions: this script built the object inline with the
    # paths correctly resolved and NO x64dbg server in it, while mcp/mcp.template.json carried
    # both servers and a hard-coded C:/repos bridge path that New-Plugin.ps1 copied verbatim into
    # every scaffold. Each file was the fix for the other one's bug and neither knew it.
    # -BridgeExe hands over the path this run already read out of the build manifest, and -Port
    # is the port this invocation is actually serving on -- which is the whole 8089-vs-8090 trap:
    # follow this script's own advice to use -Port when 8089 is busy, and a config generated with
    # the default pins the bridge to a port nothing is listening on.
    $cfg = New-McpConfigObject -Port $Port -BridgeExe $BridgeExe
    $wantCommand = "$($cfg.mcpServers.ghidra.command)"
    $wantUrl = "$($cfg.mcpServers.ghidra.env.GHIDRA_MCP_URL)"
    $wantX64 = (@($cfg.mcpServers.x64dbg.args) -join ' ')

    if (-not (Test-Path $target)) {
        # UTF-8 with NO BOM, via the same [IO.File]::WriteAllText call New-Plugin.ps1 and
        # 30-ghidra.ps1 use for the files they generate -- and NOT Set-Content -Encoding UTF8,
        # which under Windows PowerShell 5.1 emits a BOM. A U+FEFF in front of the opening brace
        # is not cosmetic here: JSON.parse rejects it, so an MCP client reading this file finds
        # NO servers at all. That is precisely the failure this whole branch exists to prevent --
        # a Phase 4 run that exits 0 over an agent session with no Ghidra tools in it -- and it
        # would also have quietly re-broken every .mcp.json New-Plugin.ps1 wrote BOM-less.
        [IO.File]::WriteAllText($target, (($cfg | ConvertTo-Json -Depth 6) + "`r`n"), [Text.UTF8Encoding]::new($false))
        Write-Host "Wrote $target - restart your agent session there to pick up both servers:"
        Write-Host "  ghidra: $wantCommand"
        Write-Host "          pinned to $wantUrl (headless serves no /mcp/instance_info, so"
        Write-Host '          bridge discovery finds nothing without that pin)'
        Write-Host "  x64dbg: cmd $wantX64"
        Write-Host '          (the debugger-side plugin is setup\40-x64dbg.ps1; the version above'
        Write-Host '          and the plugin it installs come from one pin in setup\_common.ps1)'
        return $true
    }

    # An existing file is the NORMAL case: New-Plugin.ps1 puts a .mcp.json in every project it
    # scaffolds, so `-WriteMcpConfigTo <your-plugin-dir>` -- the Phase 4 command in CLAUDE.md --
    # always lands here. This branch used to print the JSON, say "merge this in yourself" and
    # exit 0 without so much as reading the file, so a stale port, a bridge exe from another
    # checkout, or an entry left by a different Ghidra MCP extension entirely (GhidraMCP vs
    # GhidrAssistMCP is a confusion that has really happened) all survived a successful run.
    Write-Host "$target already exists; comparing it against what this run would write."
    $have = $null
    $readError = ''
    try { $have = Get-Content $target -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { $readError = $_.Exception.Message }

    $diffs = [System.Collections.Generic.List[string]]::new()
    $unreadable = ($readError -or -not $have)
    if ($unreadable) {
        $reason = if ($readError) { $readError } else { 'it parsed to nothing' }
        Write-Host "  UNREADABLE: $reason"
        Write-Host '  A .mcp.json an agent cannot parse is a .mcp.json that loads no servers at all.'
        $diffs.Add('unreadable file')
    }
    else {
        # Compare the command as a PATH, not as a string. mcp/mcp.template.json writes it with
        # forward slashes and the build manifest records backslashes; Windows spawns the same exe
        # either way, so a textual compare would report DIFFERS on a file that works perfectly --
        # and a check that cries wolf on the common case is one people learn to ignore.
        $haveCommand = "$($have.mcpServers.ghidra.command)".Trim()
        $haveUrl = "$($have.mcpServers.ghidra.env.GHIDRA_MCP_URL)".Trim()
        $haveX64 = (@($have.mcpServers.x64dbg.args) -join ' ').Trim()
        if (($haveCommand -replace '/', '\') -eq ($wantCommand -replace '/', '\')) {
            Write-Host "  ghidra command   MATCHES  $wantCommand"
        }
        else {
            Write-Host '  ghidra command   DIFFERS'
            Write-Host "    on disk:     $(if ($haveCommand) { $haveCommand } else { '(no mcpServers.ghidra.command)' })"
            Write-Host "    this server: $wantCommand"
            $diffs.Add('ghidra command')
        }
        if ($haveUrl.TrimEnd('/') -eq $wantUrl.TrimEnd('/')) {
            Write-Host "  GHIDRA_MCP_URL   MATCHES  $wantUrl"
        }
        else {
            Write-Host '  GHIDRA_MCP_URL   DIFFERS'
            Write-Host "    on disk:     $(if ($haveUrl) { $haveUrl } else { '(no mcpServers.ghidra.env.GHIDRA_MCP_URL)' })"
            Write-Host "    this server: $wantUrl"
            $diffs.Add('GHIDRA_MCP_URL')
        }
        if ($haveX64 -eq $wantX64) {
            Write-Host "  x64dbg server    MATCHES  cmd $wantX64"
        }
        else {
            Write-Host '  x64dbg server    DIFFERS'
            Write-Host "    on disk:     $(if ($haveX64) { "cmd $haveX64" } else { '(no mcpServers.x64dbg entry)' })"
            Write-Host "    this pack:   cmd $wantX64"
            $diffs.Add('x64dbg server')
        }
    }

    if ($diffs.Count -eq 0) {
        Write-Host '  Already describes this server; nothing to write.'
        return $true
    }
    if ($Force) {
        # No BOM, for the reason spelled out at the fresh-write above.
        [IO.File]::WriteAllText($target, (($cfg | ConvertTo-Json -Depth 6) + "`r`n"), [Text.UTF8Encoding]::new($false))
        Write-Host "  -Force: replaced $target. It is REGENERATED, not merged -- any other MCP"
        Write-Host '  server you had added to that file is gone, so add it back to the new one.'
        return $true
    }
    Write-Host "  Leaving $target alone: it is your project's file, and a regenerated one carries"
    Write-Host '  only this pack''s two servers -- anything else you put in it would be dropped.'
    if ($unreadable) {
        Write-Host '  Fix the JSON by hand, or re-run with -Force to replace the file wholesale.'
    }
    else {
        Write-Host '  Correct these by hand, or re-run with -Force to replace the file wholesale:'
        Write-Host "    $($diffs -join ', ')"
    }
    return $false
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
    $toolCount = -1
    $meta = $null
    # What this server was started to load, or $null when nothing here can vouch for it.
    $load = Get-LoadRecord -Server $p
    $wantedLoad = ''
    if ($load) {
        if ("$($load.file)".Trim()) { $wantedLoad = "$($load.file)".Trim() }
        elseif ("$($load.program)".Trim()) { $wantedLoad = "$($load.program)".Trim() }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $rows.Add([pscustomobject]@{ Check = 'process'; Result = $(if ($p) { "running (PID $($p.Id))" } else { 'not running' }) })
    $rows.Add([pscustomobject]@{ Check = 'check_connection'; Result = $(if ($conn.Ok) { $conn.Body.Trim() } else { "unreachable: $($conn.Body)" }) })
    if ($conn.Ok) {
        # -1 is Get-ToolCount's "/mcp/schema did not answer", not a count. Printed as
        # "-1 exposed via /mcp/schema" it read like one, which is exactly the row an agent
        # skims past on its way to an exit 0 that meant nothing.
        $toolCount = Get-ToolCount
        $rows.Add([pscustomobject]@{ Check = 'mcp tools'; Result = $(if ($toolCount -lt 0) { 'UNREADABLE - /mcp/schema did not answer' } else { "$toolCount exposed via /mcp/schema" }) })
        $meta = Invoke-Endpoint '/get_metadata' 30
        $rows.Add([pscustomobject]@{ Check = 'program'; Result = $(if ($meta.Ok) { ($meta.Body -replace '\s+', ' ').Substring(0, [Math]::Min(160, ($meta.Body -replace '\s+', ' ').Length)) } else { 'n/a' }) })
        $rows.Add([pscustomobject]@{ Check = 'started to load'; Result = $(if ($wantedLoad) { $wantedLoad } elseif ($load) { 'nothing - started without a program on purpose' } else { 'unknown - no load record here matches this process' }) })
    }
    $rows | Format-Table -AutoSize

    # THE GATE, and it is a conjunction on purpose. CLAUDE.md states Phase 4 as "-Status reports
    # a live connection, a non-zero tool count, and a loaded program", but the exit code was the
    # connection alone -- so a server whose /mcp/schema answered nothing and whose program row
    # said 'n/a' still exited 0, and the agent that gated on it went off to decompile against
    # "No program loaded". A table nobody reads is not a gate; the exit code is.
    if (-not $conn.Ok) {
        Write-Host "Nothing is answering on $baseUrl. Start it with: .\setup\36-ghidra-mcp.ps1 -Start"
        exit 1
    }
    if ($toolCount -lt 0) {
        # Not the same failure as "zero tools", and worth its own sentence: /mcp/schema IS the
        # toolset. The bridge fetches it and registers whatever it finds, so a server that will
        # not serve it hands an agent nothing, however healthy /check_connection looks.
        Write-Host 'The server answers /check_connection, but /mcp/schema did not answer at all - and'
        Write-Host 'that schema is the toolset the bridge registers from. -Stop then -Start it.'
        exit 1
    }
    if ($toolCount -lt 1) {
        Write-Host 'The server answers, but exposes no MCP tools - the bridge would connect to it and'
        Write-Host 'register nothing, so there is no toolset for an agent to reach. -Stop then -Start it.'
        exit 1
    }
    # "A loaded program WHEN ONE IS IMPLIED", and the load record is how that is decided, because
    # over HTTP the two cases are identical: /get_metadata says "No program loaded" both to a
    # server that was never given one and to a server whose --program Ghidra printed a failure
    # for and then ignored. So -Status holds this server to what it was STARTED to load. A bare
    # -Start, or the locked-project path that deliberately starts WITHOUT a project, recorded no
    # program and is not broken -- calling it broken would fail precisely the runs this script
    # chose to allow. (-Start answers the other question, "did the CALLER get what they asked
    # for", and does exit 2 when a locked project cost you the -Program you named. One server,
    # two honest answers: one about the request, one about the server.)
    #
    # With no record at all -- another checkout's server, one started before this script recorded
    # this, or one whose record no longer matches the live process -- nothing here knows what was
    # asked for. That is judged NOT passed rather than passed: a server holding no program cannot
    # answer a single decompile, and this exit code is what an agent uses to decide it may start.
    $programLoaded = $false
    if ($meta -and $meta.Ok -and ($meta.Body -notmatch 'No program loaded')) { $programLoaded = $true }
    if (-not $programLoaded) {
        if ($load -and -not $wantedLoad) {
            Write-Host 'No program is loaded, and none was asked for when this server was started'
            Write-Host '(a bare -Start, or a locked project). Nothing is wrong with the server -- but'
            Write-Host 'an agent that needs a program still has to -Stop it and -Start it with -Program.'
            exit 0
        }
        if (-not ($meta -and $meta.Ok)) {
            # /get_metadata did not ANSWER, which is a different fact from "No program loaded"
            # and must not be reported as it. The endpoint gets 30 s above, and a JVM in the
            # middle of a decompile can hold it longer -- so the honest statement is that
            # nothing here knows what is loaded. This is the same rule the already-running
            # comparison further down applies to an unreadable program_name: an answer we could
            # not read is never turned into a claim about the wrong state. The exit code is
            # unchanged (2, the same one both branches below take) because a server that will
            # not say what it holds is still not something an agent can gate on -- only the
            # sentence and the repair change.
            Write-Host "/get_metadata did not answer ($($meta.Body)), so what this server is holding"
            Write-Host 'could not be read at all. That is NOT the same as "no program loaded", and this'
            Write-Host 'gate will not claim it is.'
            Write-Host 'The Phase 4 gate is NOT passed: re-run -Status once the JVM is idle; if it still'
            Write-Host 'will not answer, -Stop and -Start it.'
            exit 2
        }
        if ($wantedLoad) {
            Write-Host "This server was started to load '$wantedLoad' and is holding NO program."
            Write-Host 'Ghidra prints --project/--program failures and carries on, so it comes up'
            Write-Host 'healthy and empty and every tool call returns "No program loaded".'
        }
        else {
            Write-Host 'No program is loaded, and nothing here recorded what this server was started to'
            Write-Host "load (no load record for port $Port matches this process) - it was started from"
            Write-Host 'another checkout, or before this script kept that record.'
        }
        Write-Host 'The Phase 4 gate is NOT passed: -Stop, then -Start with the -Program you need.'
        exit 2
    }
    exit 0
}

# --------------------------------------------------------------------------- Start
$manifest = Get-Manifest
if (-not (Test-Path $manifest.headlessCpFile)) {
    throw "Classpath argfile $($manifest.headlessCpFile) is missing - re-run setup\30-ghidra.ps1."
}
# Judge -WriteMcpConfigTo BEFORE anything is started. This check used to sit at the very end,
# after the JVM was up: a typo in the directory threw on a run that had already printed "Up:",
# leaving a server (and a project lock) behind a failure.
if ($WriteMcpConfigTo -and -not (Test-Path $WriteMcpConfigTo)) {
    throw "-WriteMcpConfigTo '$WriteMcpConfigTo' does not exist."
}

$existing = Get-ServerPid
if ($existing) {
    $conn = Invoke-Endpoint '/check_connection'
    if ($conn.Ok) {
        Write-Host "Already running (PID $($existing.Id)): $($conn.Body.Trim())"

        # The requested config is written on THIS path too. This branch used to exit 0 two
        # hundred lines above the .mcp.json block, so `-Start -Program ... -WriteMcpConfigTo
        # <dir>` -- the exact Phase 4 command CLAUDE.md gives -- silently wrote nothing whenever
        # a server happened to be up already, said nothing about it, and reported success. A run
        # that was asked for a config and did not write one must never exit 0.
        $configOk = $true
        if ($WriteMcpConfigTo) {
            $configOk = Write-McpConfigFile -Directory $WriteMcpConfigTo -BridgeExe "$($manifest.bridgeExe)"
        }

        # Up is not the same as usable, and this path never asked. The tool count is what an
        # agent actually receives: a server whose /mcp/schema is empty registers nothing through
        # the bridge, and "Already running" over the top of that is a lie the caller acts on.
        $toolCount = Get-ToolCount
        Write-Host "MCP tools exposed: $toolCount"
        if ($toolCount -lt 1) {
            Write-Host 'The server is up but exposes no tools - the bridge would connect and register nothing.'
            exit 1
        }

        # And it is not necessarily YOUR server. This path never compared the -Program you asked
        # for against what is loaded, so the exit code was identical whether the running server
        # held the game EXE you named, a loose -File DLL from an earlier session, or nothing at
        # all. Only the program can be checked: /get_metadata reports the PROGRAM, and headless
        # answers /list_project_files with "requires GUI mode", so a -Project mismatch is
        # invisible from here and is not claimed either way.
        $mismatch = ''
        $asked = ''
        if ($File) { $asked = $File }
        elseif ($Program) { $asked = $Program }
        if ($asked) {
            $meta = Invoke-Endpoint '/get_metadata' 120
            if (-not $meta.Ok -or $meta.Body -match 'No program loaded') {
                Write-Host "  It holds NO program, and you asked for '$asked'."
                $mismatch = "the running server holds no program, and you asked for '$asked'"
            }
            else {
                $loadedName = Get-MetadataProgramName $meta.Body
                $wantName = Get-RequestedProgramLeaf $asked
                if (-not $loadedName) {
                    # An answer we could not read is not evidence of the wrong program. Say so
                    # and leave the exit code alone rather than failing a server that may be
                    # exactly right -- an invented mismatch costs a -Stop and a full reload.
                    Write-Host '  (/get_metadata gave no readable program_name, so what is loaded was not compared.)'
                }
                elseif ($loadedName -ne $wantName) {
                    Write-Host "  It holds '$loadedName', and you asked for '$asked'."
                    $mismatch = "the running server holds '$loadedName', not '$wantName'"
                }
                else {
                    Write-Host "  It holds '$loadedName', which is what you asked for."
                }
            }
        }

        Write-Host 'Use -Stop first if you need to change the loaded project or program.'
        if ($mismatch -or -not $configOk) {
            Write-Host ''
            Write-Host 'Exit 2 -- the server is up and exposing its tools, but this is not the state you'
            Write-Host 'asked for:'
            if ($mismatch) { Write-Host "  * $mismatch" }
            if (-not $configOk) { Write-Host "  * the .mcp.json in $WriteMcpConfigTo does not describe this server (see above)" }
            exit 2
        }
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

# What the CALLER asked to have loaded, captured before the lock handling below can clear it
# (and after the -File branch above, whose blanking of $Program is a deliberate precedence rule,
# not a degradation). The locked-project path blanks $Program on purpose -- starting without a
# project beats failing deep inside Ghidra -- but blanking it also switched OFF the
# /get_metadata verification near the end of this file, which is gated on `if ($Program -or
# $File)`. So the one case that GUARANTEES no program was the one case that stopped checking:
# the tool count passed (tools register with nothing loaded), a .mcp.json was written pointing
# at an empty server, and the run exited 0. These three variables are what the tail holds the
# run to: you asked for a program, you did not get one, that is exit 2.
$askedProgram = $Program
$lockHolder = ''
$degraded = ''

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
        # Kept for the tail. By the time the run ends this warning has scrolled past a whole
        # server start, and an exit 2 that says "your -Program was dropped" is only actionable
        # if it can name the process to go and stop.
        $lockHolder = $who
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

# Beside it, and cross-referenced to it: what this server was TOLD to load. -Status has no other
# way to tell "started with no program on purpose" from "asked for one and does not have it",
# because /get_metadata answers "No program loaded" to both -- and that ambiguity is why -Status
# used to exit 0 on a server an agent could not decompile a single function with. Repeating the
# pid and start time is what makes it self-invalidating: a record left over from an earlier
# server on this port matches no live process and is ignored (see Get-LoadRecord), so nothing
# has to remember to delete it. Written on every start, including the ones that load nothing,
# because "no program was asked for" is the answer -Status most needs to be able to trust.
# UTF8 rather than the pid record's ascii: a -File path can hold anything the filesystem allows.
[pscustomobject]@{
    pid        = $proc.Id
    startedUtc = $procStart.ToString('o')
    port       = $Port
    program    = $Program
    file       = $File
    project    = $Project
} | ConvertTo-Json | Set-Content $loadFile -Encoding UTF8

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
        # This used to exit 1 on the spot. The server is up and serving its entire toolset -- it
        # is just empty -- which is the same state the locked-project case below lands in, so it
        # gets the same code rather than two different answers for one situation. Falling through
        # instead of exiting also matters: a -WriteMcpConfigTo was still asked for and the config
        # it writes is correct (it describes this running server), and the caller needs the
        # "Stop it with:" line for the JVM this run left behind.
        $degraded = "'$wanted' did not load, so the server is running with no program"
    }
    else {
        $flat = ($meta.Body -replace '\s+', ' ')
        Write-Host "Loaded: $($flat.Substring(0,[Math]::Min(240,$flat.Length)))"
    }
}
elseif ($askedProgram) {
    # Reached only when the lock handling above cleared the -Program you asked for, which is why
    # $askedProgram exists at all: with $Program blanked, the verification above does not run,
    # and every check that DOES run passes. The server is healthy, the tool count is full, and
    # not one MCP call will return anything but "No program loaded".
    Write-Host ''
    Write-Host "You asked for -Program '$askedProgram' and the server was started WITHOUT it,"
    Write-Host 'because the project is locked by another process.'
    if ($lockHolder) { Write-Host "  holder: $lockHolder" }
    else { Write-Host '  (holder not identified - it may be a pyghidra/python process)' }
    Write-Host '  Never delete the lock while it is held - that is how databases get corrupted.'
    $degraded = "-Program '$askedProgram' was dropped because the project is locked"
}

# --------------------------------------------------------------------------- .mcp.json
$configOk = $true
if ($WriteMcpConfigTo) {
    $configOk = Write-McpConfigFile -Directory $WriteMcpConfigTo -BridgeExe "$($manifest.bridgeExe)"
}

Write-Host ''
Write-Host "Stop it with: .\setup\36-ghidra-mcp.ps1 -Stop"

# ONE place decides the exit code, because "whichever branch fell through last" is how a run
# that dropped your -Program, or left a .mcp.json pointing at another server, still reported
# success. Exit 0 from here asserts the state the caller ASKED for holds; anything else that is
# still up and serving tools is a 2 (see EXIT CODES at the top of this file).
if ($degraded -or -not $configOk) {
    Write-Host ''
    Write-Host 'Exit 2 -- the server is up and exposing its tools, but this is not the state you'
    Write-Host 'asked for:'
    if ($degraded) { Write-Host "  * $degraded" }
    if (-not $configOk) { Write-Host "  * the .mcp.json in $WriteMcpConfigTo does not describe this server (see above)" }
    Write-Host 'Nothing else failed, so the JVM is running and still has to be stopped.'
    exit 2
}

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
