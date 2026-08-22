<#
.SYNOPSIS
    Install x64dbg + the x64dbg MCP plugin (bromoket/x64dbg_mcp).

.DESCRIPTION
    Downloads the latest x64dbg snapshot and the PINNED MCP plugin release, and installs
    the plugin into both the x64 and x32 plugin folders. The npm-side MCP server is run
    via npx pinned to the SAME version in .mcp.json -- plugin and server versions must
    match, and an unpinned npx would drift. Both halves of that pin come from one constant,
    $script:X64dbgMcpServerPin in setup\_common.ps1: this script derives the release TAG
    from it, New-McpConfigObject writes the npm spec from it.

    It then lists the .dd64 symbol databases Phase 4 exported, so a debugging session starts on
    named functions instead of raw addresses. It does not GUESS where those are: it reads the
    directory 35-ghidra-analysis.ps1 recorded in <BgsRoot>\.analysis-verified.json, falls back to
    the conventional <BgsRoot>\symbols when no record can answer, and says which of the two it
    used. Point -BgsRoot (or -Root) at your clone; nothing here is hard-coded to C:\repos.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\tools\x64dbg',

    # Where the clones live. 20-repos.ps1, 30-ghidra.ps1 and 90-verify.ps1 all spell this -Root
    # with this same default, so a machine that keeps its repos elsewhere overrides one thing,
    # the same way, everywhere.
    [string]$Root = 'C:\repos',

    # The BethesdaGhidraScripts clone whose .analysis-verified.json and symbols\ step 3 reads.
    # -BgsRoot is what 35-ghidra-analysis.ps1 calls it and what 90-verify.ps1 already passes to
    # it, so both spellings land somewhere familiar. Empty ON PURPOSE, like $McpVersion below --
    # it is derived from -Root after binding; see the comment at the resolution for why it
    # cannot be a parameter default either.
    [string]$BgsRoot = '',

    # Empty ON PURPOSE -- the real default is resolved a few lines down, after the dot-source.
    # See the comment there before "tidying" the pin back up here.
    [string]$McpVersion = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"

# The pin lives in _common.ps1 as $script:X64dbgMcpServerPin, and it has to be resolved HERE
# rather than as the parameter default above. PowerShell binds parameters -- and evaluates
# their defaults -- BEFORE the first statement of the body runs, so
# `param([string]$McpVersion = $script:X64dbgMcpReleaseTag)` binds an empty string: the
# dot-source that defines the constant has not executed yet. And it does not fail where the
# mistake is: an empty $McpVersion leaves the release URL below ending at .../releases/tags/ ,
# GitHub answers 404, and Invoke-RestMethod throws about a release that is not there -- which
# reads as "upstream deleted the pinned tag" and sends the next person to check GitHub rather
# than the param block. Default it to '' and fill it in after the dot-source; that is the only
# ordering in which the constant is readable.
#
# The TAG form, with the leading v, because that is what bromoket/x64dbg_mcp names its GitHub
# releases; .mcp.json's npm spec takes the bare form. Both are derived from the one constant so
# they cannot drift -- which is what the "keep in sync with mcp/mcp.template.json" comment that
# used to sit in the param block was asking a human to do by hand.
if (-not $McpVersion) { $McpVersion = $script:X64dbgMcpReleaseTag }

# -BgsRoot derives from -Root, and that cannot be a parameter default either -- for a different
# reason than the pin above. `[string]$BgsRoot = (Join-Path $Root 'BethesdaGhidraScripts')` does
# bind in declaration order and does see $Root, but Join-Path resolves the DRIVE through the
# provider: measured on 5.1, `Join-Path 'D:\src' 'X'` on a box with no D: writes "Cannot find
# drive. A drive with the name 'D' does not exist." and hands back NOTHING -- non-terminating at
# bind time, so -Root on a drive this machine does not have would bind $BgsRoot to '' and every
# path below would quietly become relative to the current directory. [IO.Path]::Combine is
# string math: no provider, no drive check, which is what a path that is only ever REPORTED
# wants. The same reasoning applies to the two paths built from $BgsRoot in step 3.
if (-not $BgsRoot) { $BgsRoot = [IO.Path]::Combine($Root, 'BethesdaGhidraScripts') }

# 1. x64dbg snapshot
if (-not (Test-Path (Join-Path $InstallDir 'x96dbg.exe'))) {
    Write-Host 'Downloading the latest x64dbg snapshot ...'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/x64dbg/x64dbg/releases/latest'
    $asset = $rel.assets | Where-Object name -like 'snapshot_*.zip' | Select-Object -First 1
    if (-not $asset) { $asset = $rel.assets | Where-Object name -like '*.zip' | Select-Object -First 1 }
    $zip = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    Expand-Archive $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
    # Snapshots wrap everything in a release\ folder — flatten it.
    $inner = Join-Path $InstallDir 'release'
    if (Test-Path (Join-Path $inner 'x96dbg.exe')) {
        Get-ChildItem $inner | Move-Item -Destination $InstallDir -Force
        Remove-Item $inner -Recurse -Force
    }
}
if (-not (Test-Path (Join-Path $InstallDir 'x96dbg.exe'))) { throw "x64dbg layout unexpected under $InstallDir" }
Write-Host "x64dbg: $InstallDir"

# 2. MCP plugin (pinned release; local build only needed to match a custom commit)
$relUrl = "https://api.github.com/repos/bromoket/x64dbg_mcp/releases/tags/$McpVersion"
$rel = Invoke-RestMethod $relUrl
foreach ($pair in @(@{ Ext = '.dp64'; Dir = 'x64' }, @{ Ext = '.dp32'; Dir = 'x32' })) {
    $asset = $rel.assets | Where-Object name -like "*$($pair.Ext)" | Select-Object -First 1
    if (-not $asset) { Write-Warning "No $($pair.Ext) asset in $McpVersion — skipping $($pair.Dir)."; continue }
    $plugDir = Join-Path $InstallDir "$($pair.Dir)\plugins"
    New-Item -ItemType Directory -Force $plugDir | Out-Null
    $dest = Join-Path $plugDir $asset.name
    if (-not (Test-Path $dest)) {
        Write-Host "Installing $($asset.name) -> $plugDir"
        Invoke-WebRequest $asset.browser_download_url -OutFile $dest
    }
}

# 3. point at the symbols Phase 4 exported — debugging without them is raw addresses
#
# WHERE they are is not something this script can derive. symbol_export.py writes to a slug built
# from the program's path inside the Ghidra project -- symbols\f4-vr-Fallout4VR\ -- and the export
# on the machine this was written on, made before that slug existed, sits in symbols\f4vr\
# instead. So ASK THE RECORD: 35-ghidra-analysis.ps1 writes the directory each export ACTUALLY
# wrote to into .analysis-verified.json (entries[].exportDir, set only where symbol_export.py
# exited 0), precisely so nothing downstream has to guess.
#
# The guess used to be a literal C:\repos\BethesdaGhidraScripts\symbols with no parameter to move
# it. On any machine whose repos are not on C:\repos that made this block print "run
# setup\35-ghidra-analysis.ps1 first" over a COMPLETED Phase 4 -- an instruction to redo the one
# step in this pack measured in HOURS, issued because one hard-coded directory was empty.
$markerPath = [IO.Path]::Combine($BgsRoot, '.analysis-verified.json')
# The conventional layout, for everything the record cannot describe. It is a fallback and it is
# labelled as one below -- never printed as though someone had observed it.
$symRoot = [IO.Path]::Combine($BgsRoot, 'symbols')

# Ordered: what the record names first, the convention last. The reason travels WITH each
# directory, so the not-found message can say where it looked and on whose authority.
$candidates = @()
# Every reason we ended up guessing, in plain words, printed beside the results.
$assumed = @()

if (-not (Test-Path $BgsRoot)) {
    $assumed += "there is no BethesdaGhidraScripts clone at $BgsRoot"
}
elseif (-not (Test-Path $markerPath)) {
    $assumed += "no $markerPath -- nothing here has recorded where an export wrote"
}
else {
    $marker = $null
    try { $marker = Get-Content $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch {
        # An unreadable record is not evidence that nothing was exported, and reading it that
        # way is what costs a re-run. Say what happened and fall back to the convention.
        Write-Warning ("Verification record $markerPath is unreadable: " + $_.Exception.Message)
        $assumed += "$markerPath could not be parsed"
    }
    # 5.1's ConvertFrom-Json hands a JSON array back as ONE object rather than enumerating it,
    # and ConvertTo-Json writes a single-element array as a bare object -- so a one-entry record
    # can arrive either way. @() around the VARIABLE, not the pipeline, normalises both.
    $entries = @()
    if ($marker -and $marker.PSObject.Properties['entries']) { $entries = @($marker.entries) }
    foreach ($e in $entries) {
        if (-not $e) { continue }
        # exported is the field symbol_export.py's exit code set; exportDir is where it wrote.
        # -eq $true rather than a cast, so an entry written before those fields existed reads as
        # false instead of as something truthy. A '*' (version-unknown) entry never carries an
        # exportDir, so nothing is lost by taking every entry here rather than resolving
        # exact-before-wildcard the way 35-ghidra-analysis.ps1 has to.
        $dir = "$($e.exportDir)".Trim()
        if (($e.exported -eq $true) -and $dir) {
            $candidates += [pscustomobject]@{ Dir = $dir; Why = "recorded for $($e.game)/$($e.version)" }
        }
    }
    if ($marker -and -not $candidates.Count) {
        # Distinguish the three ways a record can be present and still not answer the question.
        # None of them means "the analysis never ran", and none of them may be reported as if it
        # did: the legacy shape in particular sits on this machine over hours of finished work.
        if ($marker.PSObject.Properties['games']) {
            $assumed += "$markerPath is the legacy {games:[...]} record, which predates exportDir"
        }
        elseif ($entries.Count) {
            $assumed += "$markerPath records " +
                (@($entries | ForEach-Object { "$($_.game)/$($_.version)" }) -join ', ') +
                ' but no completed export'
        }
        else {
            $assumed += "$markerPath records no exports"
        }
    }
}
# The convention is ALWAYS searched, not only when the record is silent -- on this machine that
# is the search that finds symbols\f4vr\Fallout4VR.dd64, exported before the field existed.
$candidates += [pscustomobject]@{ Dir = $symRoot; Why = 'conventional path, assumed' }

# A recorded directory normally sits UNDER symbols\, so the two searches overlap. Dedupe the
# directories, then the files, or one .dd64 gets listed twice as though there were two.
$dirs    = @()
$seenDir = @{}
foreach ($c in $candidates) {
    $norm = "$($c.Dir)".TrimEnd('\', '/').ToLowerInvariant()
    if (-not $norm -or $seenDir.ContainsKey($norm)) { continue }
    $seenDir[$norm] = $true
    $dirs += [pscustomobject]@{ Dir = $c.Dir; Why = $c.Why; Exists = (Test-Path $c.Dir) }
}

$dd       = @()
$seenFile = @{}
foreach ($d in $dirs) {
    if (-not $d.Exists) { continue }
    foreach ($f in @(Get-ChildItem $d.Dir -Recurse -Filter '*.dd64' -ErrorAction SilentlyContinue)) {
        $k = $f.FullName.ToLowerInvariant()
        if ($seenFile.ContainsKey($k)) { continue }
        $seenFile[$k] = $true
        $dd += $f
    }
}

Write-Host ''
# A recorded export whose directory is gone is worth one line either way: it is the difference
# between "never exported" and "exported, then moved or deleted", and only the record knows.
foreach ($d in @($dirs | Where-Object { -not $_.Exists -and $_.Why -like 'recorded*' })) {
    Write-Warning ("$markerPath has an export $($d.Why) at $($d.Dir), but that directory is not there now.")
}
if ($dd.Count) {
    Write-Host 'x64dbg symbol databases exported by Phase 4 (load via File > Import database):'
    foreach ($d in $dd) { Write-Host ("  {0}  ({1:N1} MB)" -f $d.FullName, ($d.Length / 1MB)) }
    # Found by looking in the usual place rather than by being told. Say so -- an assumption that
    # happened to pay off is still an assumption, and the next machine's layout may differ.
    foreach ($a in $assumed) { Write-Host ("  (found by convention, not from the record: $a)") }
}
else {
    # This branch used to say "run setup\35-ghidra-analysis.ps1 first" on the strength of one
    # hard-coded directory being empty -- hours of re-analysis prescribed to people whose export
    # had finished and whose .dd64 files were sitting one drive letter away. All it can honestly
    # report is where it looked. Whether Phase 4 ran is 35's question, and -CheckOnly answers it
    # in seconds without starting anything.
    Write-Host 'No *.dd64 found for x64dbg. Looked in:'
    foreach ($d in $dirs) {
        Write-Host ("  {0}  [{1}]{2}" -f $d.Dir, $d.Why, $(if ($d.Exists) { '' } else { ' -- no such directory' }))
    }
    foreach ($a in $assumed) { Write-Host ("  (assumed: $a)") }
    Write-Host ''
    Write-Host 'Two different situations look like this, and this script cannot tell them apart:'
    Write-Host ' - the export has not happened yet. Ask the script that knows -- it is instant and'
    Write-Host '   starts nothing:'
    Write-Host '     setup\35-ghidra-analysis.ps1 -CheckOnly    (0 = nothing to do, 2 = work pending)'
    Write-Host '   With the analysis already recorded, that run does the EXPORT ALONE -- minutes,'
    Write-Host '   not the hours a rebuild costs.'
    Write-Host " - or they are somewhere this run never looked. It read $BgsRoot;"
    Write-Host '   if your BethesdaGhidraScripts is elsewhere, say so and nothing has to be re-run:'
    Write-Host '     setup\40-x64dbg.ps1 -BgsRoot <clone>   (or -Root <the directory your repos are in>)'
    Write-Host 'Until one of those loads, you are debugging unnamed addresses.'
}

Write-Host ''
Write-Host 'Done. Runtime contract:'
Write-Host " - Launch $InstallDir\x96dbg.exe (picks x32/x64), attach or open a target."
Write-Host ' - The plugin logs: [MCP] x64dbg MCP Server started on 127.0.0.1:27042'
Write-Host ' - Claude reaches it via the "x64dbg" entry in .mcp.json (npx x64dbg-mcp-server, pinned).'
Write-Host ' - Debugging a game under MO2: launch the game through MO2, then ATTACH x64dbg to the process.'
Write-Host ''
Write-Host 'Do NOT run `npx x64dbg-mcp-server --version` to check the install: it ignores the'
Write-Host 'flag, starts the stdio server and waits forever. A good start prints'
Write-Host '  [x64dbg-mcp] Server started (23 tools), plugin expected at 127.0.0.1:27042'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
