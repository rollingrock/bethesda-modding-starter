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
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\tools\x64dbg',
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
$symRoot = 'C:\repos\BethesdaGhidraScripts\symbols'
$dd = @(Get-ChildItem $symRoot -Recurse -Filter '*.dd64' -ErrorAction SilentlyContinue)
Write-Host ''
if ($dd.Count) {
    Write-Host 'x64dbg symbol databases exported by Phase 4 (load via File > Import database):'
    foreach ($d in $dd) { Write-Host ("  {0}  ({1:N1} MB)" -f $d.FullName, ($d.Length / 1MB)) }
}
else {
    Write-Host "No *.dd64 under $symRoot yet - run setup\35-ghidra-analysis.ps1 first, or you"
    Write-Host 'will be debugging unnamed addresses.'
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
