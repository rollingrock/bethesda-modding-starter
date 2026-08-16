<#
.SYNOPSIS
    Install (or verify) the base toolchain for Bethesda script-extender plugin dev + RE.

.DESCRIPTION
    Idempotent: checks first, installs only what is missing, prints a summary table.
    Run from an elevated PowerShell if you expect installs (winget machine-scope installs
    and VS need it); -CheckOnly never needs elevation.

    Installs via winget:
      Git, CMake, Visual Studio 2022 Community (+ Desktop C++ workload), Python 3.12,
      Temurin JDK 21 (Ghidra + the GhidraMCP build), Node.js LTS (x64dbg MCP server),
      GitHub CLI.

    Not required, deliberately:
      * Maven — winget has no such package, and 30-ghidra.ps1 uses gradlew.bat instead.
      * PowerShell 7 — every script here is Windows PowerShell 5.1 compatible on purpose,
        because 5.1 is what a fresh Windows box and `shell: powershell` in CI both run.
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly
)

. "$PSScriptRoot\_common.ps1"

# Pick up anything installed since this shell started (see Sync-Path) — otherwise a tool
# winget already installed reads as MISSING and we try to install it a second time.
Sync-Path

$results = [System.Collections.Generic.List[object]]::new()

function Ensure-Winget([string]$display, [string]$id, [scriptblock]$check, [string]$override = '') {
    $present = & $check
    if ($present) {
        $results.Add([pscustomobject]@{ Component = $display; Status = 'present'; Action = '-' })
        return
    }
    if ($CheckOnly) {
        $results.Add([pscustomobject]@{ Component = $display; Status = 'MISSING'; Action = "winget install $id" })
        return
    }
    Write-Host "Installing $display ..."
    $wingetArgs = @('install', '--id', $id, '-e', '--accept-source-agreements', '--accept-package-agreements')
    if ($override) { $wingetArgs += @('--override', $override) }
    & winget @wingetArgs
    $ok = ($LASTEXITCODE -eq 0)
    # winget put the new bin dir in the registry PATH; make it usable in THIS process so
    # the check below (and every later script) sees it without a new terminal.
    Sync-Path
    $visible = & $check
    $status = if ($visible) { 'installed' }
    elseif ($ok) { 'installed (new shell needed)' }
    else { 'FAILED' }
    $results.Add([pscustomobject]@{ Component = $display; Status = $status; Action = "winget $id" })
}

if (-not (Test-Cmd 'winget')) {
    throw 'winget is not available. Install "App Installer" from the Microsoft Store first.'
}

Ensure-Winget 'Git' 'Git.Git' { Test-Cmd 'git' }
Ensure-Winget 'CMake' 'Kitware.CMake' { Test-Cmd 'cmake' }
Ensure-Winget 'Python 3.12' 'Python.Python.3.12' { Test-Cmd 'python' }
Ensure-Winget 'Temurin JDK 21' 'EclipseAdoptium.Temurin.21.JDK' {
    try { (& java -version 2>&1 | Out-String) -match 'version "(21|2[2-9])' } catch { $false }
}
# No Maven. There is no `Apache.Maven` package in winget (`winget search maven` returns
# only unrelated packages), so requiring it made Phase 4 unreachable on a fresh machine.
# 30-ghidra.ps1 builds the GhidraMCP extension with ghidra-mcp's own gradlew.bat, which
# bootstraps Gradle itself and needs nothing but the JDK.
Ensure-Winget 'Node.js LTS' 'OpenJS.NodeJS.LTS' { Test-Cmd 'node' }
Ensure-Winget 'GitHub CLI' 'GitHub.cli' { Test-Cmd 'gh' }

# Visual Studio 2022 with the C++ workload. Detection via vswhere.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$hasVs = (Test-Path $vswhere) -and
    [bool](@(& $vswhere -products '*' -requires Microsoft.VisualStudio.Workload.NativeDesktop -property installationVersion) |
        Where-Object { [int]($_ -split '\.')[0] -ge 17 })
Ensure-Winget 'VS2022 + C++ workload' 'Microsoft.VisualStudio.2022.Community' { $hasVs } `
    '--passive --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended'
if (-not $hasVs -and -not $CheckOnly) {
    Write-Host ''
    Write-Host 'If VS2022 was already installed WITHOUT the C++ workload, winget will not add it.'
    Write-Host 'Open "Visual Studio Installer" -> Modify -> check "Desktop development with C++".'
}

Write-Host ''
$results | Format-Table -AutoSize
if ($results | Where-Object Status -in 'MISSING', 'FAILED') {
    Write-Host 'Some components are missing/failed. Re-run this script (installs are idempotent).'
    exit 1
}
if ($results | Where-Object Status -like '*new shell*') {
    Write-Host 'Installed, but not visible in this process. Start a new terminal, then re-run to confirm.'
    exit 1
}
Write-Host 'All prerequisites present.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
