<#
.SYNOPSIS
    Install (or verify) the base toolchain for Bethesda script-extender plugin dev + RE.

.DESCRIPTION
    Idempotent: checks first, installs only what is missing, prints a summary table.
    Run from an elevated PowerShell if you expect installs (winget machine-scope installs
    and VS need it); -CheckOnly never needs elevation.

    Installs via winget:
      Git, CMake, Visual Studio 2022 Community (+ Desktop C++ workload), Python 3.12,
      Temurin JDK 21 (Ghidra), Apache Maven (builds the GhidraMCP extension),
      Node.js LTS (x64dbg MCP server), PowerShell 7, GitHub CLI.
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly
)

$results = [System.Collections.Generic.List[object]]::new()

function Test-Cmd([string]$name) {
    try { $null = Get-Command $name -ErrorAction Stop; $true } catch { $false }
}

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
    $results.Add([pscustomobject]@{ Component = $display; Status = ($ok ? 'installed' : 'FAILED'); Action = "winget $id" })
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
Ensure-Winget 'Apache Maven' 'Apache.Maven' { Test-Cmd 'mvn' }
Ensure-Winget 'Node.js LTS' 'OpenJS.NodeJS.LTS' { Test-Cmd 'node' }
Ensure-Winget 'PowerShell 7' 'Microsoft.PowerShell' { Test-Cmd 'pwsh' }
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
    Write-Host 'Some components are missing/failed. New installs may need a NEW terminal (PATH refresh).'
    exit 1
}
Write-Host 'All prerequisites present.'
