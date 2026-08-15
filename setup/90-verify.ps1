<#
.SYNOPSIS
    Verify the whole environment; optionally prove it by building a scaffolded plugin.

.DESCRIPTION
    Read-only checks by default (fast). -BuildTest scaffolds a throwaway F4VR plugin into
    %TEMP% via New-Plugin.ps1 and builds it end-to-end — the single strongest signal that
    the machine is actually ready (VS, CMake, vcpkg restore, CommonLibF4 submodule, C++23).
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\repos',
    [string]$ToolsDir = 'C:\tools',
    [switch]$BuildTest
)

$rows = [System.Collections.Generic.List[object]]::new()
function Check([string]$area, [string]$name, [bool]$ok, [string]$detail = '') {
    $rows.Add([pscustomobject]@{ Area = $area; Check = $name; OK = ($ok ? 'PASS' : 'FAIL'); Detail = $detail })
}

# toolchain
foreach ($c in 'git', 'cmake', 'python', 'java', 'mvn', 'node', 'gh') {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    Check 'toolchain' $c ($null -ne $cmd) ($cmd ? $cmd.Source : 'not on PATH')
}
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsVersions = @((Test-Path $vswhere) ? (& $vswhere -products '*' -requires Microsoft.VisualStudio.Workload.NativeDesktop -property installationVersion) : @())
$vsOk = [bool]($vsVersions | Where-Object { [int]($_ -split '\.')[0] -ge 17 })
$vsDetail = $vsVersions -join ', '
if ($vsOk -and -not ($vsVersions | Where-Object { $_ -like '17.*' })) {
    $vsDetail += ' (no 17.x: templates use the "Visual Studio 17 2022" generator — adjust the preset generator)'
}
Check 'toolchain' 'VS C++ workload (17+)' $vsOk $vsDetail

# env vars — persisted at User or Machine scope (what NEW terminals will see)
function Get-PersistedEnv([string]$name) {
    $u = [Environment]::GetEnvironmentVariable($name, 'User')
    if ($u) { return "$u (User)" }
    $m = [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ($m) { return "$m (Machine)" }
    return $null
}
foreach ($v in 'VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT', 'GHIDRA_MCP_ALLOW_SCRIPTS') {
    $val = Get-PersistedEnv $v
    Check 'env' $v ([bool]$val) "$val"
}
$vcpkgRoot = [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'User') ??
    [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'Machine')
if ($vcpkgRoot) { Check 'env' 'vcpkg bootstrapped' (Test-Path (Join-Path $vcpkgRoot 'vcpkg.exe')) }

# repos
foreach ($r in 'CommonLibF4', 'commonlibsf', 'devbench', 'ghidra-mcp') {
    Check 'repos' $r (Test-Path (Join-Path $Root "$r\.git"))
}
Check 'repos' 'vr_address_tools (optional)' (Test-Path (Join-Path $Root 'vr_address_tools\.git'))

# ghidra (a machine may carry several installs; any one with the extension counts).
# BethesdaGhidraScripts manages its own install under <Root>\BethesdaGhidraScripts\tools\ghidra.
$ghidras = @(Get-ChildItem $ToolsDir -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue)
$bgsGhidra = Join-Path $Root 'BethesdaGhidraScripts\tools\ghidra'
if (Test-Path (Join-Path $bgsGhidra 'Ghidra\application.properties')) { $ghidras += Get-Item $bgsGhidra }
Check 'ghidra' 'install' ($ghidras.Count -gt 0) (($ghidras | Select-Object -ExpandProperty FullName) -join ', ')
Check 'ghidra' 'bridge exe' (Test-Path (Join-Path $Root 'ghidra-mcp\.venv\Scripts\bridge-mcp-ghidra.exe'))
if ($ghidras.Count) {
    $ext = @(Get-ChildItem (Join-Path $env:APPDATA 'ghidra') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'Extensions\GhidraMCP') })
    Check 'ghidra' 'extension deployed' ($ext.Count -gt 0) (($ext | Select-Object -ExpandProperty Name) -join ', ')
}

# x64dbg
Check 'x64dbg' 'install' (Test-Path (Join-Path $ToolsDir 'x64dbg\x96dbg.exe'))
Check 'x64dbg' 'MCP plugin x64' ([bool](Get-ChildItem (Join-Path $ToolsDir 'x64dbg\x64\plugins') -Filter '*.dp64' -ErrorAction SilentlyContinue))

# end-to-end build test
if ($BuildTest) {
    $name = "smoketest$(Get-Random -Maximum 9999)"
    $tmp = Join-Path $env:TEMP 'starter-verify'
    New-Item -ItemType Directory -Force $tmp | Out-Null
    Write-Host "Scaffolding + building $name (this takes a few minutes on first vcpkg restore) ..."
    try {
        & (Join-Path $PSScriptRoot '..\New-Plugin.ps1') -Name $name -Game F4VR -Dir $tmp
        Push-Location (Join-Path $tmp $name)
        try {
            cmake --preset vs2022-windows-vcpkg-vr | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'configure failed' }
            cmake --build buildvr --config Release | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'build failed' }
            $dll = Test-Path "buildvr\Release\$(($name -replace '-','_').ToLower()).dll"
            Check 'e2e' 'scaffold+build DLL' $dll
        }
        finally { Pop-Location }
    }
    catch {
        Check 'e2e' 'scaffold+build DLL' $false "$_"
    }
}

$rows | Format-Table -AutoSize
$failed = @($rows | Where-Object OK -eq 'FAIL')
if ($failed.Count) {
    Write-Host "$($failed.Count) check(s) failed. Optional items (vr_address_tools) may be intentional skips."
    exit 1
}
Write-Host 'Environment verified.'
