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

. "$PSScriptRoot\_common.ps1"

# A tool installed after this shell started is still only in the registry PATH; without
# this the toolchain table reports FAIL for things that are installed and working.
Sync-Path

$rows = [System.Collections.Generic.List[object]]::new()
function Check([string]$area, [string]$name, [bool]$ok, [string]$detail = '') {
    $rows.Add([pscustomobject]@{ Area = $area; Check = $name; OK = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail })
}

# toolchain. No 'mvn': the GhidraMCP extension builds with gradlew.bat (see 30-ghidra.ps1).
foreach ($c in 'git', 'cmake', 'python', 'java', 'node', 'gh') {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    Check 'toolchain' $c ($null -ne $cmd) $(if ($cmd) { $cmd.Source } else { 'not on PATH' })
}
# Ghidra 12 and the GhidraMCP build both need JDK 21+. `java` merely existing is not enough,
# and a too-old JDK fails much later with an unrelated-looking error.
if (Get-Command java -ErrorAction SilentlyContinue) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $javaVer = (& java -version 2>&1 | Out-String)
    $ErrorActionPreference = $prev
    $major = if ($javaVer -match 'version "(\d+)') { [int]$Matches[1] } else { 0 }
    Check 'toolchain' 'java >= 21' ($major -ge 21) "major=$major"
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsVersions = @(if (Test-Path $vswhere) { & $vswhere -products '*' -requires Microsoft.VisualStudio.Workload.NativeDesktop -property installationVersion })
$vsOk = [bool]($vsVersions | Where-Object { [int]($_ -split '\.')[0] -ge 17 })
$vsDetail = $vsVersions -join ', '
if ($vsOk -and -not ($vsVersions | Where-Object { $_ -like '17.*' })) {
    # Not a failure: the default `windows-vcpkg-vr` preset pins no generator, so CMake takes
    # whatever VS is installed, and alandtse/CommonLibF4 builds on both 17.x and 18.x. Only
    # the explicitly pinned vs2022-* presets need a 17.x present.
    $vsDetail += ' (no 17.x: use windows-vcpkg-vr, which is generator-agnostic; the vs2022-* presets need 17.x)'
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
$vcpkgRoot = [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'User')
if (-not $vcpkgRoot) { $vcpkgRoot = [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'Machine') }
if ($vcpkgRoot) { Check 'env' 'vcpkg bootstrapped' (Test-Path (Join-Path $vcpkgRoot 'vcpkg.exe')) }

# repos
foreach ($r in 'CommonLibF4', 'commonlibsf', 'devbench', 'ghidra-mcp', 'modlist-agent') {
    Check 'repos' $r (Test-Path (Join-Path $Root "$r\.git"))
}
# devbench must be on main: the feat/multigame-core branch predates the fix that starts the
# Fallout server at kPostLoad, and without it :8931 never opens (Phase 6 silently fails).
$devbench = Join-Path $Root 'devbench'
if (Test-Path (Join-Path $devbench '.git')) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $branch = (& git -C $devbench rev-parse --abbrev-ref HEAD 2>$null)
    $hasFix = (& git -C $devbench log --oneline -1 --grep 'kPostLoad' 2>$null)
    $ErrorActionPreference = $prev
    Check 'repos' 'devbench has the kPostLoad fix' ([bool]$hasFix) "branch=$branch"
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
    # GUI path only — headless loads the plugin off the classpath and ignores this.
    $ext = @(Get-ChildItem (Join-Path $env:APPDATA 'ghidra') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'Extensions\GhidraMCP') })
    Check 'ghidra' 'extension deployed (GUI)' ($ext.Count -gt 0) (($ext | Select-Object -ExpandProperty Name) -join ', ')
}

# headless MCP — what Phase 4 actually runs. 30-ghidra.ps1 writes both of these.
$mcpManifest = Join-Path $PSScriptRoot '.ghidra-mcp-build.json'
Check 'ghidra' 'headless build manifest' (Test-Path $mcpManifest) $mcpManifest
if (Test-Path $mcpManifest) {
    $mf = Get-Content $mcpManifest -Raw | ConvertFrom-Json
    Check 'ghidra' 'plugin jar' (Test-Path $mf.pluginJar) $mf.pluginJar
    Check 'ghidra' 'headless classpath argfile' (Test-Path $mf.headlessCpFile) $mf.headlessCpFile
}
# Live server is optional (it is started on demand), so report it without failing the run.
try {
    $c = Invoke-WebRequest 'http://127.0.0.1:8089/check_connection' -UseBasicParsing -TimeoutSec 2
    $rows.Add([pscustomobject]@{ Area = 'ghidra'; Check = 'headless server (optional)'; OK = 'PASS'; Detail = $c.Content.Trim() })
}
catch {
    $rows.Add([pscustomobject]@{ Area = 'ghidra'; Check = 'headless server (optional)'; OK = 'idle'; Detail = 'not running - start with setup\36-ghidra-mcp.ps1 -Start' })
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
            cmake --preset windows-vcpkg-vr | Out-Host
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

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
