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
#
# Every row RUNS its tool. Get-Command alone was the whole test here, and Get-Command resolves
# %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe -- the Microsoft Store app-execution-alias
# stub, which ships present and ENABLED on stock Windows 10/11 -- exactly as it resolves a real
# interpreter: same ApplicationInfo, same Source path. Run it and it prints "Python was not
# found..." and exits 9009. So a machine with NO PYTHON got a PASS row from the very table a
# user opens to find out why 30-ghidra.ps1 just died on exit 9009 building the bridge venv:
# the diagnostic layer pointing away from the missing prerequisite. java was the only row that
# ran anything, and that asymmetry was the tell. Test-CmdRuns (in _common.ps1) executes the
# tool and judges its exit code. It lives in the shared library rather than here on purpose:
# the install gate, the -CheckOnly paths and this table have to answer "is python OK?" with
# ONE predicate, because three separately written copies of that contract mean the weakest
# copy silently decides, and the weakest copy was this one.
#
# Probe arguments must be KNOWN-TERMINATING: Test-CmdRuns waits for the process, so anything
# that starts a server instead of printing a version would hang this script forever. java is
# the odd one out -- --version only arrived in JDK 9, while -version works on every JDK,
# including the ancient ones we most want to catch.
$toolProbes = [ordered]@{
    git    = @('--version')
    cmake  = @('--version')
    python = @('--version')
    java   = @('-version')
    node   = @('--version')
    gh     = @('--version')
}
foreach ($c in $toolProbes.Keys) {
    # Detail is the probe's own observation -- resolved path and version when it ran, the
    # failing exit code and the tool's own words when it did not. That is what is wanted in
    # this column: WHICH python was found, not a second opinion on whether one exists.
    $probe = Test-CmdRuns -Name $c -ProbeArgs $toolProbes[$c]
    Check 'toolchain' $c ($probe.Status -eq 'OK') $probe.Detail
}
# Ghidra 12 and the GhidraMCP build both need JDK 21+. `java` merely existing is not enough,
# and a too-old JDK fails much later with an unrelated-looking error.
#
# This row deliberately does not ask PATH. gradlew.bat resolves %JAVA_HOME%\bin\java.exe FIRST
# and consults PATH only when JAVA_HOME is unset -- and when JAVA_HOME is set but wrong it
# aborts outright ("ERROR: JAVA_HOME is set to an invalid directory") rather than falling back.
# Ghidra's own launchers prefer it too. So on a machine carrying Temurin 21 on PATH and a
# forgotten JAVA_HOME=C:\Program Files\Java\jdk1.8.0_301, the extension build died on an
# unrelated-looking Gradle error while this table printed "java >= 21  PASS  major=21" and
# ruled out the actual culprit. Test-JavaForGradle resolves the JVM the build will really use;
# its Detail names which resolution won and the path it landed on, and that string is the whole
# diagnostic, so it goes into the column verbatim.
#
# The `if (Get-Command java)` guard is gone with it: gating a correctness check on PATH
# existence is what hid this case, because a JAVA_HOME-only machine produced no row at all and
# the one JVM gradlew would have used went unreported. The probe never throws and reports "no
# JDK anywhere" as a FAIL row itself, so nothing needs to pre-screen it.
$javaProbe = Test-JavaForGradle -MinMajor 21
Check 'toolchain' 'java >= 21' ($javaProbe.Status -eq 'OK') $javaProbe.Detail

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
# EXECUTE the launcher, do not stat it. A venv resolves its base interpreter through
# pyvenv.cfg, so one orphaned by a Python upgrade (winget moving 3.12 to 3.13 removes the old
# runtime) still has the .exe on disk and dies at launch with "No Python at ...". Test-Path
# here was the second half of that blind spot -- 30-ghidra skipped rebuilding the venv because
# the file existed, and this table then confirmed it, so a broken bridge was green end to end
# and the first real symptom arrived inside the user's MCP client.
$bridge = Test-VenvExeRuns -Path (Join-Path $Root 'ghidra-mcp\.venv\Scripts\bridge-mcp-ghidra.exe')
Check 'ghidra' 'bridge exe runs' ($bridge.Status -eq 'OK') $bridge.Detail
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

# -Wrap, not just -AutoSize: Detail now carries the probes' own diagnostics, and -AutoSize
# alone TRUNCATES the last column to the console width. At a normal 120-column terminal that
# cut landed mid-sentence -- "...alias stub answering, not an installed tool. Install it, or
# turn the alias off under Settings > ..." and "(PATH java is <other JDK>, which gradlew.bat
# does NOT use)" both fell off the right edge, which is precisely the text the rows exist to
# deliver. Wrapping makes the table taller and complete instead of tidy and useless.
$rows | Format-Table -AutoSize -Wrap
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
