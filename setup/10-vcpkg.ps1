<#
.SYNOPSIS
    Clone + bootstrap vcpkg and set the environment variables the build chain reads.

.DESCRIPTION
    THE TRAP THIS SCRIPT EXISTS FOR: the plugin templates read TWO different names for
    the same thing — CMakeLists.txt reads VCPKG_ROOT, CMakePresets.json reads
    VCPKG_INSTALLATION_ROOT. Both must be set or configure fails confusingly.
    Idempotent; safe to re-run.
#>
[CmdletBinding()]
param(
    [string]$VcpkgDir = 'C:\repos\vcpkg',
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'

$ok = $true
if (-not (Test-Path (Join-Path $VcpkgDir '.git'))) {
    if ($CheckOnly) { Write-Host "MISSING: vcpkg clone at $VcpkgDir"; $ok = $false }
    else {
        git clone https://github.com/microsoft/vcpkg.git $VcpkgDir
    }
}
if ((Test-Path $VcpkgDir) -and -not (Test-Path (Join-Path $VcpkgDir 'vcpkg.exe'))) {
    if ($CheckOnly) { Write-Host 'MISSING: vcpkg.exe (bootstrap not run)'; $ok = $false }
    else { & (Join-Path $VcpkgDir 'bootstrap-vcpkg.bat') -disableMetrics }
}

foreach ($name in 'VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT') {
    # Accept an existing value at either persisted scope (some machines set these Machine-wide).
    $current = [Environment]::GetEnvironmentVariable($name, 'User') ??
        [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ($current -ne $VcpkgDir) {
        if ($CheckOnly) { Write-Host "MISSING/WRONG: user env $name (is: '$current', want: '$VcpkgDir')"; $ok = $false }
        else {
            [Environment]::SetEnvironmentVariable($name, $VcpkgDir, 'User')
            Set-Item "env:$name" $VcpkgDir
            Write-Host "Set user env $name = $VcpkgDir"
        }
    }
    else { Write-Host "OK: $name = $current" }
}

# Manifest-mode projects pick their own triplet; this is just a sane default.
$trip = [Environment]::GetEnvironmentVariable('VCPKG_DEFAULT_TRIPLET', 'User')
if (-not $trip) {
    if (-not $CheckOnly) {
        [Environment]::SetEnvironmentVariable('VCPKG_DEFAULT_TRIPLET', 'x64-windows', 'User')
        Write-Host 'Set user env VCPKG_DEFAULT_TRIPLET = x64-windows'
    }
}

if ($CheckOnly -and -not $ok) { exit 1 }
Write-Host 'vcpkg ready. NOTE: env vars set at User scope — new terminals see them; this one was updated in-place.'
