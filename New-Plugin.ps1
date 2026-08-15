<#
.SYNOPSIS
    Scaffold a new script-extender plugin repo from the starter pack's templates.

.DESCRIPTION
    Creates a fresh git repo for a new plugin, wired to the same build chain used by
    rollingrock's mods (CMake + vcpkg + CommonLib submodule).

    Games:
      F4VR / F4  -> vendored templates/f4sevr-plugin (CommonLibF4 is NG-style: the same
                    template builds for flat and VR; the preset defines FALLOUTVR)
      SF         -> clones rollingrock/sfse-template (raw SFSE hello-world, CMake)
      SkyrimNG   -> not scaffolded here; prints pointers (most Skyrim devs already have a
                    CommonLibSSE-NG flow; see docs/GAME_MATRIX.md)

.EXAMPLE
    .\New-Plugin.ps1 -Name my-cool-mod -Game F4VR -Mo2Path "C:\MO2\Fallout4VR\mods\my-cool-mod"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z][a-zA-Z0-9_-]*$')]
    [string]$Name,

    [ValidateSet('F4VR', 'F4', 'SF', 'SkyrimNG')]
    [string]$Game = 'F4VR',

    # Parent directory the new repo is created in.
    [string]$Dir = 'C:\repos',

    # Optional: MO2 mod folder; wires up auto-deploy via CMakeUserPresets.json.
    [string]$Mo2Path = ''
)

$ErrorActionPreference = 'Stop'
$packRoot = $PSScriptRoot
$target = Join-Path $Dir $Name

if (Test-Path $target) { throw "Target already exists: $target" }
if ($Game -eq 'SkyrimNG') {
    Write-Host 'Skyrim scaffolding is intentionally not duplicated here.'
    Write-Host 'Use your existing CommonLibSSE-NG template, or start from:'
    Write-Host '  https://github.com/epinter/skse-clibng-template'
    Write-Host 'See docs/GAME_MATRIX.md for the per-game stack (address libraries, registries).'
    return
}

# The identifier used inside source/config files. Keep it C-identifier-ish so it works
# as a project name, log name and TOML group. vcpkg manifest names are the one exception:
# they forbid underscores, so the manifest gets a hyphenated variant.
$token = ($Name -replace '-', '_').ToLowerInvariant()
$vcpkgName = ($Name -replace '_', '-').ToLowerInvariant()

if ($Game -in 'F4VR', 'F4') {
    Write-Host "Scaffolding $Name from templates/f4sevr-plugin ..."
    Copy-Item -Recurse (Join-Path $packRoot 'templates\f4sevr-plugin') $target
    # Never carry a test build over into a new project.
    Get-ChildItem $target -Directory -Filter 'build*' | Remove-Item -Recurse -Force

    # Rename the placeholder project. File contents first...
    $files = Get-ChildItem $target -Recurse -File | Where-Object { $_.Extension -in '.txt', '.json', '.cmake', '.cpp', '.h', '.in', '.md', '.toml', '.template' }
    foreach ($f in $files) {
        $c = Get-Content $f.FullName -Raw
        if ($c -match 'starterplugin') {
            Set-Content $f.FullName ($c -replace 'starterplugin', $token) -NoNewline
        }
    }
    # ...then the config file that carries the name.
    Rename-Item (Join-Path $target 'Data\F4SE\Plugins\starterplugin.toml') "$token.toml"

    # vcpkg manifest names must be lowercase-hyphenated (no underscores).
    $vcpkgManifest = Join-Path $target 'vcpkg.json'
    (Get-Content $vcpkgManifest -Raw) -replace "`"name`": `"$token`"", "`"name`": `"$vcpkgName`"" |
        Set-Content $vcpkgManifest -NoNewline

    Push-Location $target
    try {
        git init --initial-branch=main | Out-Null
        git submodule add https://github.com/rollingrock/CommonLibF4.git external/CommonLibF4
        git submodule update --init --recursive

        if ($Mo2Path) {
            $mo2 = ($Mo2Path -replace '\\', '/').TrimEnd('/')
            if ($mo2 -notmatch '/F4SE/Plugins$') { $mo2 = "$mo2/F4SE/Plugins" }
            $userPresets = [ordered]@{
                version          = 3
                configurePresets = @(
                    [ordered]@{
                        name           = 'vr-mo2'
                        inherits       = 'vs2022-windows-vcpkg-vr'
                        cacheVariables = [ordered]@{ MO2_INSTALL_PATH = $mo2 }
                    }
                )
            }
            $userPresets | ConvertTo-Json -Depth 5 | Set-Content 'CMakeUserPresets.json'
            Write-Host "MO2 auto-deploy preset written (deploys to $mo2)."
        }

        # Per-project MCP config so Claude Code sessions in the new repo get Ghidra + x64dbg.
        Copy-Item (Join-Path $packRoot 'mcp\mcp.template.json') '.mcp.json'

        git add -A
        git commit -m "chore: scaffold $Name from bethesda-modding-starter" | Out-Null
    }
    finally { Pop-Location }

    $preset = if ($Mo2Path) { 'vr-mo2' } else { 'vs2022-windows-vcpkg-vr' }
    Write-Host ''
    Write-Host "Done: $target"
    Write-Host 'Build it:'
    Write-Host "  cd $target"
    Write-Host "  cmake --preset $preset"
    Write-Host '  cmake --build buildvr --config Release'
    if ($Game -eq 'F4') {
        Write-Host ''
        Write-Host 'NOTE (flat F4): the vs2022 preset defines FALLOUTVR. For a flat-runtime build,'
        Write-Host 'configure without the vr preset inheritance or ask your agent to add a flat preset;'
        Write-Host 'rollingrock/CommonLibF4 itself builds both (NG-style).'
    }
}
elseif ($Game -eq 'SF') {
    Write-Host "Scaffolding $Name from rollingrock/sfse-template ..."
    git clone --depth 1 https://github.com/rollingrock/sfse-template.git $target
    Remove-Item -Recurse -Force (Join-Path $target '.git')

    $files = Get-ChildItem $target -Recurse -File | Where-Object { $_.Extension -in '.txt', '.json', '.cpp', '.h', '.md', '.cmake' }
    foreach ($f in $files) {
        $c = Get-Content $f.FullName -Raw
        if ($c -match 'sfse-template-plugin') {
            $replacement = if ($f.Name -eq 'vcpkg.json') { $vcpkgName } else { $Name }
            Set-Content $f.FullName ($c -replace 'sfse-template-plugin', $replacement) -NoNewline
        }
    }

    Push-Location $target
    try {
        git init --initial-branch=main | Out-Null
        Copy-Item (Join-Path $packRoot 'mcp\mcp.template.json') '.mcp.json'
        git add -A
        git commit -m "chore: scaffold $Name from sfse-template" | Out-Null
    }
    finally { Pop-Location }

    Write-Host ''
    Write-Host "Done: $target — see its README for build presets."
    Write-Host 'NOTE: the template''s `default` preset uses the VS2026 generator. On a VS2022-only'
    Write-Host 'machine use:  cmake --preset default -G "Visual Studio 17 2022"   (or the ninja preset).'
}
