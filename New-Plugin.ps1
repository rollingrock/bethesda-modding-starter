<#
.SYNOPSIS
    Scaffold a new script-extender plugin repo from the starter pack's templates.

.DESCRIPTION
    Creates a fresh git repo for a new plugin, wired to the same build chain used by
    rollingrock's mods (CMake + vcpkg + CommonLib submodule).

    Games:
      F4VR / F4  -> vendored templates/f4sevr-plugin. alandtse/CommonLibF4 dispatches at
                    runtime, so ONE DLL serves flat F4, Next-Gen and VR. windows-vcpkg-vr
                    deploys to the VR install and builds into buildvr/; windows-vcpkg targets
                    the flat install and builds into build/. Both take whatever Visual Studio
                    is present; vs2019/vs2022/vs2026 variants exist if you need to pin one.
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

# git writes progress AND benign warnings ("LF will be replaced by CRLF") to stderr. Under
# Windows PowerShell 5.1 a native command's stderr becomes an ErrorRecord whenever the caller
# merges streams (2>&1 — which some agent harnesses and CI wrappers do by default), and with
# $ErrorActionPreference='Stop' that aborts the scaffold half-built. The exit code is the only
# trustworthy signal, so check it explicitly.
function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments)][string[]]$GitArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & git @GitArgs }
    finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs -join ' ') failed (exit $LASTEXITCODE)" }
}

# A freshly installed git has no user.name/user.email, and `git commit` then hard-fails with
# "Author identity unknown" -- aborting the scaffold on exactly the clean machine this pack
# targets, and only after the expensive CommonLib submodule clone has already run. Supply a
# fallback identity for this one commit; a configured identity always wins.
function Get-CommitIdentityArgs {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $name = & git config --get user.name
        $haveName = ($LASTEXITCODE -eq 0) -and $name
        $email = & git config --get user.email
        $haveEmail = ($LASTEXITCODE -eq 0) -and $email
    }
    finally { $ErrorActionPreference = $prev }

    if ($haveName -and $haveEmail) { return @() }
    Write-Host 'git has no user.name/user.email set; using a scaffold identity for the initial commit.'
    Write-Host '  set yours with: git config --global user.email "you@example.com"'
    return @('-c', 'user.name=bethesda-modding-starter', '-c', 'user.email=scaffold@localhost')
}

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
    # -Mo2Path used to be written into the preset sight unseen -- no Test-Path anywhere, and the
    # preset writer below appends /F4SE/Plugins to whatever it was handed. Hand it the mods ROOT
    # (a fair reading of "MO2 mod folder") and you get <mods>/F4SE/Plugins: a mod literally named
    # F4SE, laid out wrong (F4SE loads <mod>/F4SE/Plugins/x.dll, that produces <mod>/Plugins/x.dll),
    # so the plugin never loads however carefully you enable it in MO2. A typo'd path was accepted
    # just as happily. Both were then reported as success. Check it here, before the scaffold copies
    # a single file and long before the multi-minute CommonLibF4 submodule clone, so a wrong path
    # costs seconds instead of a whole run.
    if ($Mo2Path) {
        # A full .../F4SE/Plugins path is a legitimate thing to pass (the preset writer below
        # tolerates it too), so strip that leaf off first to get at the mod folder itself.
        $mo2ModDir = $Mo2Path.TrimEnd('\', '/') -replace '[\\/]F4SE[\\/]Plugins$', ''
        # Split-Path hard-errors on a bare drive spec ("C:", what -Mo2Path "C:\" trims down to)
        # instead of returning an empty parent, so only hand it a path that has a separator to
        # split on. Anything without one is a bare segment and has no parent either way.
        $mo2Root = ''
        if ($mo2ModDir -match '[\\/]') { $mo2Root = Split-Path $mo2ModDir -Parent }
        if (-not $mo2Root) {
            throw "-Mo2Path must be the full path to the mod folder, like C:\MO2\Fallout4VR\mods\$Name (got: $Mo2Path)."
        }
        if ((Split-Path $mo2ModDir -Leaf) -eq 'mods') {
            throw @"
-Mo2Path points at the MO2 mods ROOT ($Mo2Path). Pass the mod's own folder instead:
  -Mo2Path "$mo2ModDir\$Name"
MO2 shows every subfolder of mods as a separate mod, so deploying into the root would make one
called "F4SE" whose internal layout F4SE cannot load.
"@
        }
        # The mod folder itself not existing yet is normal -- this scaffolds a NEW mod, and the
        # build creates that folder on its first deploy. Its parent, the mods root, is MO2's own
        # and must already be there; if it is not, the path is pointing somewhere MO2 is not.
        if (-not (Test-Path -LiteralPath $mo2Root -PathType Container)) {
            throw @"
-Mo2Path is $Mo2Path, but its parent $mo2Root is not an existing folder -- MO2 would never list
the mod, and every build would deploy the DLL into a tree nothing reads. Point -Mo2Path at
<mo2>\mods\<yourmod>; MO2 > Settings > Paths shows the mods folder it really uses (an
instance-mode MO2 keeps it under %LOCALAPPDATA%\ModOrganizer\<game>\mods).
"@
        }
    }

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
        Invoke-Git init --initial-branch=main | Out-Null
        Invoke-Git submodule add https://github.com/alandtse/CommonLibF4.git external/CommonLibF4
        Invoke-Git submodule update --init --recursive

        if ($Mo2Path) {
            $mo2 = ($Mo2Path -replace '\\', '/').TrimEnd('/')
            if ($mo2 -notmatch '/F4SE/Plugins$') { $mo2 = "$mo2/F4SE/Plugins" }
            $userPresets = [ordered]@{
                version          = 3
                configurePresets = @(
                    [ordered]@{
                        name           = 'vr-mo2'
                        inherits       = 'windows-vcpkg-vr'
                        cacheVariables = [ordered]@{ MO2_INSTALL_PATH = $mo2 }
                    }
                )
            }
            $userPresets | ConvertTo-Json -Depth 5 | Set-Content 'CMakeUserPresets.json'
            Write-Host "MO2 auto-deploy preset written (deploys to $mo2)."
        }

        # Per-project MCP config so Claude Code sessions in the new repo get Ghidra + x64dbg.
        Copy-Item (Join-Path $packRoot 'mcp\mcp.template.json') '.mcp.json'

        Invoke-Git add -A
        $ident = Get-CommitIdentityArgs
        Invoke-Git @ident commit -m "chore: scaffold $Name from bethesda-modding-starter" | Out-Null
    }
    finally { Pop-Location }

    $preset = if ($Mo2Path) { 'vr-mo2' } else { 'windows-vcpkg-vr' }
    Write-Host ''
    Write-Host "Done: $target"
    Write-Host 'Build it:'
    Write-Host "  cd $target"
    Write-Host "  cmake --preset $preset"
    Write-Host '  cmake --build buildvr --config Release'
    if ($Game -eq 'F4') {
        Write-Host ''
        Write-Host 'NOTE (flat F4): use the flat preset instead of the VR one above:'
        Write-Host '  cmake --preset windows-vcpkg'
        Write-Host '  cmake --build build --config Release'
        Write-Host 'That sets BUILD_FALLOUTVR=OFF, so it deploys to the flat install and builds into'
        Write-Host 'build/ rather than buildvr/. The DLL itself is identical either way -- CommonLibF4'
        Write-Host 'picks the runtime at load time, so one build already works on F4, NG and VR.'
    }
}
elseif ($Game -eq 'SF') {
    Write-Host "Scaffolding $Name from rollingrock/sfse-template ..."
    Invoke-Git clone --depth 1 https://github.com/rollingrock/sfse-template.git $target
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
        Invoke-Git init --initial-branch=main | Out-Null
        Copy-Item (Join-Path $packRoot 'mcp\mcp.template.json') '.mcp.json'
        Invoke-Git add -A
        $ident = Get-CommitIdentityArgs
        Invoke-Git @ident commit -m "chore: scaffold $Name from sfse-template" | Out-Null
    }
    finally { Pop-Location }

    Write-Host ''
    Write-Host "Done: $target — see its README for build presets."
    Write-Host 'NOTE: the template''s `default` preset uses the VS2026 generator. On a VS2022-only'
    Write-Host 'machine use:  cmake --preset default -G "Visual Studio 17 2022"   (or the ninja preset).'
}

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
