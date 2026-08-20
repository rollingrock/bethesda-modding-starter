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
# The setup scripts dot-source this as "$PSScriptRoot\_common.ps1"; from the pack root it is one
# directory down. It is pulled in for New-McpConfigObject -- the single definition of what goes
# in a .mcp.json -- and dot-sourcing has to happen at the top level, because the pin the
# generator reads lives in _common.ps1's script scope. Nothing in that file touches the machine
# at load time (see its header), so this is safe to do before the -Mo2Path checks below.
. "$PSScriptRoot\setup\_common.ps1"

$packRoot = $PSScriptRoot
$target = Join-Path $Dir $Name
# Pinned to an absolute path HERE, once, before anything Push-Locations into it. Everything
# else in this script resolves a relative $target through the PowerShell provider (Copy-Item,
# Get-ChildItem, git clone), but Write-ScaffoldMcpConfig writes through [IO.File], which is
# .NET and resolves against the PROCESS working directory -- a thing Push-Location and even
# Set-Location never change. In an interactive session that has cd'd anywhere, the two differ,
# so a relative -Dir would put the repo in one place and its .mcp.json in another (or throw
# mid-scaffold if that other place has no such folder), and `git add -A` would then commit the
# scaffold with no .mcp.json at all and still print Done. Resolving it once keeps every
# consumer below on the same directory. Get-Location is the right base precisely because it is
# what the provider-based calls would have used; when -Dir is already absolute (its default,
# and every documented invocation) this is a no-op.
if (-not [IO.Path]::IsPathRooted($target)) { $target = Join-Path (Get-Location).ProviderPath $target }

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

# .mcp.json is the only file this scaffolder writes that points at something OUTSIDE the new
# repo, and it used to be a verbatim Copy-Item of mcp\mcp.template.json -- whose ghidra command
# is the literal C:/repos/ghidra-mcp/.venv/Scripts/bridge-mcp-ghidra.exe. Every setup script in
# this pack is parameterised (-Root, -GhidraMcpDir), so on a machine set up under D:\dev that
# path does not exist: the scaffold committed a ghidra server that can never spawn and then
# printed nothing but "Done", and the first symptom was an agent session in the new repo with no
# Ghidra tools in it -- while 90-verify, which honours -Root, kept reporting the bridge as PASS
# (ids 39, 77). New-McpConfigObject in setup\_common.ps1 is now the one definition of this file's
# contents: it reads the bridge path 30-ghidra.ps1 recorded in setup\.ghidra-mcp-build.json,
# which is the only thing on the machine that knows a non-default -GhidraMcpDir, and it warns
# when it had to fall back to the conventional path. Both scaffold branches call THIS function
# rather than repeating the write, because they are the same three lines twice and the Starfield
# one is the branch that gets forgotten.
function Write-ScaffoldMcpConfig {
    param([Parameter(Mandatory)][string]$RepoRoot)

    # -WarningVariable rather than a second look at the manifest: the generator has already
    # decided whether the path is known or guessed, and re-deriving that here would be a second
    # opinion free to drift from the first. This does not silence anything -- the generator's
    # warning still prints -- it only lets the scaffold add the two things the generator cannot
    # know: which directory to re-run the resolver against, and that this file is about to be
    # committed in that state.
    $mcpWarnings = @()
    $cfg = New-McpConfigObject -WarningVariable mcpWarnings

    # Absolute path on purpose. The callers below run inside Push-Location $target, but [IO.File]
    # is .NET and resolves a relative path against the PROCESS working directory, which
    # Push-Location does not change -- a bare '.mcp.json' would be written wherever the shell
    # happened to be started, leaving the scaffold without one and silently clobbering whatever
    # sat there.
    $configPath = Join-Path $RepoRoot '.mcp.json'
    # Explicit no-BOM UTF-8 via WriteAllText, the pattern 30-ghidra.ps1 uses for the files it
    # generates, and it earns its keep twice over. Set-Content's default encoding is the ANSI
    # codepage, which mangles every non-ASCII byte in a path (corruption reproduced in this repo
    # under cp932), and that path is a Windows install location that may well contain one. A
    # UTF-8 BOM in front of the opening brace is the other half: JSON parsers are entitled to
    # reject it, and an MCP client that does simply reports no servers.
    [IO.File]::WriteAllText($configPath, (($cfg | ConvertTo-Json -Depth 6) + "`r`n"), [Text.UTF8Encoding]::new($false))

    if ($mcpWarnings.Count -gt 0) {
        # Said out loud, and NOT folded into the exit code: the repo the caller asked for exists,
        # is committed and builds, so exit 0 is still the truth about the scaffold. What is
        # unresolved is a path to a tool on THIS machine, which 30-ghidra.ps1 can supply
        # afterwards without the scaffold being redone. The failure being closed here was silence,
        # not a wrong status -- so the repair is printed with the real directory already in it.
        Write-Host ''
        Write-Host "NOTE: $configPath carries a GUESSED ghidra bridge path (see the warning above),"
        Write-Host 'and the scaffold commit below includes it in that state. New-Plugin.ps1 cannot resolve'
        Write-Host 'it alone -- it has no -Root/-GhidraMcpDir, and setup\.ghidra-mcp-build.json, the only'
        Write-Host 'record of where the bridge really is, is written by 30-ghidra.ps1. Repair it with:'
        Write-Host "  $(Join-Path $packRoot 'setup\30-ghidra.ps1')                    (if it has never run here)"
        Write-Host "  $(Join-Path $packRoot 'setup\36-ghidra-mcp.ps1') -WriteMcpConfigTo `"$RepoRoot`""
        Write-Host 'The x64dbg entry is correct either way -- it is a pinned npx package, not a path.'
    }
    else {
        Write-Host "Wrote $configPath (ghidra bridge path taken from setup\.ghidra-mcp-build.json)."
    }
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
        # Generated, never copied from mcp\mcp.template.json -- that template's ghidra command is
        # hard-coded to the default install root (see Write-ScaffoldMcpConfig above).
        Write-ScaffoldMcpConfig -RepoRoot $target

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
        # Same generated config as the F4VR branch above, for the same reason -- the Starfield
        # scaffold committed the identical dead ghidra path, one branch further down where nobody
        # was looking.
        Write-ScaffoldMcpConfig -RepoRoot $target
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
