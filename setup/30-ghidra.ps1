<#
.SYNOPSIS
    Build + deploy the GhidraMCP extension and the MCP bridge (bethington/ghidra-mcp).

.DESCRIPTION
    Builds with ghidra-mcp's Gradle build, NOT Maven. That is the upstream-canonical
    backend ("Replaces Maven as the primary Java/plugin build backend" -- build.gradle),
    and it removes two hard blockers:

      * Maven is not installable. There is no `Apache.Maven` package in winget (search
        "maven" returns only unrelated packages), so a fresh Windows machine could never
        satisfy the old Maven prereq. gradlew.bat bootstraps Gradle itself -- nothing to
        install beyond the JDK.
      * The Maven path needed `mvn install:install-file` for 18 Ghidra jars before it
        could compile. Gradle consumes them straight out of the install via fileTree.

    THE VERSION GATE: the extension only loads in the exact Ghidra version it was built
    for (extension.properties `version` must equal the install's application.version).
    Gradle's processResources stamps that from GHIDRA_INSTALL_DIR, so passing the right
    install is the whole configuration -- and this script re-reads the built zip to prove
    the stamp matches before deploying.

    Which Ghidra? In order:
      1. -GhidraPath, if given.
      2. BethesdaGhidraScripts' managed install (<Root>\BethesdaGhidraScripts\tools\ghidra)
         -- preferred, so ONE Ghidra serves both the enrichment pipeline and MCP, and so
         MCP can open the project that pipeline produced.
      3. An existing <ToolsDir>\ghidra_* install (newest wins).

    Also (all idempotent):
      * creates ghidra-mcp's .venv -> bridge-mcp-ghidra.exe
      * writes setup/.ghidra-headless-cp.txt, a java @argfile holding the ~194-jar
        classpath the headless server needs (see 36-ghidra-mcp.ps1)
      * records what it built in setup/.ghidra-mcp-build.json

    Does NOT start Ghidra and does NOT require the GUI. See 36-ghidra-mcp.ps1.
#>
[CmdletBinding()]
param(
    [string]$GhidraMcpDir = 'C:\repos\ghidra-mcp',
    [string]$ToolsDir = 'C:\tools',
    [string]$Root = 'C:\repos',
    # Explicit Ghidra install to build the extension for (overrides auto-detection).
    [string]$GhidraPath = '',
    # Skip the GUI-only deploy (extension zip + user profile + FrontEndTool.xml patch).
    # Headless does not read any of it -- it loads the plugin classes off the classpath.
    [switch]$HeadlessOnly
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"
Sync-Path

if (-not (Test-Path (Join-Path $GhidraMcpDir 'gradlew.bat'))) {
    throw "ghidra-mcp not found at $GhidraMcpDir - run setup/20-repos.ps1 first."
}
if (-not (Test-Cmd 'java')) {
    throw 'java is not on PATH. Run setup/00-prereqs.ps1 (Temurin JDK 21).'
}

function Get-GhidraProps([string]$installDir) {
    $propFile = Join-Path $installDir 'Ghidra\application.properties'
    if (-not (Test-Path $propFile)) { return $null }
    $props = @{}
    Get-Content $propFile | ForEach-Object { if ($_ -match '^([^=#]+)=(.*)$') { $props[$Matches[1].Trim()] = $Matches[2].Trim() } }
    $props
}

# ---------------------------------------------------------------- pick the install
$ghidraHome = $null
if ($GhidraPath) {
    if (-not (Get-GhidraProps $GhidraPath)) { throw "-GhidraPath $GhidraPath is not a Ghidra install (no Ghidra\application.properties)" }
    $ghidraHome = Get-Item $GhidraPath
}
if (-not $ghidraHome) {
    $bgs = Join-Path $Root 'BethesdaGhidraScripts\tools\ghidra'
    if (Get-GhidraProps $bgs) {
        $ghidraHome = Get-Item $bgs
        Write-Host 'Using BethesdaGhidraScripts'' managed Ghidra (one Ghidra for pipeline + MCP).'
    }
}
if (-not $ghidraHome) {
    $ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue |
        Where-Object { Get-GhidraProps $_.FullName } | Sort-Object Name -Descending | Select-Object -First 1
}
if (-not $ghidraHome) {
    throw @"
No Ghidra install found. Install one first -- the enrichment pipeline and MCP should share it:
  cd $(Join-Path $Root 'BethesdaGhidraScripts'); python run.py setup
(or pass -GhidraPath <dir> to build against an install you already have).
"@
}

$props = Get-GhidraProps $ghidraHome.FullName
$ver = $props['application.version']
$profileName = "ghidra_$($ver)_$($props['application.release.name'])"
Write-Host "Ghidra install: $($ghidraHome.FullName)  (version $ver, profile $profileName)"

# ---------------------------------------------------------------- build the extension
$gradlew = Join-Path $GhidraMcpDir 'gradlew.bat'
$gradleArgs = @('--no-daemon', "-PGHIDRA_INSTALL_DIR=$($ghidraHome.FullName)")

Push-Location $GhidraMcpDir
try {
    Write-Host "Building the GhidraMCP extension for Ghidra $ver (first run downloads Gradle) ..."
    # A cold wrapper can lose the Ghidra fileTree on its very first invocation and fail
    # with a wall of "package ghidra.* does not exist"; the identical command then
    # succeeds. Retry once so that flake never becomes a human decision.
    try {
        Invoke-Native -Exe $gradlew -Arguments ($gradleArgs + 'buildExtension') -ErrorMessage 'gradlew buildExtension failed.'
    }
    catch {
        Write-Host 'First Gradle run failed; retrying once (cold-wrapper flake) ...'
        Invoke-Native -Exe $gradlew -Arguments ($gradleArgs + 'buildExtension') -ErrorMessage 'gradlew buildExtension failed twice.'
    }
}
finally { Pop-Location }

$extZip = Get-ChildItem (Join-Path $GhidraMcpDir 'build\distributions') -Filter 'GhidraMCP-*.zip' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $extZip) { throw 'Gradle reported success but produced no GhidraMCP-*.zip in build/distributions.' }

# Prove the version gate rather than trusting it: read the stamp back out of the zip.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($extZip.FullName)
try {
    $entry = $zip.Entries | Where-Object FullName -like '*extension.properties' | Select-Object -First 1
    if (-not $entry) { throw "No extension.properties inside $($extZip.Name)." }
    $reader = New-Object IO.StreamReader($entry.Open())
    $extProps = $reader.ReadToEnd()
    $reader.Close()
}
finally { $zip.Dispose() }
if ($extProps -notmatch '(?m)^version=(.+)$') { throw "extension.properties in $($extZip.Name) has no version= line." }
$stamped = $Matches[1].Trim()
if ($stamped -ne $ver) {
    throw "Version gate would reject this build: extension.properties says $stamped, Ghidra is $ver."
}
Write-Host "Built $($extZip.Name)  (version gate: $stamped == $ver OK)"

$pluginJar = Get-ChildItem (Join-Path $GhidraMcpDir 'build\libs') -Filter 'GhidraMCP-*.jar' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $pluginJar) { throw 'No GhidraMCP-*.jar in build/libs - headless has nothing to run.' }

# ---------------------------------------------------------------- deploy (GUI path only)
# gradlew's `deploy` depends on a `stopGhidra` task that FORCE-KILLS every process whose
# command line contains this install's path AND `ghidra.Ghidra`/`ghidraRun`. An
# AnalyzeHeadless run from the enrichment pipeline matches both, so deploying while the
# pipeline is analysing would destroy hours of work with no prompt. Refuse instead.
# (The extension build above is safe -- it only writes into ghidra-mcp\build.)
# Consider java/javaw AND python/pythonw: pyghidra embeds the JVM in the python process, so
# BethesdaGhidraScripts' pipeline holds this install while no java.exe exists anywhere.
# Filtering on the command line alone would also match the shell that invoked THIS script
# (its own command line quotes the install path), so require a real JVM first.
$busy = @(Get-Process -Name java, javaw, python, pythonw -ErrorAction SilentlyContinue | Where-Object {
        $isJvm = $_.ProcessName -in 'java', 'javaw'
        if (-not $isJvm) { try { $isJvm = [bool]($_.Modules | Where-Object ModuleName -eq 'jvm.dll') } catch { $isJvm = $false } }
        if (-not $isJvm) { return $false }
        # A JVM counts as "using this install" if it loaded a module from it, or names it.
        $usesInstall = $false
        try { $usesInstall = [bool]($_.Modules | Where-Object { $_.FileName -and $_.FileName.ToLower().StartsWith($ghidraHome.FullName.ToLower()) }) } catch {}
        if (-not $usesInstall) {
            $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
            $usesInstall = $cl -and $cl.ToLower().Contains($ghidraHome.FullName.ToLower())
        }
        $usesInstall
    } | ForEach-Object {
        $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
        [pscustomobject]@{ ProcessId = $_.Id; CommandLine = $(if ($cl) { $cl } else { $_.ProcessName }) }
    })
if ($busy.Count -and -not $HeadlessOnly) {
    Write-Host ''
    Write-Host 'REFUSING to deploy: something is running from this Ghidra install right now.'
    foreach ($b in $busy) {
        $short = $b.CommandLine.Substring(0, [Math]::Min(160, $b.CommandLine.Length))
        Write-Host "  PID $($b.ProcessId): $short"
    }
    Write-Host '`gradlew deploy` would force-kill it (its stopGhidra task), and if that is an'
    Write-Host 'AnalyzeHeadless run you would lose the analysis and be left with a stale project'
    Write-Host 'lock. Wait for it to finish, then re-run. The extension jar is already built, so'
    Write-Host 'you can use the headless server now with:  .\setup\30-ghidra.ps1 -HeadlessOnly'
    exit 2
}

if ($HeadlessOnly) {
    Write-Host 'Skipping the GUI deploy (-HeadlessOnly).'
}
else {
    Push-Location $GhidraMcpDir
    try {
        # `deploy` = stopGhidra + deployExtension + installUserExtension + patchGhidraUserConfig.
        Invoke-Native -Exe $gradlew -Arguments ($gradleArgs + 'deploy') -ErrorMessage 'gradlew deploy failed.'
    }
    finally { Pop-Location }

    $userExt = Join-Path $env:APPDATA "ghidra\$profileName\Extensions\GhidraMCP"
    if (-not (Test-Path $userExt)) { throw "deploy reported success but $userExt is missing." }
    Write-Host "Extension deployed to $userExt"

    # patchGhidraUserConfig can only edit FrontEndTool.xml if it exists, and it does not
    # exist until the Ghidra GUI has been launched at least once. On a fresh machine the
    # patch is therefore a silent no-op and the plugin will not auto-load in the GUI.
    # Headless is unaffected, so this is a note rather than a failure.
    if (-not (Test-Path (Join-Path $env:APPDATA "ghidra\$profileName\FrontEndTool.xml"))) {
        Write-Host 'NOTE: the Ghidra GUI has never run for this profile, so FrontEndTool.xml does'
        Write-Host '      not exist yet and the plugin auto-load patch was a no-op. Either use the'
        Write-Host '      headless server (36-ghidra-mcp.ps1, no GUI needed) or launch Ghidra once'
        Write-Host '      and re-run this script to make the GUI auto-start the MCP server too.'
    }
}

# ---------------------------------------------------------------- bridge venv
$venvExe = Join-Path $GhidraMcpDir '.venv\Scripts\bridge-mcp-ghidra.exe'
if (-not (Test-Path $venvExe)) {
    Write-Host 'Creating ghidra-mcp .venv and installing the bridge (pip install -e .) ...'
    Push-Location $GhidraMcpDir
    try {
        Invoke-Native -Exe 'python' -Arguments @('-m', 'venv', '.venv')
        Invoke-Native -Exe (Join-Path $GhidraMcpDir '.venv\Scripts\python.exe') -Arguments @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pip')
        Invoke-Native -Exe (Join-Path $GhidraMcpDir '.venv\Scripts\pip.exe') -Arguments @('install', '--quiet', '-e', '.')
    }
    finally { Pop-Location }
    if (-not (Test-Path $venvExe)) { throw 'bridge-mcp-ghidra.exe did not appear - pip install failed?' }
}
Write-Host "Bridge: $venvExe"

# ---------------------------------------------------------------- headless classpath argfile
# The headless server is a GhidraLaunchable, not a fat jar: `java -jar` cannot work because
# the assembly deliberately excludes the Ghidra jars ("provided by Ghidra at runtime").
# Docker's entrypoint.sh builds the classpath from Framework/Features/Processors; we do the
# same here. ~194 jars is ~20 KB of command line, close enough to Windows' 32 KB limit to
# be worth avoiding, so it goes in a java @argfile instead.
$jars = @($pluginJar.FullName)
foreach ($d in 'Framework', 'Features', 'Processors', 'Debug') {
    $jars += Get-ChildItem (Join-Path $ghidraHome.FullName "Ghidra\$d") -Recurse -Filter '*.jar' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
}
$cpFile = Join-Path $PSScriptRoot '.ghidra-headless-cp.txt'
# Forward slashes: an @argfile treats backslash as an escape character.
$cpText = '-classpath "' + (($jars | ForEach-Object { $_ -replace '\\', '/' }) -join ';') + '"'
[IO.File]::WriteAllText($cpFile, $cpText, [Text.UTF8Encoding]::new($false))
Write-Host "Headless classpath: $($jars.Count) jars -> $cpFile"

# ---------------------------------------------------------------- run_script_inline gate
# Off by default upstream since v5.4.1 because /run_script_inline and /run_ghidra_script
# execute arbitrary Java in the Ghidra process. We turn it on deliberately: it is the
# difference between one call and N round-trips for every "for each X tell me Y" question
# (see docs/GHIDRA_WORKFLOW.md), and both servers here bind 127.0.0.1 only.
# It is read by the Ghidra JVM, NOT by the bridge -- putting it in .mcp.json's env is inert.
# Persisted at User scope for the GUI; 36-ghidra-mcp.ps1 also injects it into the headless
# process so it applies without opening a new terminal.
if ([Environment]::GetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', 'User') -ne '1') {
    [Environment]::SetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', '1', 'User')
    $env:GHIDRA_MCP_ALLOW_SCRIPTS = '1'
    Write-Host 'Set user env GHIDRA_MCP_ALLOW_SCRIPTS=1 (enables run_script_inline).'
    Write-Host '  To opt out: [Environment]::SetEnvironmentVariable(''GHIDRA_MCP_ALLOW_SCRIPTS'', $null, ''User'')'
}

# ---------------------------------------------------------------- manifest
$manifest = [ordered]@{
    generatedAt    = (Get-Date).ToString('o')
    ghidraHome     = $ghidraHome.FullName
    ghidraVersion  = $ver
    ghidraProfile  = $profileName
    extensionZip   = $extZip.FullName
    pluginJar      = $pluginJar.FullName
    bridgeExe      = $venvExe
    headlessCpFile = $cpFile
    headlessClass  = 'com.xebyte.headless.GhidraMCPHeadlessServer'
    guiDeployed    = (-not $HeadlessOnly)
}
$manifestPath = Join-Path $PSScriptRoot '.ghidra-mcp-build.json'
$manifest | ConvertTo-Json | Set-Content $manifestPath -Encoding UTF8
Write-Host "Wrote $manifestPath"

Write-Host ''
Write-Host 'Next: .\setup\36-ghidra-mcp.ps1 -Start   (headless MCP server, no GUI, no clicks)'
