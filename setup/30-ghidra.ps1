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

    Every "is this already fine?" question here is answered by RUNNING the thing, through the
    capability probes in setup/_common.ps1 -- because each of the three used to be answered by
    a file test that a broken machine passes: the JDK is the one gradlew.bat resolves (JAVA_HOME
    beats PATH), the Ghidra install has to be COMPLETE (application.properties is the front of
    the zip, so a truncated extraction parses), and the bridge launcher has to start (a venv
    orphaned by a Python upgrade keeps its .exe).

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

# The java this script can SEE is not the java the build USES. ghidra-mcp's gradlew.bat does
# `if defined JAVA_HOME goto findJavaFromJavaHome` -> `set JAVA_EXE=%JAVA_HOME%/bin/java.exe`,
# and falls back to PATH only when JAVA_HOME is UNSET -- set but wrong, it aborts with "ERROR:
# JAVA_HOME is set to an invalid directory" instead of falling back. Nothing else in this pack
# sets or reads JAVA_HOME (00-prereqs.ps1 installs Temurin 21 onto PATH and leaves it alone),
# so the old `Test-Cmd 'java'` -- a Get-Command PATH lookup -- verified a JVM the build never
# runs: with a leftover JAVA_HOME=C:\Program Files\Java\jdk1.8.0_202 it passed, the build failed
# under JDK 8, the cold-wrapper retry below repeated that failure verbatim, and the user was
# left with "gradlew buildExtension failed twice." without one line of output naming JAVA_HOME.
# Test-JavaForGradle resolves java exactly the way gradlew.bat does, and its Detail names the
# winner and its path -- print it on success too, because "which JDK did it build with?" has no
# answer anywhere else. The floor is 21 rather than "any JDK": the wrapper pins gradle-9.6.1,
# which refuses to start on a JVM below 17, and build.gradle pins `JavaLanguageVersion.of(21)`,
# a toolchain that resolves without hunting for a second JDK only when the JVM gradlew launched
# under is itself 21. A bare JRE 8 satisfied the old check completely.
$javaProbe = Test-JavaForGradle -MinMajor 21
Write-ProbeResult -Result $javaProbe
if ($javaProbe.Status -ne 'OK') {
    throw @"
The JDK gradlew.bat would build with is not usable: $($javaProbe.Detail)
  reproduce: $($javaProbe.Command)
Install Temurin JDK 21 with setup/00-prereqs.ps1. If JAVA_HOME is set it WINS over PATH here,
so point it at that JDK 21 or clear it -- gradlew.bat reads it before it looks at PATH.
"@
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
    # Rank on a PARSED version, never on the directory name. A string sort puts '9' after
    # '1', so ghidra_9.2.4_PUBLIC beats ghidra_11.3.2_PUBLIC (and ghidra_11.9 beats
    # ghidra_11.10) -- "newest wins" would quietly build the extension for a years-old
    # install. The version gate below is physically incapable of catching that: it only
    # proves the zip was stamped for the install we PICKED, so it prints "9.2.4 == 9.2.4 OK"
    # while the user's real 11.3.2 never receives the extension and every line of output
    # claims success. Rank on application.version rather than on the folder name because it
    # is the authoritative version -- it is what the rest of this script builds and gates
    # against, and users do rename these directories.
    $ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue |
        ForEach-Object {
            # The same filter this used to do in a Where-Object, but reading the properties
            # once: a directory with no Ghidra\application.properties is not a Ghidra
            # install and never becomes a candidate.
            $p = Get-GhidraProps $_.FullName
            if ($p) {
                # Never throw on a version we did not expect -- a dev build stamps
                # "11.4-DEV" and [version] needs at least two components, so '11' alone
                # would throw. Anything unparseable floors to 0.0 and sorts last instead of
                # taking the whole script down.
                $v = [version]'0.0'
                if ("$($p['application.version'])" -match '^\d+(\.\d+)*') {
                    $n = $Matches[0]
                    if ($n -notmatch '\.') { $n = "$n.0" }
                    try { $v = [version]$n } catch {}
                }
                [pscustomobject]@{ Dir = $_; Version = $v }
            }
        } | Sort-Object Version -Descending | Select-Object -First 1 -ExpandProperty Dir
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

# Everything above proves only that Ghidra\application.properties parses, and that file sits
# near the FRONT of the distribution zip -- Ghidra/ before GPL/ and support/, and inside it
# before Features/Framework/Processors. An interrupted or disk-full `python run.py setup`
# therefore leaves a tools\ghidra that every check in this script used to accept: the Gradle
# compile succeeds (its dependencies live in the Framework jars that did land), the version
# gate passes, and the truncation only surfaces hours later as a LanguageNotFoundException
# inside a headless analysis run, several tools away from the unzip that died.
# One probe covers all three sources above (-GhidraPath, BGS's managed install, ToolsDir) --
# and it is run on the install we PICKED rather than used to filter candidates, deliberately:
# a truncated BGS tools\ghidra must say "the install you are pointed at is incomplete", not
# quietly disappear from the running and hand the pipeline and MCP two different Ghidras.
# It also runs before the build, so a truncated install costs seconds instead of a full
# Gradle run.
$installProbe = Test-GhidraInstallComplete -Path $ghidraHome.FullName
Write-ProbeResult -Result $installProbe
if ($installProbe.Status -ne 'OK') {
    throw @"
The Ghidra install at $($ghidraHome.FullName) is not complete: $($installProbe.Detail)
  reproduce: $($installProbe.Command)
Re-extract it. For the BethesdaGhidraScripts-managed install that is:
  cd $(Join-Path $Root 'BethesdaGhidraScripts'); python run.py setup
(or pass -GhidraPath <dir> to build against an install you already have).
"@
}

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
        # Name the JDK in the failure. A retry that repeats an identical command can only fix
        # a flake, so when it does not, the next question is always "which JVM ran this?" --
        # and JAVA_HOME's answer is invisible from the Gradle output alone.
        Invoke-Native -Exe $gradlew -Arguments ($gradleArgs + 'buildExtension') -ErrorMessage "gradlew buildExtension failed twice (JDK used: $($javaProbe.Detail))."
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
# `if (-not (Test-Path $venvExe))` asked whether a FILE is there, and then printed
# "Bridge: <path>" as if that were a working bridge. A console-script .exe in <venv>\Scripts
# reaches its interpreter through .venv\Scripts\python.exe, which reads pyvenv.cfg to find the
# base install -- so upgrade the Python that created the venv (winget 3.12 -> 3.13 REMOVES the
# 3.12 runtime) and the stub is still sitting there, byte for byte, dying at launch with
# "No Python at '...'". The file test skipped the rebuild, every line here and in 90-verify
# reported success, and the first thing to notice was an MCP client saying "MCP server failed
# to start" days later, pointing at nothing. Running the launcher is the only way to tell a
# live venv from an orphaned one; --help is safe because the entry point
# (bridge_mcp_ghidra.cli:main) calls parse_args() before it starts anything, while a bare
# invocation would start the stdio server and never return.
$bridgeProbe = Test-VenvExeRuns -Path $venvExe
if ($bridgeProbe.Status -ne 'OK') {
    Write-ProbeResult -Result $bridgeProbe
    Write-Host 'Creating ghidra-mcp .venv and installing the bridge (pip install -e .) ...'
    $venvFailMsg = 'python -m venv --clear .venv failed. Exit 9009 is the Microsoft Store ' +
        'alias stub answering instead of a real interpreter (run setup/00-prereqs.ps1); an ' +
        'access-denied means something still holds the old venv -- stop the MCP client or ' +
        'headless server using the bridge, then re-run.'
    Push-Location $GhidraMcpDir
    try {
        # --clear, because the repair case is an EXISTING .venv whose base interpreter is
        # gone: plain `python -m venv .venv` reuses the directory and leaves site-packages
        # built against the old minor version in place. It is a no-op when nothing is there.
        Invoke-Native -Exe 'python' -Arguments @('-m', 'venv', '--clear', '.venv') -ErrorMessage $venvFailMsg
        Invoke-Native -Exe (Join-Path $GhidraMcpDir '.venv\Scripts\python.exe') -Arguments @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pip')
        Invoke-Native -Exe (Join-Path $GhidraMcpDir '.venv\Scripts\pip.exe') -Arguments @('install', '--quiet', '-e', '.')
    }
    finally { Pop-Location }
    # Re-run the SAME predicate instead of Test-Path'ing the .exe back into existence. The
    # state this block was asked to produce is a launcher that RUNS, and "pip put a file
    # there" is exactly the evidence that was not good enough the first time.
    $bridgeProbe = Test-VenvExeRuns -Path $venvExe
    if ($bridgeProbe.Status -ne 'OK') {
        throw @"
The bridge venv was rebuilt and its launcher still does not run: $($bridgeProbe.Detail)
  reproduce: $($bridgeProbe.Command)
"@
    }
}
Write-ProbeResult -Result $bridgeProbe
Write-Host "Bridge: $venvExe"

# ---------------------------------------------------------------- headless classpath argfile
# The headless server is a GhidraLaunchable, not a fat jar: `java -jar` cannot work because
# the assembly deliberately excludes the Ghidra jars ("provided by Ghidra at runtime").
# Docker's entrypoint.sh builds the classpath from Framework/Features/Processors; we do the
# same here. ~194 jars is ~20 KB of command line, close enough to Windows' 32 KB limit to
# be worth avoiding, so it goes in a java @argfile instead.
#
# Prove the install once more, with the SAME predicate the selection above used, before its
# jar list becomes the file 36-ghidra-mcp.ps1 launches the headless server from. The glob
# below has to be -ErrorAction SilentlyContinue (Debug legitimately does not exist in older
# Ghidras), which means a missing Processors or Features tree contributes ZERO jars and says
# nothing: "Headless classpath: 71 jars" was printed in exactly the same voice as a healthy
# ~194. The floor lives in the predicate and both call sites take its default, so the two
# cannot drift apart. Refusing to write is the point -- an argfile is read minutes or days
# later by another script, and a stale-but-complete one from an earlier run is worth more
# than a fresh truncated one. (The count printed below is one HIGHER than the probe's: the
# argfile puts the freshly built GhidraMCP jar in front of the install's own jars.)
$cpProbe = Test-GhidraInstallComplete -Path $ghidraHome.FullName
if ($cpProbe.Status -ne 'OK') {
    Write-ProbeResult -Result $cpProbe
    throw "Refusing to write a headless classpath from an incomplete Ghidra install: $($cpProbe.Detail)"
}

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

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
