<#
.SYNOPSIS
    Install Ghidra + the GhidraMCP extension + the MCP bridge (bethington/ghidra-mcp).

.DESCRIPTION
    THE VERSION GATE: the GhidraMCP extension only loads in the exact Ghidra version it was
    built for (extension.properties version == Ghidra's application.version). This script
    builds the extension AGAINST the chosen install's version (mvn -Dghidra.version=...),
    so bridge, extension and Ghidra always agree.

    Which Ghidra? In order:
      1. -GhidraPath, if given.
      2. BethesdaGhidraScripts' managed install (<Root>\BethesdaGhidraScripts\tools\ghidra) —
         preferred, so ONE Ghidra serves both the enrichment pipeline and the MCP bridge.
         (Run its `python run.py` menu option 1 first to install it.)
      3. An existing <ToolsDir>\ghidra_<pom-version>_* install.
      4. Download the stock release matching ghidra-mcp's pom from the NSA GitHub.

    Also (idempotent): creates ghidra-mcp's .venv (pip install -e . -> bridge exe), installs
    the Ghidra jars into ~/.m2, builds the extension with Maven (JDK 21 + Maven from
    00-prereqs), unzips it into the per-version user Extensions dir (never restarts Ghidra),
    and sets user env GHIDRA_MCP_ALLOW_SCRIPTS=1 (read by the Ghidra JVM, NOT the bridge —
    putting it in .mcp.json env would be inert; it gates run_script_inline).
#>
[CmdletBinding()]
param(
    [string]$GhidraMcpDir = 'C:\repos\ghidra-mcp',
    [string]$ToolsDir = 'C:\tools',
    [string]$Root = 'C:\repos',
    # Explicit Ghidra install to build the extension for (overrides auto-detection).
    [string]$GhidraPath = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path (Join-Path $GhidraMcpDir 'pom.xml'))) {
    throw "ghidra-mcp not found at $GhidraMcpDir — run setup/20-repos.ps1 first."
}

[xml]$pom = Get-Content (Join-Path $GhidraMcpDir 'pom.xml')
$pomVer = $pom.project.properties.'ghidra.version'
if (-not $pomVer) { throw 'Could not read <ghidra.version> from pom.xml' }
Write-Host "ghidra-mcp's pom targets Ghidra $pomVer (used only if no local install is found)"

function Get-GhidraProps([string]$installDir) {
    $propFile = Join-Path $installDir 'Ghidra\application.properties'
    if (-not (Test-Path $propFile)) { return $null }
    $props = @{}
    Get-Content $propFile | ForEach-Object { if ($_ -match '^([^=#]+)=(.*)$') { $props[$Matches[1].Trim()] = $Matches[2].Trim() } }
    $props
}

# pick the install
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
    $ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter "ghidra_${pomVer}_*" -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $ghidraHome) {
    Write-Host "Fetching Ghidra $pomVer release info from GitHub ..."
    $releases = Invoke-RestMethod 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=100'
    $rel = $releases | Where-Object { $_.tag_name -like "Ghidra_${pomVer}_*" } | Select-Object -First 1
    if (-not $rel) { throw "No NSA Ghidra release found for version $pomVer. Check https://github.com/NationalSecurityAgency/ghidra/releases" }
    $asset = $rel.assets | Where-Object name -like '*.zip' | Select-Object -First 1
    $zip = Join-Path $env:TEMP $asset.name
    Write-Host "Downloading $($asset.name) ($([math]::Round($asset.size/1MB)) MB) ..."
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip
    if (-not (Test-Path $ToolsDir)) { New-Item -ItemType Directory -Force $ToolsDir | Out-Null }
    Write-Host "Extracting to $ToolsDir ..."
    Expand-Archive $zip -DestinationPath $ToolsDir
    Remove-Item $zip
    $ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter "ghidra_${pomVer}_*" | Select-Object -First 1
    if (-not $ghidraHome) { throw 'Extraction did not produce the expected ghidra_* folder.' }
}

# the REAL version + user-profile dir name come from the install itself, not its folder name
$props = Get-GhidraProps $ghidraHome.FullName
$ver = $props['application.version']
$profileName = "ghidra_$($ver)_$($props['application.release.name'])"
Write-Host "Ghidra install: $($ghidraHome.FullName)  (version $ver, profile $profileName)"

# 3. bridge venv (console script bridge-mcp-ghidra.exe; runtime dep is just `mcp`)
$venvExe = Join-Path $GhidraMcpDir '.venv\Scripts\bridge-mcp-ghidra.exe'
if (-not (Test-Path $venvExe)) {
    Write-Host 'Creating ghidra-mcp .venv and installing the bridge (pip install -e .) ...'
    Push-Location $GhidraMcpDir
    try {
        python -m venv .venv
        & .\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
        & .\.venv\Scripts\pip.exe install --quiet -e .
    }
    finally { Pop-Location }
    if (-not (Test-Path $venvExe)) { throw 'bridge-mcp-ghidra.exe did not appear — pip install failed?' }
}
Write-Host "Bridge: $venvExe"

# 4. install the Ghidra jars into ~/.m2, then build the extension with Maven directly.
# We deliberately do NOT use ghidra-mcp's `tools.setup` here: it hard-requires `uv` and its
# deploy step restarts Ghidra (dangerous under a running instance with unsaved analysis).
# Everything it does for us is three plain steps: install-file the jars, mvn package, unzip.
$extZip = Get-ChildItem (Join-Path $GhidraMcpDir 'target') -Filter 'GhidraMCP-*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
# A zip built for a DIFFERENT Ghidra version fails the load gate — force a rebuild then.
$builtProps = Join-Path $GhidraMcpDir 'target\classes\extension.properties'
if ($extZip -and (Test-Path $builtProps) -and -not ((Get-Content $builtProps) -contains "version=$ver")) {
    Write-Host "Existing build targets a different Ghidra version — rebuilding for $ver."
    $extZip = $null
}
if (-not $extZip) {
    # The pom depends on ghidra:* artifacts that only exist inside a Ghidra install.
    # Derive the list from the pom itself so upstream changes don't strand us.
    $ghidraDeps = @($pom.project.dependencies.dependency | Where-Object groupId -eq 'ghidra')
    Write-Host "Installing $($ghidraDeps.Count) Ghidra jars into the local Maven repo (version $ver) ..."
    foreach ($dep in $ghidraDeps) {
        $m2jar = Join-Path $env:USERPROFILE ".m2\repository\ghidra\$($dep.artifactId)\$ver\$($dep.artifactId)-$ver.jar"
        if (Test-Path $m2jar) { continue }
        $jar = Get-ChildItem $ghidraHome.FullName -Recurse -Filter "$($dep.artifactId).jar" -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $jar) { throw "Could not find $($dep.artifactId).jar inside $($ghidraHome.FullName)" }
        & mvn --quiet install:install-file "-Dfile=$($jar.FullName)" '-DgroupId=ghidra' `
            "-DartifactId=$($dep.artifactId)" "-Dversion=$ver" '-Dpackaging=jar'
        if ($LASTEXITCODE -ne 0) { throw "mvn install:install-file failed for $($dep.artifactId)" }
    }
    # Clear failed-download markers a previous broken attempt may have left; they make
    # Maven ignore the jars we just installed.
    Get-ChildItem (Join-Path $env:USERPROFILE '.m2\repository\ghidra') -Recurse -Filter '*.lastUpdated' -ErrorAction SilentlyContinue | Remove-Item -Force

    Write-Host "Building the GhidraMCP extension for Ghidra $ver (first run takes a few minutes) ..."
    Push-Location $GhidraMcpDir
    try {
        # -Dghidra.version overrides the pom property, so the extension's version gate
        # matches whatever install we resolved above (verified: CLI -D wins over the pom).
        & mvn clean package assembly:single -DskipTests "-Dghidra.version=$ver" --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Maven build of the GhidraMCP extension failed.' }
    }
    finally { Pop-Location }
    $extZip = Get-ChildItem (Join-Path $GhidraMcpDir 'target') -Filter 'GhidraMCP-*.zip' | Select-Object -First 1
    if (-not $extZip) { throw 'Build reported success but no GhidraMCP-*.zip in target/.' }
}

# Deploy = unzip into the per-version user Extensions dir (the same thing Ghidra's
# File > Install Extensions does). No Ghidra restart is ever triggered from here.
# NOTE: the profile dir is named from application.properties, NOT the install folder —
# BethesdaGhidraScripts' install lives in a folder called just "ghidra".
$userExt = Join-Path $env:APPDATA "ghidra\$profileName\Extensions"
New-Item -ItemType Directory -Force $userExt | Out-Null
Expand-Archive $extZip.FullName -DestinationPath $userExt -Force
Write-Host "Extension deployed to $userExt"

# 5. script-execution gate for run_script_inline (JVM-side env var)
if ([Environment]::GetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', 'User') -ne '1') {
    [Environment]::SetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', '1', 'User')
    Write-Host 'Set user env GHIDRA_MCP_ALLOW_SCRIPTS=1 (enables run_script_inline; restart Ghidra to pick it up).'
}

Write-Host ''
Write-Host '=== Once-per-machine manual steps ==='
Write-Host '1. Build the analysis database with BethesdaGhidraScripts (types + vtables + names):'
Write-Host "   cd $(Join-Path $Root 'BethesdaGhidraScripts'); drop game EXEs into exes\<game>\<ver>\; python run.py"
Write-Host '   -> menu 1 (prereqs), 2 (submodules), 7 (full rebuild; auto-analysis takes hours - let it finish).'
Write-Host "2. Start Ghidra: $($ghidraHome.FullName)\ghidraRun.bat (or BGS menu option 6)."
Write-Host '3. File > Install Extensions -> verify GhidraMCP is listed and checked; restart Ghidra if it was not.'
Write-Host '4. In the CodeBrowser: Tools > GhidraMCP > Start MCP Server (listens on 127.0.0.1:8089).'
Write-Host '5. In every Claude session: list_instances() -> connect_instance(...) FIRST, or analysis tools do not exist.'
