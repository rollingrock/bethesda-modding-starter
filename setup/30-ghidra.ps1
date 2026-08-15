<#
.SYNOPSIS
    Install stock Ghidra + the GhidraMCP extension + the MCP bridge (bethington/ghidra-mcp).

.DESCRIPTION
    THE VERSION GATE: the GhidraMCP extension only loads in the exact Ghidra version it was
    built for (extension.properties version == Ghidra's application.version). This script
    therefore reads <ghidra.version> out of ghidra-mcp's pom.xml and downloads THAT stock
    Ghidra release from the NSA GitHub, so bridge, extension and Ghidra always agree.

    Steps (idempotent):
      1. Read target version from C:\repos\ghidra-mcp\pom.xml
      2. Download + extract the matching stock Ghidra release to C:\tools\
      3. Create ghidra-mcp's .venv and pip install -e . (provides bridge-mcp-ghidra.exe)
      4. Build + deploy the GhidraMCP extension (needs JDK 21 + Maven from 00-prereqs)
      5. Set user env GHIDRA_MCP_ALLOW_SCRIPTS=1 (read by the Ghidra JVM, NOT the bridge —
         putting it in .mcp.json env would be inert; it gates run_script_inline)

    After this script, the manual once-per-machine ritual is printed at the end.
#>
[CmdletBinding()]
param(
    [string]$GhidraMcpDir = 'C:\repos\ghidra-mcp',
    [string]$ToolsDir = 'C:\tools'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path (Join-Path $GhidraMcpDir 'pom.xml'))) {
    throw "ghidra-mcp not found at $GhidraMcpDir — run setup/20-repos.ps1 first."
}

# 1. target Ghidra version from the pom
[xml]$pom = Get-Content (Join-Path $GhidraMcpDir 'pom.xml')
$ver = $pom.project.properties.'ghidra.version'
if (-not $ver) { throw 'Could not read <ghidra.version> from pom.xml' }
Write-Host "ghidra-mcp targets Ghidra $ver"

# 2. download the matching stock release
$ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter "ghidra_${ver}_*" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $ghidraHome) {
    Write-Host "Fetching Ghidra $ver release info from GitHub ..."
    $releases = Invoke-RestMethod 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases?per_page=100'
    $rel = $releases | Where-Object { $_.tag_name -like "Ghidra_${ver}_*" } | Select-Object -First 1
    if (-not $rel) { throw "No NSA Ghidra release found for version $ver. Check https://github.com/NationalSecurityAgency/ghidra/releases" }
    $asset = $rel.assets | Where-Object name -like '*.zip' | Select-Object -First 1
    $zip = Join-Path $env:TEMP $asset.name
    Write-Host "Downloading $($asset.name) ($([math]::Round($asset.size/1MB)) MB) ..."
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip
    if (-not (Test-Path $ToolsDir)) { New-Item -ItemType Directory -Force $ToolsDir | Out-Null }
    Write-Host "Extracting to $ToolsDir ..."
    Expand-Archive $zip -DestinationPath $ToolsDir
    Remove-Item $zip
    $ghidraHome = Get-ChildItem $ToolsDir -Directory -Filter "ghidra_${ver}_*" | Select-Object -First 1
    if (-not $ghidraHome) { throw 'Extraction did not produce the expected ghidra_* folder.' }
}
Write-Host "Ghidra install: $($ghidraHome.FullName)"

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

    Write-Host 'Building the GhidraMCP extension (first run takes a few minutes) ...'
    Push-Location $GhidraMcpDir
    try {
        & mvn clean package assembly:single -DskipTests --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Maven build of the GhidraMCP extension failed.' }
    }
    finally { Pop-Location }
    $extZip = Get-ChildItem (Join-Path $GhidraMcpDir 'target') -Filter 'GhidraMCP-*.zip' | Select-Object -First 1
    if (-not $extZip) { throw 'Build reported success but no GhidraMCP-*.zip in target/.' }
}

# Deploy = unzip into the per-version user Extensions dir (the same thing Ghidra's
# File > Install Extensions does). No Ghidra restart is ever triggered from here.
$userExt = Join-Path $env:APPDATA "ghidra\$($ghidraHome.Name)\Extensions"
New-Item -ItemType Directory -Force $userExt | Out-Null
Expand-Archive $extZip.FullName -DestinationPath $userExt -Force
Write-Host "Extension deployed to $userExt"

# 5. script-execution gate for run_script_inline (JVM-side env var)
if ([Environment]::GetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', 'User') -ne '1') {
    [Environment]::SetEnvironmentVariable('GHIDRA_MCP_ALLOW_SCRIPTS', '1', 'User')
    Write-Host 'Set user env GHIDRA_MCP_ALLOW_SCRIPTS=1 (enables run_script_inline; restart Ghidra to pick it up).'
}

Write-Host ''
Write-Host '=== Once-per-machine manual steps (GUI) ==='
Write-Host "1. Start Ghidra: $($ghidraHome.FullName)\ghidraRun.bat"
Write-Host '2. File > Install Extensions -> verify GhidraMCP is listed and checked; restart if it was not.'
Write-Host '3. (Only for the legacy Jython import scripts in ghidra-scripts/) also install the Jython extension.'
Write-Host '4. Create a project, import your game EXE, run auto-analysis (hours for a Bethesda binary; let it finish).'
Write-Host '5. In the CodeBrowser: Tools > GhidraMCP > Start MCP Server (listens on 127.0.0.1:8089).'
Write-Host '6. In every Claude session: list_instances() -> connect_instance(...) FIRST, or analysis tools do not exist.'
