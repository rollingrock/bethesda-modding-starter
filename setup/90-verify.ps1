<#
.SYNOPSIS
    The state oracle: what phase is this machine actually in? Optionally prove it by building
    a scaffolded plugin.

.DESCRIPTION
    This changes NOTHING about how the machine is set up, and that is a contract rather than an
    accident: agents and the other setup scripts run it to find out where they are, so it has to
    be safe at any moment and it must never throw.

    Two exceptions, both deliberate and both named here because a promise with a silent
    exception is worse than no promise. -BuildTest scaffolds a throwaway F4VR plugin into %TEMP%
    via New-Plugin.ps1 and builds it end-to-end — the single strongest signal that the machine is
    actually ready (VS, CMake, vcpkg restore, CommonLibF4 submodule, C++23). And the delegated
    Phase 4 gate row runs `35-ghidra-analysis.ps1 -CheckOnly`, which reclaims any game binaries a
    previous interrupted `-OnlyGame` run stranded under .exes-held before it reports (see that
    script's own -CheckOnly note for why the repair happens even in check mode). It moves those
    files back where they came from and touches nothing else; `-Fast` skips it entirely.

    Every row lands in one of five states and only FAIL gates the exit code; see the row
    vocabulary next to Check() below for what the other four mean and why they exist.

    -Json emits the rows as a JSON array on stdout instead of the table, so an agent gets the
    same answer a human does without parsing a Format-Table render.
    -Fast drops the delegated -CheckOnly gate rows, which are the only rows that spawn a
    process rather than reading state.

.EXAMPLE
    .\setup\90-verify.ps1
    .\setup\90-verify.ps1 -Json -Fast
#>
[CmdletBinding()]
param(
    [string]$Root = 'C:\repos',
    [string]$ToolsDir = 'C:\tools',
    [switch]$BuildTest,

    # Emit the rows as JSON on stdout instead of rendering the table. CLAUDE.md points an agent
    # at this script to answer "what phase am I actually in", and an agent cannot parse a
    # Format-Table render: -Wrap breaks Detail across lines and -AutoSize moves the column
    # boundaries with the terminal width, so the same machine reports differently in a 120- and
    # a 200-column terminal. The exit-code contract is unchanged, so one run answers both the
    # gate question (the code) and the state question (the rows).
    [switch]$Json,

    # Skip the delegated -CheckOnly gate rows at the bottom of this file. Those spawn one child
    # powershell each, which is seconds rather than the milliseconds every other row costs;
    # -Fast is for callers who only want the cheap rows. The skip is still printed as a row --
    # a check that was not made must never look like a check that passed.
    [switch]$Fast
)

. "$PSScriptRoot\_common.ps1"

# A tool installed after this shell started is still only in the registry PATH; without
# this the toolchain table reports FAIL for things that are installed and working.
Sync-Path

$rows = [System.Collections.Generic.List[object]]::new()

<#
THE ROW VOCABULARY, which the exit gate at the bottom of this file reads:
  PASS     the check was made and it held
  FAIL     the check was made and it did not hold -- the ONLY state that gates the exit code
  skip     the check does not apply to THIS machine because it was set up that way on purpose:
           20-repos.ps1 -SkipAddressTools, 30-ghidra.ps1 -HeadlessOnly, an analysis nobody has
           spent the hours on yet
  pending  work is outstanding but nothing is broken -- the exit-2 answer the -CheckOnly gates
           give
  idle     an optional service is simply not running right now

Only FAIL is a failure, and that distinction is the whole of finding 37. 'vr_address_tools
(optional)' was an ordinary failable row, so a machine set up with the documented
`20-repos.ps1 -SkipAddressTools` flow failed verify FOREVER and taught its owner to read the
exit code as noise; the closing message could only apologise for not knowing ("may be
intentional skips") because nothing in the table modelled the difference between "not there"
and "deliberately not there". The headless-server row had been demonstrating the correct
non-gating pattern with its 'idle' state the entire time.
#>
function Check([string]$area, [string]$name, [bool]$ok, [string]$detail = '', [switch]$Optional) {
    $state = 'FAIL'
    if ($ok) { $state = 'PASS' }
    elseif ($Optional) { $state = 'skip' }
    $rows.Add([pscustomobject]@{ Area = $area; Check = $name; OK = $state; Detail = $detail })
}

# For the states that are not one of a boolean's two answers. ONE place writes the row shape,
# so a row added here and a row added by Check can never disagree about their property names --
# which now matters beyond the table's alignment, because -Json hands these very objects to an
# agent that will index them by name.
function Add-Row([string]$area, [string]$name, [string]$state, [string]$detail = '') {
    $rows.Add([pscustomobject]@{ Area = $area; Check = $name; OK = $state; Detail = $detail })
}

<#
.SYNOPSIS
    Read ONE field out of a parsed JSON record, returning $null when it is not there.

.DESCRIPTION
    Both state files this script reads (setup\.ghidra-mcp-build.json and
    BethesdaGhidraScripts\.analysis-verified.json) are written by scripts that have grown fields
    over time, so a record missing a field is an ordinary thing to find on a real machine rather
    than corruption. Naive access is unsafe in both directions: `$mf.ghidraProfile` on an older
    manifest is $null, `Test-Path $null` returns FALSE -- which would report a missing FIELD as
    a broken INSTALL -- and `Join-Path $null 'x'` THROWS, which would take this whole read-only
    script down over a manifest it was merely trying to describe. Ask the property bag whether
    the field exists at all, and let the caller emit a row that names the repair.

    Returns the value (which may legitimately be $false, as guiDeployed is) or $null.
#>
function Get-JsonField {
    param($Record, [Parameter(Mandatory)][string]$Name)
    if (-not $Record) { return $null }
    $prop = $null
    try { $prop = $Record.PSObject.Properties[$Name] } catch { return $null }
    if (-not $prop) { return $null }
    $prop.Value
}

# One sentence for every missing manifest field, so all of them read identically and every one
# of them names the same repair instead of leaving the reader to infer it from an empty column.
function Get-StaleManifestDetail([string]$field) {
    "the build manifest carries no '$field' field -- it was written by an older setup\30-ghidra.ps1 " +
    'that did not record it, so there is nothing here to check against. Re-run setup\30-ghidra.ps1.'
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

# Test-VsWorkload, not a second inline vswhere call. 00-prereqs.ps1 gates the VS install on the
# shared probe, and a private copy here is precisely the "three separately authored truth
# systems" this layer replaced: the copies drift, and the weakest one quietly decides. It also
# treats vswhere's exit-0-with-no-output -- VS present, C++ workload absent -- as the failure it
# is, which the old inline `[bool]($vsVersions | Where-Object ...)` reached only by accident.
$vsProbe = Test-VsWorkload -MinMajor 17
$vsDetail = $vsProbe.Detail
if ($vsProbe.Status -eq 'OK' -and $vsDetail -notmatch '(^|\D)17\.') {
    # Not a failure: the default `windows-vcpkg-vr` preset pins no generator, so CMake takes
    # whatever VS is installed, and alandtse/CommonLibF4 builds on both 17.x and 18.x. Only
    # the explicitly pinned vs2022-* presets need a 17.x present.
    $vsDetail += ' (no 17.x: use windows-vcpkg-vr, which is generator-agnostic; the vs2022-* presets need 17.x)'
}
Check 'toolchain' 'VS C++ workload (17+)' ($vsProbe.Status -eq 'OK') $vsDetail

# env vars — persisted at User or Machine scope (what NEW terminals will see). Returns the
# value AND the scope it came from, because on a machine where a User value shadows a stale
# Machine one the reader has to know which of the two these rows actually judged.
function Get-PersistedEnv([string]$name) {
    foreach ($scope in 'User', 'Machine') {
        $v = [Environment]::GetEnvironmentVariable($name, $scope)
        if ($v) { return [pscustomobject]@{ Name = $name; Value = $v; Scope = $scope } }
    }
    return $null
}

# VALIDATE THE VARIABLE THE BUILD ACTUALLY READS. templates\f4sevr-plugin\CMakePresets.json
# resolves CMAKE_TOOLCHAIN_FILE as "$env{VCPKG_INSTALLATION_ROOT}/scripts/buildsystems/
# vcpkg.cmake", and the generated CMakeLists.txt reads VCPKG_ROOT -- two names for one thing,
# which is the trap 10-vcpkg.ps1 exists for. These rows used to test only that the NAMES were
# non-empty, so a value left pointing at a vcpkg that has since been deleted, moved or renamed
# PASSED; and the single content check there was (Test-Path vcpkg.exe) ran against VCPKG_ROOT
# and was GATED on VCPKG_ROOT being set, so on a machine carrying only VCPKG_INSTALLATION_ROOT
# no content check ran at all. Every vcpkg row could be green while `cmake --preset
# windows-vcpkg-vr` died at configure with "Could not find toolchain file", and only the
# optional -BuildTest would ever have noticed (id 31). So assert THE FILE THE PRESET NAMES,
# under both names, and report the scope each value came from.
foreach ($name in 'VCPKG_ROOT', 'VCPKG_INSTALLATION_ROOT') {
    $e = Get-PersistedEnv $name
    if (-not $e) {
        Check 'env' $name $false "not set at User or Machine scope -- run setup\10-vcpkg.ps1 (CMakePresets.json reads VCPKG_INSTALLATION_ROOT, CMakeLists.txt reads VCPKG_ROOT; both must be set)"
        continue
    }
    $toolchain = ''
    $found = $false
    try {
        $toolchain = Join-Path $e.Value 'scripts\buildsystems\vcpkg.cmake'
        $found = Test-Path -LiteralPath $toolchain -ErrorAction Stop
    }
    catch {
        # -ErrorAction Stop, and it is load-bearing. These values come out of the REGISTRY, not
        # out of this pack, and on one containing a | or a " Test-Path raises "Illegal characters
        # in path" as a NON-TERMINATING error: measured, a bare `try { Test-Path 'C:\a|b' } catch`
        # does NOT enter its catch -- it prints a red ErrorRecord to stderr and hands back $false.
        # So a catch without -ErrorAction Stop is dead code that reports a MALFORMED value as a
        # merely absent toolchain file, while spraying PowerShell's own error block across the
        # console of a script whose contract is to stay quiet and never throw.
        #
        # -LiteralPath is the other half of the same problem: Test-Path GLOBS by default, so a
        # file that really is there under a directory containing [ or ] answers False (measured).
        # Every path this row and the manifest diff below stat comes from OUTSIDE this script --
        # a registry value, or a field in .ghidra-mcp-build.json -- so all of them take both.
        Check 'env' $name $false "$($e.Value) ($($e.Scope) scope) -- cannot be probed: $($_.Exception.Message)"
        continue
    }
    if ($found) {
        Check 'env' $name $true "$($e.Value) ($($e.Scope) scope); $toolchain is present"
    }
    else {
        Check 'env' $name $false "$($e.Value) ($($e.Scope) scope) -- but there is no scripts\buildsystems\vcpkg.cmake under it, so CMakePresets.json cannot resolve CMAKE_TOOLCHAIN_FILE and every preset fails at configure. Re-run setup\10-vcpkg.ps1."
    }
}

$flag = Get-PersistedEnv 'GHIDRA_MCP_ALLOW_SCRIPTS'
# Existence really is the whole question for this one: it is a flag read by the Ghidra JVM, not
# a path, so there is nothing behind it to stat.
$flagDetail = 'not set at User or Machine scope -- /run_script_inline and /run_ghidra_script are refused; setup\30-ghidra.ps1 sets it'
if ($flag) { $flagDetail = "$($flag.Value) ($($flag.Scope) scope)" }
Check 'env' 'GHIDRA_MCP_ALLOW_SCRIPTS' ([bool]$flag) $flagDetail

# ...and the OTHER question, kept deliberately separate. The rows above prove the toolchain file
# the presets name is on disk. This one runs vcpkg.exe and asks whether the builtin-baseline
# that templates\f4sevr-plugin\vcpkg.json pins is both present in the clone AND checked out.
# The two fail for unrelated reasons and want unrelated repairs -- a missing toolchain file
# means the env var points somewhere wrong, a missing baseline means the clone needs a fetch and
# a fast-forward -- and one merged verdict could only name one of them. Judged against the value
# CMakePresets.json reads, falling back to VCPKG_ROOT, because that is the clone a build started
# on this machine would really use. Test-VcpkgUsable is the LIBRARY's definition, the same one
# 10-vcpkg.ps1 gates on: a local copy here would drift, and a gate is only as strong as its
# weakest copy.
$vcpkgFor = Get-PersistedEnv 'VCPKG_INSTALLATION_ROOT'
if (-not $vcpkgFor) { $vcpkgFor = Get-PersistedEnv 'VCPKG_ROOT' }
if ($vcpkgFor) {
    $vcpkgProbe = Test-VcpkgUsable -VcpkgDir $vcpkgFor.Value
    Check 'env' 'vcpkg usable (runs + pinned baseline)' ($vcpkgProbe.Status -eq 'OK') "$($vcpkgProbe.Detail) [judged against $($vcpkgFor.Name), $($vcpkgFor.Scope) scope]"
}
else {
    Check 'env' 'vcpkg usable (runs + pinned baseline)' $false 'neither VCPKG_ROOT nor VCPKG_INSTALLATION_ROOT is persisted, so there is no clone to run'
}

# repos. BethesdaGhidraScripts is in this list now. It is the Phase 4 centrepiece -- the repo
# 20-repos.ps1 clones and 35-ghidra-analysis.ps1 drives -- and it was the one repo the table
# never mentioned, so a machine with no BGS clone at all read "Environment verified." and exited
# 0 while CLAUDE.md calls that machine "at parity" (id 67).
#
# WHICH repository each clone actually is stays out of this loop on purpose. Test-RepoIdentity
# answers that by reading origin, 20-repos.ps1 -CheckOnly is the script that owns the question
# (alandtse/BethesdaGhidraScripts and 1001Bits/BethesdaGhidraScripts put an identical .git in an
# identically named directory), and the delegated gate row at the bottom of this file asks it
# THERE rather than growing a second, weaker copy of it here.
foreach ($r in 'CommonLibF4', 'commonlibsf', 'devbench', 'ghidra-mcp', 'modlist-agent', 'BethesdaGhidraScripts') {
    $repoDir = Join-Path $Root $r
    $cloned = Test-Path (Join-Path $repoDir '.git')
    $repoDetail = "no .git under $repoDir -- run setup\20-repos.ps1"
    if ($cloned) { $repoDetail = $repoDir }
    Check 'repos' $r $cloned $repoDetail
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
# -Optional, so an absent clone is a 'skip' and never gates. README.md documents
# `20-repos.ps1 -SkipAddressTools` as a supported way to set this machine up (the clone is
# ~1.1 GB), and as an ordinary failable row this line meant every machine that took that
# documented path failed verify forever -- a permanently red table teaches its reader that red
# means nothing, which costs far more than the row was ever worth (id 37). A skip is not
# silence: the row is still printed and still says what is on disk; it just does not gate.
$vrAddressTools = Join-Path $Root 'vr_address_tools'
$vratCloned = Test-Path (Join-Path $vrAddressTools '.git')
$vratDetail = "no .git under $vrAddressTools -- consistent with setup\20-repos.ps1 -SkipAddressTools; a plain 20-repos.ps1 run clones it later"
if ($vratCloned) { $vratDetail = $vrAddressTools }
Check 'repos' 'vr_address_tools (optional)' $vratCloned $vratDetail -Optional

# ghidra (a machine may carry several installs).
# BethesdaGhidraScripts manages its own install under <Root>\BethesdaGhidraScripts\tools\ghidra.
$ghidras = @(Get-ChildItem $ToolsDir -Directory -Filter 'ghidra_*' -ErrorAction SilentlyContinue)
$bgsGhidra = Join-Path $Root 'BethesdaGhidraScripts\tools\ghidra'
if (Test-Path (Join-Path $bgsGhidra 'Ghidra\application.properties')) { $ghidras += Get-Item $bgsGhidra }
$ghidraPaths = @($ghidras | Select-Object -ExpandProperty FullName)

# Counting DIRECTORIES here would be the same defect this table exists to expose, one level up:
# application.properties lands early in zip-extraction order, so a run that died mid-unzip
# leaves a directory that passes any presence test while its Processors and Features trees are
# missing entirely -- and 30-ghidra.ps1 then builds a classpath out of however many jars it
# happens to find. Ask Test-GhidraInstallComplete, the same predicate 30-ghidra and
# 35-ghidra-analysis gate on, so all three agree on what "installed" means.
# The row passes when at least one COMPLETE install exists; incomplete ones are still listed,
# because "there is a Ghidra here but it is truncated" is the actionable half of the message.
# $ghidraPaths keeps EVERY candidate, complete or not, because the manifest row below asks a
# different question -- is the Ghidra we built against still here at all -- and answering that
# with the completeness-filtered list would report a truncated install as an absent one.
$completeGhidras = @()
$installParts = @()
foreach ($g in $ghidraPaths) {
    $probe = Test-GhidraInstallComplete -Path $g
    # The probe's own Detail already names the path it judged, so it is not repeated here.
    if ($probe.Status -eq 'OK') {
        $completeGhidras += $g
        $installParts += $probe.Detail
    }
    else { $installParts += "INCOMPLETE: $($probe.Detail)" }
}
$installDetail = "no ghidra_* directory under $ToolsDir and no install under $bgsGhidra -- run setup\30-ghidra.ps1"
if ($installParts.Count) { $installDetail = $installParts -join ' | ' }
Check 'ghidra' 'install' ($completeGhidras.Count -gt 0) $installDetail

# headless MCP — what Phase 4 actually runs. 30-ghidra.ps1 writes this manifest and
# 36-ghidra-mcp.ps1 launches the server straight out of it, so it is this pack's own record of
# WHAT was built and against WHICH Ghidra. It is read first because every row below is a diff
# against it.
#
# ConvertFrom-Json is guarded now: a truncated or hand-edited manifest threw out of the middle
# of a script whose entire job is to describe machines that are not quite right.
$mcpManifest = Join-Path $PSScriptRoot '.ghidra-mcp-build.json'
$mf = $null
$mfError = ''
if (Test-Path $mcpManifest) {
    try { $mf = Get-Content $mcpManifest -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { $mf = $null; $mfError = $_.Exception.Message }
}
$mfDetail = "$mcpManifest has not been written -- run setup\30-ghidra.ps1"
if ($mf) {
    $mfDetail = "$mcpManifest (written $(Get-JsonField $mf 'generatedAt'), against Ghidra $(Get-JsonField $mf 'ghidraVersion'))"
}
elseif ($mfError) {
    $mfDetail = "$mcpManifest exists but is not parseable JSON: $mfError -- re-run setup\30-ghidra.ps1"
}
Check 'ghidra' 'headless build manifest' ([bool]$mf) $mfDetail

if ($mf) {
    # ------------------------------------------------------------------ THE CLAIMS-DIFF
    # Every row below asks one question in a different place: does what 30-ghidra.ps1 RECORDED
    # still describe this machine? They used to be pure Test-Path against paths that survive any
    # change to Ghidra -- the plugin jar lives under <Root>\ghidra-mcp\build\libs and the argfile
    # under setup\ -- so after one successful 30-ghidra.ps1 run they were physically incapable of
    # ever failing again (id 28). Delete or upgrade the Ghidra those artifacts were built
    # against and 36-ghidra-mcp.ps1 -Start dies on a classpath of ~194 jars that are not there,
    # while this table stayed green. A check that can only report success is not a check.

    # 1) The install the manifest names. Test-GhidraInstallComplete is this pack's ONE answer to
    #    "is this a complete Ghidra" -- 30-ghidra.ps1 refuses to write a classpath without it and
    #    35-ghidra-analysis.ps1 gates menu 1 on it -- so it is the answer here too, rather than a
    #    third private copy that would be the weakest and would therefore decide. The membership
    #    half is separate: an install that is complete but is not one of the installs enumerated
    #    above means the build is pinned to a Ghidra this table cannot see, and the reader needs
    #    to be told which of the two halves gave way.
    $claimHome = Get-JsonField $mf 'ghidraHome'
    if ($null -eq $claimHome -or -not "$claimHome".Trim()) {
        Check 'ghidra' 'manifest ghidraHome still installed' $false (Get-StaleManifestDetail 'ghidraHome')
    }
    else {
        $homeProbe = Test-GhidraInstallComplete -Path "$claimHome"
        $known = @($ghidraPaths | Where-Object { $_.TrimEnd('\') -ieq "$claimHome".TrimEnd('\') })
        $where = 'and it is one of the installs on the row above'
        if (-not $known.Count) {
            $where = "but it is NOT among the installs found under $ToolsDir or in the BethesdaGhidraScripts clone ($($ghidraPaths -join ', ')) -- the headless build is pinned to a Ghidra this machine no longer advertises"
        }
        Check 'ghidra' 'manifest ghidraHome still installed' (($homeProbe.Status -eq 'OK') -and ($known.Count -gt 0)) "$($homeProbe.Detail); $where"
    }

    # 2) Read the argfile ONCE: both the jar row and the argfile row are diffs against it.
    #    30-ghidra.ps1 writes a single line, `-classpath "<jar>;<jar>;..."`, with forward slashes
    #    because an @argfile treats a backslash as an escape character.
    $claimCp = Get-JsonField $mf 'headlessCpFile'
    $cpJars = @()
    $cpError = ''
    if ($null -eq $claimCp -or -not "$claimCp".Trim()) { $cpError = '<missing field>' }
    else {
        try {
            # -LiteralPath + -ErrorAction Stop on every stat below, for the reason spelled out at
            # the VCPKG_ROOT row: Test-Path globs (a real file under a [bracketed] directory
            # answers False) and reports an illegal character NON-terminatingly, which would walk
            # straight past these catch blocks and print an ErrorRecord instead of a row.
            if (Test-Path -LiteralPath "$claimCp" -ErrorAction Stop) {
                $cpText = Get-Content -LiteralPath "$claimCp" -Raw -ErrorAction Stop
                if ($cpText -match '(?s)-classpath\s+"(.*)"') {
                    $cpJars = @($Matches[1] -split ';' | Where-Object { "$_".Trim() })
                }
                else {
                    $cpError = 'the file is not a -classpath argfile (30-ghidra.ps1 writes one line: -classpath "<jar>;<jar>;...")'
                }
            }
            else { $cpError = 'no such file' }
        }
        catch { $cpError = "cannot be read: $($_.Exception.Message)" }
    }

    # 3) The plugin jar, AND whether the argfile is naming that same jar. 30-ghidra.ps1 writes
    #    both in one pass, so a disagreement means one of them is left over from an earlier
    #    build -- and 36-ghidra-mcp.ps1 -Start would load the argfile's jar, not the manifest's,
    #    so the version this table reports would not be the version answering on :8089.
    $claimJar = Get-JsonField $mf 'pluginJar'
    if ($null -eq $claimJar -or -not "$claimJar".Trim()) {
        Check 'ghidra' 'plugin jar' $false (Get-StaleManifestDetail 'pluginJar')
    }
    else {
        $jarThere = $false
        try { $jarThere = Test-Path -LiteralPath "$claimJar" -ErrorAction Stop } catch { $jarThere = $false }
        if (-not $jarThere) {
            Check 'ghidra' 'plugin jar' $false "$claimJar is gone -- gradlew builds it into ghidra-mcp\build\libs; re-run setup\30-ghidra.ps1"
        }
        elseif ($cpJars.Count -gt 0) {
            # Normalise the separator before comparing, for the forward-slash reason above.
            $normJar = "$claimJar".Trim().Replace('/', '\').TrimEnd('\')
            $normCp0 = "$($cpJars[0])".Trim().Replace('/', '\').TrimEnd('\')
            if ($normCp0 -ieq $normJar) {
                Check 'ghidra' 'plugin jar' $true "$claimJar is present, and it is the first entry on the headless classpath"
            }
            else {
                Check 'ghidra' 'plugin jar' $false "$claimJar is present, but the headless argfile puts $($cpJars[0]) on the classpath instead -- one of the two is left over from an earlier build, and 36-ghidra-mcp.ps1 -Start would run the argfile's. Re-run setup\30-ghidra.ps1."
            }
        }
        else {
            # Never silently pass the half that was not tested.
            Check 'ghidra' 'plugin jar' $true "$claimJar is present -- NOT cross-checked against the headless classpath, because the argfile yielded no classpath entry to compare it against (see the row below, which fails for that reason)"
        }
    }

    # 4) The argfile itself. This is the row id 28 is really about: the file's own existence is
    #    worthless evidence, because it survives everything, while the ~194 ABSOLUTE jar paths
    #    inside it all live under the manifest's ghidraHome and do not.
    if ($cpError -eq '<missing field>') {
        Check 'ghidra' 'headless classpath argfile' $false (Get-StaleManifestDetail 'headlessCpFile')
    }
    elseif ($cpError) {
        Check 'ghidra' 'headless classpath argfile' $false "$claimCp -- $cpError. Re-run setup\30-ghidra.ps1."
    }
    elseif (-not $cpJars.Count) {
        # ZERO IS NOT A CLEAN SWEEP. `-classpath ""` (or a quoted run of whitespace) parses as a
        # perfectly well-formed argfile that names NOTHING, and the loop below then reports "0
        # jar(s); every one of them was stat'ed and every one is present" -- vacuously true, and
        # a row that announces success for an argfile 36-ghidra-mcp.ps1 -Start would launch an
        # empty-classpath JVM from. That is precisely the disease the rest of this block exists
        # to cure, so the empty set is judged before the all-present verdict can be reached.
        Check 'ghidra' 'headless classpath argfile' $false "$claimCp parses as a -classpath argfile but names NO jars at all -- setup\30-ghidra.ps1 writes the GhidraMCP jar plus ~194 more from the Ghidra install, so an empty classpath means the file was truncated or hand-edited and 36-ghidra-mcp.ps1 -Start would launch a JVM that cannot find a single class. Re-run setup\30-ghidra.ps1."
    }
    else {
        # EVERY path is stat'ed, not a sample. Measured on this machine at 45 ms for the 194 jars
        # a Ghidra 12 install yields -- an order of magnitude below the child processes the
        # delegated gates at the bottom of this file already spawn, so there is nothing to buy by
        # sampling. Checking a subset while the Detail implied the whole set is the exact disease
        # this move exists to cure, so if that cost ever changes, change the Detail with it.
        $missingJars = @()
        foreach ($j in $cpJars) {
            $there = $false
            try { $there = Test-Path -LiteralPath $j -ErrorAction Stop } catch { $there = $false }
            if (-not $there) { $missingJars += $j }
        }
        if ($missingJars.Count) {
            Check 'ghidra' 'headless classpath argfile' $false "$($missingJars.Count) of the $($cpJars.Count) jar(s) named by $claimCp are NOT on disk (first: $($missingJars[0])) -- 36-ghidra-mcp.ps1 -Start would launch a JVM on a classpath of files that do not exist and die on a missing class. Re-run setup\30-ghidra.ps1 to rebuild it against the Ghidra installed now."
        }
        else {
            Check 'ghidra' 'headless classpath argfile' $true "$claimCp names $($cpJars.Count) jar(s); every one of them was stat'ed and every one is present"
        }
    }

    # 5) The GUI extension, in the ONE profile the manifest names. The old row scanned every
    #    %APPDATA%\ghidra\* directory and passed if ANY of them held Extensions\GhidraMCP -- but
    #    Ghidra keys those profile directories by version and loads extensions only out of the
    #    one matching the RUNNING version, so a profile left behind by a Ghidra uninstalled a
    #    year ago satisfied this row forever (id 35).
    $claimGui = Get-JsonField $mf 'guiDeployed'
    $claimProfile = Get-JsonField $mf 'ghidraProfile'
    if ($null -eq $claimGui) {
        Check 'ghidra' 'extension deployed (GUI)' $false (Get-StaleManifestDetail 'guiDeployed')
    }
    elseif (-not [bool]$claimGui) {
        # A skip, for the same reason vr_address_tools is one: `30-ghidra.ps1 -HeadlessOnly` is a
        # documented setup, headless loads the plugin off the classpath checked above and never
        # looks in a profile at all -- and the manifest RECORDS which of the two was done. The
        # data needed to tell an intentional skip from a broken deploy has been sitting in the
        # file this script already parses the whole time (id 37).
        $guiSkip = 'the build manifest records guiDeployed=false (setup\30-ghidra.ps1 -HeadlessOnly): the GUI copy was never deployed, and the headless server loads the plugin off the classpath instead'
        if ("$claimProfile".Trim()) {
            try {
                $guiDir = Join-Path $env:APPDATA "ghidra\$claimProfile\Extensions\GhidraMCP"
                if (Test-Path -LiteralPath $guiDir -ErrorAction Stop) { $guiSkip += ". ($guiDir does exist, left by some earlier GUI deploy.)" }
            }
            catch { }
        }
        Check 'ghidra' 'extension deployed (GUI)' $false $guiSkip -Optional
    }
    elseif ($null -eq $claimProfile -or -not "$claimProfile".Trim()) {
        Check 'ghidra' 'extension deployed (GUI)' $false (Get-StaleManifestDetail 'ghidraProfile')
    }
    else {
        $guiDir = ''
        $guiThere = $false
        try {
            $guiDir = Join-Path $env:APPDATA "ghidra\$claimProfile\Extensions\GhidraMCP"
            $guiThere = Test-Path -LiteralPath $guiDir -ErrorAction Stop
        }
        catch { $guiThere = $false }
        if ($guiThere) {
            Check 'ghidra' 'extension deployed (GUI)' $true "$guiDir -- profile $claimProfile, which is the one Ghidra $(Get-JsonField $mf 'ghidraVersion') reads"
        }
        else {
            Check 'ghidra' 'extension deployed (GUI)' $false "the manifest says guiDeployed=true, but there is no $guiDir -- the profile Ghidra $(Get-JsonField $mf 'ghidraVersion') actually loads extensions from has no GhidraMCP in it. Re-run setup\30-ghidra.ps1."
        }
    }
}
else {
    # The row SET has to be stable, or the table lies by omission. Without this, a missing or
    # unparseable manifest simply deleted the four rows above -- and a vanished row reads as a
    # question nobody asked, which is worse than a red one. It matters more under -Json than in
    # the table: an agent keying rows by name gets $null for 'plugin jar' and cannot tell
    # "not checked" from "checked and fine". The manifest row above already carries the real
    # diagnosis, so these say what they could not do and point at it rather than repeating it.
    $noMf = 'not checked: there is no usable build manifest to diff against (see the row above)'
    foreach ($r in 'manifest ghidraHome still installed', 'plugin jar', 'headless classpath argfile') {
        Check 'ghidra' $r $false $noMf
    }
    Check 'ghidra' 'extension deployed (GUI)' $false $noMf -Optional
}

# EXECUTE the launcher, do not stat it. A venv resolves its base interpreter through
# pyvenv.cfg, so one orphaned by a Python upgrade (winget moving 3.12 to 3.13 removes the old
# runtime) still has the .exe on disk and dies at launch with "No Python at ...". Test-Path
# here was the second half of that blind spot -- 30-ghidra skipped rebuilding the venv because
# the file existed, and this table then confirmed it, so a broken bridge was green end to end
# and the first real symptom arrived inside the user's MCP client.
#
# The manifest's own bridgeExe wins when there is one: that is the launcher 30-ghidra.ps1 built
# and the path .mcp.json was written with, so it is the claim worth diffing. The conventional
# path under -Root is the fallback for a machine whose manifest predates the field.
$claimBridge = Get-JsonField $mf 'bridgeExe'
$bridgePath = Join-Path $Root 'ghidra-mcp\.venv\Scripts\bridge-mcp-ghidra.exe'
$bridgeFrom = 'the conventional path under -Root; the build manifest does not name one'
if ($claimBridge -and "$claimBridge".Trim()) {
    $bridgePath = "$claimBridge"
    $bridgeFrom = 'the path the build manifest records'
}
$bridge = Test-VenvExeRuns -Path $bridgePath
Check 'ghidra' 'bridge exe runs' ($bridge.Status -eq 'OK') "$($bridge.Detail) [$bridgeFrom]"
# Live server is optional (it is started on demand), so report it without failing the run.
# This row is where the non-gating pattern was invented; it goes through Add-Row now so that
# 'idle', 'skip' and 'pending' all come from the same place the exit gate below reads.
try {
    $c = Invoke-WebRequest 'http://127.0.0.1:8089/check_connection' -UseBasicParsing -TimeoutSec 2
    Add-Row 'ghidra' 'headless server (optional)' 'PASS' $c.Content.Trim()
}
catch {
    Add-Row 'ghidra' 'headless server (optional)' 'idle' 'not running - start with setup\36-ghidra-mcp.ps1 -Start'
}

# ---------------------------------------------------------------- Phase 4 analysis
# CLAUDE.md calls an all-PASS run "the machine is at parity", and until now that claim did not
# reach Phase 4 at all: a machine with no BethesdaGhidraScripts clone and no analysis ever run
# got "Environment verified." and exit 0 (id 67). The enriched database is what makes every
# decompile in this pack readable, and nothing on disk can tell an enriched project from an
# imported-then-rolled-back one -- Ghidra creates the project and imports the binary before the
# CommonLib enrichment runs, and a failed post-import verification rolls the enrichment back and
# leaves a multi-hundred-MB project sitting there looking finished. That is exactly why
# 35-ghidra-analysis.ps1 records its own verdict in .analysis-verified.json, and this is the row
# that reads it back.
#
# -Optional, so it never gates: the analysis is HOURS per binary and plenty of legitimate
# machines have not spent them. It has to be VISIBLE, not fatal -- being invisible was the
# finding.
$bgsRoot = Join-Path $Root 'BethesdaGhidraScripts'
$analysisMarker = Join-Path $bgsRoot '.analysis-verified.json'
$analysisOk = $false
$analysisDetail = "no $analysisMarker -- BethesdaGhidraScripts analysis has never been run and verified here. Start with setup\35-ghidra-analysis.ps1 -CheckOnly (the real run is HOURS per binary)."
if (-not (Test-Path $bgsRoot)) {
    $analysisDetail = "no BethesdaGhidraScripts clone at $bgsRoot, so there is nothing staged to analyze -- setup\20-repos.ps1 clones it"
}
elseif (Test-Path $analysisMarker) {
    $rec = $null
    try { $rec = Get-Content $analysisMarker -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch {
        $rec = $null
        $analysisDetail = "$analysisMarker is not parseable JSON: $($_.Exception.Message) -- re-run setup\35-ghidra-analysis.ps1"
    }
    if ($rec) {
        # 35-ghidra-analysis.ps1 writes { games, verifiedAt, ghidra }; there are no per-game
        # versions in the marker, so this row reports what the marker really carries and nothing
        # more. `games` is NOT reliably an array: Windows PowerShell's ConvertTo-Json unwraps a
        # one-element array to a bare string, so a machine verified for exactly one game can have
        # written "games": "f4". @() around the VALUE normalises both shapes -- @() around the
        # pipeline would not, because it keeps an already-array as a single nested element.
        $games = @()
        $gv = Get-JsonField $rec 'games'
        if ($null -ne $gv) { $games = @($gv) | Where-Object { "$_".Trim() } }
        $verifiedAt = Get-JsonField $rec 'verifiedAt'
        $ghidraUsed = Get-JsonField $rec 'ghidra'
        if ($games.Count) {
            $analysisOk = $true
            $analysisDetail = "verified for: $($games -join ', ')"
            if ("$verifiedAt".Trim()) { $analysisDetail += "; recorded $verifiedAt" }
            if ("$ghidraUsed".Trim()) { $analysisDetail += "; against tools\$ghidraUsed" }
            $analysisDetail += " [$analysisMarker]"
        }
        else {
            $analysisDetail = "$analysisMarker exists but records no verified game -- a run that never reached its own verdict. Re-run setup\35-ghidra-analysis.ps1."
        }
    }
}
Check 'analysis' 'BethesdaGhidraScripts analysis verified' $analysisOk $analysisDetail -Optional

# x64dbg. Detail carries the path that was looked at: a bare FAIL with an empty column sends the
# reader back into this file to find out WHERE it looked, which is the one thing the row already
# knew.
$x64dbgExe = Join-Path $ToolsDir 'x64dbg\x96dbg.exe'
$x64dbgThere = Test-Path $x64dbgExe
$x64dbgDetail = "no $x64dbgExe -- run setup\40-x64dbg.ps1"
if ($x64dbgThere) { $x64dbgDetail = $x64dbgExe }
Check 'x64dbg' 'install' $x64dbgThere $x64dbgDetail

$dp64Dir = Join-Path $ToolsDir 'x64dbg\x64\plugins'
$dp64 = @(Get-ChildItem $dp64Dir -Filter '*.dp64' -ErrorAction SilentlyContinue)
$dp64Detail = "no *.dp64 under $dp64Dir -- run setup\40-x64dbg.ps1"
if ($dp64.Count) { $dp64Detail = "$dp64Dir : " + (($dp64 | Select-Object -ExpandProperty Name) -join ', ') }
Check 'x64dbg' 'MCP plugin x64' ($dp64.Count -gt 0) $dp64Detail

# ---------------------------------------------------------------- delegated gates
# ASK THE SCRIPT THAT OWNS THE GATE. Move 2's rule was one predicate consumed by every caller,
# because the weakest copy otherwise silently decides; the same rule applies one level up.
# 10-vcpkg.ps1, 20-repos.ps1 and 35-ghidra-analysis.ps1 each already answer "is my phase done?"
# with -CheckOnly, and every answer this file re-derived by hand was a second, weaker copy of one
# of theirs -- the repo rows above still cannot tell alandtse/BethesdaGhidraScripts from
# 1001Bits/BethesdaGhidraScripts, which is precisely what 20-repos.ps1 -CheckOnly exists to say.
#
# IN A CHILD POWERSHELL, ALWAYS. -CheckOnly is read-only with respect to the MACHINE but not with
# respect to the process: 10-vcpkg.ps1 -CheckOnly calls Set-Item env:VCPKG_ROOT to align the
# running shell with the registry, and running any of these in-process would also destroy this
# script's $LASTEXITCODE -- the very thing being read. A child gets its own environment block and
# its own exit code, and 90-verify stays a reader of state rather than a participant in it.
#
# NOT DELEGATED: 00-prereqs.ps1 -CheckOnly. Its checks are the same Test-CmdRuns calls the
# toolchain rows at the top of this file already make, so a second pass would re-run every
# winget-installed tool probe and learn nothing new while doubling the slowest part of the run.
# The asymmetry is deliberate, not an oversight.
#
# EXIT 2 IS NOT A FAILURE. 20-repos.ps1 and 35-ghidra-analysis.ps1 both document it as "work is
# pending", and for 35 that is the normal state of most machines -- the analysis is hours per
# binary. Mapping it to FAIL would turn every healthy machine red, which is finding 37 again in
# a new place.

<#
.SYNOPSIS
    Run a setup script's -CheckOnly gate in a child Windows PowerShell; never throw, never block
    forever. Returns @{ ExitCode; Output; StdOut; Command }.

.DESCRIPTION
    Deliberately NOT Invoke-ProbeCapture from _common.ps1. That runner waits for the process with
    no timeout, which is correct for the known-terminating --version probes it was written for
    and wrong for a whole setup script, which can block on a prompt, a network call or a lock.
    Delegation is what turned this read-only script into something that spawns processes, and a
    hung child must cost it one FAIL row, not the run.

    The child's stdin is closed immediately, so anything that tries to read a keypress sees EOF
    and gives up instead of waiting on a console nobody is watching. Both output pipes are read
    asynchronously: draining one to the end synchronously deadlocks the moment the child fills
    the other one's buffer, and these scripts are chatty.

    ExitCode is $null when the child could not be launched or had to be killed; Output then
    carries the reason, and Command is always the exact line a human can re-run by hand.

    Output is both pipes concatenated (what a human running the command by hand would see);
    StdOut is stdout ALONE, because for the one-line summary the two are not interchangeable --
    see Get-GateSummary.
#>
function Invoke-GateScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Script,
        [string[]]$GateArgs = @(),
        [int]$TimeoutSec = 180
    )
    # $PSHOME, not a bare 'powershell': this pack is Windows PowerShell 5.1 only and CI parses
    # every .ps1 under 5.1, so resolving the interpreter off PATH -- where pwsh 7 sits on plenty
    # of machines -- would run these gates under a shell they were never tested against.
    $psExe = Join-Path $PSHOME 'powershell.exe'
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Script) + $GateArgs
    $quoted = @($all | ForEach-Object {
            $a = "$_"
            if ($a -match '[\s"]') {
                # A run of backslashes immediately before the CLOSING quote is consumed as an
                # escape by the Windows command-line parser rather than passed through, so
                # `-Root "C:\my repos\"` reaches the child as `C:\my repos"` -- and the gate then
                # reports on a directory nobody has, which is a red row aimed at the wrong
                # subsystem. Doubling the run makes it literal. Only QUOTED arguments are
                # affected, which is why a plain -Root C:\repos\ never showed it.
                $a = $a -replace '(\\+)$', '$1$1'
                '"' + $a + '"'
            }
            else { $a }
        })
    $shown = '"' + $psExe + '" ' + ($quoted -join ' ')

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $psExe
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true

    $proc = $null
    try { $proc = [Diagnostics.Process]::Start($psi) }
    catch { return @{ ExitCode = $null; Output = "could not be launched: $($_.Exception.Message)"; StdOut = ''; Command = $shown } }
    try {
        try { $proc.StandardInput.Close() } catch { }
        $so = $proc.StandardOutput.ReadToEndAsync()
        $se = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
            try { $proc.Kill() } catch { }
            return @{ ExitCode = $null; Output = "did not exit within $TimeoutSec s; the child was killed"; StdOut = ''; Command = $shown }
        }
        # BOUND THE DRAIN TOO. The timed overload above returns the moment the process OBJECT
        # exits; the untimed one is the usual way to let the redirected readers finish -- but it
        # waits on the pipe HANDLES, which any grandchild that inherited them keeps open after the
        # child itself is gone, and it takes no timeout. So the wait that exists to stop a hung
        # gate from taking this read-only script down was itself unbounded: measured, a stub that
        # Start-Process'es a sleeping grandchild and then exits blocked this function past 30 s
        # with the child already reaped and $TimeoutSec long since satisfied. Wait on the reader
        # TASKS with a deadline instead and still return the exit code -- that is the contract;
        # the text is a convenience, and it says so below when it could not be collected.
        $drained = $false
        try { $drained = [Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($so, $se), 10000) }
        catch { $drained = $false }
        # Kept apart as well as together. Merged is what a human re-running the command sees, and
        # is what the FAIL-line scan wants; stdout alone is what the tail rule needs, because
        # these gates print their VERDICT on stdout while stderr carries whatever a native tool or
        # an unhandled error record happened to emit. Concatenating and then taking the last line
        # reports that stray line as the gate's verdict (measured: a stub ending 'vcpkg ready.' on
        # stdout with any stderr at all summarised as its last stderr line instead).
        $outText = ''
        $errText = ''
        if ($drained) {
            try { $outText = "$($so.Result)" } catch { }
            try { $errText = "$($se.Result)" } catch { }
        }
        else {
            # Task.Result BLOCKS on an incomplete task, so reading it here would undo the bounded
            # wait above. Say what happened on stdout, where the tail rule will find it.
            $outText = 'the gate exited, but its output could not be collected: something it started still holds its output pipes open'
        }
        return @{ ExitCode = $proc.ExitCode; Output = "$outText`n$errText"; StdOut = $outText; Command = $shown }
    }
    finally { try { $proc.Dispose() } catch { } }
}

# Squeeze a gate's page of output into one table cell. The exit code is the CONTRACT and this
# text is a convenience, so everything here degrades to something harmless rather than guessing:
# the row always carries the exact command, and a reader who wants the full output runs it.
#
# Get-ProbeFirstLine from the probe layer is the wrong end of this output -- these scripts put
# their verdict LAST ('vcpkg ready.', 'All wanted repos are present and came from the pinned
# URLs.'), not first.
function Get-GateSummary([string]$text, [string]$stdout = '') {
    if (-not $text) { return '' }
    $lines = @("$text" -split '\r?\n' | ForEach-Object { $_.TrimEnd() } | Where-Object { $_.Trim() })
    if (-not $lines.Count) { return '' }

    # Prefer the probe layer's own alarm lines. Write-ProbeResult in _common.ps1 is the shared
    # display rule every -CheckOnly path prints through -- "  FAIL <name> <detail>" -- so this
    # finds WHAT is wrong without this file knowing anything about an individual gate's prose,
    # which is the coupling that would rot first. 35-ghidra-analysis.ps1 reports its status in
    # its own words rather than through Write-ProbeResult and so falls through to the tail below.
    $bad = @($lines | Where-Object { $_ -match '^\s*FAIL\s' } | Select-Object -First 2)
    $s = ''
    if ($bad.Count) { $s = ($bad | ForEach-Object { $_.Trim() }) -join ' / ' }
    else {
        # Just the tail, deliberately. A gate with no FAIL line has succeeded or is merely
        # pending, and in both cases its last line IS its verdict ('vcpkg ready.', 'All wanted
        # repos are present and came from the pinned URLs.', 'Nothing to do: analysis already
        # verified for f4.'). Stitching wrapped sentences back together was tried and dropped:
        # every rule for "is this line a continuation?" -- starts lowercase, previous line has
        # no terminator -- also matches 'vcpkg ready.' following 'OK: VCPKG_ROOT = C:\repos\vcpkg',
        # and glued two unrelated lines into one sentence that was never written.
        #
        # The tail is read off STDOUT alone. Every one of those verdicts is a Write-Host, and a
        # gate that also wrote anything to stderr -- a native tool's progress chatter, a
        # non-terminating error record -- would otherwise have that stray line reported as its
        # verdict purely because it was concatenated last.
        $tail = @("$stdout" -split '\r?\n' | ForEach-Object { $_.TrimEnd() } | Where-Object { $_.Trim() })
        if ($tail.Count) { $s = $tail[$tail.Count - 1].Trim() }
        else {
            # Nothing on stdout at all: the child died before it reached a verdict, so what is
            # left is an error record on stderr, and THAT one reads from the front -- its first
            # line is the exception's message ('BethesdaGhidraScripts not found at ...'), while
            # its last is the '+ FullyQualifiedErrorId : ...' boilerplate.
            $s = $lines[0].Trim()
        }
    }
    if ($s.Length -gt 240) { $s = $s.Substring(0, 240) + '...' }
    $s
}

# -States maps an exit code to a row state; ANY code not listed is a FAIL, which is what keeps a
# gate that grows a new exit code from being quietly absorbed as success. Non-PASS rows carry the
# command, because the next thing a reader does is run it themselves to see the full output this
# row compressed into one line.
function Add-GateRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Row,
        [Parameter(Mandatory)][string]$Script,
        [string[]]$GateArgs = @(),
        [hashtable]$States = @{}
    )
    $res = Invoke-GateScript -Script $Script -GateArgs $GateArgs
    if ($null -eq $res.ExitCode) {
        Add-Row 'gates' $Row 'FAIL' "$($res.Output). Run it yourself: $($res.Command)"
        return
    }
    $state = 'FAIL'
    if ($States.ContainsKey($res.ExitCode)) { $state = "$($States[$res.ExitCode])" }
    $detail = "exit $($res.ExitCode)"
    $summary = Get-GateSummary $res.Output $res.StdOut
    if ($summary) { $detail += " -- $summary" }
    if ($state -ne 'PASS') { $detail += " [$($res.Command)]" }
    Add-Row 'gates' $Row $state $detail
}

if ($Fast) {
    # Printed rather than omitted: a check that was not made must never be indistinguishable
    # from a check that passed, which is the whole thesis of this script.
    Add-Row 'gates' 'delegated -CheckOnly gates' 'skip' '-Fast was passed: 10-vcpkg.ps1, 20-repos.ps1 and 35-ghidra-analysis.ps1 were not asked'
}
else {
    # 10-vcpkg.ps1 -CheckOnly: 0 = ready, 1 = not. It is given no -VcpkgDir on purpose. With none
    # it adopts whatever healthy clone VCPKG_ROOT/VCPKG_INSTALLATION_ROOT already name, which is
    # the machine's real answer and the same clone the env rows above judged; passing one would
    # make it report on a directory nothing on this machine points at.
    Add-GateRow -Row 'phase 1: 10-vcpkg.ps1 -CheckOnly' -Script (Join-Path $PSScriptRoot '10-vcpkg.ps1') `
        -GateArgs @('-CheckOnly') -States @{ 0 = 'PASS' }

    # 20-repos.ps1 -CheckOnly: 0 = every pinned repo present AND cloned from the pinned URL,
    # 2 = work pending, 1 = git itself does not run so no identity question can be answered.
    # 'pending' rather than FAIL because a machine that took the documented -SkipAddressTools
    # path reports 2 here and is not broken.
    Add-GateRow -Row 'phase 2: 20-repos.ps1 -CheckOnly' -Script (Join-Path $PSScriptRoot '20-repos.ps1') `
        -GateArgs @('-CheckOnly', '-Root', $Root) -States @{ 0 = 'PASS'; 2 = 'pending' }

    # 35-ghidra-analysis.ps1 -CheckOnly: 0 = nothing to do, 2 = work pending, 1 = failure.
    # GUARDED on the clone existing, because the script THROWS on its way in without one
    # ("BethesdaGhidraScripts not found at ... Run setup\20-repos.ps1 first") and a thrown child
    # would read as a broken gate rather than as a phase nobody has started.
    if (Test-Path $bgsRoot) {
        Add-GateRow -Row 'phase 4: 35-ghidra-analysis.ps1 -CheckOnly' -Script (Join-Path $PSScriptRoot '35-ghidra-analysis.ps1') `
            -GateArgs @('-CheckOnly', '-BgsRoot', $bgsRoot) -States @{ 0 = 'PASS'; 2 = 'pending' }
    }
    else {
        Add-Row 'gates' 'phase 4: 35-ghidra-analysis.ps1 -CheckOnly' 'skip' "not asked: there is no clone at $bgsRoot, and 35-ghidra-analysis.ps1 throws without one"
    }
}

# -Json promises VALID JSON on stdout with nothing interleaved, and -BuildTest runs three
# programs that write to the console. Route their output through here: to the host exactly as
# before when a human is reading the table, into the void when a machine is reading the JSON.
filter Out-Noise { if (-not $Json) { $_ | Out-Host } }

# end-to-end build test
if ($BuildTest) {
    $name = "smoketest$(Get-Random -Maximum 9999)"
    $tmp = Join-Path $env:TEMP 'starter-verify'
    New-Item -ItemType Directory -Force $tmp | Out-Null
    if (-not $Json) { Write-Host "Scaffolding + building $name (this takes a few minutes on first vcpkg restore) ..." }
    try {
        # *>&1 rather than a plain pipe: New-Plugin.ps1 reports with Write-Host, which is stream
        # 6 and would reach stdout untouched by a success-stream redirect.
        & (Join-Path $PSScriptRoot '..\New-Plugin.ps1') -Name $name -Game F4VR -Dir $tmp *>&1 | Out-Noise
        Push-Location (Join-Path $tmp $name)
        try {
            cmake --preset windows-vcpkg-vr *>&1 | Out-Noise
            if ($LASTEXITCODE -ne 0) { throw 'configure failed' }
            cmake --build buildvr --config Release *>&1 | Out-Noise
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

if ($Json) {
    # -InputObject, NOT the pipeline. Piping @($oneRow) into ConvertTo-Json unrolls the array and
    # emits a bare OBJECT under Windows PowerShell 5.1, so an agent written to index [0] would
    # break on exactly the machine that had only one row to report -- the rarest case, found
    # last, at the worst moment. -InputObject preserves the array in every case.
    #
    # Write-Output, and every other line in this script that talks to a human is guarded on
    # -not $Json below, because the contract is JSON on stdout with NOTHING interleaved: one
    # stray Write-Host and the caller's ConvertFrom-Json throws on the whole run.
    Write-Output (ConvertTo-Json -InputObject @($rows) -Depth 4)
}
else {
    # -Wrap, not just -AutoSize: Detail now carries the probes' own diagnostics, and -AutoSize
    # alone TRUNCATES the last column to the console width. At a normal 120-column terminal that
    # cut landed mid-sentence -- "...alias stub answering, not an installed tool. Install it, or
    # turn the alias off under Settings > ..." and "(PATH java is <other JDK>, which gradlew.bat
    # does NOT use)" both fell off the right edge, which is precisely the text the rows exist to
    # deliver. Wrapping makes the table taller and complete instead of tidy and useless.
    $rows | Format-Table -AutoSize -Wrap
}
# Only FAIL gates -- 'skip', 'pending' and 'idle' are states this table can now name, and naming
# them is what earns the right to treat a FAIL as a real failure.
$failed = @($rows | Where-Object OK -eq 'FAIL')
if ($failed.Count) {
    # The old message hedged: "Optional items (vr_address_tools) may be intentional skips." That
    # sentence was the script admitting it could not tell a deliberate skip from a breakage --
    # while the manifest it already parses had recorded guiDeployed, and README.md had documented
    # -SkipAddressTools, all along. The rows carry that answer now, so the prose stops apologising
    # and just names what failed.
    # Area-qualified, because 'install' is the name of two different rows (ghidra and x64dbg)
    # and a bare list naming it twice tells the reader nothing about which one to go look at.
    if (-not $Json) { Write-Host "$($failed.Count) check(s) failed: $(($failed | ForEach-Object { "$($_.Area)/$($_.Check)" }) -join ', ')" }
    exit 1
}
if (-not $Json) { Write-Host 'Environment verified.' }

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
