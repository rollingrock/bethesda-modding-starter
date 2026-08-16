<#
.SYNOPSIS
    Decide whether BethesdaGhidraScripts analysis is needed, and run it unattended.

.DESCRIPTION
    Phase 4's enriched analysis database is what makes Ghidra decompiles readable (CommonLib
    types, vtables, signatures, address-library names instead of FUN_*). BGS ships an
    interactive menu, but the menu items this needs take no input of their own -- option 1
    (prereqs), 2 (submodules) and 7 (full rebuild) each run straight through, and 7 discovers
    every staged .exe by itself. So the whole pipeline can be driven by feeding menu keys on
    stdin, which is what this script does.

    It reports what is missing before it touches anything, so an agent can answer "does Ghidra
    need to run for this game?" with -CheckOnly and never start an hours-long job by accident.

    SCOPE IS THE exes/ TREE. Option 7 processes every staged binary. Use -OnlyGame to run one
    game: the others are moved aside for the duration and restored afterwards, including on
    failure or Ctrl-C.

    THIS IS SLOW. Ghidra auto-analysis is hours per binary. Run it detached (or overnight) and
    do not interrupt it. -CheckOnly is instant.

.EXAMPLE
    .\setup\35-ghidra-analysis.ps1 -CheckOnly
    .\setup\35-ghidra-analysis.ps1 -OnlyGame f4
#>
[CmdletBinding()]
param(
    [string]$BgsRoot = 'C:\repos\BethesdaGhidraScripts',

    # Report what would run; change nothing. Exit 0 = nothing to do, 2 = work is pending.
    [switch]$CheckOnly,

    # Restrict the run to one game directory under exes\ (skyrim, f4, starfield, fnv).
    [string]$OnlyGame = '',

    # Re-run the analysis even when a Ghidra project already exists.
    [switch]$Force,

    # Skip the menu-9 improve pass (CommonLib apply + RTTI vtable walk + reconciler).
    # That pass is what makes a VR-only setup worth anything -- see the note below.
    [switch]$SkipImprove
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $BgsRoot)) {
    throw "BethesdaGhidraScripts not found at $BgsRoot. Run setup\20-repos.ps1 first."
}

# BGS installs clang to tools\llvm\bin but resolves it as a bare "clang" on PATH
# (run.py's _clang_version() takes no executable for the status panel and for script
# generation). Menu 1 only appears to work because it checks the explicit path and mutates
# PATH inside that one process; a later process sees no clang, prints "Clang: not installed",
# and SILENTLY SKIPS generating the import scripts -- the run then imports binaries and ports
# nothing, with no error. Put it on PATH for every child process we spawn.
$llvmBin = Join-Path $BgsRoot 'tools\llvm\bin'
if ((Test-Path (Join-Path $llvmBin 'clang.exe')) -and ($env:PATH -notlike "*$llvmBin*")) {
    $env:PATH = "$llvmBin;$env:PATH"
}

$exesRoot    = Join-Path $BgsRoot 'exes'
$projectGpr  = Join-Path $BgsRoot 'ghidraprojects\BethesdaGhidraScripts\BethesdaGhidraScripts.gpr'
$ghidraDir   = Join-Path $BgsRoot 'tools\ghidra'
# The .gpr is NOT evidence of a good analysis: Ghidra creates the project and imports the
# binary before the CommonLib enrichment runs, and a failed post-import verification rolls the
# enrichment back while leaving a multi-hundred-MB project behind. Nothing on disk
# distinguishes "enriched" from "imported then rolled back", so record our own verdict.
$markerPath  = Join-Path $BgsRoot '.analysis-verified.json'

# ---- What is staged? (mirrors BGS's own _discover_exes: exes\<game>\<ver>\*.exe) ----
$staged = @()
if (Test-Path $exesRoot) {
    foreach ($gameDir in Get-ChildItem $exesRoot -Directory | Sort-Object Name) {
        foreach ($verDir in Get-ChildItem $gameDir.FullName -Directory | Sort-Object Name) {
            $exe = @(Get-ChildItem $verDir.FullName -Filter '*.exe' -File |
                Where-Object { $_.Name -notlike '*unpacked*' })
            if ($exe.Count -gt 1) {
                throw "Ambiguous target dir $($verDir.FullName): found $($exe.Name -join ', ')"
            }
            if ($exe.Count -eq 1) {
                $staged += [pscustomobject]@{
                    Game    = $gameDir.Name
                    Version = $verDir.Name
                    Exe     = $exe[0].FullName
                }
            }
        }
    }
}

# ---- What is already done? ----
$toolsReady   = Test-Path $ghidraDir
$projectReady = Test-Path $projectGpr

# Ask git rather than guessing a path: `submodule status` prefixes uninitialised entries with
# '-', so any such line means menu 2 still has work. (BGS clones without submodules on
# purpose; its menu 2 restores the reviewed revisions.)
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$subStatus = @(git -C $BgsRoot submodule status --recursive 2>$null)
$subRc = $LASTEXITCODE
$ErrorActionPreference = $prevEap
$submodsReady = ($subRc -eq 0) -and $subStatus.Count -gt 0 -and
                -not ($subStatus | Where-Object { $_ -match '^\-' })

$verifiedGames = @()
if (Test-Path $markerPath) {
    try { $verifiedGames = @((Get-Content $markerPath -Raw | ConvertFrom-Json).games) } catch { $verifiedGames = @() }
}

Write-Host ''
Write-Host "BethesdaGhidraScripts at $BgsRoot"
Write-Host ("  tools (Ghidra/Clang/...) : " + $(if ($toolsReady) { 'installed' } else { 'MISSING -> menu 1' }))
Write-Host ("  CommonLib submodules     : " + $(if ($submodsReady) { 'restored' } else { 'MISSING -> menu 2' }))
Write-Host ("  Ghidra project           : " + $(if ($projectReady) { 'present' } else { 'not created' }))
Write-Host ("  Verified analysis for    : " + $(if ($verifiedGames.Count) { $verifiedGames -join ', ' } else { 'nothing yet' }))
Write-Host ''
if ($staged.Count -eq 0) {
    Write-Host '  No game executables staged under exes\. Nothing to analyze.'
    Write-Host '  Stage them as exes\<game>\<ver>\<Game>.exe -- see the BGS README for the exact'
    Write-Host '  paths. The binaries come from your own game installs; they cannot be downloaded.'
    exit 0
}
Write-Host '  Staged binaries:'
foreach ($s in $staged) { Write-Host ("    {0,-10} {1,-6} {2}" -f $s.Game, $s.Version, $s.Exe) }

# Fallout 4 coverage preflight. BGS ships address-library symbols for the flat builds; VR and
# OG get their function names by porting byte signatures ACROSS versions. With no NG/AE binary
# staged, an f4 run imports types but names ~nothing, and BGS's own ">=100 named functions"
# check then fails the run and rolls everything back -- after the full analysis has been paid
# for. Say so before that happens, not after.
$f4Versions   = @($staged | Where-Object { $_.Game -eq 'f4' } | Select-Object -ExpandProperty Version)
$f4TypesOnly  = @($f4Versions | Where-Object { $_ -in 'vr', 'og' })
$f4Donor      = @($f4Versions | Where-Object { $_ -in 'ng', 'ae', '221' })
if ($f4TypesOnly.Count -gt 0 -and $f4Donor.Count -eq 0) {
    Write-Host ''
    Write-Warning ("Fallout 4 " + ($f4TypesOnly -join '/') + " is staged with no flat NG/AE binary.")
    Write-Host '    F4 VR and OG use ID namespaces CommonLibF4 does not reference, so names can'
    Write-Host '    only arrive via the cross-version byte-signature port -- which needs an AE'
    Write-Host '    (or NG) binary to anchor on. Without one, option 7 imports types, names ~13'
    Write-Host '    functions, and its own >=100-named check rejects and rolls that apply back.'
    Write-Host '    This is NOT fatal: the improve pass (menu 9) then walks RTTI vtables in the VR'
    Write-Host '    binary itself and needs no donor -- measured here at 13 -> 34,507 named.'
    Write-Host '    Staging exes\f4\ae\Fallout4.exe (or \ng\) additionally unlocks the byte-sig'
    Write-Host '    port for real CommonLib function names on top of that.'
}

if ($OnlyGame) {
    $match = @($staged | Where-Object { $_.Game -eq $OnlyGame })
    if ($match.Count -eq 0) {
        throw "-OnlyGame '$OnlyGame' matches nothing staged. Staged games: $(($staged.Game | Select-Object -Unique) -join ', ')"
    }
    Write-Host ''
    Write-Host ("  Scoped to '{0}' ({1} binary/binaries); others are moved aside for the run." -f $OnlyGame, $match.Count)
}

# ---- Decide the menu sequence ----
# Which games does this invocation care about, and are they already verified?
$wantGames = if ($OnlyGame) { @($OnlyGame) } else { @($staged.Game | Select-Object -Unique) }
$unverified = @($wantGames | Where-Object { $_ -notin $verifiedGames })

$steps = @()
if (-not $toolsReady)   { $steps += '1' }
if (-not $submodsReady) { $steps += '2' }
if ($unverified.Count -or $Force) { $steps += '7' }

Write-Host ''
if ($steps.Count -eq 0) {
    Write-Host ("  Nothing to do: analysis already verified for " + ($wantGames -join ', ') + '.')
    Write-Host '  Re-run with -Force to rebuild it anyway.'
    exit 0
}
if ($unverified.Count) {
    Write-Host ("  Not yet verified: " + ($unverified -join ', '))
}
Write-Host ("  Menu sequence to run: " + ($steps -join ', '))
if ($steps -contains '7') {
    Write-Host '  NOTE: menu 7 runs Ghidra auto-analysis -- HOURS per binary. Do not interrupt it.'
}

if ($CheckOnly) {
    Write-Host ''
    Write-Host '  -CheckOnly: nothing was run.'
    exit 2
}

# ---- Scope the exes\ tree if asked ----
$holdRoot = Join-Path $BgsRoot '.exes-held'
$moved = @()
function Restore-HeldExes {
    foreach ($m in $script:moved) {
        if (Test-Path $m.From) {
            New-Item -ItemType Directory -Force (Split-Path $m.To) | Out-Null
            Move-Item $m.From $m.To -Force
        }
    }
    if ((Test-Path $script:holdRoot) -and -not (Get-ChildItem $script:holdRoot -Recurse -File)) {
        Remove-Item $script:holdRoot -Recurse -Force
    }
}

try {
    if ($OnlyGame) {
        foreach ($s in $staged | Where-Object { $_.Game -ne $OnlyGame }) {
            $rel  = $s.Exe.Substring($exesRoot.Length).TrimStart('\')
            $dest = Join-Path $holdRoot $rel
            New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
            Move-Item $s.Exe $dest -Force
            $moved += [pscustomobject]@{ From = $dest; To = $s.Exe }
        }
    }

    # ---- Drive the menu ----
    # PowerShell has no stdin redirect for native commands, so hand the key sequence to cmd.
    # A trailing 'q' leaves the menu cleanly; run.py also treats EOF as quit.
    $keyFile = Join-Path $env:TEMP ("bgs-keys-" + [Guid]::NewGuid().ToString('N') + ".txt")
    Set-Content $keyFile (($steps + 'q') -join "`n") -Encoding ascii
    Write-Host ''
    Write-Host ("  Driving run.py with: " + (($steps + 'q') -join ' ') + "  (this is the slow part)")
    Write-Host ''

    $runLog = Join-Path $env:TEMP ("bgs-run-" + [Guid]::NewGuid().ToString('N') + ".log")
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $BgsRoot
    try {
        & cmd /c "python run.py < `"$keyFile`"" 2>&1 | Tee-Object -FilePath $runLog
        $rc = $LASTEXITCODE
    }
    finally {
        Pop-Location
        $ErrorActionPreference = $prevEap
        Remove-Item $keyFile -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host ("  run.py exit=$rc")

    # run.py exits 0 even when a binary fails BGS's own post-import verification and every
    # importer change is rolled back. The .gpr also exists either way -- it is created before
    # the import runs. So neither the exit code nor the project file is a result; read the
    # report instead.
    $runOut = @(Get-Content $runLog -ErrorAction SilentlyContinue)
    Remove-Item $runLog -Force -ErrorAction SilentlyContinue
    $script:verifyFailures = @($runOut |
        Where-Object { $_ -match 'VERIFICATION FAILURES|post-import verification failed|^\s*FAILURES:' })
    $script:rolledBack = @($runOut | Where-Object { $_ -match 'changes were rolled back' })
    $script:namedLow   = @($runOut | Where-Object { $_ -match 'Named functions too low' })

    # run.py can also die outright -- a step raising inside generate_scripts kills the whole
    # menu with a Python traceback, long before any import or verification happens. That
    # leaves none of the markers above, so without this an aborted run reads as a clean pass.
    $script:crashed = @($runOut | Where-Object { $_ -match 'Traceback \(most recent call last\)|^\s*\w+Error: ' })
    if ($crashed.Count) {
        Write-Host ''
        Write-Warning 'run.py aborted with a Python traceback; the pipeline did not complete.'
        foreach ($l in @($runOut | Where-Object { $_ -match '^\s*\w+(Error|Exception): ' } | Select-Object -Last 3)) {
            Write-Host ("    $($l.Trim())")
        }
        Write-Host '    Nothing was verified. Fix the error above and re-run.'
        exit 1
    }
}
finally {
    Restore-HeldExes
}

# ---- Report the outcome ----
$projectNow = Test-Path $projectGpr
Write-Host ''
Write-Host ("  Ghidra project file: " + $(if ($projectNow) { 'present' } else { 'NOT CREATED' }))

if ($verifyFailures.Count -or $rolledBack.Count) {
    Write-Host ''
    Write-Warning 'BGS post-import verification FAILED; the importer changes were rolled back.'
    foreach ($l in ($verifyFailures + $namedLow | Select-Object -Unique)) { Write-Host ("    $($l.Trim())") }
    Write-Host ''
    Write-Host '  Expected when only a VR (or only an OG) Fallout 4 binary is staged: those two'
    Write-Host '  use ID namespaces CommonLibF4 does not reference, so names can only arrive via'
    Write-Host '  the cross-version byte-signature port, which needs an AE/NG binary to anchor on.'
    Write-Host '  The import and Ghidra auto-analysis DID survive -- only the name/type apply was'
    Write-Host '  rolled back -- so the improve pass below can still rescue this run.'
    $script:importRolledBack = $true
}

if (-not $projectNow) {
    Write-Host '  The analysis did not produce a project. Re-run and read run.py output; a failed'
    Write-Host '  step there prompts for retry, which this script answers with EOF (i.e. gives up).'
    exit 1
}

# ---- Menu 9: CommonLib apply + RTTI vtable walk + reconciler ----
# This is what rescues a VR-only setup. The RTTI walk derives names from vtables in the
# binary itself, so it needs no donor: on Fallout 4 VR with nothing else staged it took the
# program from 13 named functions out of 201,005 to 34,507 out of 216,903 (+34,494), and the
# changes were SAVED rather than rolled back. Run it whenever a run completed, whether or not
# option 7's own verification passed.
if (-not $SkipImprove) {
    Write-Host ''
    Write-Host '  Improve pass (menu 9: CommonLib apply + RTTI vtable walk + reconciler) ...'

    # Menu 9 wants a project index then a program index, and the program list depends on what
    # has been imported so far -- so ask it, rather than assuming index 1.
    $probeKeys = Join-Path $env:TEMP ("bgs-probe-" + [Guid]::NewGuid().ToString('N') + ".txt")
    Set-Content $probeKeys "9`n1`nb`nq`n" -Encoding ascii
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $BgsRoot
    try { $probe = @(& cmd /c "python run.py < `"$probeKeys`"" 2>&1) }
    finally { Pop-Location; $ErrorActionPreference = $prevEap; Remove-Item $probeKeys -Force -ErrorAction SilentlyContinue }

    # Lines look like:   1) /f4/vr/Fallout4VR.exe.unpacked.exe
    $programs = @()
    foreach ($line in $probe) {
        if ($line -match '^\s*(\d+)\)\s+(/\S+)') {
            $programs += [pscustomobject]@{ Index = $Matches[1]; Path = $Matches[2] }
        }
    }
    if ($programs.Count -eq 0) {
        Write-Warning '  Could not read the program list from menu 9; skipping the improve pass.'
    }
    else {
        $targets = if ($OnlyGame) { @($programs | Where-Object { $_.Path -match "^/$OnlyGame/" }) } else { $programs }
        if ($targets.Count -eq 0) { $targets = $programs }
        foreach ($t in $targets) {
            Write-Host ("    improving $($t.Path) (program $($t.Index)) ...")
            $keys = Join-Path $env:TEMP ("bgs-imp-" + [Guid]::NewGuid().ToString('N') + ".txt")
            # 9, project 1, program N, then 'Y' to the "Apply CommonLibImport first?" prompt.
            Set-Content $keys "9`n1`n$($t.Index)`nY`nq`n" -Encoding ascii
            $impLog = Join-Path $env:TEMP ("bgs-imp-" + [Guid]::NewGuid().ToString('N') + ".log")
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            Push-Location $BgsRoot
            try { & cmd /c "python run.py < `"$keys`"" 2>&1 | Tee-Object -FilePath $impLog | Out-Null }
            finally { Pop-Location; $ErrorActionPreference = $prevEap; Remove-Item $keys -Force -ErrorAction SilentlyContinue }

            $impOut = @(Get-Content $impLog -ErrorAction SilentlyContinue)
            Remove-Item $impLog -Force -ErrorAction SilentlyContinue
            $named = @($impOut | Where-Object { $_ -match 'named after:' }) | Select-Object -Last 1
            $delta = @($impOut | Where-Object { $_ -match '^\s*delta:' })   | Select-Object -Last 1
            if ($named) { Write-Host ("      $($named.Trim())") }
            if ($delta) { Write-Host ("      $($delta.Trim())") }
            if (-not $named) { Write-Warning "      no naming summary from the improve pass for $($t.Path)" }
        }
    }
}

Write-Host ''
if ($importRolledBack) {
    Write-Host '  Note: option 7 rolled its own type/name apply back; the improve pass above is'
    Write-Host '  what this project is carrying. That is expected for a VR-only Fallout 4 setup.'
}
else { Write-Host '  Post-import verification: passed.' }

# Only now is the analysis known good. Record it so a later -CheckOnly can answer "does this
# still need to run?" without re-deriving it from a project directory that cannot tell us.
$nowVerified = @($verifiedGames + $wantGames | Select-Object -Unique | Sort-Object)
[pscustomobject]@{
    games      = $nowVerified
    verifiedAt = (Get-Date).ToString('s')
    ghidra     = (Split-Path $ghidraDir -Leaf)
} | ConvertTo-Json | Set-Content $markerPath -Encoding ascii
Write-Host ("  Recorded verified analysis for: " + ($nowVerified -join ', '))

Write-Host ''
Write-Host 'Next: setup\30-ghidra.ps1 builds the MCP extension against this Ghidra, then open'
Write-Host 'Ghidra (BGS menu 6) and start the MCP server. See CLAUDE.md Phase 4.'
