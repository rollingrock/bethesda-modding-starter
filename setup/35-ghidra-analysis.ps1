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
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $BgsRoot)) {
    throw "BethesdaGhidraScripts not found at $BgsRoot. Run setup\20-repos.ps1 first."
}

$exesRoot    = Join-Path $BgsRoot 'exes'
$projectGpr  = Join-Path $BgsRoot 'ghidraprojects\BethesdaGhidraScripts\BethesdaGhidraScripts.gpr'
$ghidraDir   = Join-Path $BgsRoot 'tools\ghidra'

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

Write-Host ''
Write-Host "BethesdaGhidraScripts at $BgsRoot"
Write-Host ("  tools (Ghidra/Clang/...) : " + $(if ($toolsReady) { 'installed' } else { 'MISSING -> menu 1' }))
Write-Host ("  CommonLib submodules     : " + $(if ($submodsReady) { 'restored' } else { 'MISSING -> menu 2' }))
Write-Host ("  Ghidra project           : " + $(if ($projectReady) { 'created' } else { 'not created -> menu 7' }))
Write-Host ''
if ($staged.Count -eq 0) {
    Write-Host '  No game executables staged under exes\. Nothing to analyze.'
    Write-Host '  Stage them as exes\<game>\<ver>\<Game>.exe -- see the BGS README for the exact'
    Write-Host '  paths. The binaries come from your own game installs; they cannot be downloaded.'
    exit 0
}
Write-Host '  Staged binaries:'
foreach ($s in $staged) { Write-Host ("    {0,-10} {1,-6} {2}" -f $s.Game, $s.Version, $s.Exe) }

if ($OnlyGame) {
    $match = @($staged | Where-Object { $_.Game -eq $OnlyGame })
    if ($match.Count -eq 0) {
        throw "-OnlyGame '$OnlyGame' matches nothing staged. Staged games: $(($staged.Game | Select-Object -Unique) -join ', ')"
    }
    Write-Host ''
    Write-Host ("  Scoped to '{0}' ({1} binary/binaries); others are moved aside for the run." -f $OnlyGame, $match.Count)
}

# ---- Decide the menu sequence ----
$steps = @()
if (-not $toolsReady)   { $steps += '1' }
if (-not $submodsReady) { $steps += '2' }
if ((-not $projectReady) -or $Force) { $steps += '7' }

Write-Host ''
if ($steps.Count -eq 0) {
    Write-Host '  Nothing to do: tools, submodules and the Ghidra project are all present.'
    Write-Host '  Re-run with -Force to rebuild the analysis anyway.'
    exit 0
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

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $BgsRoot
    try {
        & cmd /c "python run.py < `"$keyFile`""
        $rc = $LASTEXITCODE
    }
    finally {
        Pop-Location
        $ErrorActionPreference = $prevEap
        Remove-Item $keyFile -Force -ErrorAction SilentlyContinue
    }

    Write-Host ''
    Write-Host ("  run.py exit=$rc")
    if ($rc -ne 0) {
        Write-Warning 'run.py reported a non-zero exit. Check its output above before trusting the project.'
    }
}
finally {
    Restore-HeldExes
}

# ---- Report the outcome ----
$projectNow = Test-Path $projectGpr
Write-Host ''
Write-Host ("  Ghidra project: " + $(if ($projectNow) { "created ($projectGpr)" } else { 'STILL NOT CREATED' }))
if (-not $projectNow) {
    Write-Host '  The analysis did not produce a project. Re-run and read run.py output; a failed'
    Write-Host '  step there prompts for retry, which this script answers with EOF (i.e. gives up).'
    exit 1
}
Write-Host ''
Write-Host 'Next: setup\30-ghidra.ps1 builds the MCP extension against this Ghidra, then open'
Write-Host 'Ghidra (BGS menu 6) and start the MCP server. See CLAUDE.md Phase 4.'
