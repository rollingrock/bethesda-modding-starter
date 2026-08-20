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
    game: the others are moved aside into .exes-held for the duration and restored afterwards.
    The planned moves are written to .exes-held\.restore.json BEFORE anything is moved, and
    EVERY run of this script restores from that record on the way in. So the borrowed binaries
    come back not only on failure or Ctrl-C (the finally block) but also after a hard kill --
    a closed terminal window, Stop-Process, a power cut, or a Windows Update reboot partway
    through an hours-long analysis -- none of which ever reach a finally block.

    THIS IS SLOW. Ghidra auto-analysis is hours per binary. Run it detached (or overnight) and
    do not interrupt it. -CheckOnly is instant.

.EXAMPLE
    .\setup\35-ghidra-analysis.ps1 -CheckOnly
    .\setup\35-ghidra-analysis.ps1 -OnlyGame f4
#>
[CmdletBinding()]
param(
    [string]$BgsRoot = 'C:\repos\BethesdaGhidraScripts',

    # Report what would run; start nothing. Exit 0 = nothing to do, 2 = work is pending.
    # The one thing it does change is repairing a previous run's damage: binaries stranded
    # under .exes-held by an interrupted -OnlyGame run are moved back before the staging scan
    # reads exes\ (see the custody-record block below). Withholding that here would make
    # -CheckOnly report "nothing to do" for a game whose binary it had just declined to
    # reclaim -- the silent-loss answer this record exists to prevent.
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
$ProjectName = 'BethesdaGhidraScripts'
$projectRoot = Join-Path $BgsRoot "ghidraprojects\$ProjectName"

# ---- Custody record for borrowed game binaries ----
# -OnlyGame moves the other games' staged binaries aside so option 7 does not analyze them.
# Those are the user's own game installs -- they cannot be re-downloaded -- so the move has to
# be reversible by a LATER process, not just by this one's finally block. The run that needs
# holding is by definition the slow one (hours per binary, documented above as "run it
# detached (or overnight)"), which is exactly the run a closed terminal window, a Stop-Process,
# a power cut or a Windows Update reboot interrupts, and none of those unwind a finally.
# So the planned moves go on disk BEFORE anything moves, and every run reads that record back.
#
# These live here, above the staging scan, only because the self-heal below has to run before
# the scan -- PowerShell binds function calls at runtime in script order, so the definition
# must precede the call.
$holdRoot   = Join-Path $BgsRoot '.exes-held'
$restoreLog = Join-Path $holdRoot '.restore.json'

# Puts back everything the record says is held, and returns how many it moved. Cheap and safe
# to call when nothing is held: no record file means nothing to do.
function Restore-HeldExes {
    if (-not (Test-Path $script:restoreLog)) { return 0 }

    $entries = @()
    try {
        # Windows PowerShell 5.1's ConvertFrom-Json hands a JSON array back as ONE object
        # rather than enumerating it, so @( ...| ConvertFrom-Json ) collects a single nested
        # Object[] and the loop below runs ONCE with $m bound to the whole set. $m.From then
        # member-enumerates to an ARRAY of paths, Test-Path returns an array of booleans, and
        # a non-empty array is truthy -- so every entry looks "re-staged" and nothing is ever
        # restored. Wrap the VARIABLE, not the pipeline: @($alreadyAnArray) keeps its length.
        $parsed  = Get-Content $script:restoreLog -Raw -Encoding UTF8 | ConvertFrom-Json
        $entries = @($parsed)
    }
    catch {
        # Never guess. Without the record we do not know where these belong, and deleting or
        # relocating a game binary on a hunch is the failure this whole record exists to avoid.
        Write-Warning ("Held-binary record $($script:restoreLog) is unreadable: " + $_.Exception.Message)
        Write-Warning ("  Move the .exe files under $($script:holdRoot) back into exes\ by hand, then " +
                       "delete that record. Nothing here will touch them.")
        return 0
    }

    # An entry missing either end of the move is as useless as an unreadable file, and worse
    # than useless here: Test-Path on a null path throws, and this function also runs from a
    # finally block where that would replace whatever error was actually being reported.
    if (@($entries | Where-Object { -not $_.From -or -not $_.To }).Count) {
        Write-Warning ("Held-binary record $($script:restoreLog) has incomplete entries; nothing was restored.")
        Write-Warning ("  Move the .exe files under $($script:holdRoot) back into exes\ by hand, then " +
                       "delete that record.")
        return 0
    }

    $restored  = 0
    $stillHeld = 0
    foreach ($m in $entries) {
        # Missing source = already restored by an earlier run, or the crash beat the move.
        # Recording a move that never happened is harmless; this is why we record first.
        if (-not (Test-Path $m.From)) { continue }
        # No -Force, ever, in this direction. A target that exists again means the user
        # re-staged that binary while ours was held aside, so their copy is the live one --
        # overwriting it would destroy a file this script did not create. Keep both, say so,
        # and leave the entry in the record so the state stays visible.
        if (Test-Path $m.To) {
            Write-Warning ("Not restoring $($m.From): $($m.To) exists again -- it was re-staged since " +
                           "the run that moved it started.")
            Write-Host   ('    Both copies are on disk; keep whichever one you want and delete the other.')
            $stillHeld++
            continue
        }
        New-Item -ItemType Directory -Force (Split-Path $m.To) | Out-Null
        Move-Item $m.From $m.To
        $restored++
    }

    # Drop the record only after a COMPLETE restore. While anything is still held, this file is
    # the only thing on disk that knows where it belongs, so the next run must still find it.
    if ($stillHeld -eq 0) {
        Remove-Item $script:restoreLog -Force -ErrorAction SilentlyContinue
        if ((Test-Path $script:holdRoot) -and -not (Get-ChildItem $script:holdRoot -Recurse -File)) {
            Remove-Item $script:holdRoot -Recurse -Force
        }
    }
    return $restored
}

# Self-heal before anything else looks at exes\. This repairs damage left by a previous run
# rather than starting work, so it happens even under -CheckOnly (which still cannot start an
# analysis -- its early exit is below and no move happens before it). It has to happen BEFORE
# the staging scan because that scan only looks under exes\: a binary stranded in .exes-held
# would otherwise just be absent from the staged table, the run would report success for the
# one game it did analyze, and the user's un-redownloadable copy of the other game would have
# left the pipeline with nothing ever mentioning it.
$strandedRestored = Restore-HeldExes
if ($strandedRestored -gt 0) {
    Write-Host ''
    Write-Host ("Restored {0} game binar{1} stranded by an interrupted -OnlyGame run (from {2})." -f $strandedRestored, $(if ($strandedRestored -eq 1) { 'y' } else { 'ies' }), $holdRoot)
}

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
# $holdRoot, $restoreLog and Restore-HeldExes are defined near the top of the script instead of
# here, because the self-heal that reclaims a previous run's held binaries has to run before
# the staging scan. See the custody-record block up there for why the record exists at all.
try {
    if ($OnlyGame) {
        $newMoves = @()
        foreach ($s in $staged | Where-Object { $_.Game -ne $OnlyGame }) {
            $rel = $s.Exe.Substring($exesRoot.Length).TrimStart('\')
            $newMoves += [pscustomobject]@{ From = (Join-Path $holdRoot $rel); To = $s.Exe }
        }
        if ($newMoves.Count) {
            # A record can outlive the self-heal above: the restore refuses to overwrite a
            # binary the user re-staged and leaves that entry held. The record has to describe
            # EVERYTHING currently under .exes-held or that leftover is stranded all over
            # again, so carry the surviving entries forward rather than overwriting the file.
            $carried = @()
            if (Test-Path $restoreLog) {
                $prior = $null
                # No @() around the pipeline here either -- see Restore-HeldExes. Wrapping it
                # would nest the whole record inside one element, and ConvertTo-Json below
                # would then write a record nested one level too deep for any future run to
                # read back.
                try { $prior = Get-Content $restoreLog -Raw -Encoding UTF8 | ConvertFrom-Json }
                catch {
                    throw ("Cannot read the held-binary record $restoreLog, and overwriting it would " +
                           "strand whatever is under $holdRoot. Move those .exe files back under exes\ " +
                           "by hand, delete the record, then re-run.")
                }
                $carried = @(@($prior) | Where-Object { $_ -and $_.From -and (Test-Path $_.From) })
            }
            New-Item -ItemType Directory -Force $holdRoot | Out-Null
            # Written BEFORE the first Move-Item, deliberately. A crash after a move but before
            # the record would leave a binary sitting outside exes\ with nothing on disk saying
            # where it came from -- which is the exact way these get lost. The other order is
            # harmless: the restore skips any entry whose source never appeared.
            # A carried entry and a new move can name the same held path (the user re-staged a
            # binary we are still holding). Keep one entry per held path so a run that is
            # refused below and retried does not grow the record -- and its warnings -- forever.
            $record = @()
            $seen   = @{}
            foreach ($m in @($carried + $newMoves)) {
                if ($seen.ContainsKey($m.From)) { continue }
                $seen[$m.From] = $true
                $record += $m
            }
            ConvertTo-Json @($record) | Set-Content $restoreLog -Encoding UTF8
            foreach ($m in $newMoves) {
                if (Test-Path $m.From) {
                    throw ("$($m.From) already exists -- an earlier interrupted run is still holding a " +
                           "copy of $($m.To). Overwriting it would destroy a game binary this script did " +
                           "not create. Decide which copy you want, delete the other, then re-run.")
                }
                New-Item -ItemType Directory -Force (Split-Path $m.From) | Out-Null
                Move-Item $m.To $m.From
            }
        }
    }

    # ---- Drive the menu ----
    # PowerShell has no stdin redirect for native commands, so hand the key sequence to cmd.
    # A trailing 'q' leaves the menu cleanly; run.py also treats EOF as quit.
    # run.py ships proper subcommands for the main path -- `setup` (menu 1+2), `build`
    # (menu 7), `all`, `clean` -- so use those rather than feeding menu keys. Only the
    # improve pass (menu 9) has no subcommand and still needs stdin.
    $subcommands = @()
    if (($steps -contains '1') -or ($steps -contains '2')) { $subcommands += 'setup' }
    if ($steps -contains '7') { $subcommands += 'build' }
    Write-Host ''
    Write-Host ("  run.py subcommands: " + ($subcommands -join ', ') + "  (this is the slow part)")
    Write-Host ''

    $runLog = Join-Path $env:TEMP ("bgs-run-" + [Guid]::NewGuid().ToString('N') + ".log")
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $rc = 0
    Push-Location $BgsRoot
    try {
        foreach ($sub in $subcommands) {
            Write-Host "  -> python run.py $sub"
            & python run.py $sub 2>&1 | Tee-Object -FilePath $runLog -Append
            if ($LASTEXITCODE -ne 0) { $rc = $LASTEXITCODE; break }
        }
    }
    finally {
        Pop-Location
        $ErrorActionPreference = $prevEap
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
    # The fast path back: a normal exit, a throw, or Ctrl-C restores here immediately. It is no
    # longer the ONLY path -- the record on disk plus the self-heal at the top cover the kills
    # that never reach a finally. The count it returns is only interesting to the self-heal.
    Restore-HeldExes | Out-Null
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

# ---- Export symbols (this is what Phase 5 consumes) ----
# scripts/core/symbol_export.py is scriptable and turns the named project into a .dd64
# x64dbg database, a .map, and a full .symbols.json with prototypes. Menu 10 wraps the same
# code behind prompts. Without this the analysis stays locked inside Ghidra.
if (-not $SkipImprove -and $programs -and $programs.Count) {
    $symRoot = Join-Path $BgsRoot 'symbols'
    Write-Host ''
    Write-Host '  Exporting symbols (.dd64 for x64dbg, .map, .symbols.json) ...'
    foreach ($t in $targets) {
        $leaf = ($t.Path -split '/')[-1] -replace '\.unpacked\.exe$', '.exe'
        $slug = ($t.Path.Trim('/') -replace '/', '-') -replace '\.exe.*$', ''
        $outDir = Join-Path $symRoot $slug
        New-Item -ItemType Directory -Force $outDir | Out-Null
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Push-Location $BgsRoot
        try {
            & python scripts\core\symbol_export.py $projectRoot $ProjectName $t.Path $outDir `
                --module $leaf --signatures 2>&1 |
                Where-Object { $_ -match 'functions:|wrote:|ERROR|Error' } |
                ForEach-Object { Write-Host ("      " + $_) }
        }
        finally { Pop-Location; $ErrorActionPreference = $prevEap }
    }
    Write-Host ("    symbols under $symRoot")
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

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
