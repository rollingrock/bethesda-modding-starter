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

    IT ALSO EXPORTS. The symbols Phase 5 (x64dbg) consumes are written here, not by a later
    script, and .analysis-verified.json records the directory each export actually wrote to
    (<bgs>\symbols\<game>-<ver>-<Name>\) so nothing downstream has to re-derive a path only
    this script knows. A run whose analysis is already recorded but whose export is not does
    the export ALONE -- minutes -- instead of needing -Force and a rebuild measured in hours.

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
    [switch]$SkipImprove,

    # Skip the symbol export (.dd64 for x64dbg, .map, .symbols.json) that Phase 5 consumes.
    # This exists because -SkipImprove used to do it as an undocumented side effect: the export
    # block was guarded by '-not $SkipImprove -and $programs', so skipping the naming pass also
    # skipped the only step that writes anything OUTSIDE Ghidra -- while the parameter help
    # promised it skipped "the menu-9 improve pass", and CLAUDE.md and docs\GHIDRA_WORKFLOW.md
    # both state flatly that this script writes the symbols Phase 5 consumes. The run then
    # recorded itself verified, so the NEXT run answered "Nothing to do" before reaching the
    # export at all: 40-x64dbg.ps1 said "run 35 first", 35 said there was nothing to do, and
    # -Force -- hours of re-analysis for a step that takes minutes -- was the only way out.
    [switch]$SkipExport
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"

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
# distinguishes "enriched" from "imported then rolled back", so record our own verdict --
# one entry per (game, VERSION), each field written only by the code that observed it. See
# ConvertFrom-MarkerFile below for the shape and for the legacy record it still has to read.
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
# The directory existing is not the toolchain being installed. Menu 1 unzips the Ghidra
# distribution into tools\ghidra, so a menu 1 killed mid-unzip -- or one that ran out of disk,
# or an older Ghidra left behind by a previous BGS revision -- leaves that directory sitting
# there and a bare Test-Path calls it done. Menu 1 is then skipped on the exact machine that
# needs it, and the failure lands HOURS later inside BethesdaGhidraScripts, against a Ghidra
# missing the modules the import needs. Worse, run.py reports that as its own "ERROR: ..."
# line and still exits 0, so it clears the traceback check below and the run reads as a pass.
# Ask the shared predicate instead of the filesystem: application.properties must parse, the
# processor modules -- which sit at the FAR end of the archive, where a truncated extraction
# stops -- must be present, and the jar count must clear a floor. A half-extracted tree is
# then NOT ready and menu 1 runs again. Measured at ~110ms on a real install, so -CheckOnly
# stays instant as documented above.
$ghidraProbe  = Test-GhidraInstallComplete -Path $ghidraDir
$toolsReady   = ($ghidraProbe.Status -eq 'OK')
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

# ---- What is already verified? ONE ENTRY PER (GAME, VERSION) ----
# The record used to store game names only -- {"games":["f4"]} -- while binaries are staged per
# (game, VERSION) under exes\<game>\<ver>\. So after one verified f4 run, staging the donor that
# CLAUDE.md and the warning block below BOTH tell a VR-only user to add (exes\f4\ae\Fallout4.exe,
# which is what unlocks the cross-version byte-signature port) left nothing unverified: this
# script printed "Nothing to do: analysis already verified for f4." and exited 0, on real runs
# and -CheckOnly alike, and that donor was never imported. The remediation the pack documents
# was silently a no-op, and nothing at any layer observed that a staged version never arrived.
#
# An entry therefore carries the pair plus the three things its consumers actually ask about,
# each set below by the code that OBSERVED it and by nothing else:
#   analyzed       the enrichment survived -- not that a .gpr exists, which it does either way
#   improvedNamed  the menu-9 pass ran AND its 'named after:' summary was parsed
#   exported       symbol_export.py exited 0; exportDir is where it wrote
function ConvertFrom-MarkerFile {
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @() }
    # Read the TEXT first, and check it before it reaches ConvertFrom-Json. Get-Content -Raw on a
    # zero-byte file hands back $null, and `$null | ConvertFrom-Json` raises a parameter BINDING
    # failure that try/catch does not catch -- measured on 5.1, EAP=Stop included. So a record
    # truncated by an interrupted write, a full disk or a killed process slipped past the handler
    # below and returned silently: no warning at all, "Verified analysis for: nothing yet", and
    # menu 7 -- hours -- prescribed for an analysis that may well be finished. A present-but-empty
    # record is a DAMAGED one, not an absent one, and the difference is worth a line.
    $text = Get-Content $Path -Raw -Encoding UTF8
    if (-not "$text".Trim()) {
        Write-Warning "Verification record $Path is present but EMPTY -- a truncated or interrupted write."
        Write-Warning ('  Treating it as empty. Nothing here will delete it -- move it aside ' +
                       'yourself if you want a clean record, or the run below will overwrite it.')
        return @()
    }
    $raw = $null
    try { $raw = $text | ConvertFrom-Json }
    catch {
        # Never let a parse failure read as "not verified". That answer costs hours of
        # re-analysis, so say what happened and leave the file alone for a human to look at.
        Write-Warning ("Verification record $Path is unreadable: " + $_.Exception.Message)
        Write-Warning ('  Treating it as empty. Nothing here will delete it -- move it aside ' +
                       'yourself if you want a clean record, or the run below will overwrite it.')
        return @()
    }
    if (-not $raw) { return @() }

    $out = @()
    # 5.1's ConvertFrom-Json hands a JSON array back as ONE object rather than enumerating it,
    # and ConvertTo-Json writes a single-element array as a bare object -- so a one-entry record
    # can arrive either way. @() around the VARIABLE (see Restore-HeldExes) normalises both.
    $entries = @()
    if ($raw.PSObject.Properties['entries']) { $entries = @($raw.entries) }
    foreach ($e in $entries) {
        if (-not $e -or -not $e.game) { continue }
        $ver = "$($e.version)".Trim()
        if (-not $ver) { $ver = '*' }
        # A missing property yields $null silently in 5.1, so compare rather than cast: -eq
        # $true reads an absent field as false instead of as [bool]$null's accidental truth.
        $out += [pscustomobject]@{
            game          = "$($e.game)"
            version       = $ver
            analyzed      = ($e.analyzed -eq $true)
            improvedNamed = ($e.improvedNamed -eq $true)
            exported      = ($e.exported -eq $true)
            exportDir     = "$($e.exportDir)"
            verifiedAt    = "$($e.verifiedAt)"
            # An entries-shape record can ALSO hold the wildcard, because that is how a migrated
            # legacy record is written back (see the migration below and the carry-forward at the
            # tail). Version '*' is the assumption, wherever it is stored: no run can record it
            # as an observation, since every version here is a directory name under exes\ and '*'
            # is not a legal one. Reading it back as an observation is what silently retired the
            # "ASSUMED verified:" disclosure after the FIRST run over a legacy marker -- the
            # record kept the guess and stopped saying it was one.
            legacy        = ($ver -eq '*')
        }
    }

    # LEGACY MARKERS ARE REAL AND MUST NOT COST HOURS. The machine this was written on carries
    # {"games":["f4"],"verifiedAt":"2026-08-15T21:53:55","ghidra":"ghidra"} -- an analysis that
    # took hours and left 13,055 applied prototypes behind it. A legacy game becomes the pair
    # (game, '*'), meaning "some version of this game was verified, we do not know which", and
    # Get-MarkerEntry lets '*' answer for every version of that game. So upgrading this script
    # can never re-run an analysis that is already done; what it cannot do is tell f4/vr from a
    # freshly staged f4/ae, which is why the pairs resolved that way are printed as an
    # assumption rather than as an observation.
    $games = @()
    if ($raw.PSObject.Properties['games']) { $games = @($raw.games | Where-Object { $_ }) }
    foreach ($g in $games) {
        if (@($out | Where-Object { $_.game -eq "$g" }).Count) { continue }
        $out += [pscustomobject]@{
            game          = "$g"
            version       = '*'
            analyzed      = $true
            # A legacy record says nothing about either of these, and false here is not a claim
            # that they did not happen. It is what makes the CHEAP half re-run once -- minutes
            # for the export, never the hours menu 7 costs -- so the pair ends up with an
            # exportDir that was observed rather than one 40-x64dbg.ps1 has to guess at.
            improvedNamed = $false
            exported      = $false
            exportDir     = ''
            verifiedAt    = "$($raw.verifiedAt)"
            legacy        = $true
        }
    }
    $out
}

# Exact beats wildcard, always. Once a real run has recorded (f4, vr) the migrated (f4, '*')
# must not be the entry that answers for it, or an OBSERVED exported/exportDir would be
# shadowed by the guess that was only ever there to avoid re-running the analysis.
function Get-MarkerEntry {
    [CmdletBinding()]
    param([psobject[]]$Entries, [string]$Game, [string]$Version)

    $hit = @($Entries | Where-Object { $_ -and $_.game -eq $Game -and $_.version -eq $Version })
    if ($hit.Count) { return $hit[0] }
    $hit = @($Entries | Where-Object { $_ -and $_.game -eq $Game -and $_.version -eq '*' })
    if ($hit.Count) { return $hit[0] }
    return $null
}

# One place that renders a pair list, because five messages below print one.
function Format-PairList {
    [CmdletBinding()]
    param([psobject[]]$Pairs)
    (@($Pairs | ForEach-Object { "$($_.Game)/$($_.Version)" }) -join ', ')
}

$markerEntries = @(ConvertFrom-MarkerFile $markerPath)

Write-Host ''
Write-Host "BethesdaGhidraScripts at $BgsRoot"
# Print what was OBSERVED, not the word 'installed'. That word over a half-extracted tree is
# the whole of this defect: it told the user the toolchain was fine right up to the point the
# build failed inside BGS. A version, a processor-module count and a jar count are something a
# human can compare against a working machine; on failure the probe's Detail names which of
# the three gave way, so 'menu 1' is a repair with a reason attached rather than a guess.
Write-Host ("  tools (Ghidra/Clang/...) : " + $(if ($toolsReady) { $ghidraProbe.Detail } else { 'NOT USABLE -> menu 1: ' + $ghidraProbe.Detail }))
Write-Host ("  CommonLib submodules     : " + $(if ($submodsReady) { 'restored' } else { 'MISSING -> menu 2' }))
Write-Host ("  Ghidra project           : " + $(if ($projectReady) { 'present' } else { 'not created' }))
$verifiedText = 'nothing yet'
# Only the entries this record calls ANALYZED. Unlike the game-name list it replaced, an entries
# record also holds pairs it could not verify -- the write below records analyzed=false for a
# staged pair that never reached the Ghidra project, which is exactly the observation the
# per-version record exists to make. Listing those here printed "Verified analysis for : f4/ae"
# three lines above "Not yet verified: f4/ae" (measured), and this is the line an agent reads to
# answer "has Phase 4 been done for this binary?".
$analyzedEntries = @($markerEntries | Where-Object { $_.analyzed })
if ($analyzedEntries.Count) {
    $verifiedText = (@($analyzedEntries | ForEach-Object {
        if ($_.legacy) { "$($_.game)/* (legacy record: version not stated)" } else { "$($_.game)/$($_.version)" }
    }) -join ', ')
}
Write-Host ("  Verified analysis for    : " + $verifiedText)
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
# Which (game, VERSION) pairs does this invocation care about, and what does the record say
# about each? Pair granularity IS the fix: at game granularity a newly staged version of an
# already-verified game is invisible, which is how the AE donor recommended twelve lines above
# could be staged, reported as already verified, and never imported.
$wantPairs = @($staged | Where-Object { (-not $OnlyGame) -or ($_.Game -eq $OnlyGame) })
# The same pairs as lookup keys, lower-cased once. BGS prints its verdicts lower-case
# ("f4/vr:") while its per-target headers are upper-case ("F4 / VR:"), so every pair key in
# this script is folded the same way or the two never meet.
$wantKeys = @{}
foreach ($p in $wantPairs) { $wantKeys[("$($p.Game)/$($p.Version)").ToLowerInvariant()] = $true }

$needAnalysis  = @()
$needExport    = @()
$exportGone    = @()
$assumedLegacy = @()
foreach ($p in $wantPairs) {
    $e = Get-MarkerEntry $markerEntries $p.Game $p.Version
    if (-not $e -or -not $e.analyzed) { $needAnalysis += $p; continue }
    if ($e.legacy) { $assumedLegacy += $p }
    if (-not $e.exported) { $needExport += $p; continue }
    # A recorded export whose directory is no longer on disk is not an export any more, and
    # treating it as one revives the 35 <-> 40 loop the fast path below exists to break, one
    # level deeper: with symbols\ deleted, moved, or restored from a backup that predates it,
    # 40-x64dbg.ps1 warns "exported, then moved or deleted" and sends the user HERE -- and this
    # script answered "Nothing to do: analysis already verified", exit 0. The two point at each
    # other again, with -Force -- hours of re-analysis -- the only way back to files the export
    # rewrites in minutes. The -or short-circuits left to right, and it has to: Test-Path on the
    # empty string throws under $ErrorActionPreference = 'Stop'.
    if ((-not $e.exportDir) -or (-not (Test-Path $e.exportDir))) {
        $needExport += $p
        $exportGone += $p
    }
}

$steps = @()
if (-not $toolsReady)   { $steps += '1' }
if (-not $submodsReady) { $steps += '2' }
if ($needAnalysis.Count -or $Force) { $steps += '7' }

# The export-only fast path. An analyzed run whose export never happened -- -SkipImprove used to
# skip the export too, and a legacy record cannot prove it ever ran -- had exactly one way out:
# -Force, i.e. repeating a multi-hour analysis to reach a step that takes minutes. Meanwhile
# 40-x64dbg.ps1 says "run 35 first" and this script says there is nothing to do, and the two
# point at each other forever. So schedule the export ON ITS OWN when the analysis is already
# recorded. Only when menu 7 is NOT running: a rebuild exports as part of its normal flow.
$exportOnly = @()
if ((-not $SkipExport) -and ($steps -notcontains '7')) { $exportOnly = $needExport }

Write-Host ''
if ($steps.Count -eq 0 -and $exportOnly.Count -eq 0) {
    Write-Host ("  Nothing to do: analysis already verified for " + (Format-PairList $wantPairs) + '.')
    Write-Host '  Re-run with -Force to rebuild it anyway.'
    exit 0
}
if ($needAnalysis.Count) {
    Write-Host ("  Not yet verified: " + (Format-PairList $needAnalysis))
}
if ($assumedLegacy.Count) {
    Write-Host ("  ASSUMED verified: " + (Format-PairList $assumedLegacy))
    Write-Host '    A pre-pair record names games, not versions, so it cannot say WHICH version it'
    Write-Host '    verified. Treating it as covering these, rather than re-running hours of'
    Write-Host '    analysis because a record was in an older shape. If one of them was staged'
    Write-Host '    AFTER that run, -Force is what imports it. The assumption stays visible: the'
    Write-Host "    '*' entry remains in the record, and only a real run replaces it with"
    Write-Host '    something observed.'
}
if ($exportGone.Count) {
    # Distinguish "never exported" from "exported, then the directory went away" -- 40-x64dbg.ps1
    # makes the same distinction from the other side, and only the record can make it at all.
    Write-Host ("  Export recorded but its directory is gone: " + (Format-PairList $exportGone))
    Write-Host '    The record says symbol_export.py wrote there and it is not there now, so the'
    Write-Host '    export is scheduled again. The analysis itself is untouched -- this is minutes.'
}
if ($exportOnly.Count) {
    # The gone-directory pairs are already in $exportOnly and already explained above; listing
    # them again under "no symbol export recorded" would contradict the line that just said one
    # WAS recorded. Name only the pairs nothing ever exported.
    $goneKeys = @{}
    foreach ($g in $exportGone) { $goneKeys[("$($g.Game)/$($g.Version)").ToLowerInvariant()] = $true }
    $neverExported = @($exportOnly | Where-Object {
        -not $goneKeys.ContainsKey(("$($_.Game)/$($_.Version)").ToLowerInvariant())
    })
    if ($neverExported.Count) {
        Write-Host ("  Analyzed, but no symbol export recorded: " + (Format-PairList $neverExported))
    }
    Write-Host '    The export alone will run -- minutes, not the hours menu 7 costs.'
}
if ($steps.Count) {
    Write-Host ("  Menu sequence to run: " + ($steps -join ', '))
}
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

    $rc = 0
    $runOut = @()
    if ($subcommands.Count -eq 0) {
        # The export-only fast path decided above. Nothing to build, so run.py is not invoked at
        # all and $rc stays 0 -- which is honest: this run observed nothing about the analysis
        # and will carry the recorded verdict forward rather than re-assert it.
        Write-Host ''
        Write-Host '  The analysis is already recorded; run.py is not being invoked. Export only.'
    }
    else {
        Write-Host ''
        Write-Host ("  run.py subcommands: " + ($subcommands -join ', ') + "  (this is the slow part)")
        Write-Host ''

        $runLog = Join-Path $env:TEMP ("bgs-run-" + [Guid]::NewGuid().ToString('N') + ".log")
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
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

        $runOut = @(Get-Content $runLog -ErrorAction SilentlyContinue)
        Remove-Item $runLog -Force -ErrorAction SilentlyContinue
    }

    # THE EXIT CODE IS THE GATE. What used to sit here justified ignoring $rc entirely -- "run.py
    # exits 0 even when a binary fails BGS's own post-import verification" -- and for the `build`
    # subcommand this script actually runs, that is FALSE: scripts\run_headless.py sys.exit(1)s
    # from its FAILURES block, and run.py's _cmd_build sys.exit()s that same rc. Ignoring it cost
    # this pack its worst failure. A project held by Ghidra or by any pyghidra/MCP server makes
    # run_headless print "ERROR opening project: <e>" and exit 1 with NO traceback and with no
    # word character before 'Error:', so the crash regex below cannot match it even
    # case-insensitively; the probe then warned and skipped, the export never happened -- and the
    # run still printed "Post-import verification: passed." and recorded every wanted game as
    # verified, exit 0. The regexes stay as SUPPLEMENTARY detail (they carry BGS's per-pair
    # verdicts, which an exit code cannot), but anything unrecognised is now a FAILURE.
    $script:verifyFailures = @($runOut |
        Where-Object { $_ -match 'VERIFICATION FAILURES|post-import verification failed|^\s*FAILURES:' })
    $script:rolledBack = @($runOut | Where-Object { $_ -match 'changes were rolled back' })
    $script:namedLow   = @($runOut | Where-Object { $_ -match 'Named functions too low' })

    # BGS reports per (game, version) in two places and both are worth reading, because they
    # answer different questions. run_headless.py prints "  F4 / VR: <binary>" as it STARTS each
    # target -- the only evidence that a staged pair was processed at all, and a staged pair that
    # never appears was never imported no matter what the exit code says. Then, if anything
    # failed, it prints a FAILURES: block of "  f4/vr: <reason>" lines and exits 1. The header
    # form has spaces around the slash and the verdict form does not, which is what keeps these
    # two patterns from reading each other's lines.
    $processedPairs = @{}
    $failedPairs    = @{}
    $inFailures     = $false
    foreach ($line in $runOut) {
        if ($line -match '^\s*FAILURES:\s*$') { $inFailures = $true; continue }
        if ($inFailures) {
            # ONCE INSIDE THE BLOCK, STAY IN IT. A line this does not recognise is a
            # CONTINUATION of the verdict above it, not the end of the list: run_headless
            # appends str(e) verbatim, and BGS's standard failed-script exception --
            # scripts\core\pyghidra_result.py's require_script_success -- raises
            # "<script> failed:\n<up to 12,000 chars of Java traceback>". Clearing the flag on
            # the first unparsed line dropped EVERY LATER failed pair. Measured, with f4/vr
            # failing that way and f4/ae rolled back after it: only f4/vr was captured, f4/ae
            # reached the verdict block with nothing against it and was recorded analyzed=true
            # AND exported=true -- a .dd64 written out of a rolled-back project, which the next
            # run read as "nothing to do" and 40-x64dbg.ps1 offered as a symbol database.
            # Nothing follows this block to be confused by staying in it: run_headless
            # sys.exit(1)s immediately after printing it.
            if ($line -match '^\s+([A-Za-z0-9_\-]+)/([A-Za-z0-9_.\-]+):\s*(\S.*)$') {
                $failKey = ("$($Matches[1])/$($Matches[2])").ToLowerInvariant()
                # Only a pair THIS run staged can carry a verdict. A traceback line is free text
                # and could shape like "  foo/bar: baz"; a pair name cannot be invented, because
                # run_headless only ever reports binaries under exes\ that this run left in
                # place (-OnlyGame moves the rest aside). A genuine verdict that somehow failed
                # this test is not lost either: it leaves $failedPairs empty, and the
                # default-to-FAIL gate below then refuses the whole run.
                if ($wantKeys.ContainsKey($failKey)) {
                    $failedPairs[$failKey] = "$($Matches[3])".Trim()
                }
            }
            continue
        }
        if ($line -match '^\s*([A-Za-z0-9_\-]+)\s+/\s+([A-Za-z0-9_.\-]+):\s+\S') {
            $processedPairs[("$($Matches[1])/$($Matches[2])").ToLowerInvariant()] = $true
        }
    }

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

    # Default to FAIL on output we do not recognise. That is the inversion this whole script
    # needed: unknown used to mean success. A non-zero rc with no per-pair verdict to explain it
    # is exactly the locked-project case above, and there is nothing in it to record.
    if ($rc -ne 0 -and $failedPairs.Count -eq 0) {
        Write-Host ''
        Write-Warning "run.py exited $rc and reported no per-(game,version) verdict. Nothing was verified."
        foreach ($l in @($runOut | Where-Object { $_ -match 'ERROR|error:' } | Select-Object -Last 5)) {
            Write-Host ("    $($l.Trim())")
        }
        Write-Host '    A held Ghidra project reports exactly this ("ERROR opening project: ..."), and'
        Write-Host '    pyghidra embeds the JVM in the python process -- so the holder can be an MCP'
        Write-Host '    server with no java.exe anywhere on the machine. Close it and re-run.'
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
    if ($subcommands -contains 'build') {
        Write-Host '  The analysis did not produce a project. Re-run and read run.py output; a failed'
        Write-Host '  step there prompts for retry, which this script answers with EOF (i.e. gives up).'
    }
    else {
        # The export-only path with no project to export FROM. Almost always a -BgsRoot pointing
        # somewhere other than the root that holds the record's work, which is worth saying: the
        # alternative reading -- "re-run the analysis" -- costs hours and would fix nothing.
        Write-Host "  The record says this analysis is done, but there is no project at $projectGpr,"
        Write-Host '  and nothing can be exported from a project that is not there. Check -BgsRoot'
        Write-Host '  points at the root that holds it; -Force rebuilds from scratch (hours).'
    }
    exit 1
}

# ---- Which programs does the project actually hold? ----
# Hoisted out of the improve block below, because the export needs this list too. While it
# lived inside 'if (-not $SkipImprove)', a -SkipImprove run left $programs undefined and the
# export block's '-and $programs' then silently made -SkipImprove skip the export as well.
# It is also the only cheap OBSERVATION of what was imported: a staged pair with no program
# here was never imported, whatever any exit code or marker says.
$programs = @()
$targets  = @()
# The improve pass runs only when this invocation actually built something. On the export-only
# fast path there is nothing to rescue and the pass is not free (the RTTI walk is a full pass
# over a 200k-function program), so the fast path stays what its name promises: the export.
$improveWanted = (-not $SkipImprove) -and ($subcommands -contains 'build')
if ($improveWanted -or (-not $SkipExport)) {
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
    foreach ($line in $probe) {
        if ($line -match '^\s*(\d+)\)\s+(/\S+)') {
            # Read both captures out BEFORE the next -match: $Matches is rebuilt by every
            # successful match, so the game/version split below would otherwise overwrite the
            # index and the path this entry is being built from.
            $pIndex = "$($Matches[1])"
            $pPath  = "$($Matches[2])"
            $pGame  = ''
            $pVer   = ''
            # The project mirrors exes\<game>\<ver>\, so the program path is the only thing here
            # that knows which (game, version) a program belongs to -- and pair-keyed entries,
            # the export's exportDir and the "staged but never imported" check below all need it.
            if ($pPath -match '^/([^/]+)/([^/]+)/') { $pGame = "$($Matches[1])"; $pVer = "$($Matches[2])" }
            $programs += [pscustomobject]@{ Index = $pIndex; Path = $pPath; Game = $pGame; Version = $pVer }
        }
    }
    if ($programs.Count -eq 0) {
        Write-Host ''
        Write-Warning '  Could not read the program list from menu 9. The improve pass and the symbol'
        Write-Host   '    export both need it, so neither runs and nothing below is recorded as'
        Write-Host   '    improved or exported.'
    }
    else {
        # Scope the improve and the export to what is STAGED, which is the rule this script's
        # own header states ("SCOPE IS THE exes/ TREE"). A program some earlier run left in the
        # project whose binary is no longer staged is not this run's business -- and
        # symbol_export.py exits 4 on it anyway, "the recorded backing executable is gone".
        # It also keeps every observation below attributable to a pair the record carries: work
        # done for a pair outside $wantPairs would be thrown away at the write.
        $targets = @($programs | Where-Object {
            $prog = $_
            @($wantPairs | Where-Object { $_.Game -eq $prog.Game -and $_.Version -eq $prog.Version }).Count
        })
        # A project laid out other than /<game>/<ver>/ leaves Game empty and nothing matches.
        # Fall back to every program rather than silently doing nothing: the export still runs,
        # and the per-pair recording below simply has nothing to attribute it to.
        if ($targets.Count -eq 0) { $targets = @($programs) }
    }
}

# The observation nothing at any layer used to make. This is the other half of the per-version
# defect: a donor could be staged, reported "already verified" by a game-keyed marker, and never
# appear in Ghidra, with no line anywhere saying so.
if ($programs.Count) {
    $notImported = @($wantPairs | Where-Object {
        $pair = $_
        -not @($programs | Where-Object { $_.Game -eq $pair.Game -and $_.Version -eq $pair.Version }).Count
    })
    if ($notImported.Count) {
        Write-Host ''
        Write-Warning ("Staged but NOT in the Ghidra project: " + (Format-PairList $notImported))
        Write-Host '    Nothing is recorded as analyzed for those. -Force imports them, which is the'
        Write-Host '    full menu 7 rebuild -- hours per binary.'
    }
}

# ---- Menu 9: CommonLib apply + RTTI vtable walk + reconciler ----
# This is what rescues a VR-only setup. The RTTI walk derives names from vtables in the
# binary itself, so it needs no donor: on Fallout 4 VR with nothing else staged it took the
# program from 13 named functions out of 201,005 to 34,507 out of 216,903 (+34,494), and the
# changes were SAVED rather than rolled back. Run it whenever a run completed, whether or not
# option 7's own verification passed.
$improvedPairs = @{}
if ($improveWanted -and $targets.Count) {
    Write-Host ''
    Write-Host '  Improve pass (menu 9: CommonLib apply + RTTI vtable walk + reconciler) ...'
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
        if (-not $named) {
            # The RTTI pipeline can fail inside run.py and print nothing this recognises. That
            # is a non-fatal warning -- but it is also the ONLY thing standing between a
            # rolled-back import and a marker claiming the run was verified, so it decides
            # improvedNamed rather than merely printing.
            Write-Warning "      no naming summary from the improve pass for $($t.Path)"
        }
        elseif ($t.Game) {
            $improvedPairs[("$($t.Game)/$($t.Version)").ToLowerInvariant()] = $true
        }
    }
}
elseif ($SkipImprove) {
    Write-Host ''
    Write-Host '  -SkipImprove: the menu-9 pass did not run, so nothing is recorded as improved.'
}

# ---- The analyzed verdict, decided once, here, where all of its evidence exists ----
# Deliberately BEFORE the export rather than at the write: a pair whose enrichment was rolled
# back and never rescued must not have symbols written from it. Those files look exactly like
# good ones to 40-x64dbg.ps1 -- a .dd64 of ~13 named functions loads without complaint -- so
# exporting first and judging afterwards would put a plausible-looking lie on disk.
$analyzedPairs = @{}
foreach ($p in $wantPairs) {
    $key   = ("$($p.Game)/$($p.Version)").ToLowerInvariant()
    $prior = Get-MarkerEntry $markerEntries $p.Game $p.Version

    if ($subcommands -notcontains 'build') {
        # Export-only run: this invocation built nothing, so it carries the recorded verdict
        # forward rather than re-asserting it -- EXCEPT where that verdict is an ASSUMPTION and
        # the program probe contradicts it. A legacy '*' entry vouches for "some version of this
        # game", so it also answers for a version staged LATER; writing a concrete (game,
        # version) entry off the back of it hardens the guess into an observation, and
        # Get-MarkerEntry prefers the exact entry -- so the "ASSUMED verified:" line would never
        # print for it again and -Force would be the only way to revisit it. Measured before this
        # guard: an export-only run warned "Staged but NOT in the Ghidra project: f4/ae" and then
        # printed "Recorded analyzed: f4/ae" and wrote analyzed=true for it, after which every
        # later run tried an export that cannot happen and exited 1 forever.
        # The probe is the observation that settles it: a pair with no program in the project was
        # never imported, whatever the record assumes. An EXACT entry is not touched here -- it
        # was observed -- and an empty $programs means the probe failed, not that nothing is
        # imported, so it carries forward rather than throwing away hours of good analysis.
        if ($prior -and $prior.analyzed) {
            $seenInProject = ($programs.Count -eq 0) -or
                [bool]@($programs | Where-Object { $_.Game -eq $p.Game -and $_.Version -eq $p.Version }).Count
            if ((-not $prior.legacy) -or $seenInProject) { $analyzedPairs[$key] = $true }
        }
        continue
    }

    $inProject = $true
    if ($programs.Count) {
        $inProject = [bool]@($programs | Where-Object { $_.Game -eq $p.Game -and $_.Version -eq $p.Version }).Count
    }
    # An empty $processedPairs means run_headless's per-target header moved, not that nothing
    # ran, so it falls back to the exit code rather than throwing away hours of good analysis.
    $processedOk = ($processedPairs.Count -eq 0) -or $processedPairs.ContainsKey($key)
    $fail = ''
    if ($failedPairs.ContainsKey($key)) { $fail = "$($failedPairs[$key])" }

    if (-not $processedOk -or -not $inProject) { continue }
    if ($fail) {
        # BGS names the rescuable failure exactly: the VR/OG rollback, whose import and Ghidra
        # auto-analysis survive and whose names the menu-9 RTTI walk then supplies (13 ->
        # 34,507 here). Any other verdict -- a missing script, an exception out of the importer
        # -- is not something the improve pass fixes, so it is not rescuable and not analyzed.
        $rescuable = ($fail -match 'rolled back|verification failed|too low')
        if ($rescuable -and $improvedPairs.ContainsKey($key)) { $analyzedPairs[$key] = $true }
        continue
    }
    # No verdict against this pair, and the gate above already refused any non-zero rc that no
    # per-pair verdict explained. run_headless.py exits 1 if ANY target fails, so rc 0 is BGS's
    # own statement that every target it processed passed.
    $analyzedPairs[$key] = $true
}

# ---- Export symbols (this is what Phase 5 consumes) ----
# scripts/core/symbol_export.py is scriptable and turns the named project into a .dd64
# x64dbg database, a .map, and a full .symbols.json with prototypes. Menu 10 wraps the same
# code behind prompts. Without this the analysis stays locked inside Ghidra.
$exportedPairs = @{}
$exportDirs    = @{}
if ($SkipExport) {
    Write-Host ''
    Write-Host '  -SkipExport: no .dd64/.map/.symbols.json were written, so Phase 5 (x64dbg) has'
    Write-Host '  nothing to consume. Re-run without it -- the export alone takes minutes.'
}
elseif ($targets.Count) {
    Write-Host ''
    Write-Host '  Exporting symbols (.dd64 for x64dbg, .map, .symbols.json) ...'
    foreach ($t in $targets) {
        $tKey = ''
        if ($t.Game) { $tKey = ("$($t.Game)/$($t.Version)").ToLowerInvariant() }
        # Only a WANTED pair can be refused here. The fallback above can hand back programs
        # this run knows nothing about, and refusing those would turn a path-format change into
        # an export that silently does nothing.
        if ($tKey -and $wantKeys.ContainsKey($tKey) -and -not $analyzedPairs.ContainsKey($tKey)) {
            Write-Warning ("      skipping $($t.Path): nothing verified its analysis in this run, and")
            Write-Host   ('        a .dd64 exported from a rolled-back project loads without complaint.')
            continue
        }
        $leaf = ($t.Path -split '/')[-1] -replace '\.unpacked\.exe$', '.exe'
        $slug = ($t.Path.Trim('/') -replace '/', '-') -replace '\.exe.*$', ''
        $outDir = Join-Path (Join-Path $BgsRoot 'symbols') $slug
        New-Item -ItemType Directory -Force $outDir | Out-Null
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $exportRc = 0
        Push-Location $BgsRoot
        try {
            & python scripts\core\symbol_export.py $projectRoot $ProjectName $t.Path $outDir `
                --module $leaf --signatures 2>&1 |
                Where-Object { $_ -match 'functions:|wrote:|ERROR|Error' } |
                ForEach-Object { Write-Host ("      " + $_) }
            $exportRc = $LASTEXITCODE
        }
        finally { Pop-Location; $ErrorActionPreference = $prevEap }

        # symbol_export.py's exit code was never read, and "symbols under ..." printed
        # unconditionally underneath it. It exits 3 when the program is not in the project and 4
        # when the backing executable is gone and no candidate matches the import-time SHA-256 --
        # both of which write NOTHING, and both of which used to read as a successful export.
        if ($exportRc -eq 0) {
            Write-Host ("      wrote $outDir")
            if ($t.Game) {
                $key = ("$($t.Game)/$($t.Version)").ToLowerInvariant()
                $exportedPairs[$key] = $true
                $exportDirs[$key]    = $outDir
            }
        }
        else {
            Write-Warning ("      symbol_export.py exited $exportRc for $($t.Path); nothing was exported there.")
        }
    }
}

Write-Host ''
if ($importRolledBack) {
    # Per rolled-back PAIR, not "did any improve pass anywhere report something". A run that
    # rescued skyrim and lost f4/vr must not describe itself with one sentence.
    $rescued   = @($failedPairs.Keys | Where-Object { $improvedPairs.ContainsKey($_) })
    $unrescued = @($failedPairs.Keys | Where-Object { -not $improvedPairs.ContainsKey($_) })
    if ($rescued.Count) {
        Write-Host ('  Note: option 7 rolled its own type/name apply back for ' + ($rescued -join ', ') + ';')
        Write-Host '  the improve pass above is what this project is carrying for them. That is'
        Write-Host '  expected for a VR-only Fallout 4 setup.'
    }
    if ($unrescued.Count) {
        # That "the improve pass above is what this project is carrying" sentence used to print
        # here unconditionally -- including on -SkipImprove, where no improve pass ran at all,
        # and on a run whose program probe came back empty. EVERY way the rescue can fail is a
        # non-fatal warning, so this is the only place that can say it did not happen.
        Write-Warning ('option 7 rolled its type/name apply back for ' + ($unrescued -join ', ') +
                       ' and NOTHING rescued it.')
        Write-Host '    No improve pass reported a naming summary for those, so the project is'
        Write-Host '    carrying an import with ~13 named functions rather than the 34,507 the RTTI'
        Write-Host '    walk produces. They are not recorded as analyzed.'
    }
}
elseif ($subcommands -contains 'build') { Write-Host '  Post-import verification: passed.' }

# ---- Record what was OBSERVED, field by field ----
# The write used to sit here unconditionally and fire whenever a project file existed -- on
# rolled-back runs, on runs whose improve pass never happened, on -SkipImprove runs, and on the
# locked-project run that never imported anything. So the one durable answer to "has this
# machine's analysis actually been done?", which -CheckOnly, CLAUDE.md and 40-x64dbg.ps1 all
# trust, was the pack's biggest liar. Every field below is set by the code that saw its evidence:
# analyzed by the verdict block above, improvedNamed by a parsed 'named after:' summary, and
# exported by symbol_export.py's exit code.
$now = (Get-Date).ToString('s')
$newEntries = @()
foreach ($p in $wantPairs) {
    $key      = ("$($p.Game)/$($p.Version)").ToLowerInvariant()
    $prior    = Get-MarkerEntry $markerEntries $p.Game $p.Version
    $analyzed = $analyzedPairs.ContainsKey($key)

    # A rebuild invalidates whatever a previous run improved and exported -- those ran against
    # the program the rebuild replaced. So they are carried forward only when nothing was built,
    # which also means a -SkipExport rebuild drops back to exported=false and the NEXT run picks
    # it up on the export-only fast path instead of demanding -Force.
    $improved  = $improvedPairs.ContainsKey($key)
    $exported  = $exportedPairs.ContainsKey($key)
    $exportDir = ''
    if ($exported) { $exportDir = "$($exportDirs[$key])" }
    if ($prior -and ($subcommands -notcontains 'build')) {
        if (-not $improved) { $improved = [bool]$prior.improvedNamed }
        # A RECORDED export is carried forward only while its directory is still THERE. Measured
        # without that condition: a record whose exportDir had been deleted made the plan above
        # print "Export recorded but its directory is gone", scheduled the export, watched
        # symbol_export.py exit 3 ("nothing was exported there") -- and then re-asserted the old
        # exported=true with the old dead path, printed "symbols f4/vr: Q:\gone\symbols\f4-vr",
        # and exited 0. That is the 35 <-> 40 loop again with 35 now claiming success: 40-x64dbg.ps1
        # warns "exported, then moved or deleted" and sends the user here, and an agent gating on
        # this script's exit code is told the export worked. exported=false only ever costs the
        # export-only fast path -- minutes -- never the hours menu 7 costs, so the strict answer
        # is also the cheap one. Test-Path is guarded by the non-empty check: it throws on '' under
        # $ErrorActionPreference = 'Stop', and -and short-circuits left to right.
        if ((-not $exported) -and $prior.exported -and "$($prior.exportDir)" -and (Test-Path "$($prior.exportDir)")) {
            $exported  = $true
            $exportDir = "$($prior.exportDir)"
        }
    }

    $stamp = ''
    if ($prior) { $stamp = "$($prior.verifiedAt)" }
    if (($subcommands -contains 'build') -or $improvedPairs.ContainsKey($key) -or $exportedPairs.ContainsKey($key)) {
        $stamp = $now
    }
    if (-not $stamp) { $stamp = $now }

    $newEntries += [pscustomobject]@{
        game          = $p.Game
        version       = $p.Version
        analyzed      = $analyzed
        improvedNamed = $improved
        exported      = $exported
        exportDir     = $exportDir
        verifiedAt    = $stamp
    }
}

# Carry forward everything this run did not look at: other games, other versions, and the
# migrated '*' entries. A run scoped with -OnlyGame must never drop the record for the games it
# moved aside, and a '*' entry stays even once concrete pairs exist beside it because it still
# vouches for versions of that game which are not staged right now -- Get-MarkerEntry prefers
# the exact pair, so it can no longer shadow an observation.
foreach ($e in $markerEntries) {
    if (@($newEntries | Where-Object { $_.game -eq $e.game -and $_.version -eq $e.version }).Count) { continue }
    $newEntries += [pscustomobject]@{
        game          = $e.game
        version       = $e.version
        analyzed      = $e.analyzed
        improvedNamed = $e.improvedNamed
        exported      = $e.exported
        exportDir     = $e.exportDir
        verifiedAt    = $e.verifiedAt
    }
}

# -Depth 6 for headroom, NOT because the default is broken today -- measured on 5.1, the default
# of 2 serialises this exact shape correctly, and -Depth 1 is where each object inside the
# entries array collapses to the string "@{game=f4; version=vr; analyzed=True}" and the record
# reads back with every field $null. The default is therefore exact-fit with zero margin: root
# object (1) -> entries array (2) -> entry object. Any future field that is itself an object or
# an array -- a per-pair list of exported files, say -- lands at depth 3 and would be silently
# stringified. 6 costs nothing and removes that trap from the next person's path.
# UTF8 rather than ascii because exportDir is a real filesystem path: on a machine whose
# user name is not ASCII, ascii writes '?' into the one field 40-x64dbg.ps1 exists to read
# instead of guessing.
[pscustomobject]@{
    schema     = 2
    entries    = @($newEntries | Sort-Object game, version)
    verifiedAt = $now
    ghidra     = (Split-Path $ghidraDir -Leaf)
} | ConvertTo-Json -Depth 6 | Set-Content $markerPath -Encoding UTF8

# Report only the pairs THIS run is about. Entries carried forward -- other games, and the
# migrated '*' whose version nobody knows -- are in the file but were not established here, and
# listing them under "Recorded" is how a record starts sounding more certain than it is.
$mine     = @($newEntries | Where-Object { $wantKeys.ContainsKey(("$($_.game)/$($_.version)").ToLowerInvariant()) })
$recorded = @($mine | Where-Object { $_.analyzed })
Write-Host ("  Recorded analyzed: " + $(if ($recorded.Count) { (@($recorded | ForEach-Object { "$($_.game)/$($_.version)" }) -join ', ') } else { 'nothing' }))
foreach ($e in @($mine | Where-Object { $_.exported })) {
    # Print the REAL directory. "symbols under <root>" used to print here unconditionally and
    # named the ROOT rather than the per-program slug directory the export actually writes to
    # (symbols\f4-vr-Fallout4VR\), and CLAUDE.md documents two other paths, both wrong. This
    # line and the exportDir recorded above are now the only two answers to where they are.
    Write-Host ("    symbols $($e.game)/$($e.version): $($e.exportDir)")
}

# A wanted pair that ended up unanalyzed is a failed run, and callers gate on the exit code.
# Falling off the end with exit 0 here is what let a rolled-back, unrescued run look like a
# success to 40-x64dbg.ps1, to CI and to an agent.
$notAnalyzed = @($wantPairs | Where-Object {
    -not $analyzedPairs.ContainsKey(("$($_.Game)/$($_.Version)").ToLowerInvariant())
})
if ($notAnalyzed.Count) {
    Write-Host ''
    Write-Warning ("No verified analysis for: " + (Format-PairList $notAnalyzed) + '. See the output above for why.')
    exit 1
}
$notExported = @($wantPairs | Where-Object {
    $pair = $_
    @($mine | Where-Object { $_.game -eq $pair.Game -and $_.version -eq $pair.Version -and -not $_.exported }).Count
})
if ((-not $SkipExport) -and $notExported.Count) {
    Write-Host ''
    Write-Warning ("Analyzed but not exported: " + (Format-PairList $notExported) + '.')
    Write-Host '    Phase 5 (x64dbg) consumes those symbols. Re-run this script -- with the analysis'
    Write-Host '    recorded it will run the export alone, minutes rather than the hours menu 7 costs.'
    exit 1
}

Write-Host ''
Write-Host 'Next: setup\30-ghidra.ps1 builds the MCP extension against this Ghidra, then open'
Write-Host 'Ghidra (BGS menu 6) and start the MCP server. See CLAUDE.md Phase 4.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
