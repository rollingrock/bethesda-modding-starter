<#
.SYNOPSIS
    Install x64dbg + the x64dbg MCP plugin (bromoket/x64dbg_mcp).

.DESCRIPTION
    Downloads the latest x64dbg snapshot and the PINNED MCP plugin release, and installs
    the plugin into both the x64 and x32 plugin folders. The npm-side MCP server is run
    via npx pinned to the SAME version in .mcp.json -- plugin and server versions must
    match, and an unpinned npx would drift. Both halves of that pin come from one constant,
    $script:X64dbgMcpServerPin in setup\_common.ps1: this script derives the release TAG
    from it, New-McpConfigObject writes the npm spec from it.

    What a RE-RUN does is decided by <InstallDir>\.starter-pack-install.json, the receipt this
    script writes once it has watched an install finish: { preExisting, snapshotAsset,
    mcpVersion, at }. It is the only thing on the machine that tells the x64dbg this pack
    created from the x64dbg that was already here -- the first may be re-extracted over to
    repair it, the second never is -- and the only witness to WHICH MCP release the .dp64 came
    from, since every release ships that file under the same name. Delete it to force the
    plugin to be fetched again.

    It then lists the .dd64 symbol databases Phase 4 exported, so a debugging session starts on
    named functions instead of raw addresses. It does not GUESS where those are: it reads the
    directory 35-ghidra-analysis.ps1 recorded in <BgsRoot>\.analysis-verified.json, falls back to
    the conventional <BgsRoot>\symbols when no record can answer, and says which of the two it
    used. Point -BgsRoot (or -Root) at your clone; nothing here is hard-coded to C:\repos.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\tools\x64dbg',

    # Where the clones live. 20-repos.ps1, 30-ghidra.ps1 and 90-verify.ps1 all spell this -Root
    # with this same default, so a machine that keeps its repos elsewhere overrides one thing,
    # the same way, everywhere.
    [string]$Root = 'C:\repos',

    # The BethesdaGhidraScripts clone whose .analysis-verified.json and symbols\ step 3 reads.
    # -BgsRoot is what 35-ghidra-analysis.ps1 calls it and what 90-verify.ps1 already passes to
    # it, so both spellings land somewhere familiar. Empty ON PURPOSE, like $McpVersion below --
    # it is derived from -Root after binding; see the comment at the resolution for why it
    # cannot be a parameter default either.
    [string]$BgsRoot = '',

    # Empty ON PURPOSE -- the real default is resolved a few lines down, after the dot-source.
    # See the comment there before "tidying" the pin back up here.
    [string]$McpVersion = ''
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_common.ps1"

# The pin lives in _common.ps1 as $script:X64dbgMcpServerPin, and it has to be resolved HERE
# rather than as the parameter default above. PowerShell binds parameters -- and evaluates
# their defaults -- BEFORE the first statement of the body runs, so
# `param([string]$McpVersion = $script:X64dbgMcpReleaseTag)` binds an empty string: the
# dot-source that defines the constant has not executed yet. And it does not fail where the
# mistake is: an empty $McpVersion leaves the release URL below ending at .../releases/tags/ ,
# GitHub answers 404, and Invoke-RestMethod throws about a release that is not there -- which
# reads as "upstream deleted the pinned tag" and sends the next person to check GitHub rather
# than the param block. Default it to '' and fill it in after the dot-source; that is the only
# ordering in which the constant is readable.
#
# The TAG form, with the leading v, because that is what bromoket/x64dbg_mcp names its GitHub
# releases; .mcp.json's npm spec takes the bare form. Both are derived from the one constant so
# they cannot drift -- which is what the "keep in sync with mcp/mcp.template.json" comment that
# used to sit in the param block was asking a human to do by hand.
if (-not $McpVersion) { $McpVersion = $script:X64dbgMcpReleaseTag }

# -BgsRoot derives from -Root, and that cannot be a parameter default either -- for a different
# reason than the pin above. `[string]$BgsRoot = (Join-Path $Root 'BethesdaGhidraScripts')` does
# bind in declaration order and does see $Root, but Join-Path resolves the DRIVE through the
# provider: measured on 5.1, `Join-Path 'D:\src' 'X'` on a box with no D: writes "Cannot find
# drive. A drive with the name 'D' does not exist." and hands back NOTHING -- non-terminating at
# bind time, so -Root on a drive this machine does not have would bind $BgsRoot to '' and every
# path below would quietly become relative to the current directory. [IO.Path]::Combine is
# string math: no provider, no drive check, which is what a path that is only ever REPORTED
# wants. The same reasoning applies to the two paths built from $BgsRoot in step 3.
if (-not $BgsRoot) { $BgsRoot = [IO.Path]::Combine($Root, 'BethesdaGhidraScripts') }

# ---------------------------------------------------------------- the install receipt
# The one thing on this machine that can tell the x64dbg this pack installed from the x64dbg
# that was already here. From the outside they are the same file -- an x96dbg.exe under
# $InstallDir -- and they need OPPOSITE handling: a tree the pack created may be re-extracted
# over to repair it, a tree the user brought may not, because that directory is where x64dbg
# keeps their settings, their databases and their other plugins. The standing rule is that
# nothing is overwritten without local evidence that the pack made it, and existence is not
# that evidence. This file is.
#
# It also records WHICH MCP release the plugin came from, and that is the whole of id 30:
# bromoket/x64dbg_mcp ships the plugin under the same two names in every release -- v2.2.1,
# v2.2.2 and v2.3.0 all contain exactly x64dbg_mcp.dp64 and x64dbg_mcp.dp32 -- so the file on
# disk cannot say which version it is, and the `if (-not (Test-Path $dest))` guard replaced
# below could never reinstall after a pin bump. A 2.2.2 plugin under a .mcp.json pinning server
# 2.3.0 then fails at the handshake INSIDE an agent session, hours from here, which is exactly
# the drift this script's own description says must not happen.
#
# Deleting <InstallDir>\.starter-pack-install.json is the force-reinstall knob for the plugin:
# with no recorded version nothing here can vouch for the .dp64, so the next run fetches it
# again. It does NOT force the snapshot to be re-downloaded -- with no receipt a complete tree
# reads as the user's own, which is the safe reading. Delete the tree itself for that.
function Write-InstallReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [bool]$PreExisting,
        [string]$SnapshotAsset,
        [string]$McpVersion
    )
    [pscustomobject]@{
        preExisting   = $PreExisting
        snapshotAsset = $SnapshotAsset
        mcpVersion    = $McpVersion
        at            = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content $Path -Encoding UTF8
}

$receiptPath = Join-Path $InstallDir '.starter-pack-install.json'
$receipt = $null
if (Test-Path $receiptPath) {
    try { $receipt = Get-Content $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch {
        # A receipt that will not parse is not evidence that the pack created this tree, and
        # reading it as though it were is how somebody's own x64dbg gets extracted over. Say
        # what happened and fall through to the conservative reading.
        Write-Warning ("Install receipt $receiptPath is unreadable: " + $_.Exception.Message +
            ' -- this run will treat the x64dbg there as one it did not create.')
    }
}

# Read through the property bag rather than the property, the same way New-McpConfigObject
# reads bridgeExe: a receipt written before a field existed hands back $null for it, and for
# preExisting a $null taken as $false is precisely the answer nobody may guess -- it means "the
# pack made this", which is what unlocks the overwrite.
$recordedPre      = $null
$recordedMcp      = ''
$recordedSnapshot = ''
if ($receipt) {
    $prop = $receipt.PSObject.Properties['preExisting']
    if ($prop -and $prop.Value -is [bool]) { $recordedPre = [bool]$prop.Value }
    $prop = $receipt.PSObject.Properties['snapshotAsset']
    if ($prop) { $recordedSnapshot = "$($prop.Value)".Trim() }
    $prop = $receipt.PSObject.Properties['mcpVersion']
    if ($prop) { $recordedMcp = "$($prop.Value)".Trim() }
}

$launcher = Join-Path $InstallDir 'x96dbg.exe'
# COMPLETE means both halves, and that second test is id 38. x96dbg.exe is only the picker --
# 199 KB, next to the 208 KB x64\x64dbg.exe it hands off to -- so a run interrupted during the
# flatten below, launcher already moved out of release\ and the x64 engine not yet, leaves a
# tree that cannot debug a single 64-bit target while every layer of this pack calls it done:
# the install used to be skipped on x96dbg.exe alone, step 2 CREATES x64\plugins itself, and
# 90-verify passes on x96dbg.exe plus any *.dp64.
$engineExe    = Join-Path $InstallDir 'x64\x64dbg.exe'
$haveLauncher = Test-Path $launcher
$haveEngine   = Test-Path $engineExe
$complete     = $haveLauncher -and $haveEngine

# Three states, and only the first may be extracted over.
#   pack-owned  a receipt that says preExisting=false. This pack made the tree, so it may
#               repair it -- which is how a bumped pin and a half-flattened extract both get
#               fixed instead of being skipped forever.
#   adopted     a launcher that is either COMPLETE with no such receipt, or recorded as
#               pre-existing. Somebody else's install -- or one from before receipts existed,
#               which as evidence is the same thing.
#   neither     nothing there, or a launcher with no engine and no receipt. That last one is
#               deliberately NOT adopted: an interrupted flatten leaves no receipt behind, so
#               "launcher present means the user's" would read a tree this script itself broke
#               as somebody else's and never repair it.
$packOwned = ($recordedPre -eq $false)
$adopted   = $haveLauncher -and (-not $packOwned) -and ($complete -or ($recordedPre -eq $true))

# 1. x64dbg snapshot
$snapshotAsset = $recordedSnapshot
$ownership     = 'installed by this pack'
if ($adopted) {
    # Nothing under here is this pack's, so nothing under here is downloaded, flattened or
    # moved. The only writes are the two plugin files named in step 2, and the receipt.
    $ownership     = 'already on this machine, adopted as-is'
    $snapshotAsset = ''
    Write-Host "x64dbg at $InstallDir was not installed by this pack -- adopting it as it stands."
    Write-Host '  No snapshot is fetched and nothing is flattened: that directory holds your settings,'
    Write-Host '  your databases and your other plugins. For a copy this pack manages -- and can repair'
    Write-Host '  when a snapshot lands half-extracted -- install a second one somewhere it owns:'
    Write-Host '    setup\40-x64dbg.ps1 -InstallDir <a directory for a pack-managed x64dbg>'
    if (-not $haveEngine) {
        Write-Warning ("There is no $engineExe under that install, so it cannot debug a 64-bit target " +
            'at all -- x96dbg.exe is only the picker. This run will not repair a tree it did not ' +
            "create, and 90-verify's 'MCP plugin x64' row passes on the .dp64 alone, so this warning " +
            'is the only thing on the machine that says so. Repair that install, or use -InstallDir.')
    }
}
elseif ($complete) {
    if ($recordedSnapshot) { $ownership = "installed by this pack from $recordedSnapshot" }
}
else {
    if ($haveLauncher) {
        # The only case that writes over a directory which already has an x64dbg in it, and it is
        # reached ONLY when the receipt says this pack put it there or the tree is missing the
        # engine x96dbg.exe exists to launch.
        Write-Host "The x64dbg at $InstallDir is incomplete -- $engineExe is missing. Re-extracting over it."
    }
    Write-Host 'Downloading the latest x64dbg snapshot ...'
    $rel = Invoke-RestMethod 'https://api.github.com/repos/x64dbg/x64dbg/releases/latest'
    $asset = $rel.assets | Where-Object name -like 'snapshot_*.zip' | Select-Object -First 1
    if (-not $asset) { $asset = $rel.assets | Where-Object name -like '*.zip' | Select-Object -First 1 }
    # Recorded on the receipt below: the snapshot names carry a date, so it is the only line
    # anyone will ever have saying which build of x64dbg this tree actually is.
    $snapshotAsset = $asset.name
    $zip = Join-Path $env:TEMP $asset.name
    Invoke-WebRequest $asset.browser_download_url -OutFile $zip
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    Expand-Archive $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
    # Snapshots wrap everything in a release\ folder — flatten it.
    #
    # Copy-Item -Recurse -Force, NOT Move-Item. Move-Item cannot merge a directory into an
    # existing directory of the same name -- it fails with "Cannot create a file when that file
    # already exists" -- and this arm now runs over trees that ALREADY have x64\ and x32\,
    # because the whole point of the receipt is to re-extract over an install that is present
    # but incomplete. Step 2 below creates x64\plugins and x32\plugins on every run, so the
    # canonical repairable tree always collides. Measured: with Move-Item the repair threw,
    # exited 1, left the engine still missing AND a stray release\ directory inside the install
    # dir, and a re-run reproduced it exactly -- the tree came out worse than it went in, with
    # no way back but deleting the whole InstallDir by hand. Copy-Item descends into the
    # existing directories and overwrites file by file; the Remove-Item below then clears
    # release\ either way. (The likeliest producer of this tree in the wild is not an
    # interrupted flatten at all -- it is Defender quarantining x64\x64dbg.exe.)
    $inner = Join-Path $InstallDir 'release'
    if (Test-Path (Join-Path $inner 'x96dbg.exe')) {
        Copy-Item (Join-Path $inner '*') -Destination $InstallDir -Recurse -Force
        Remove-Item $inner -Recurse -Force
    }
    # An extract that lands the launcher but not the engine is the half-flattened tree the
    # receipt exists to keep repairable -- it is NOT a success, and throwing here is what keeps
    # exit 0 an assertion about the tree rather than about the last line having run. It also
    # comes BEFORE the receipt write below, so nothing records an install nobody watched finish.
    if (-not (Test-Path $engineExe)) {
        throw ("The snapshot extracted under $InstallDir but there is no $engineExe -- x96dbg.exe " +
            "cannot hand off to a 64-bit engine that is not there. Check $snapshotAsset for a layout " +
            "change; delete $InstallDir and re-run to start clean.")
    }
}
if (-not (Test-Path (Join-Path $InstallDir 'x96dbg.exe'))) { throw "x64dbg layout unexpected under $InstallDir" }
Write-Host "x64dbg: $InstallDir ($ownership)"

# Write the receipt as soon as the tree is proved, not at the end of the script: if the plugin
# download in step 2 fails, the snapshot that just landed is still this pack's, and a run that
# forgot that would read it as the user's next time -- adopted, and so unrepairable forever, on
# the strength of one network error. mcpVersion carries whatever was recorded before, because
# only step 2 watches a .dp64 land and only it may change that field.
#
# Written ONLY when something it records has changed, so a re-run over a correct install leaves
# the file byte-identical (CI asserts exactly that shape of idempotence on 30-ghidra's manifest)
# and 'at' keeps meaning when this state came to be, not when it was last looked at.
$receiptStale = (-not $receipt) -or ($recordedPre -ne $adopted) -or ($recordedSnapshot -ne $snapshotAsset)
if ($receiptStale) {
    Write-InstallReceipt -Path $receiptPath -PreExisting $adopted -SnapshotAsset $snapshotAsset -McpVersion $recordedMcp
    Write-Host "Wrote $receiptPath"
}

# 2. MCP plugin (pinned release; local build only needed to match a custom commit)
$relUrl = "https://api.github.com/repos/bromoket/x64dbg_mcp/releases/tags/$McpVersion"
$rel = Invoke-RestMethod $relUrl

# Resolve BOTH assets before writing anything, so an adopted install can be told the exact files
# this pack is about to add to it -- and so that list is the whole of what it adds. The release's
# published byte size travels with each one: it is the only way to tell a complete .dp64 from the
# front half of one left by an interrupted download, which the existence test this replaces
# accepted forever (the second half of id 30).
$plan = @()
foreach ($pair in @(@{ Ext = '.dp64'; Dir = 'x64' }, @{ Ext = '.dp32'; Dir = 'x32' })) {
    $asset = $rel.assets | Where-Object name -like "*$($pair.Ext)" | Select-Object -First 1
    if (-not $asset) { Write-Warning "No $($pair.Ext) asset in $McpVersion — skipping $($pair.Dir)."; continue }
    # GitHub states each asset's byte size, and that is the only integrity figure available
    # without a second request (no checksum is published): v2.3.0 says 1,582,592 for
    # x64dbg_mcp.dp64 and 1,134,080 for the .dp32. A release that ever stopped stating one must
    # not be able to look like a verified download, so 0 means UNKNOWN here and every use of it
    # says so out loud rather than passing the half it did not test.
    [int64]$size = 0
    $sizeProp = $asset.PSObject.Properties['size']
    if ($sizeProp) { $null = [int64]::TryParse("$($sizeProp.Value)", [ref]$size) }
    $plugDir = Join-Path $InstallDir "$($pair.Dir)\plugins"
    $plan += [pscustomobject]@{
        Name    = $asset.name
        Url     = $asset.browser_download_url
        Size    = $size
        PlugDir = $plugDir
        Dest    = Join-Path $plugDir $asset.name
    }
}

if ($adopted -and $plan.Count) {
    Write-Host ''
    Write-Host 'Plugin-only install into an x64dbg this pack did not create. These files, and nothing else:'
    foreach ($p in $plan) { Write-Host "  $($p.Dest)" }
}

# What the receipt claims the plugin on disk IS. Empty covers both "no receipt" and a tree set
# up by a release of this pack that never wrote one -- in either case nothing here can vouch for
# the file, so it is fetched again. That one re-download is how id 30 closes on the machines
# already carrying a plugin nobody can identify.
$recordedText = $recordedMcp
if (-not $recordedText) { $recordedText = 'nothing' }

foreach ($p in $plan) {
    New-Item -ItemType Directory -Force $p.PlugDir | Out-Null
    # WHY this file is being written, decided before anything is fetched so the reason prints
    # beside it. Three different failures, and the middle one is the finding: the asset names
    # carry no version, so a bumped pin is invisible on disk and only the receipt can see it.
    $why = ''
    if (-not (Test-Path $p.Dest)) {
        $why = 'not installed yet'
    }
    elseif ($recordedMcp -ne $McpVersion) {
        $why = "the receipt records $recordedText, this run pins $McpVersion, and the asset names carry no version"
    }
    else {
        [int64]$have = (Get-Item $p.Dest).Length
        if ($p.Size -gt 0 -and $have -ne $p.Size) {
            $why = "$have bytes on disk against the $($p.Size) $McpVersion publishes -- an interrupted download"
        }
    }
    $sizeText = 'size not stated by the release'
    if ($p.Size -gt 0) { $sizeText = "$($p.Size) bytes" }
    if (-not $why) {
        Write-Host "  $($p.Name) is already $McpVersion ($sizeText) -- $($p.PlugDir)"
        continue
    }
    Write-Host "Installing $($p.Name) -> $($p.PlugDir)  ($why)"
    Invoke-WebRequest $p.Url -OutFile $p.Dest

    # Judge what LANDED, not that Invoke-WebRequest returned. A transfer cut partway through
    # leaves a short file and no error, x64dbg refuses to load it, and the only symptom is MCP
    # tools missing from a session hours later -- so compare against the size the release states.
    [int64]$got = (Get-Item $p.Dest).Length
    if ($p.Size -le 0) {
        Write-Warning ("The $McpVersion release states no size for $($p.Name), so the $got bytes just " +
            'written could not be checked against anything. It is installed and NOT verified.')
    }
    elseif ($got -ne $p.Size) {
        # Deleting is allowed here and nowhere else in this script: this run wrote this file
        # seconds ago, which is the local evidence the standing rule asks for. Leaving it would
        # hand the next run a file it can only report the same way.
        Remove-Item $p.Dest -Force -ErrorAction SilentlyContinue
        throw ("$($p.Name) downloaded short: $got bytes against the $($p.Size) $McpVersion publishes. " +
            "The partial file has been deleted -- re-run setup\40-x64dbg.ps1. If it keeps happening, " +
            "fetch $($p.Url) by hand into $($p.PlugDir).")
    }
}

# Record the pin only now, and only if the release offered something to install: everything in
# $plan reached its destination at the published size, or the loop threw. Recording it any
# earlier writes a claim the next run cannot check, because the file itself never says which
# release it is -- which is the whole reason this receipt exists.
$installedMcp = $recordedMcp
if ($plan.Count) { $installedMcp = $McpVersion }
if ($installedMcp -ne $recordedMcp) {
    Write-InstallReceipt -Path $receiptPath -PreExisting $adopted -SnapshotAsset $snapshotAsset -McpVersion $installedMcp
    Write-Host "Recorded MCP plugin $installedMcp in $receiptPath"
}

# 3. point at the symbols Phase 4 exported — debugging without them is raw addresses
#
# WHERE they are is not something this script can derive. symbol_export.py writes to a slug built
# from the program's path inside the Ghidra project -- symbols\f4-vr-Fallout4VR\ -- and the export
# on the machine this was written on, made before that slug existed, sits in symbols\f4vr\
# instead. So ASK THE RECORD: 35-ghidra-analysis.ps1 writes the directory each export ACTUALLY
# wrote to into .analysis-verified.json (entries[].exportDir, set only where symbol_export.py
# exited 0), precisely so nothing downstream has to guess.
#
# The guess used to be a literal C:\repos\BethesdaGhidraScripts\symbols with no parameter to move
# it. On any machine whose repos are not on C:\repos that made this block print "run
# setup\35-ghidra-analysis.ps1 first" over a COMPLETED Phase 4 -- an instruction to redo the one
# step in this pack measured in HOURS, issued because one hard-coded directory was empty.
$markerPath = [IO.Path]::Combine($BgsRoot, '.analysis-verified.json')
# The conventional layout, for everything the record cannot describe. It is a fallback and it is
# labelled as one below -- never printed as though someone had observed it.
$symRoot = [IO.Path]::Combine($BgsRoot, 'symbols')

# Ordered: what the record names first, the convention last. The reason travels WITH each
# directory, so the not-found message can say where it looked and on whose authority.
$candidates = @()
# Every reason we ended up guessing, in plain words, printed beside the results.
$assumed = @()

if (-not (Test-Path $BgsRoot)) {
    $assumed += "there is no BethesdaGhidraScripts clone at $BgsRoot"
}
elseif (-not (Test-Path $markerPath)) {
    $assumed += "no $markerPath -- nothing here has recorded where an export wrote"
}
else {
    $marker = $null
    try { $marker = Get-Content $markerPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch {
        # An unreadable record is not evidence that nothing was exported, and reading it that
        # way is what costs a re-run. Say what happened and fall back to the convention.
        Write-Warning ("Verification record $markerPath is unreadable: " + $_.Exception.Message)
        $assumed += "$markerPath could not be parsed"
    }
    # 5.1's ConvertFrom-Json hands a JSON array back as ONE object rather than enumerating it,
    # and ConvertTo-Json writes a single-element array as a bare object -- so a one-entry record
    # can arrive either way. @() around the VARIABLE, not the pipeline, normalises both.
    $entries = @()
    if ($marker -and $marker.PSObject.Properties['entries']) { $entries = @($marker.entries) }
    foreach ($e in $entries) {
        if (-not $e) { continue }
        # exported is the field symbol_export.py's exit code set; exportDir is where it wrote.
        # -eq $true rather than a cast, so an entry written before those fields existed reads as
        # false instead of as something truthy. A '*' (version-unknown) entry never carries an
        # exportDir, so nothing is lost by taking every entry here rather than resolving
        # exact-before-wildcard the way 35-ghidra-analysis.ps1 has to.
        $dir = "$($e.exportDir)".Trim()
        if (($e.exported -eq $true) -and $dir) {
            $candidates += [pscustomobject]@{ Dir = $dir; Why = "recorded for $($e.game)/$($e.version)" }
        }
    }
    if ($marker -and -not $candidates.Count) {
        # Distinguish the three ways a record can be present and still not answer the question.
        # None of them means "the analysis never ran", and none of them may be reported as if it
        # did: the legacy shape in particular sits on this machine over hours of finished work.
        if ($marker.PSObject.Properties['games']) {
            $assumed += "$markerPath is the legacy {games:[...]} record, which predates exportDir"
        }
        elseif ($entries.Count) {
            $assumed += "$markerPath records " +
                (@($entries | ForEach-Object { "$($_.game)/$($_.version)" }) -join ', ') +
                ' but no completed export'
        }
        else {
            $assumed += "$markerPath records no exports"
        }
    }
}
# The convention is ALWAYS searched, not only when the record is silent -- on this machine that
# is the search that finds symbols\f4vr\Fallout4VR.dd64, exported before the field existed.
$candidates += [pscustomobject]@{ Dir = $symRoot; Why = 'conventional path, assumed' }

# A recorded directory normally sits UNDER symbols\, so the two searches overlap. Dedupe the
# directories, then the files, or one .dd64 gets listed twice as though there were two.
$dirs    = @()
$seenDir = @{}
foreach ($c in $candidates) {
    $norm = "$($c.Dir)".TrimEnd('\', '/').ToLowerInvariant()
    if (-not $norm -or $seenDir.ContainsKey($norm)) { continue }
    $seenDir[$norm] = $true
    $dirs += [pscustomobject]@{ Dir = $c.Dir; Why = $c.Why; Exists = (Test-Path $c.Dir) }
}

$dd       = @()
$seenFile = @{}
foreach ($d in $dirs) {
    if (-not $d.Exists) { continue }
    foreach ($f in @(Get-ChildItem $d.Dir -Recurse -Filter '*.dd64' -ErrorAction SilentlyContinue)) {
        $k = $f.FullName.ToLowerInvariant()
        if ($seenFile.ContainsKey($k)) { continue }
        $seenFile[$k] = $true
        $dd += $f
    }
}

Write-Host ''
# A recorded export whose directory is gone is worth one line either way: it is the difference
# between "never exported" and "exported, then moved or deleted", and only the record knows.
foreach ($d in @($dirs | Where-Object { -not $_.Exists -and $_.Why -like 'recorded*' })) {
    Write-Warning ("$markerPath has an export $($d.Why) at $($d.Dir), but that directory is not there now.")
}
if ($dd.Count) {
    Write-Host 'x64dbg symbol databases exported by Phase 4 (load via File > Import database):'
    foreach ($d in $dd) { Write-Host ("  {0}  ({1:N1} MB)" -f $d.FullName, ($d.Length / 1MB)) }
    # Found by looking in the usual place rather than by being told. Say so -- an assumption that
    # happened to pay off is still an assumption, and the next machine's layout may differ.
    foreach ($a in $assumed) { Write-Host ("  (found by convention, not from the record: $a)") }
}
else {
    # This branch used to say "run setup\35-ghidra-analysis.ps1 first" on the strength of one
    # hard-coded directory being empty -- hours of re-analysis prescribed to people whose export
    # had finished and whose .dd64 files were sitting one drive letter away. All it can honestly
    # report is where it looked. Whether Phase 4 ran is 35's question, and -CheckOnly answers it
    # in seconds without starting anything.
    Write-Host 'No *.dd64 found for x64dbg. Looked in:'
    foreach ($d in $dirs) {
        Write-Host ("  {0}  [{1}]{2}" -f $d.Dir, $d.Why, $(if ($d.Exists) { '' } else { ' -- no such directory' }))
    }
    foreach ($a in $assumed) { Write-Host ("  (assumed: $a)") }
    Write-Host ''
    Write-Host 'Two different situations look like this, and this script cannot tell them apart:'
    Write-Host ' - the export has not happened yet. Ask the script that knows -- it is instant and'
    Write-Host '   starts nothing:'
    Write-Host '     setup\35-ghidra-analysis.ps1 -CheckOnly    (0 = nothing to do, 2 = work pending)'
    Write-Host '   With the analysis already recorded, that run does the EXPORT ALONE -- minutes,'
    Write-Host '   not the hours a rebuild costs.'
    Write-Host " - or they are somewhere this run never looked. It read $BgsRoot;"
    Write-Host '   if your BethesdaGhidraScripts is elsewhere, say so and nothing has to be re-run:'
    Write-Host '     setup\40-x64dbg.ps1 -BgsRoot <clone>   (or -Root <the directory your repos are in>)'
    Write-Host 'Until one of those loads, you are debugging unnamed addresses.'
}

Write-Host ''
Write-Host 'Done. Runtime contract:'
Write-Host " - Launch $InstallDir\x96dbg.exe (picks x32/x64), attach or open a target."
Write-Host ' - The plugin logs: [MCP] x64dbg MCP Server started on 127.0.0.1:27042'
Write-Host ' - Claude reaches it via the "x64dbg" entry in .mcp.json (npx x64dbg-mcp-server, pinned).'
Write-Host ' - Debugging a game under MO2: launch the game through MO2, then ATTACH x64dbg to the process.'
Write-Host " - Receipt: $receiptPath ($ownership)."
Write-Host '   It is what makes a re-run able to reinstall the plugin at all: every release ships the'
Write-Host '   .dp64 under the same name, so the file on disk cannot say which one it is. Delete the'
Write-Host '   receipt to force it to be fetched again.'
Write-Host ''
Write-Host 'Do NOT run `npx x64dbg-mcp-server --version` to check the install: it ignores the'
Write-Host 'flag, starts the stdio server and waits forever. A good start prints'
Write-Host '  [x64dbg-mcp] Server started (23 tools), plugin expected at 127.0.0.1:27042'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
