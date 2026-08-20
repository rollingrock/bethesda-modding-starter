<#
.SYNOPSIS
    Helpers shared by the setup scripts. Dot-source it: . "$PSScriptRoot\_common.ps1"

.DESCRIPTION
    Nothing here has side effects at load time except Sync-Path, which you call yourself.
#>

<#
.SYNOPSIS
    Rebuild $env:Path from the registry so freshly-installed tools are visible NOW.

.DESCRIPTION
    A process inherits its PATH at creation. winget writes the new entry to the User (or
    Machine) environment in the registry and broadcasts WM_SETTINGCHANGE — which explorer
    and new shells honour, but an already-running PowerShell never sees. So a script that
    installs a tool and then probes for it with Get-Command reports MISSING for something
    it just installed, and the next run tries to install it AGAIN (winget exits non-zero on
    "already installed", which then reads as FAILED). That loop is the classic
    "restart your terminal" step, and an unattended agent has no way to satisfy it.

    Measured on a real machine: CMake and GitHub CLI were installed and working, yet
    00-prereqs reported both MISSING, because their winget shims live under
    %LOCALAPPDATA%\Microsoft\WinGet\Packages and were added to the User PATH after this
    shell started.

    Entries that exist only in this process (a caller that prepended a tools dir, e.g.
    35-ghidra-analysis.ps1 adding LLVM) are preserved and kept in front.
#>
function Sync-Path {
    [CmdletBinding()]
    param()
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $persisted = @(($machine, $user) | Where-Object { $_ } | ForEach-Object { $_ -split ';' }) |
        Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

    # keep anything this process added that the registry does not know about
    $processOnly = @($env:Path -split ';' | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') } |
        Where-Object { $persisted -notcontains $_ })

    $merged = [System.Collections.Generic.List[string]]::new()
    foreach ($p in @($processOnly + $persisted)) {
        if ($p -and -not $merged.Contains($p)) { $merged.Add($p) }
    }
    $env:Path = $merged -join ';'
}

<#
.SYNOPSIS
    Is <name> runnable? Re-probes the registry PATH once before giving up.
#>
function Test-Cmd([string]$name) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { return $true }
    Sync-Path
    [bool](Get-Command $name -ErrorAction SilentlyContinue)
}

<#
.SYNOPSIS
    Is a Ghidra project currently held? Returns $true when something owns its lock.

.DESCRIPTION
    Ghidra arbitrates a project with an OS file-channel lock on <name>.lock~ (the sibling
    <name>.lock only carries hostname/user/timestamp metadata). So the ONLY reliable test is
    whether that file can be opened exclusively -- try it and you get ground truth,
    independent of which process holds it.

    Do not test this by scanning for java.exe/javaw.exe. pyghidra embeds the JVM inside the
    *python* process, so BethesdaGhidraScripts' own pipeline -- and any pyghidra-based MCP
    server -- holds a project while no process named java exists anywhere on the machine.
    A name-based scan reports "stale, safe to break" for a project that is very much in use.
#>
function Test-GhidraProjectLocked {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProjectDir)

    $channel = Get-ChildItem $ProjectDir -Filter '*.lock~' -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $channel) { return $false }
    try {
        $fs = [IO.File]::Open($channel.FullName, 'Open', 'ReadWrite', 'None')
        $fs.Close()
        return $false
    }
    catch { return $true }
}

<#
.SYNOPSIS
    Best-effort description of the process holding a Ghidra project, for error messages.

.DESCRIPTION
    Considers java/javaw AND python/pythonw, because of the pyghidra case above; a python
    process with jvm.dll loaded is a JVM. Naming the holder is advisory only -- authority
    belongs to Test-GhidraProjectLocked.
#>
function Get-GhidraHolderDescription {
    [CmdletBinding()]
    param([string]$Hint = '')

    foreach ($p in Get-Process -Name java, javaw, python, pythonw -ErrorAction SilentlyContinue) {
        $isJvm = $p.ProcessName -in 'java', 'javaw'
        if (-not $isJvm) {
            try { $isJvm = [bool]($p.Modules | Where-Object ModuleName -eq 'jvm.dll') } catch { $isJvm = $false }
        }
        if (-not $isJvm) { continue }
        $cmd = ''
        try { $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).CommandLine } catch {}
        if ($Hint -and $cmd -and -not $cmd.ToLower().Contains($Hint.ToLower())) { continue }
        $shown = if ($cmd) { $cmd.Substring(0, [Math]::Min(150, $cmd.Length)) } else { $p.ProcessName }
        return "PID $($p.Id) ($($p.ProcessName), JVM): $shown"
    }
    return $null
}

<#
.SYNOPSIS
    Run a native exe and judge it by its exit code, not by whether it wrote to stderr.

.DESCRIPTION
    Under PowerShell 5.1, a native command's stderr becomes ErrorRecords; with
    $ErrorActionPreference='Stop' a perfectly successful command that merely warns
    (git's "LF will be replaced by CRLF", maven's download notices) aborts the script.
    Throws only on a non-zero exit code.
#>
function Invoke-Native {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$ErrorMessage = ''
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Exe @Arguments }
    finally { $ErrorActionPreference = $prev }
    if ($LASTEXITCODE -ne 0) {
        if (-not $ErrorMessage) { $ErrorMessage = "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
        throw $ErrorMessage
    }
}

# ------------------------------------------------------------------ capability probes
# THE PREDICATE LAYER: one shared answer to "is this OK?", and every answer is reached by
# USING the thing rather than by finding it on disk.
#
# Existence is not capability, and this pack learned that the expensive way. Stock Windows
# ships 0-byte Microsoft Store app-execution-alias stubs at
# %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe; Get-Command resolves one as a perfectly
# ordinary ApplicationInfo with a Source path, so a machine with NO PYTHON ON IT reported
# "Python 3.12 present" and "All prerequisites present.", 90-verify agreed, and the first
# thing that actually RAN python -- 30-ghidra.ps1 building the bridge venv, two phases
# later -- got exit 9009 and a message about a venv. CI cannot catch that class of defect
# either: GitHub runners ship a real python, a real JDK and a fresh vcpkg. The only test
# that tells a tool apart from a placeholder for it is running the tool.
#
# Every probe returns ONE [pscustomobject] with exactly four properties (see
# New-ProbeResult, which is the single place that shape is written down):
#   Name     short stable identifier -- 'python', 'java (gradle)', 'vcpkg'
#   Status   'OK' or 'FAIL', and nothing else
#   Detail   what was OBSERVED: a version string, a resolved path, an exit code, the tool's
#            own error text. Never a restatement of the question.
#   Command  the exact invocation attempted, so a human can reproduce the failure by hand.
#
# Probes NEVER throw and NEVER write to the host. A caller running under
# $ErrorActionPreference='Stop' must be able to call any of them safely, and the caller --
# a -CheckOnly path, the do-path that just finished installing, or 90-verify -- decides what
# to print and what to do about it. That is what lets ONE predicate serve all three consumers
# instead of three separately authored truth systems that quietly disagree.
#
# PROBE ARGUMENTS MUST BE KNOWN-TERMINATING. These functions wait for the process, so they
# may only ever be handed arguments that exit on their own: --version, -version, version, or
# --help on a CLI proven to parse it. The x64dbg MCP server is the documented counterexample
# -- the npx server ignores --version and --help, starts the stdio server and logs
# "Timeout: none (waits indefinitely)", so the call never returns and the phase hangs
# forever. Never probe it with Test-CmdRuns; confirm its pin from mcp/mcp.template.json.
#
# Judge a probe by its .Status, never by $LASTEXITCODE afterwards: running a native command
# necessarily overwrites the caller's $LASTEXITCODE, and that is the probe's business, not
# the caller's result.

<#
.SYNOPSIS
    Build the four-property result every probe in this layer returns. Internal.

.DESCRIPTION
    One constructor so the contract cannot drift between probes: six callers are written
    against exactly Name/Status/Detail/Command, and a probe that quietly grew a fifth
    property (or dropped Command on one branch) would break them one at a time.
#>
function New-ProbeResult {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail,
        [string]$Command
    )
    [pscustomobject]@{
        Name    = $Name
        Status  = $Status
        Detail  = $Detail
        Command = $Command
    }
}

<#
.SYNOPSIS
    Run a native exe, capture its output and exit code, and never throw. Internal.

.DESCRIPTION
    The same $ErrorActionPreference='Continue' dance as Invoke-Native above, for the same 5.1
    reason: a native command's stderr becomes ErrorRecords, and java prints its VERSION on
    stderr -- so under 'Stop' the successful answer to "which JDK is this?" aborts the script
    that asked. Unlike Invoke-Native this one reports instead of throwing, because a probe
    that throws is a probe every caller has to wrap.

    Returns @{ Output; ExitCode; Error }. ExitCode is $null only when the command could not
    be launched at all (a path that vanished between Get-Command and here, a file that is not
    a valid image); Error then carries the reason.
#>
function Invoke-ProbeCapture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @()
    )
    $out = ''
    $code = $null
    $err = ''
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # Pre-set it: if the launch itself throws we must not read whatever the LAST native
        # command on this machine happened to leave behind and report it as this tool's.
        $global:LASTEXITCODE = 0
        $lines = & $Exe @Arguments 2>&1
        # Merged stderr arrives as ErrorRecord objects, and ToString() on one is the raw line
        # the tool wrote. Rendering them with Out-String instead splices PowerShell's own
        # "+ CategoryInfo ..." block into what we then report as the tool's output.
        $out = (@($lines) | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
        $code = $LASTEXITCODE
    }
    catch { $err = $_.Exception.Message }
    finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{ Output = $out.Trim(); ExitCode = $code; Error = $err }
}

<#
.SYNOPSIS
    First non-empty line of a captured output, truncated. Internal.

.DESCRIPTION
    Detail is read in a table and in a gate message, so it has to stay one line. java -version
    writes three, cmake writes several; the first carries the version in every tool this pack
    probes.
#>
function Get-ProbeFirstLine {
    [CmdletBinding()]
    param([string]$Text, [int]$Max = 200)
    if (-not $Text) { return '' }
    $line = @($Text -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $line.Count) { return '' }
    $s = "$($line[0])".Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    $s
}

<#
.SYNOPSIS
    Does <Name> actually RUN? Resolves it, executes it, and judges the exit code.

.DESCRIPTION
    The capability answer that Test-Cmd only pretends to give. Test-Cmd asks Get-Command, and
    Get-Command resolves the 0-byte Store app-execution-alias stub for python exactly as it
    resolves a real interpreter -- so id 0 (a machine with no Python passing 00-prereqs) and
    id 29 (90-verify repeating the same probe, and so pointing AWAY from the one missing
    prerequisite) are both the same bug: nobody ran it. A real python prints its version and
    exits 0; the stub exits 9009.

    -ProbeArgs must be KNOWN-TERMINATING (see the layer header) -- this function waits for the
    process. Default @('--version').

    -MinMajor is optional; absent (or 0) means "runs at all". Pass one whenever a floor
    exists, and prefer passing one even when any version would do: a tool that exits 0 and
    prints nothing has proved less than it looks like it has.

    -VersionPattern must capture the major version in group 1. The default finds the usual
    "<major>.<minor>" anywhere in the output (Python 3.12.10, cmake version 3.29.2,
    git version 2.47.0.windows.2, node v22.11.0 does NOT match -- pass 'v(\d+)\.' for node).

    Name on the result is the -Name you passed.

.EXAMPLE
    $p = Test-CmdRuns -Name python -ProbeArgs @('--version') -MinMajor 3
#>
function Test-CmdRuns {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$ProbeArgs = @('--version'),
        [int]$MinMajor = 0,
        [string]$VersionPattern = '(\d+)\.(\d+)'
    )

    $argText = ($ProbeArgs -join ' ')
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        # The same one-shot retry Test-Cmd does, and for the same reason: a tool winget
        # installed after this shell started exists only in the registry PATH until
        # Sync-Path rebuilds this process's copy.
        Sync-Path
        $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    }
    if (-not $cmd) {
        return New-ProbeResult $Name 'FAIL' 'not on PATH (re-read the registry PATH with Sync-Path and looked again)' "$Name $argText"
    }
    $exe = "$($cmd.Source)"
    if (-not $exe) { $exe = $Name }
    $shown = '"' + $exe + '" ' + $argText

    $run = Invoke-ProbeCapture -Exe $exe -Arguments $ProbeArgs
    if ($run.Error) {
        return New-ProbeResult $Name 'FAIL' "resolved to $exe but could not be launched: $($run.Error)" $shown
    }
    $first = Get-ProbeFirstLine $run.Output
    if ($run.ExitCode -ne 0) {
        $why = "exit code $($run.ExitCode) from $exe"
        if ($run.ExitCode -eq 9009) {
            $why += ' -- that is the Microsoft Store app-execution-alias stub answering, not an installed tool. Install it, or turn the alias off under Settings > Apps > Advanced app settings > App execution aliases'
        }
        if ($first) { $why += ": $first" }
        return New-ProbeResult $Name 'FAIL' $why $shown
    }
    if ($MinMajor -gt 0) {
        $matched = $false
        try { $matched = ($run.Output -match $VersionPattern) }
        catch {
            return New-ProbeResult $Name 'FAIL' "-VersionPattern /$VersionPattern/ is not a valid regex: $($_.Exception.Message)" $shown
        }
        if (-not $matched) {
            return New-ProbeResult $Name 'FAIL' "ran (exit 0) but nothing matched /$VersionPattern/ in its output: $first" $shown
        }
        $majorText = ''
        if ($Matches.Count -ge 2) { $majorText = "$($Matches[1])" }
        $major = 0
        $isNum = [int]::TryParse($majorText, [ref]$major)
        if (-not $isNum) {
            return New-ProbeResult $Name 'FAIL' "matched /$VersionPattern/ but capture group 1 ('$majorText') is not a number: $first" $shown
        }
        if ($major -lt $MinMajor) {
            return New-ProbeResult $Name 'FAIL' "major version $major is below the required $($MinMajor): $first [$exe]" $shown
        }
    }
    $detail = $first
    if (-not $detail) { $detail = 'exit 0 (no output)' }
    New-ProbeResult $Name 'OK' "$detail [$exe]" $shown
}

<#
.SYNOPSIS
    Which java will gradlew.bat actually use, and does it clear -MinMajor?

.DESCRIPTION
    Probing `java` on PATH answers a question nobody asks. ghidra-mcp's gradlew.bat resolves
    %JAVA_HOME%\bin\java.exe FIRST and only falls back to PATH when JAVA_HOME is unset -- and
    when JAVA_HOME is set but wrong it does not fall back at all, it aborts with "ERROR:
    JAVA_HOME is set to an invalid directory". Nothing else in this pack even mentions
    JAVA_HOME (ids 10, 36), so a leftover JDK 8 JAVA_HOME left every check green and failed
    the extension build with an unrelated-looking Gradle error. This probe resolves java the
    way gradlew.bat does and says which resolution won.

    A legacy JDK reports version "1.8.0_402", so its major reads as 1 and any modern floor
    rejects it -- which is the right answer, and the Detail carries the real string.

    Ghidra 12 and the GhidraMCP gradle build both need 21, so callers gating either should
    pass -MinMajor 21. Name on the result is 'java (gradle)'.
#>
function Test-JavaForGradle {
    [CmdletBinding()]
    param([int]$MinMajor = 0)

    $name = 'java (gradle)'
    $javaHome = "$env:JAVA_HOME".Trim().Trim('"')
    $exe = ''
    $how = ''
    if ($javaHome) {
        $candidate = Join-Path $javaHome 'bin\java.exe'
        $shown = '"' + $candidate + '" -version'
        $found = $false
        try { $found = Test-Path $candidate -ErrorAction Stop }
        catch {
            return New-ProbeResult $name 'FAIL' "JAVA_HOME is '$javaHome' and cannot be probed: $($_.Exception.Message)" $shown
        }
        if (-not $found) {
            return New-ProbeResult $name 'FAIL' "JAVA_HOME is set to '$javaHome' but there is no bin\java.exe under it -- gradlew.bat aborts with 'ERROR: JAVA_HOME is set to an invalid directory' and never falls back to PATH" $shown
        }
        $exe = $candidate
        $how = 'JAVA_HOME wins'
    }
    else {
        $cmd = Get-Command java -ErrorAction SilentlyContinue
        if (-not $cmd) { Sync-Path; $cmd = Get-Command java -ErrorAction SilentlyContinue }
        if (-not $cmd) {
            return New-ProbeResult $name 'FAIL' 'JAVA_HOME is not set and java is not on PATH either, so gradlew.bat has no JDK to run' 'java -version'
        }
        $exe = "$($cmd.Source)"
        if (-not $exe) { $exe = 'java' }
        $how = 'PATH wins (JAVA_HOME is not set)'
    }
    $shown = '"' + $exe + '" -version'

    $run = Invoke-ProbeCapture -Exe $exe -Arguments @('-version')
    if ($run.Error) {
        return New-ProbeResult $name 'FAIL' "$($how): $exe could not be launched: $($run.Error)" $shown
    }
    $first = Get-ProbeFirstLine $run.Output
    if ($run.ExitCode -ne 0) {
        return New-ProbeResult $name 'FAIL' "$($how): $exe exited $($run.ExitCode): $first" $shown
    }

    # Name the OTHER java when the two disagree. This is the whole of ids 10/36 in one line:
    # the java a human types and the java the build uses are different programs, and until
    # something printed both, the wrong one looked fine.
    $other = ''
    if ($javaHome) {
        try {
            $pathJava = Get-Command java -ErrorAction SilentlyContinue
            if ($pathJava -and "$($pathJava.Source)" -and "$($pathJava.Source)" -ne $exe) {
                $other = " (PATH java is $($pathJava.Source), which gradlew.bat does NOT use)"
            }
        }
        catch { $other = '' }
    }

    if ($MinMajor -gt 0) {
        $major = 0
        if ($run.Output -match 'version "(\d+)') {
            $isNum = [int]::TryParse("$($Matches[1])", [ref]$major)
            if (-not $isNum) { $major = 0 }
        }
        if ($major -lt $MinMajor) {
            return New-ProbeResult $name 'FAIL' "$($how): $exe is major $major, below the required $MinMajor -- $first$other" $shown
        }
    }
    New-ProbeResult $name 'OK' "$($how): $exe -- $first$other" $shown
}

<#
.SYNOPSIS
    Does this vcpkg run, AND does it carry the baseline commit the template pins?

.DESCRIPTION
    Two failures wear the same face here, and 10-vcpkg.ps1 could see neither. It measured
    staleness with `git rev-list --count HEAD..@{u}`, which ERRORS on a detached HEAD or a
    tag checkout -- the officially documented way to pin vcpkg -- and on a fork with no
    upstream. stderr was discarded, so the count came back empty and the script printed
    "vcpkg is up to date." over a clone that cannot resolve the manifest at all (ids 1, 74).

    `git cat-file -e <sha>^{commit}` asks the question that actually matters -- is the pinned
    builtin-baseline commit PRESENT in this clone -- and unlike @{u} it is true or false on a
    detached HEAD, a tag checkout and a fork alike. Without that commit, configure fails with
    "failed to git show versions/baseline.json ... exists on disk, but not in <sha>", which
    reads like a corrupt checkout rather than an old one.

    -BaselineSha defaults to builtin-baseline from templates\f4sevr-plugin\vcpkg.json,
    because that is the commit the scaffolded project actually demands. If that file cannot
    be read the probe still reports on vcpkg.exe and says plainly that the baseline half went
    unchecked -- it never silently passes the part it did not test.

    Name on the result is 'vcpkg'.
#>
function Test-VcpkgUsable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VcpkgDir,
        [string]$BaselineSha = ''
    )

    $name = 'vcpkg'
    $exe = Join-Path $VcpkgDir 'vcpkg.exe'
    $shownVersion = '"' + $exe + '" version'

    $found = $false
    try { $found = Test-Path $exe -ErrorAction Stop }
    catch {
        return New-ProbeResult $name 'FAIL' "cannot probe '$exe': $($_.Exception.Message)" $shownVersion
    }
    if (-not $found) {
        return New-ProbeResult $name 'FAIL' "no vcpkg.exe at $exe -- the clone was never bootstrapped (bootstrap-vcpkg.bat -disableMetrics)" $shownVersion
    }
    $run = Invoke-ProbeCapture -Exe $exe -Arguments @('version')
    if ($run.Error) {
        return New-ProbeResult $name 'FAIL' "$exe could not be launched: $($run.Error)" $shownVersion
    }
    $ver = Get-ProbeFirstLine $run.Output
    if ($run.ExitCode -ne 0) {
        # A vcpkg.exe built from an older checkout is the other half of this story: it exits
        # non-zero against newer scripts with "vcpkg-tools.json: document schema version 2 is
        # not supported", which says nothing about being stale. Re-bootstrap fixes it.
        return New-ProbeResult $name 'FAIL' "$exe exited $($run.ExitCode): $ver" $shownVersion
    }

    # $PSScriptRoot inside a function defined here is _common.ps1's OWN directory (setup\),
    # whoever dot-sourced it, so the pack root is one level up.
    $baselineFrom = 'the -BaselineSha argument'
    if (-not $BaselineSha) {
        $manifest = Join-Path (Split-Path $PSScriptRoot -Parent) 'templates\f4sevr-plugin\vcpkg.json'
        $baselineFrom = $manifest
        try {
            $json = Get-Content $manifest -Raw -ErrorAction Stop | ConvertFrom-Json
            $BaselineSha = "$($json.'builtin-baseline')".Trim()
        }
        catch { $BaselineSha = '' }
    }
    if (-not $BaselineSha) {
        return New-ProbeResult $name 'OK' "$ver at $VcpkgDir -- baseline NOT checked: no builtin-baseline could be read from $baselineFrom" $shownVersion
    }

    $rev = $BaselineSha + '^{commit}'
    $shownGit = 'git -C "' + $VcpkgDir + '" cat-file -e ' + $rev
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { Sync-Path; $git = Get-Command git -ErrorAction SilentlyContinue }
    if (-not $git) {
        return New-ProbeResult $name 'FAIL' "$ver runs, but git is not on PATH, so whether the pinned baseline $BaselineSha is present in $VcpkgDir could not be established" $shownGit
    }
    $exeGit = "$($git.Source)"
    if (-not $exeGit) { $exeGit = 'git' }
    $cat = Invoke-ProbeCapture -Exe $exeGit -Arguments @('-C', $VcpkgDir, 'cat-file', '-e', $rev)
    if ($cat.Error) {
        return New-ProbeResult $name 'FAIL' "$ver runs, but git could not be launched to check the baseline: $($cat.Error)" $shownGit
    }
    if ($cat.ExitCode -ne 0) {
        $extra = Get-ProbeFirstLine $cat.Output
        $why = "$ver runs, but the pinned builtin-baseline $BaselineSha (from $baselineFrom) is NOT in $VcpkgDir -- git cat-file exited $($cat.ExitCode)"
        if ($extra) { $why += ": $extra" }
        $why += '. Configure will fail with "failed to git show versions/baseline.json". Fetch it: git -C ' + $VcpkgDir + ' fetch origin'
        return New-ProbeResult $name 'FAIL' $why $shownGit
    }
    $shortSha = $BaselineSha
    if ($shortSha.Length -gt 12) { $shortSha = $shortSha.Substring(0, 12) }

    # Having the object is NOT the question. `git fetch` puts the baseline commit in the
    # database, and vcpkg resolves port versions out of the WORKING TREE -- so a clone that
    # fetched but was never advanced (a detached HEAD, a tag checkout, a fast-forward that
    # failed) holds that commit and still fails every configure with "no version database
    # entry for <port> at <version>". Stopping at cat-file would also make this predicate
    # useless as a postcondition: the repair fetches, so the check judging the repair would
    # pass on a tree the repair never touched, and 10-vcpkg would print "ready" over it.
    # `merge-base --is-ancestor <baseline> HEAD` asks the local half -- is the CHECKED-OUT
    # commit at or past the baseline, making versions/ a superset of what the manifest names
    # -- and like cat-file it answers on a branch, a tag, a detached HEAD and a fork alike.
    # Both stages stay, because they need different repairs: a missing object wants a fetch,
    # a non-ancestor HEAD wants a fast-forward, and one message cannot say both.
    $shownAnc = 'git -C "' + $VcpkgDir + '" merge-base --is-ancestor ' + $BaselineSha + ' HEAD'
    $anc = Invoke-ProbeCapture -Exe $exeGit -Arguments @('-C', $VcpkgDir, 'merge-base', '--is-ancestor', $BaselineSha, 'HEAD')
    if ($anc.Error) {
        return New-ProbeResult $name 'FAIL' "$ver runs and the pinned baseline $shortSha is in $VcpkgDir, but git could not be launched to check whether it is CHECKED OUT: $($anc.Error)" $shownAnc
    }
    if ($anc.ExitCode -ne 0) {
        $head = ''
        $rp = Invoke-ProbeCapture -Exe $exeGit -Arguments @('-C', $VcpkgDir, 'rev-parse', '--short', 'HEAD')
        if (-not $rp.Error -and $rp.ExitCode -eq 0) { $head = Get-ProbeFirstLine $rp.Output }
        if (-not $head) { $head = 'unknown' }
        $why = "$ver runs and the pinned baseline $shortSha (from $baselineFrom) is present in $VcpkgDir, but it is NOT an ancestor of the checked-out HEAD ($head) -- git merge-base --is-ancestor exited $($anc.ExitCode)"
        $extra = Get-ProbeFirstLine $anc.Output
        if ($extra) { $why += ": $extra" }
        $why += '. The objects were fetched but the working tree was never advanced, and vcpkg reads port versions out of the working tree. Advance it: git -C ' + $VcpkgDir + " merge --ff-only '@{u}'"
        return New-ProbeResult $name 'FAIL' $why $shownAnc
    }
    New-ProbeResult $name 'OK' "$ver at $VcpkgDir; pinned baseline $shortSha present and checked out" ($shownVersion + '; ' + $shownGit + '; ' + $shownAnc)
}

<#
.SYNOPSIS
    Is the clone at -Path the repo this pack pinned, or merely A repo?

.DESCRIPTION
    20-repos.ps1 skips a destination the moment <dest>\.git exists, which blesses a
    wrong-fork clone forever (id 7). That is not hypothetical here:
    alandtse/BethesdaGhidraScripts is an actively developed sibling of the
    1001Bits/BethesdaGhidraScripts this pack needs, the two have diverged, and both put a
    .git in a directory called BethesdaGhidraScripts. Only origin's URL tells them apart.

    URL comparison is tolerant where tolerance is harmless -- a trailing .git, a trailing
    slash, the scheme, an SSH git@host:owner/repo form and letter case are all the same
    remote -- and deliberately intolerant about the OWNER segment, which is the entire point.

    Name on the result is the leaf of -Path (e.g. 'BethesdaGhidraScripts').
#>
function Test-RepoIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Url
    )

    $name = $Path
    try { $name = Split-Path $Path -Leaf } catch { $name = $Path }
    if (-not $name) { $name = $Path }
    $shown = 'git -C "' + $Path + '" remote get-url origin'

    # Kept local to this function on purpose: it is a comparison rule, not a utility, and the
    # rule is the finding.
    $key = {
        param([string]$u)
        $s = "$u".Trim()
        if (-not $s) { return '' }
        $s = $s -replace '^[A-Za-z][A-Za-z0-9+.\-]*://', ''   # https:// ssh:// git://
        $s = $s -replace '^[^/@]+@', ''                       # git@github.com:owner/repo
        $s = $s -replace '[/\\]+$', ''
        $s = $s -replace '\.git$', ''
        $s = $s -replace '[/\\]+$', ''
        $s = $s -replace ':', '/'                             # scp-style host:owner -> host/owner
        $s = $s -replace '/+', '/'
        $s.ToLowerInvariant()
    }

    $hasGit = $false
    try { $hasGit = Test-Path (Join-Path $Path '.git') -ErrorAction Stop }
    catch {
        return New-ProbeResult $name 'FAIL' "cannot probe '$Path': $($_.Exception.Message)" $shown
    }
    if (-not $hasGit) {
        return New-ProbeResult $name 'FAIL' "no .git under $Path -- nothing is cloned there (a ZIP extract or an unrelated folder of the same name looks identical from the outside)" $shown
    }

    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { Sync-Path; $git = Get-Command git -ErrorAction SilentlyContinue }
    if (-not $git) {
        return New-ProbeResult $name 'FAIL' "a .git exists at $Path, but git is not on PATH, so which repository it is could not be established" $shown
    }
    $exeGit = "$($git.Source)"
    if (-not $exeGit) { $exeGit = 'git' }
    $run = Invoke-ProbeCapture -Exe $exeGit -Arguments @('-C', $Path, 'remote', 'get-url', 'origin')
    if ($run.Error) {
        return New-ProbeResult $name 'FAIL' "git could not be launched: $($run.Error)" $shown
    }
    $actual = Get-ProbeFirstLine $run.Output
    if ($run.ExitCode -ne 0) {
        return New-ProbeResult $name 'FAIL' "git exited $($run.ExitCode) reading origin at $Path -- $actual" $shown
    }
    if (-not $actual) {
        return New-ProbeResult $name 'FAIL' "the clone at $Path has no origin URL" $shown
    }
    $have = & $key $actual
    $want = & $key $Url
    if ($have -ne $want) {
        return New-ProbeResult $name 'FAIL' "origin is $actual -- this pack pins $Url. Different repository (typically the other fork): move $Path aside and re-clone; the .git test alone would keep skipping it as done" $shown
    }
    New-ProbeResult $name 'OK' "origin = $actual" $shown
}

<#
.SYNOPSIS
    Does the venv launcher .exe still start, or is it orphaned?

.DESCRIPTION
    A console-script .exe in <venv>\Scripts is a stub with the ABSOLUTE path of the python
    that created the venv baked into it. Upgrade or uninstall that python and the .exe is
    still sitting there -- so 30-ghidra.ps1's `if (-not (Test-Path $venvExe))` skips the
    rebuild, and the bridge dies at launch with "No Python at '...'" (id 12), during an MCP
    session rather than during setup. Running the stub is the only way to tell a live venv
    from a dead one.

    --help is used because ghidra-mcp's entry point (bridge_mcp_ghidra.cli:main) is argparse,
    so it prints and exits 0. That matters: invoked with NO arguments the same exe starts the
    stdio MCP server and never returns. See the layer header on known-terminating arguments.

    Name on the result is the leaf of -Path (e.g. 'bridge-mcp-ghidra.exe').
#>
function Test-VenvExeRuns {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $name = $Path
    try { $name = Split-Path $Path -Leaf } catch { $name = $Path }
    if (-not $name) { $name = $Path }
    $shown = '"' + $Path + '" --help'

    $found = $false
    try { $found = Test-Path $Path -ErrorAction Stop }
    catch {
        return New-ProbeResult $name 'FAIL' "cannot probe '$Path': $($_.Exception.Message)" $shown
    }
    if (-not $found) {
        return New-ProbeResult $name 'FAIL' "no launcher at $Path -- the venv was never created" $shown
    }
    $run = Invoke-ProbeCapture -Exe $Path -Arguments @('--help')
    if ($run.Error) {
        return New-ProbeResult $name 'FAIL' "$Path could not be launched: $($run.Error)" $shown
    }
    $first = Get-ProbeFirstLine $run.Output
    if ($run.ExitCode -ne 0) {
        $why = "exit code $($run.ExitCode) from $Path"
        if ($first) { $why += ": $first" }
        $why += '. An orphaned venv (its interpreter moved or was upgraded) reports "No Python at ..." -- delete the .venv directory and re-run setup\30-ghidra.ps1'
        return New-ProbeResult $name 'FAIL' $why $shown
    }
    # On success the first line of --help is boilerplate (or, in this venv's case, a pydantic
    # deprecation warning), so reporting it as the Detail would fill 90-verify's table with
    # noise. What was actually observed, and what the caller needs, is that THIS launcher ran.
    # The FAIL branches above keep $first, because there it carries the error.
    New-ProbeResult $name 'OK' "$Path runs (exit 0)" $shown
}

<#
.SYNOPSIS
    Is this a COMPLETE Ghidra install, or the front of a truncated one?

.DESCRIPTION
    Every consumer in this pack decided "is this Ghidra?" by testing
    Ghidra\application.properties alone (ids 11, 26). That file sits near the FRONT of the
    distribution zip, so an extraction that ran out of disk, was interrupted, or was killed
    mid-write leaves it in place and passes -- and the install then fails hours later with a
    missing-class error from a module that never landed. Three things have to hold: the
    properties parse (it is Ghidra), Ghidra\Processors exists and is populated (the extraction
    reached the far end of the archive), and the jar count clears a floor.

    Jars are counted under Ghidra\{Framework,Features,Processors,Debug} -- exactly the set
    30-ghidra.ps1 turns into the headless classpath argfile, so the floor is measured against
    the same thing the headless server needs. A healthy Ghidra 11/12 install yields ~194
    there; -MinJars defaults to 150 so a normal version-to-version difference never trips it.

    Name on the result is 'ghidra install'.
#>
function Test-GhidraInstallComplete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinJars = 150
    )

    $name = 'ghidra install'
    $props = Join-Path $Path 'Ghidra\application.properties'
    $shownProps = 'Get-Content "' + $props + '"'

    $found = $false
    try { $found = Test-Path $props -ErrorAction Stop }
    catch {
        return New-ProbeResult $name 'FAIL' "cannot probe '$Path': $($_.Exception.Message)" $shownProps
    }
    if (-not $found) {
        return New-ProbeResult $name 'FAIL' "no Ghidra\application.properties under $Path -- not a Ghidra install" $shownProps
    }
    $version = ''
    try {
        foreach ($line in (Get-Content $props -ErrorAction Stop)) {
            if ($line -match '^\s*application\.version\s*=\s*(.+)$') { $version = "$($Matches[1])".Trim(); break }
        }
    }
    catch {
        return New-ProbeResult $name 'FAIL' "cannot read $props : $($_.Exception.Message)" $shownProps
    }
    if (-not $version) {
        return New-ProbeResult $name 'FAIL' "$props carries no application.version -- the file is truncated, or this is not Ghidra's" $shownProps
    }

    $processors = Join-Path $Path 'Ghidra\Processors'
    $shownProc = 'Get-ChildItem "' + $processors + '" -Directory'
    $procCount = 0
    try { $procCount = @(Get-ChildItem $processors -Directory -ErrorAction SilentlyContinue).Count }
    catch { $procCount = 0 }
    if ($procCount -eq 0) {
        return New-ProbeResult $name 'FAIL' "application.version $version parses, but $processors is missing or empty -- a truncated extraction: application.properties lands near the front of the archive and the processor modules near the end" $shownProc
    }

    $shownJars = '@(''Framework'',''Features'',''Processors'',''Debug'') | ForEach-Object { Get-ChildItem "' +
        $Path + '\Ghidra\$_" -Recurse -Filter *.jar -File -ErrorAction SilentlyContinue } | Measure-Object'
    $jars = 0
    foreach ($d in 'Framework', 'Features', 'Processors', 'Debug') {
        try { $jars += @(Get-ChildItem (Join-Path $Path "Ghidra\$d") -Recurse -Filter '*.jar' -File -ErrorAction SilentlyContinue).Count }
        catch { }
    }
    if ($jars -lt $MinJars) {
        return New-ProbeResult $name 'FAIL' "application.version $version and $procCount processor module(s), but only $jars jar(s) under Ghidra\{Framework,Features,Processors,Debug} (floor $MinJars) -- an incomplete extraction; re-extract the distribution zip over $Path" $shownJars
    }
    New-ProbeResult $name 'OK' "version $version, $procCount processor module(s), $jars jars [$Path]" $shownJars
}

<#
.SYNOPSIS
    Is a Visual Studio with the Desktop C++ workload installed, at major >= -MinMajor?

.DESCRIPTION
    Re-invokes vswhere on EVERY call, which is the whole point (id 4). 00-prereqs.ps1
    captured $hasVs into a variable before installing and then handed that same captured
    boolean back as the post-install re-check, so a Visual Studio install that took 30-60
    minutes and succeeded still reported "installed (new shell needed)" and exited 1 -- the
    one component whose install is far too expensive to repeat was the one guaranteed to be
    reported as unfinished. A probe re-run at the moment of the question cannot do that.
    Never assign this to a variable and pass the variable as a later check.

    No Sync-Path here, deliberately: vswhere lives at a fixed absolute path under Program
    Files (x86) and Visual Studio never puts itself on PATH, so a stale process PATH cannot
    affect this answer.

    -MinMajor defaults to 17 (VS2022), which is the floor the C++23 templates in this pack
    need. Name on the result is 'VS C++ workload'.
#>
function Test-VsWorkload {
    [CmdletBinding()]
    param([int]$MinMajor = 17)

    $name = 'VS C++ workload'
    $pf86 = "${env:ProgramFiles(x86)}"
    if (-not $pf86) { $pf86 = 'C:\Program Files (x86)' }
    $vswhere = Join-Path $pf86 'Microsoft Visual Studio\Installer\vswhere.exe'
    $probeArgs = @('-products', '*', '-requires', 'Microsoft.VisualStudio.Workload.NativeDesktop', '-property', 'installationVersion')
    $shown = '"' + $vswhere + '" ' + ($probeArgs -join ' ')

    $found = $false
    try { $found = Test-Path $vswhere -ErrorAction Stop }
    catch { $found = $false }
    if (-not $found) {
        return New-ProbeResult $name 'FAIL' "no vswhere.exe at $vswhere -- the Visual Studio Installer is not on this machine, so no VS is either" $shown
    }
    $run = Invoke-ProbeCapture -Exe $vswhere -Arguments $probeArgs
    if ($run.Error) {
        return New-ProbeResult $name 'FAIL' "vswhere could not be launched: $($run.Error)" $shown
    }
    if ($run.ExitCode -ne 0) {
        return New-ProbeResult $name 'FAIL' "vswhere exited $($run.ExitCode): $(Get-ProbeFirstLine $run.Output)" $shown
    }
    # vswhere exits 0 and prints NOTHING when no install matches, so the exit code alone says
    # nothing: VS present without the C++ workload looks exactly like VS present with it.
    $versions = @($run.Output -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $versions.Count) {
        return New-ProbeResult $name 'FAIL' 'vswhere ran and found NO install carrying Microsoft.VisualStudio.Workload.NativeDesktop -- VS may be installed without the C++ workload, which winget will not add (Visual Studio Installer -> Modify -> Desktop development with C++)' $shown
    }
    $best = 0
    foreach ($v in $versions) {
        if ($v -match '^(\d+)') {
            $m = 0
            $isNum = [int]::TryParse("$($Matches[1])", [ref]$m)
            if ($isNum -and $m -gt $best) { $best = $m }
        }
    }
    if ($best -lt $MinMajor) {
        return New-ProbeResult $name 'FAIL' "installationVersion $($versions -join ', ') -- newest major $best is below the required $MinMajor" $shown
    }
    New-ProbeResult $name 'OK' "installationVersion $($versions -join ', ') with the NativeDesktop workload" $shown
}

<#
.SYNOPSIS
    Print one probe result (pipeline-friendly). FAIL always prints the command that was run.

.DESCRIPTION
    The layer's display rule, in one place so a -CheckOnly summary, a do-path and 90-verify
    all read identically. A failure prints its Command because the very next thing a human or
    an agent does is run it by hand -- "python MISSING" with no command sent people off to
    reinstall a Python that was already there, while the line that would have ended it,
    `"C:\...\WindowsApps\python.exe" --version` returning 9009, was never shown.

    Printing stays out of the probes themselves so they remain safe to call under
    $ErrorActionPreference='Stop' and free to be composed into a table or a gate instead.
#>
function Write-ProbeResult {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][psobject[]]$Result)
    process {
        foreach ($r in @($Result)) {
            if (-not $r) { continue }
            $label = "$($r.Name)"
            if ($label.Length -lt 20) { $label = $label.PadRight(20) }
            if ("$($r.Status)" -eq 'OK') {
                Write-Host "  OK   $label $($r.Detail)"
            }
            else {
                Write-Host "  FAIL $label $($r.Detail)"
                Write-Host "       command: $($r.Command)"
            }
        }
    }
}

# ------------------------------------------------------------------ .mcp.json generator
# ONE answer to "what goes in .mcp.json", because there used to be two and they disagreed in
# both directions at once.
#
# mcp/mcp.template.json carried BOTH servers but hard-coded
# C:/repos/ghidra-mcp/.venv/Scripts/bridge-mcp-ghidra.exe, and New-Plugin.ps1 Copy-Item'd it
# verbatim into every scaffold and then committed it -- so a machine whose repos are not under
# C:\repos got a .mcp.json whose ghidra server can never spawn, with nothing on the machine
# saying so until an agent session came up with no Ghidra tools (ids 39, 77).
# 36-ghidra-mcp.ps1 built its own object inline with the paths correctly resolved from the
# build manifest and NO x64dbg entry at all -- so the config the template's own _comment
# promises "36 generates this for you" silently dropped the server 40-x64dbg.ps1 spends an
# entire phase installing (id 75). Each file was the fix for the other one's bug, and neither
# knew it. With one generator the two failures cannot both be true of the same object.
#
# This is NOT part of the probe layer above and is deliberately placed after it: a probe
# answers a question and stays silent, this one produces configuration and WARNS when it had
# to guess. Keeping them apart is what lets the probes keep their never-write rule.
#
# The two assignments below are the only statements in this file that run at dot-source time.
# The header's "nothing here has side effects at load time" still holds -- they define values,
# they do not touch the machine.

# ONE pin for the x64dbg MCP pair, stored in the bare npm form.
#
# MIND THE TWO FORMS, because they are not interchangeable and nothing but this comment says
# so: bromoket/x64dbg_mcp tags its GitHub releases with a leading v ('v2.3.0', which is what
# 40-x64dbg.ps1 fetches /releases/tags/<tag> with), while the npm spec in .mcp.json has no v
# ('x64dbg-mcp-server@2.3.0'). Store the bare version, derive the tag, and the pair cannot
# drift. Until this existed, 40-x64dbg.ps1 carried a comment asking a HUMAN to keep its default
# in step with a string buried in a JSON file -- and 40-x64dbg.ps1's own description states the
# stake plainly: plugin and server versions must match. A drifted pair installs a .dp64 from
# one release and npx-fetches a server from another, which fails at the handshake inside an MCP
# session rather than during setup, where somebody is watching.
$script:X64dbgMcpServerPin = '2.3.0'
$script:X64dbgMcpReleaseTag = 'v' + $script:X64dbgMcpServerPin

<#
.SYNOPSIS
    Build the .mcp.json object -- BOTH servers, bridge path resolved -- that every consumer writes.

.DESCRIPTION
    Returns one [ordered] hashtable and leaves the serialising to the caller
    (ConvertTo-Json -Depth 6), because the two consumers do different things with it:
    New-Plugin.ps1 drops it into a fresh scaffold, 36-ghidra-mcp.ps1 holds it up against a
    .mcp.json that may already exist. Handing back an object rather than text is what lets the
    second one DIFF instead of overwrite.

    The ghidra command is resolved in this order, and the order is the point:
      1. an explicit -BridgeExe, for a caller that already knows the path (36-ghidra-mcp.ps1 has
         the build manifest open in front of it);
      2. bridgeExe from setup\.ghidra-mcp-build.json, which 30-ghidra.ps1 writes and which is the
         only thing on the machine that knows a non-default -GhidraMcpDir;
      3. the conventional C:\repos\ghidra-mcp path -- a GUESS about this machine, which is why
         reaching it WARNS.

    -ManifestPath overrides where step 2 looks; empty means .ghidra-mcp-build.json beside this
    file. -Port (default 8089) feeds GHIDRA_MCP_URL and nothing else, and it must be the port
    the headless server was actually started on: 36-ghidra-mcp.ps1 takes -Port for a machine
    where 8089 is busy, and a config pinned to the other number describes a server that is not
    there.

    That warning on step 3 makes this the one function in this file that writes to the host. It
    is a generator, not a probe, and the probe layer above it is forbidden from printing (see
    its header) precisely so callers can compose probes; nothing composes this. A silent guess
    is the exact failure being closed here -- the hard-coded template path was wrong on any
    machine that did not use the defaults, and said nothing.

    It does NOT check that the resolved exe exists, let alone that it runs. Existence is not
    capability in this pack and that question already has an owner: Test-VenvExeRuns EXECUTES
    the launcher, which is the only way to tell a live venv from one orphaned by a Python
    upgrade (id 12). A Test-Path here would read like verification and be neither.

    The x64dbg entry is always present, pinned from $script:X64dbgMcpServerPin above.

.EXAMPLE
    New-McpConfigObject -Port 8090 | ConvertTo-Json -Depth 6
#>
function New-McpConfigObject {
    [CmdletBinding()]
    param(
        [int]$Port = 8089,
        [string]$BridgeExe = '',
        [string]$ManifestPath = ''
    )

    # $PSScriptRoot inside a function defined here is _common.ps1's OWN directory (setup\), no
    # matter who dot-sourced it -- the same property Test-VcpkgUsable relies on -- and setup\ is
    # where 30-ghidra.ps1 writes the manifest. So New-Plugin.ps1, running from the pack root or
    # from a scaffold directory, finds it without being told where it is.
    if (-not $ManifestPath) { $ManifestPath = Join-Path $PSScriptRoot '.ghidra-mcp-build.json' }

    # 30-ghidra.ps1's -GhidraMcpDir default with the layout pip -e leaves under it. It is the
    # only guess available, and it is the guess that shipped hard-coded in the template.
    $conventional = 'C:\repos\ghidra-mcp\.venv\Scripts\bridge-mcp-ghidra.exe'

    $command = "$BridgeExe".Trim()
    if (-not $command) {
        # Every branch here records WHY the manifest could not answer, because the three causes
        # want the same repair but read completely differently to a human: never built, built by
        # a version that did not record the field, or a file that will not parse.
        $why = ''
        $found = $false
        try { $found = Test-Path $ManifestPath -ErrorAction Stop }
        catch { $found = $false }
        if (-not $found) {
            $why = "there is no build manifest at $ManifestPath, so nothing here has ever built the bridge"
        }
        else {
            try {
                $rec = Get-Content $ManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json
                # Ask the property bag rather than the property: an older manifest is missing
                # fields as a matter of course (30-ghidra.ps1 has grown them), and reading
                # $rec.bridgeExe straight would turn "field absent" into a $null that reads
                # exactly like "path is empty".
                $prop = $null
                if ($rec) { $prop = $rec.PSObject.Properties['bridgeExe'] }
                if ($prop) { $command = "$($prop.Value)".Trim() }
                if (-not $command) {
                    $why = "$ManifestPath carries no bridgeExe -- it was written by an older setup\30-ghidra.ps1 that did not record one"
                }
            }
            catch {
                $why = "$ManifestPath could not be read: $($_.Exception.Message)"
            }
        }
        if (-not $command) {
            $command = $conventional
            Write-Warning ("The ghidra bridge path in this .mcp.json is a GUESS: $why. " +
                "Using $conventional. That is only where setup\30-ghidra.ps1 puts it BY DEFAULT: " +
                'on a machine whose repos live anywhere else, the ghidra server in this config can ' +
                'never spawn, and the first symptom is an agent session with no Ghidra tools in it. ' +
                'Run setup\30-ghidra.ps1 -- it records the real path -- and generate this again.')
        }
    }

    $pin = "$script:X64dbgMcpServerPin".Trim()
    if (-not $pin) {
        # Not reachable from any argument: it means the constant above is gone, or that a caller
        # dot-sourced _common.ps1 somewhere its script scope cannot see. Refuse rather than emit
        # 'x64dbg-mcp-server@', which npx resolves to whatever is newest -- an unpinned server
        # against a pinned plugin is the drift this constant exists to make impossible.
        throw 'X64dbgMcpServerPin is empty -- setup\_common.ps1 defines it, so dot-source it at your script''s top level. Refusing to write an unpinned x64dbg-mcp-server@ into .mcp.json.'
    }

    [ordered]@{
        mcpServers = [ordered]@{
            ghidra = [ordered]@{
                type    = 'stdio'
                command = $command
                args    = @()
                env     = [ordered]@{
                    PYTHONIOENCODING = 'utf-8'
                    # REQUIRED for the headless server, not a convenience. The bridge discovers
                    # instances by probing /mcp/instance_info across 8089..8104, and that endpoint
                    # is registered only by the Ghidra GUI plugin -- headless never serves it, so
                    # list_instances() returns [] and NO tools register at all. This pins the
                    # bridge's TCP fallback instead, which fetches /mcp/schema directly and
                    # auto-connects. Drop it only if you are driving the GUI.
                    GHIDRA_MCP_URL   = "http://127.0.0.1:$Port"
                }
            }
            x64dbg = [ordered]@{
                type    = 'stdio'
                command = 'cmd'
                # 'cmd /c npx' rather than 'npx': on Windows npx is npx.cmd, a batch script, and
                # an MCP client spawns its servers directly with no shell -- which cannot execute
                # one. The '-y' matters as much: without it npx stops to ask before fetching the
                # package, and the only console a stdio server has is the client's pipe, so that
                # prompt is never seen, never answered, and the server never starts.
                args    = @('/c', 'npx', '-y', "x64dbg-mcp-server@$pin")
            }
        }
    }
}
