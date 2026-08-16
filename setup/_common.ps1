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
