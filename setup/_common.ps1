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
