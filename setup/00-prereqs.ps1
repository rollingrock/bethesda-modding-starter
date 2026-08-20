<#
.SYNOPSIS
    Install (or verify) the base toolchain for Bethesda script-extender plugin dev + RE.

.DESCRIPTION
    Idempotent: checks first, installs only what is missing, prints a summary table.
    Run from an elevated PowerShell if you expect installs (winget machine-scope installs
    and VS need it); -CheckOnly never needs elevation.

    Every check RUNS the tool it is about -- Test-CmdRuns / Test-VsWorkload from _common.ps1 --
    and re-runs it after an install instead of re-reading a captured answer. Both halves were
    real defects: the Microsoft Store's 0-byte python.exe stub satisfied a Get-Command check on
    a machine with no Python at all, and a captured vswhere result made every successful Visual
    Studio install report failure.

    Installs via winget:
      Git, CMake, Visual Studio 2022 Community (+ Desktop C++ workload), Python 3.12,
      Temurin JDK 21 (Ghidra + the GhidraMCP build), Node.js LTS (x64dbg MCP server),
      GitHub CLI.

    Not required, deliberately:
      * Maven — winget has no such package, and 30-ghidra.ps1 uses gradlew.bat instead.
      * PowerShell 7 — every script here is Windows PowerShell 5.1 compatible on purpose,
        because 5.1 is what a fresh Windows box and `shell: powershell` in CI both run.
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly
)

. "$PSScriptRoot\_common.ps1"

# Pick up anything installed since this shell started (see Sync-Path) — otherwise a tool
# winget already installed reads as MISSING and we try to install it a second time.
Sync-Path

$results = [System.Collections.Generic.List[object]]::new()

# The scriptblock handed in is a PROBE, not a boolean: it RUNS the tool and returns the
# four-property result (Name/Status/Detail/Command) from _common.ps1's predicate layer. Two
# consequences, and each one was a bug in this file.
#
# It is EXECUTED, so "present" means the tool answered -- not that Get-Command found a file
# with the right name sitting on PATH.
#
# It is RE-INVOKED after the install rather than re-read. Handing in `{ $hasVs }`, a bare
# variable computed before the install, made the post-install question return the pre-install
# answer, so the VS row -- the one install measured in tens of minutes -- always reported
# unfinished. Sync-Path, the fix for the earlier stale-check bug, only refreshes a stale PATH;
# a stale ANSWER is immune to it, which is exactly why a vswhere probe that never consults PATH
# was affected at all. Nothing in this file may capture a probe result and hand the capture
# back as a check.
function Ensure-Winget([string]$display, [string]$id, [scriptblock]$probe, [string]$override = '') {
    $before = & $probe
    if ("$($before.Status)" -eq 'OK') {
        $results.Add([pscustomobject]@{ Component = $display; Status = 'present'; Action = '-' })
        return
    }
    # Print what the probe OBSERVED before acting on it: the table's verdict column cannot carry
    # it, and the distinction decides what a human does next. "exit code 9009 from
    # %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" and "not on PATH" are different machine
    # states with different fixes, and only the first sends anyone to Settings > App execution
    # aliases. Write-ProbeResult prints the exact command underneath, so a failure can be
    # reproduced by hand instead of guessed at.
    Write-ProbeResult $before
    if ($CheckOnly) {
        $results.Add([pscustomobject]@{ Component = $display; Status = 'MISSING'; Action = "winget install $id" })
        return
    }
    Write-Host "Installing $display ..."
    $wingetArgs = @('install', '--id', $id, '-e', '--accept-source-agreements', '--accept-package-agreements')
    if ($override) { $wingetArgs += @('--override', $override) }
    & winget @wingetArgs
    # Read winget's own exit code HERE, before anything else runs a native command: the re-probe
    # below runs one or more, and $LASTEXITCODE always belongs to whatever ran last. Judge a
    # probe by its .Status, never by the exit code it left behind.
    $ok = ($LASTEXITCODE -eq 0)
    # winget put the new bin dir in the registry PATH; make it usable in THIS process so
    # the check below (and every later script) sees it without a new terminal.
    Sync-Path
    $after = & $probe
    $visible = ("$($after.Status)" -eq 'OK')
    # An install that did not take is the case most worth explaining, and 'FAILED' in a table
    # explains nothing. This is the tool's own account of why it still is not usable.
    if (-not $visible) { Write-ProbeResult $after }
    $status = if ($visible) { 'installed' }
    elseif ($ok) { 'installed (new shell needed)' }
    else { 'FAILED' }
    $results.Add([pscustomobject]@{ Component = $display; Status = $status; Action = "winget $id" })
}

# The rule the rest of this file now follows, applied first to the installer itself: RUN it.
# winget.exe under WindowsApps is an app-execution alias exactly like python's, so Get-Command
# resolving it establishes only that Windows has an entry by that name -- App Installer can be
# un-provisioned for this user or mid-update, and then the alias resolves and the invocation
# does not. Every row below depends on winget working, so this one is fatal instead of a row.
# The message keeps the words 'winget is not available' verbatim: ps-compat.yml's smoke step
# tolerates exactly that thrown message on runner images that ship without winget, and it
# matches by text.
$wingetProbe = Test-CmdRuns -Name 'winget' -ProbeArgs @('--version') -MinMajor 1
if ($wingetProbe.Status -ne 'OK') {
    Write-ProbeResult $wingetProbe
    throw "winget is not available: $($wingetProbe.Detail). Install `"App Installer`" from the Microsoft Store first."
}

# Every row below RUNS its tool and judges the exit code, because existence is not capability.
# Stock Windows 10/11 ships 0-byte Microsoft Store app-execution-alias stubs at
# %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe, that directory is on the User PATH, and
# Get-Command resolves the stub as an ordinary ApplicationInfo -- so `Test-Cmd 'python'` said
# "present" on a fresh consumer machine with no Python on it, winget never installed
# Python.Python.3.12, this script printed "All prerequisites present." and exited 0, and the
# first thing that actually ran python -- `python -m venv .venv` in 30-ghidra.ps1, two phases
# later -- died on exit 9009. Running the tool is the only thing that tells an interpreter apart
# from a placeholder for one, and CI cannot cover it: GitHub runners ship a real Python, so the
# single machine state this row exists for is never exercised there.
#
# Only KNOWN-TERMINATING probe arguments appear here (--version / -version): Test-CmdRuns waits
# for the process, so an argument that starts a server instead of printing a version would hang
# phase 1 forever.
#
# The floors. -MinMajor compares the MAJOR only, so a floor that lives in a minor (CMake 3.23,
# Python 3.10) is encoded in -VersionPattern instead: the pattern matches only versions at or
# above the floor, group 1 stays the major, and -MinMajor still does the major half. Each floor
# below is one some pinned artifact in this pack actually demands, and nothing beyond it -- a
# floor set higher than what is required turns a working machine red, which is a worse defect
# than the version-blindness being fixed.

# git 2.0 introduced `git -C <dir>`, which 10-vcpkg.ps1, 20-repos.ps1 and the baseline/identity
# probes in _common.ps1 all use; a 1.x git fails every one of them on the argument.
Ensure-Winget 'Git' 'Git.Git' { Test-CmdRuns -Name 'git' -ProbeArgs @('--version') -MinMajor 2 }

# CMake floor 3.23, straight from templates\f4sevr-plugin\CMakeLists.txt:1
# (cmake_minimum_required(VERSION 3.23)): anything older refuses to configure the scaffolded
# project at all. The pattern reads "3.23 or newer within the 3.x line, or any major above 3",
# because what winget installs today is CMake 4.x -- a floor phrased about 3.x that rejected the
# newest supported toolchain would be the exact false failure this change exists to avoid.
Ensure-Winget 'CMake' 'Kitware.CMake' {
    Test-CmdRuns -Name 'cmake' -ProbeArgs @('--version') -MinMajor 3 `
        -VersionPattern 'cmake version (3(?=\.(?:2[3-9]|[3-9]\d|\d{3}))|[4-9]|\d\d+)'
}

# Python floor 3.10, not the 3.12 in the label. 3.12 is which winget package this row installs;
# 3.10 is what the toolchain demands -- ghidra-mcp's pyproject.toml declares
# requires-python = ">=3.10", so 30-ghidra.ps1's `pip install -e .` into the bridge venv refuses
# an older interpreter. A working 3.10 or 3.11 must not be reddened for not being the packaged
# version. Python 2.7, which satisfied the old existence check on a row labelled 3.12, is now
# rejected by the major floor, and the Store stub never reaches the version test at all: it
# exits 9009 first, and that is the whole point of executing the thing.
Ensure-Winget 'Python 3.12' 'Python.Python.3.12' {
    Test-CmdRuns -Name 'python' -ProbeArgs @('--version') -MinMajor 3 `
        -VersionPattern 'Python (3(?=\.\d{2})|[4-9]|\d\d+)'
}

# Temurin: run the java on PATH and floor it at 21, which is what Ghidra 12 and the GhidraMCP
# gradle build both need. Deliberately Test-CmdRuns and NOT Test-JavaForGradle: this row is
# about what winget put on PATH, while Test-JavaForGradle answers the BUILD's question by
# resolving %JAVA_HOME%\bin\java.exe first. Gating an install on that would make a stale
# JAVA_HOME pointing at a JDK 8 winget-install Temurin 21 on every run over a JDK 21 that is
# already installed and already on PATH, and never converge. The JAVA_HOME question belongs to
# 30-ghidra.ps1, where the gradle build actually lives; 90-verify.ps1 carries its own
# 'java >= 21' row for it.
#
# -version, not --version: --version only arrived in JDK 9, so a JDK 8 -- precisely the case
# this floor exists for -- would otherwise fail on the ARGUMENT and report nothing about its
# version. The floor also replaces a hand-rolled 'version "(21|2[2-9])' match that would read a
# future JDK 30 as missing and try to install 21 over it. When this row fails, the Detail names
# the java.exe that answered, which is what identifies an older JDK shadowing a newer one.
Ensure-Winget 'Temurin JDK 21' 'EclipseAdoptium.Temurin.21.JDK' {
    Test-CmdRuns -Name 'java' -ProbeArgs @('-version') -MinMajor 21 -VersionPattern 'version "(\d+)'
}

# No Maven. There is no `Apache.Maven` package in winget (`winget search maven` returns
# only unrelated packages), so requiring it made Phase 4 unreachable on a fresh machine.
# 30-ghidra.ps1 builds the GhidraMCP extension with ghidra-mcp's own gradlew.bat, which
# bootstraps Gradle itself and needs nothing but the JDK.

# Node floor 18: mcp\mcp.template.json launches the x64dbg server as
# `npx -y x64dbg-mcp-server@2.3.0`, an MCP stdio server on the TypeScript SDK, which needs
# Node 18+; Node 16 went end-of-life in September 2023 and cannot run it. 18 rather than the
# current LTS on purpose -- a machine on 20 or 22 works and has to stay green. node prints
# 'v22.11.0', so 'v(\d+)\.' takes the major off the v-prefixed leader instead of trusting the
# default two-number pattern to land on the same digits.
#
# Note what is NOT probed here: the x64dbg MCP server itself. `npx x64dbg-mcp-server` ignores
# --version and --help, starts the stdio server and waits indefinitely, so probing it the way
# this row probes node would hang phase 1 forever -- see the known-terminating-arguments rule
# in _common.ps1 and the same warning at the end of 40-x64dbg.ps1. Node running is as far as
# this script can go, and that is on purpose.
Ensure-Winget 'Node.js LTS' 'OpenJS.NodeJS.LTS' {
    Test-CmdRuns -Name 'node' -ProbeArgs @('--version') -MinMajor 18 -VersionPattern 'v(\d+)\.'
}

# gh: nothing in this pack shells out to gh -- it is installed for the work around the pack
# (issues and PRs against the forks) -- so "does the binary answer" is the whole question, with
# a floor of 2 only because gh 1.x has been out of support since 2021.
Ensure-Winget 'GitHub CLI' 'GitHub.cli' { Test-CmdRuns -Name 'gh' -ProbeArgs @('--version') -MinMajor 2 }

# Visual Studio 2022 with the C++ workload. Detection via vswhere, RE-INVOKED at every ask:
# what used to be here was a $hasVs computed once above this line and a `{ $hasVs }` scriptblock
# handing that capture back as the post-install check. So a VS install that took 30-60 minutes
# and succeeded re-read a boolean that predated it, the row read 'installed (new shell needed)',
# the script exited 1, and the advice was to start a new terminal -- which could not have helped,
# because vswhere lives at a fixed absolute path and no PATH change affects its answer. That is
# the tell for this class of bug: Sync-Path cures a stale PATH, and a captured answer needs
# re-invocation. Test-VsWorkload re-runs vswhere on every call, so passing it as a scriptblock
# is what makes the second question a second question.
Ensure-Winget 'VS2022 + C++ workload' 'Microsoft.VisualStudio.2022.Community' { Test-VsWorkload -MinMajor 17 } `
    '--passive --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended'
# The hint asks vswhere AGAIN for the same reason: it used to test that same stale $hasVs, so it
# printed "VS2022 was already installed WITHOUT the C++ workload" immediately after a clean,
# successful install of exactly that workload. It is worth printing only while the workload is
# still missing right now -- that is the one state a re-run of this script cannot fix by itself,
# since winget will not add a workload to an existing VS. -and short-circuits, so -CheckOnly
# does not pay for the extra vswhere call.
if (-not $CheckOnly -and (Test-VsWorkload -MinMajor 17).Status -ne 'OK') {
    Write-Host ''
    Write-Host 'If VS2022 was already installed WITHOUT the C++ workload, winget will not add it.'
    Write-Host 'Open "Visual Studio Installer" -> Modify -> check "Desktop development with C++".'
}

Write-Host ''
$results | Format-Table -AutoSize
if ($results | Where-Object Status -in 'MISSING', 'FAILED') {
    Write-Host 'Some components are missing/failed. Re-run this script (installs are idempotent).'
    exit 1
}
if ($results | Where-Object Status -like '*new shell*') {
    Write-Host 'Installed, but not visible in this process. Start a new terminal, then re-run to confirm.'
    exit 1
}
Write-Host 'All prerequisites present.'

# $LASTEXITCODE is set by native commands, not by a .ps1 falling off the end -- without
# this an explicit success is indistinguishable from a stale exit code left by whatever
# ran before. Callers (agents, CI, the other setup scripts) gate on it.
exit 0
