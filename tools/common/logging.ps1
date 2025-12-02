<#
.SYNOPSIS
  Shared logging helpers for capturing stderr from external tooling.

.NOTES
  Logs are written under repo_root/logs/{script-name}/
  Individual log files are created per command invocation to avoid race conditions.
#>

$__loggingScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$__loggingRepoRoot   = Split-Path (Split-Path $__loggingScriptRoot)

function Get-LogRoot {
  $logRoot = Join-Path $__loggingRepoRoot 'logs'
  if (-not (Test-Path $logRoot)) {
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
  }
  return $logRoot
}

function New-LogFilePath {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptName
  )
  $scriptFolder = Join-Path (Get-LogRoot) $ScriptName
  if (-not (Test-Path $scriptFolder)) {
    New-Item -ItemType Directory -Path $scriptFolder -Force | Out-Null
  }
  $fileName = "{0}-PID{1}-{2}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmssfff'), $PID, ([Guid]::NewGuid().ToString("N").Substring(0,8))
  return Join-Path $scriptFolder $fileName
}

function Write-CommandErrorLog {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptName,
    [Parameter(Mandatory=$true)][string]$CommandLine,
    [int]$ExitCode = 0,
    [string]$StdErr = "",
    [switch]$TreatExitCodeOneAsSuccess
  )

  $trimmedErr = if ($StdErr) { $StdErr.Trim() } else { "" }
  $exitIsOk = ($ExitCode -eq 0) -or ($TreatExitCodeOneAsSuccess -and $ExitCode -eq 1)

  if ($exitIsOk -and [string]::IsNullOrWhiteSpace($trimmedErr)) {
    return $null
  }

  $logPath = New-LogFilePath -ScriptName $ScriptName
  $header = @"
# Script : $ScriptName
# Command: $CommandLine
# Started: $(Get-Date -Format 'u')
# Exit   : $ExitCode
"@
  $header | Out-File -FilePath $logPath -Encoding UTF8

  if (-not [string]::IsNullOrWhiteSpace($trimmedErr)) {
    "---- stderr ----" | Out-File -FilePath $logPath -Encoding UTF8 -Append
    $StdErr | Out-File -FilePath $logPath -Encoding UTF8 -Append
  }

  return $logPath
}
