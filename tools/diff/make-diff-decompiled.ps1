param(
  [Parameter(Mandatory=$true)][string]$FromDir,  # e.g. src_decompiled\SERVERA\v1_YYYY...\code
  [Parameter(Mandatory=$true)][string]$ToDir,    # e.g. src_decompiled\SERVERB\v2_YYYY...\code
  [string]$OutDir = "",
  # Only include C# source and project files (per agent.md specifications)
  # Excludes binary resources, images, and metadata files
  [string[]]$IncludeExt = @('*.cs','*.csproj','*.vbproj','*.props','*.targets','*.sln','*.resx')
)

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrEmpty($OutDir)) {
  $OutDir = Join-Path (Split-Path (Split-Path $scriptRoot)) 'diff_reports'
}
$repoRoot = Split-Path (Split-Path $scriptRoot)
. (Join-Path $repoRoot 'tools\common\logging.ps1')

# Helper function to normalize version names (remove timestamps)
function Normalize-VersionName {
  param([string]$Path)
  $leaf = Split-Path $Path -Leaf
  # Strip timestamp suffix: v1_20240115-1430 or v1-20240115-1430 -> v1
  if ($leaf -match '^(v\d+)[-_]\d{8}-\d{4}$') {
    return $matches[1]
  }
  return $leaf
}

function Invoke-GitDiffLogged {
  param(
    [Parameter(Mandatory=$true)][string[]]$Arguments,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$Description
  )

  $stderrTemp = [System.IO.Path]::GetTempFileName()
  Push-Location $repoRoot
  try {
    $gitArgs = @('-c','core.autocrlf=false','-c','core.safecrlf=false') + $Arguments
    & git @gitArgs 2> $stderrTemp | Out-File -FilePath $OutputPath -Encoding UTF8
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }

  $stderr = if (Test-Path $stderrTemp) { Get-Content $stderrTemp -Raw } else { "" }
  Remove-Item $stderrTemp -Force -ErrorAction SilentlyContinue

  $cmdLine = "git {0}" -f ($Arguments -join ' ')
  $logPath = Write-CommandErrorLog -ScriptName 'make-diff-decompiled' -CommandLine $cmdLine -StdErr $stderr -ExitCode $exitCode -TreatExitCodeOneAsSuccess

  if ($logPath) {
    Write-Warning "$Description produced diagnostics. See $logPath"
  }

  if ($exitCode -gt 1) {
    throw "git diff failed while generating $Description. See $logPath for details."
  }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "Git is required. Install Git and try again."
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# Use normalized names for consistent output across machines
$fromNorm = Normalize-VersionName (Split-Path $FromDir -Leaf)
$toNorm = Normalize-VersionName (Split-Path $ToDir -Leaf)
$pairName = "$fromNorm-to-$toNorm.decompiled"
$patch = Join-Path $OutDir "$pairName.patch"
$stat  = Join-Path $OutDir "$pairName.stat.txt"

$fromPath = (Resolve-Path $FromDir).Path
$toPath   = (Resolve-Path $ToDir).Path

Write-Host "Generating diff between $fromNorm and $toNorm..."

# Build git pathspecs from IncludeExt to filter file types
$pathspecs = @()
$pathspecs += ':(exclude)**/source-path.txt'  # Always exclude metadata
foreach ($ext in $IncludeExt) {
  # Convert *.cs to :(glob)**/*.cs pathspec format
  $pathspecs += ":(glob)**/$ext"
}

$sharedArgs = @('--no-index','--text','--ignore-cr-at-eol',$fromPath,$toPath,'--') + $pathspecs

$patchArgs = @('diff','--patch') + $sharedArgs
Invoke-GitDiffLogged -Arguments $patchArgs -OutputPath $patch -Description "$pairName patch"

$statArgs = @('diff','--stat') + $sharedArgs
Invoke-GitDiffLogged -Arguments $statArgs -OutputPath $stat -Description "$pairName stat"

Write-Host "Decompiled code diff ready:"
Write-Host " - $patch"
Write-Host " - $stat"
