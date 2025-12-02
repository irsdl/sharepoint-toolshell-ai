param(
  [Parameter(Mandatory=$true)][string]$FromDir,  # e.g. snapshots_norm/v1
  [Parameter(Mandatory=$true)][string]$ToDir,    # e.g. snapshots_norm/v2
  [string]$OutDir = ""
)

# Generate server-side-only diffs (C# code + SharePoint configs/pages)
# This is a focused subset for SharePoint security analysis
# Includes: .cs (from decompiled), .config, .aspx, .ascx, .asmx, .svc, .master, .cshtml (from norm)

$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrEmpty($OutDir)) {
  $OutDir = Join-Path (Split-Path (Split-Path $scriptRoot)) 'diff_reports'
}
$repoRoot = Split-Path (Split-Path $scriptRoot)
. (Join-Path $repoRoot 'tools\common\logging.ps1')

function Normalize-VersionName {
  param([string]$Path)
  $leaf = Split-Path $Path -Leaf
  if ($leaf -match '^(v\d+)[-_]\d{8}-\d{4}$') {
    return $matches[1]
  }
  return $leaf
}

function Invoke-GitDiffLogged {
  param(
    [Parameter(Mandatory=$true)][string]$WorkingDir,
    [Parameter(Mandatory=$true)][string[]]$Arguments,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$Description
  )

  $stderrTemp = [System.IO.Path]::GetTempFileName()
  Push-Location $WorkingDir
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
  $logPath = Write-CommandErrorLog -ScriptName 'make-diff-server-side' -CommandLine $cmdLine -StdErr $stderr -ExitCode $exitCode -TreatExitCodeOneAsSuccess

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

$fromNormDir = (Resolve-Path $FromDir).Path
$toNormDir   = (Resolve-Path $ToDir).Path
$fromVersion = Normalize-VersionName $fromNormDir
$toVersion   = Normalize-VersionName $toNormDir

$decompiledRoot = Join-Path $repoRoot 'snapshots_decompiled'
$decompiled1 = Join-Path $decompiledRoot $fromVersion
$decompiled2 = Join-Path $decompiledRoot $toVersion

# Verify directories exist
foreach ($dir in @($fromNormDir, $toNormDir, $decompiled1, $decompiled2)) {
  if (-not (Test-Path $dir)) {
    throw "Directory not found: $dir"
  }
}

$pairName = "$fromVersion-to-$toVersion.server-side"
$patch = Join-Path $OutDir "$pairName.patch"
$stat  = Join-Path $OutDir "$pairName.stat.txt"

Write-Host "Generating server-side diff between $fromVersion and $toVersion..."
Write-Host "This includes:"
Write-Host "  - .cs files (decompiled managed code)"
Write-Host "  - .config, .aspx, .ascx, .asmx, .svc, .master, .cshtml (SharePoint web files)"

# Create temporary combined directories for each version
$runId = [Guid]::NewGuid().ToString("N").Substring(0,4)
$tempRoot = Join-Path $OutDir ".temp-$runId"
$temp1 = Join-Path $tempRoot $fromVersion
$temp2 = Join-Path $tempRoot $toVersion

if (Test-Path $tempRoot) { Remove-Item $tempRoot -Recurse -Force }
New-Item -ItemType Directory -Path $temp1 -Force | Out-Null
New-Item -ItemType Directory -Path $temp2 -Force | Out-Null

# Copy relevant files to temp directories
Write-Host "Preparing temporary directories..."

# Helper function to copy files with specific extensions
function Copy-FilteredFiles {
  param(
    [string]$Source,
    [string]$Dest,
    [string[]]$Extensions
  )

  foreach ($ext in $Extensions) {
    $files = Get-ChildItem -Path $Source -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $files) {
      $relativePath = $file.FullName.Substring($Source.Length + 1)
      $destPath = Join-Path $Dest $relativePath
      $destDir = Split-Path $destPath

      if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
      }

      Copy-Item $file.FullName -Destination $destPath -Force
    }
  }
}

# Copy .cs files from decompiled directories
Write-Host "  Copying .cs files from decompiled sources..."
Copy-FilteredFiles -Source $decompiled1 -Dest $temp1 -Extensions @('*.cs')
Copy-FilteredFiles -Source $decompiled2 -Dest $temp2 -Extensions @('*.cs')

# Copy web/config files from norm directories
Write-Host "  Copying SharePoint web and config files from normalized sources..."
$webExtensions = @('*.config', '*.aspx', '*.ascx', '*.asmx', '*.svc', '*.master', '*.cshtml')
Copy-FilteredFiles -Source $fromNormDir -Dest $temp1 -Extensions $webExtensions
Copy-FilteredFiles -Source $toNormDir -Dest $temp2 -Extensions $webExtensions

# Count files
$count1 = (Get-ChildItem $temp1 -Recurse -File).Count
$count2 = (Get-ChildItem $temp2 -Recurse -File).Count
Write-Host "  ${fromVersion}: $count1 files, ${toVersion}: $count2 files"

# Generate diff using relative paths to avoid leaking local drive details
Write-Host "Running git diff..."
$patchArgs = @('diff','--no-index','--patch','--text','--ignore-cr-at-eol',$temp1,$temp2)
Invoke-GitDiffLogged -WorkingDir $OutDir -Arguments $patchArgs -OutputPath $patch -Description "$pairName patch"

$statArgs = @('diff','--no-index','--stat','--text','--ignore-cr-at-eol',$temp1,$temp2)
Invoke-GitDiffLogged -WorkingDir $OutDir -Arguments $statArgs -OutputPath $stat -Description "$pairName stat"

# Clean up temp directories
Write-Host "Cleaning up temporary directories..."
Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Server-side diff ready:"
Write-Host " - $patch"
Write-Host " - $stat"
