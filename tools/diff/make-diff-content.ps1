param(
  [Parameter(Mandatory=$true)][string]$FromDir,  # e.g. snapshots_norm/v1
  [Parameter(Mandatory=$true)][string]$ToDir,    # e.g. snapshots_norm/v2
  [string]$OutDir = "",
  [string[]]$IncludeExt = @('*.config','*.xml','*.json','*.aspx','*.ascx','*.master','*.cshtml',
                            '*.svc','*.asmx','*.xaml','*.xamlx','*.xoml','*.ashx','*.axd','*.soap',
                            '*.js','*.html','*.htm','*.ps1','*.psm1','*.psd1','*.resx','*.xslt','*.css','*.ts'),
  [switch]$ExcludeManagedDlls
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

function Get-RelativePath {
  param(
    [Parameter(Mandatory=$true)][string]$BasePath,
    [Parameter(Mandatory=$true)][string]$TargetPath
  )
  $base = (Resolve-Path $BasePath).Path
  $target = (Resolve-Path $TargetPath).Path
  if (-not $base.EndsWith('\')) { $base += '\' }
  $baseUri = New-Object System.Uri($base, [System.UriKind]::Absolute)
  $targetUri = New-Object System.Uri($target, [System.UriKind]::Absolute)
  return [System.Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()).Replace('/', '\')
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
  $logPath = Write-CommandErrorLog -ScriptName 'make-diff-content' -CommandLine $cmdLine -StdErr $stderr -ExitCode $exitCode -TreatExitCodeOneAsSuccess

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
$pairName = "$fromNorm-to-$toNorm"
$outputLabel = 'content'
$patch = Join-Path $OutDir "$pairName.$outputLabel.patch"
$stat  = Join-Path $OutDir "$pairName.$outputLabel.stat.txt"

# Build optional exclusions for managed DLLs
$managedPaths = @{}
if ($ExcludeManagedDlls) {
  $hashesRoot = Join-Path $repoRoot 'artifacts\file-hashes'
  $exclusions = @()

  foreach ($version in @($fromNorm, $toNorm)) {
    $csvPath = Join-Path $hashesRoot "$version.csv"
    if (Test-Path $csvPath) {
      Write-Host "Loading managed DLL exclusions from: $version"
      $all = Import-Csv $csvPath -Encoding UTF8
      $managed = $all | Where-Object { $_.IsManaged -eq 'True' }
      Write-Host "  Found $($managed.Count) managed assemblies to exclude"
      foreach ($entry in $managed) {
        $relPath = $entry.Path
        if ($relPath) { $exclusions += ":(exclude)$relPath" }
      }
    } else {
      Write-Warning "Hash CSV not found: $csvPath - managed DLL exclusion skipped for this version"
    }
  }

  if ($exclusions.Count -gt 0) {
    Write-Host "Building exclusion set for $($exclusions.Count) managed assemblies..."
    foreach ($exclusion in $exclusions) {
      $path = $exclusion -replace '^\:\(exclude\)', ''
      $managedPaths[$path] = $true
    }
  }
} else {
  Write-Host "ExcludeManagedDlls disabled - managed assemblies will be included in diff."
}

Write-Host "Generating content diff between $fromNorm and $toNorm..."

if ($ExcludeManagedDlls -and $managedPaths.Count -gt 0) {
  # Create temporary directories with filtered files (excluding managed DLLs)
  Write-Host "Filtering out managed DLLs..."
  $runId   = [Guid]::NewGuid().ToString("N").Substring(0,4)
  $tempRoot = Join-Path $OutDir ".temp-$runId"
  $temp1 = Join-Path $tempRoot $fromNorm
  $temp2 = Join-Path $tempRoot $toNorm

  if (Test-Path $tempRoot) { Remove-Item $tempRoot -Recurse -Force }
  New-Item -ItemType Directory -Path $temp1 -Force | Out-Null
  New-Item -ItemType Directory -Path $temp2 -Force | Out-Null

  # Copy files excluding managed DLLs
  foreach ($dirInfo in @(@{Source=$FromDir; Dest=$temp1}, @{Source=$ToDir; Dest=$temp2})) {
    $srcPath = (Resolve-Path $dirInfo.Source).Path.TrimEnd('\', '/')
    $destPath = $dirInfo.Dest
    $allFiles = Get-ChildItem -Path $srcPath -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $allFiles) {
      # Calculate relative path from source directory
      $relativePath = $file.FullName.Substring($srcPath.Length).TrimStart('\', '/')
      # Normalize to backslashes to match CSV format
      $relativePath = $relativePath.Replace('/', '\')

      # Check if file extension matches IncludeExt patterns
      $matchesExt = $false
      foreach ($pattern in $IncludeExt) {
        if ($file.Name -like $pattern) {
          $matchesExt = $true
          break
        }
      }

      # Include file if it matches extension AND is not a managed DLL
      if ($matchesExt -and -not $managedPaths.ContainsKey($relativePath)) {
        $targetPath = Join-Path $destPath $relativePath
        $targetDir = Split-Path $targetPath -Parent
        if (-not (Test-Path $targetDir)) {
          New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }
        Copy-Item $file.FullName -Destination $targetPath -Force
      }
    }
  }

  $count1 = (Get-ChildItem $temp1 -Recurse -File).Count
  $count2 = (Get-ChildItem $temp2 -Recurse -File).Count
  Write-Host "  ${fromNorm}: $count1 files (excluding managed), ${toNorm}: $count2 files (excluding managed)"

  $patchArgs = @('diff','--no-index','--patch','--text','--ignore-cr-at-eol',$temp1,$temp2)
  Invoke-GitDiffLogged -WorkingDir $OutDir -Arguments $patchArgs -OutputPath $patch -Description "$pairName content patch"

  $statArgs = @('diff','--no-index','--stat','--text','--ignore-cr-at-eol',$temp1,$temp2)
  Invoke-GitDiffLogged -WorkingDir $OutDir -Arguments $statArgs -OutputPath $stat -Description "$pairName content stat"

  # Clean up temp directories
  Remove-Item $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
} else {
  if ($ExcludeManagedDlls -and $managedPaths.Count -eq 0) {
    Write-Host "  No managed assemblies detected (or CSV missing) - running full diff."
  }
  # No exclusions, run directly from repo root using relative paths
  $relativeFrom = Get-RelativePath -BasePath $repoRoot -TargetPath $FromDir
  $relativeTo   = Get-RelativePath -BasePath $repoRoot -TargetPath $ToDir
  $patchArgs = @('diff','--no-index','--patch','--text','--ignore-cr-at-eol',$relativeFrom,$relativeTo)
  Invoke-GitDiffLogged -WorkingDir $repoRoot -Arguments $patchArgs -OutputPath $patch -Description "$pairName content patch"

  $statArgs = @('diff','--no-index','--stat','--text','--ignore-cr-at-eol',$relativeFrom,$relativeTo)
  Invoke-GitDiffLogged -WorkingDir $repoRoot -Arguments $statArgs -OutputPath $stat -Description "$pairName content stat"
}

Write-Host "Content diff ready:"
Write-Host " - $patch"
Write-Host " - $stat"
