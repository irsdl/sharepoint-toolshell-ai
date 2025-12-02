param(
  [Parameter(Mandatory=$true)][string]$SnapshotsRoot,
  [string]$NormalizedName = "BUILD_VERSION",
  [string]$VersionPattern = '^\d+\.\d+\.\d+\.\d+$',
  [switch]$DryRun,
  [switch]$SkipConsistent,
  [switch]$ShowDetails
)

$ErrorActionPreference = "Stop"

Write-Host "=== Version Folder Normalization Utility ===" -ForegroundColor Cyan
Write-Host "Purpose: Normalize version-numbered folders for cross-version diffing" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $SnapshotsRoot)) {
  throw "SnapshotsRoot does not exist: $SnapshotsRoot"
}

if ($DryRun) {
  Write-Host "DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
  Write-Host ""
}

# Function to resolve conflict names
function Resolve-ConflictName {
  param(
    [string]$ParentPath,
    [string]$BaseName
  )

  # Try base name first
  $targetPath = Join-Path $ParentPath $BaseName
  if (-not (Test-Path $targetPath)) {
    return @{ Name = $BaseName; Conflict = $false }
  }

  # Try with one underscore
  $targetPath = Join-Path $ParentPath "${BaseName}_"
  if (-not (Test-Path $targetPath)) {
    return @{ Name = "${BaseName}_"; Conflict = $true; Level = 1 }
  }

  # Try with two underscores
  $targetPath = Join-Path $ParentPath "${BaseName}__"
  if (-not (Test-Path $targetPath)) {
    return @{ Name = "${BaseName}__"; Conflict = $true; Level = 2 }
  }

  # Try with three underscores
  $targetPath = Join-Path $ParentPath "${BaseName}___"
  if (-not (Test-Path $targetPath)) {
    return @{ Name = "${BaseName}___"; Conflict = $true; Level = 3 }
  }

  # All options exhausted
  return @{ Name = $null; Conflict = $true; Level = 4; Error = $true }
}

# Discover version folders
Write-Host "[1/5] Discovering version folders..." -ForegroundColor Cyan

$versions = Get-ChildItem $SnapshotsRoot -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^v\d+' } |
  Sort-Object Name

if ($versions.Count -eq 0) {
  Write-Host "No version directories found in $SnapshotsRoot" -ForegroundColor Yellow
  exit 0
}

$allVersionFolders = @{}
$totalFound = 0

foreach ($ver in $versions) {
  Write-Host "  Scanning $($ver.Name)..." -NoNewline

  # Find all folders matching version pattern
  $versionFolders = Get-ChildItem $ver.FullName -Directory -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $VersionPattern }

  $allVersionFolders[$ver.Name] = @()

  foreach ($folder in $versionFolders) {
    # Calculate relative parent path (without the version folder itself)
    $relativePath = $folder.FullName.Substring($ver.FullName.Length).TrimStart('\','/')
    $parentPath = Split-Path $relativePath -Parent

    $allVersionFolders[$ver.Name] += [PSCustomObject]@{
      FullPath = $folder.FullName
      ParentPath = $parentPath
      VersionNumber = $folder.Name
      RelativePath = $relativePath
    }
  }

  Write-Host " $($allVersionFolders[$ver.Name].Count) version folders" -ForegroundColor Gray
  $totalFound += $allVersionFolders[$ver.Name].Count
}

Write-Host "  Total: $totalFound version folders scanned" -ForegroundColor Green
Write-Host ""

# Analyze consistency
Write-Host "[2/5] Analyzing consistency..." -ForegroundColor Cyan

# Build map of parent paths to version numbers
$pathMap = @{}

foreach ($verName in $allVersionFolders.Keys) {
  foreach ($folder in $allVersionFolders[$verName]) {
    if (-not $pathMap.ContainsKey($folder.ParentPath)) {
      $pathMap[$folder.ParentPath] = @{}
    }
    $pathMap[$folder.ParentPath][$verName] = $folder.VersionNumber
  }
}

Write-Host "  Analyzing $($pathMap.Keys.Count) unique parent paths..." -ForegroundColor Gray
Write-Host ""

$inconsistentPaths = @()
$consistentPaths = @()
$renameList = @()

foreach ($parentPath in $pathMap.Keys | Sort-Object) {
  $versionsBySnapshot = $pathMap[$parentPath]
  $uniqueVersions = $versionsBySnapshot.Values | Sort-Object -Unique

  if ($uniqueVersions.Count -gt 1) {
    # Inconsistent - different versions across snapshots
    $inconsistentPaths += $parentPath

    if ($ShowDetails) {
      Write-Host "  Path: $parentPath" -ForegroundColor Yellow
      foreach ($snap in $versionsBySnapshot.Keys | Sort-Object) {
        Write-Host "    $snap`: $($versionsBySnapshot[$snap])" -ForegroundColor Gray
      }
      Write-Host "    Status: REQUIRES NORMALIZATION" -ForegroundColor Yellow
      Write-Host ""
    }

    # Add to rename list
    foreach ($verName in $versions.Name) {
      if ($versionsBySnapshot.ContainsKey($verName)) {
        $originalFolder = $allVersionFolders[$verName] | Where-Object { $_.ParentPath -eq $parentPath }
        if ($originalFolder) {
          $renameList += $originalFolder
        }
      }
    }
  } else {
    # Consistent - same version across all snapshots
    $consistentPaths += $parentPath

    if ($ShowDetails) {
      Write-Host "  Path: $parentPath" -ForegroundColor Gray
      Write-Host "    Version: $($uniqueVersions[0]) (consistent across all)" -ForegroundColor Gray
      Write-Host "    Status: SKIPPED" -ForegroundColor Green
      Write-Host ""
    }
  }
}

Write-Host "  Analysis complete:" -ForegroundColor Cyan
Write-Host "    - Inconsistent paths: $($inconsistentPaths.Count)" -ForegroundColor Yellow
Write-Host "    - Already consistent: $($consistentPaths.Count)" -ForegroundColor Green
Write-Host "    - Total renames needed: $($renameList.Count)" -ForegroundColor Yellow
Write-Host ""

if ($renameList.Count -eq 0) {
  Write-Host "All version folders are already consistent - no action needed!" -ForegroundColor Green
  exit 0
}

# Resolve conflicts
Write-Host "[3/5] Resolving conflicts..." -ForegroundColor Cyan

$resolvedRenames = @()
$conflictsResolved = 0
$errors = @()

foreach ($folder in $renameList) {
  $parentFullPath = Split-Path $folder.FullPath -Parent
  $resolution = Resolve-ConflictName -ParentPath $parentFullPath -BaseName $NormalizedName

  if ($resolution.Error) {
    $errorMsg = "CONFLICT: Cannot resolve name for $($folder.FullPath) - all options exhausted"
    $errors += $errorMsg
    Write-Host "  X $($folder.RelativePath) -> ERROR (all naming options exhausted)" -ForegroundColor Red
  } else {
    $resolvedRenames += [PSCustomObject]@{
      OriginalPath = $folder.FullPath
      TargetName = $resolution.Name
      RelativePath = $folder.RelativePath
      ConflictResolved = $resolution.Conflict
    }

    if ($resolution.Conflict) {
      $conflictsResolved++
      Write-Host "  $($folder.RelativePath) -> $($resolution.Name) (conflict level $($resolution.Level))" -ForegroundColor Yellow
    } else {
      Write-Host "  $($folder.RelativePath) -> $($resolution.Name)" -ForegroundColor Green
    }
  }
}

Write-Host ""
Write-Host "  Conflict resolution:" -ForegroundColor Cyan
Write-Host "    - Successful renames: $($resolvedRenames.Count)" -ForegroundColor Green
Write-Host "    - Conflicts resolved: $conflictsResolved" -ForegroundColor Yellow
Write-Host "    - Errors: $($errors.Count)" -ForegroundColor $(if ($errors.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($errors.Count -gt 0) {
  Write-Host "=== CRITICAL ERRORS ===" -ForegroundColor Red
  foreach ($error in $errors) {
    Write-Host "  $error" -ForegroundColor Red
  }
  Write-Host ""
  Write-Host "ACTION REQUIRED: Manual intervention needed" -ForegroundColor Yellow
  Write-Host "  1. Review existing $NormalizedName* folders" -ForegroundColor Yellow
  Write-Host "  2. Determine if they can be merged or renamed" -ForegroundColor Yellow
  Write-Host "  3. Re-run script after cleanup" -ForegroundColor Yellow
  exit 1
}

# Execute renames
Write-Host "[4/5] Execution..." -ForegroundColor Cyan

if ($DryRun) {
  Write-Host "  Skipped (DRY RUN MODE)" -ForegroundColor Yellow
} else {
  $renamed = 0
  foreach ($rename in $resolvedRenames) {
    try {
      $parentPath = Split-Path $rename.OriginalPath -Parent
      $targetPath = Join-Path $parentPath $rename.TargetName

      Move-Item -LiteralPath $rename.OriginalPath -Destination $targetPath -Force
      $renamed++
      Write-Host "  Renamed: $($rename.RelativePath) → $($rename.TargetName)" -ForegroundColor Green
    } catch {
      Write-Host "  FAILED: $($rename.OriginalPath)" -ForegroundColor Red
      Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    }
  }
  Write-Host ""
  Write-Host "  Renamed $renamed folders successfully" -ForegroundColor Green
}

Write-Host ""

# Summary
Write-Host "[5/5] Summary" -ForegroundColor Cyan
Write-Host "  Total version folders: $totalFound" -ForegroundColor Gray
Write-Host "  Paths analyzed: $($pathMap.Keys.Count)" -ForegroundColor Gray
Write-Host "  Inconsistent paths: $($inconsistentPaths.Count)" -ForegroundColor Yellow
Write-Host "  Folders to rename: $($renameList.Count)" -ForegroundColor Yellow
Write-Host "  Conflicts resolved: $conflictsResolved" -ForegroundColor $(if ($conflictsResolved -gt 0) { "Yellow" } else { "Gray" })
Write-Host "  Errors: $($errors.Count)" -ForegroundColor $(if ($errors.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""

# Generate report
if (-not $DryRun -and $resolvedRenames.Count -gt 0) {
  $reportPath = Join-Path $SnapshotsRoot "version-normalize-report-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"

  "Version Folder Normalization Report" | Out-File -FilePath $reportPath -Encoding UTF8
  "=====================================" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "Normalized Name: $NormalizedName" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "Version Pattern: $VersionPattern" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "RENAMES APPLIED:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  "" | Out-File -FilePath $reportPath -Append -Encoding UTF8

  foreach ($rename in $resolvedRenames) {
    $conflictNote = if ($rename.ConflictResolved) { " [CONFLICT RESOLVED]" } else { "" }
    "$($rename.RelativePath) → $($rename.TargetName)$conflictNote" | Out-File -FilePath $reportPath -Append -Encoding UTF8
  }

  Write-Host "Report written: $reportPath" -ForegroundColor Gray
  Write-Host ""
}

if ($DryRun) {
  Write-Host "Dry run complete. Run without -DryRun to execute renames." -ForegroundColor Yellow
} else {
  Write-Host "Version folder normalization complete!" -ForegroundColor Green
}
