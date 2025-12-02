param(
  [Parameter(Mandatory=$true)][string]$SnapshotsRoot,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host "=== Snapshot Folder Rename Utility ===" -ForegroundColor Cyan
Write-Host "Purpose: Remove timestamps from folder names for cross-machine compatibility" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $SnapshotsRoot)) {
  throw "SnapshotsRoot does not exist: $SnapshotsRoot"
}

if ($DryRun) {
  Write-Host "DRY RUN MODE - No changes will be made" -ForegroundColor Yellow
  Write-Host ""
}

$renames = @()
$conflicts = @()

# Pattern for timestamped folders (note: uses DASH not underscore before timestamp)
$timestampPattern = '-(\d{8}-\d{4})$'

# Step 1: Check version folders for timestamps (e.g., v1_20240115-1430 -> v1)
Write-Host "Scanning version folders..." -ForegroundColor Cyan
$versionFolders = Get-ChildItem $SnapshotsRoot -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^v\d+' }

foreach ($folder in $versionFolders) {
  # Version folders could use underscore or dash: v1_20240115-1430 or v1-20240115-1430
  if ($folder.Name -match "^(v\d+)[-_](\d{8}-\d{4})$") {
    $cleanName = $matches[1]
    $cleanPath = Join-Path $SnapshotsRoot $cleanName

    # Check for conflict
    if ((Test-Path $cleanPath) -and $cleanPath -ne $folder.FullName) {
      $conflicts += [PSCustomObject]@{
        Original = $folder.FullName
        Target = $cleanPath
        Type = "Version folder conflict"
      }
      Write-Host "  CONFLICT: $($folder.Name) -> $cleanName (target already exists)" -ForegroundColor Red
    } else {
      $renames += [PSCustomObject]@{
        Original = $folder.FullName
        Target = $cleanPath
        Type = "Version folder"
      }
      Write-Host "  $($folder.Name) -> $cleanName" -ForegroundColor Yellow
    }
  }
}

# Step 2: Check subfolders within each version (_REG-*, _INVENTORY-*, _WSP-*)
Write-Host "`nScanning subfolders for timestamps..." -ForegroundColor Cyan
$allVersionFolders = Get-ChildItem $SnapshotsRoot -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^v\d+' }

foreach ($versionFolder in $allVersionFolders) {
  $subfolders = Get-ChildItem $versionFolder.FullName -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^_(REG|INVENTORY|WSP|SINGLEFILES)' }

  foreach ($subfolder in $subfolders) {
    if ($subfolder.Name -match "^(_(?:REG|INVENTORY|WSP|SINGLEFILES))$timestampPattern") {
      $cleanName = $matches[1]
      $cleanPath = Join-Path $versionFolder.FullName $cleanName

      # Check for conflict
      if ((Test-Path $cleanPath) -and $cleanPath -ne $subfolder.FullName) {
        $conflicts += [PSCustomObject]@{
          Original = $subfolder.FullName
          Target = $cleanPath
          Type = "Subfolder conflict"
        }
        Write-Host "  CONFLICT: $($versionFolder.Name)/$($subfolder.Name) -> $cleanName (target exists)" -ForegroundColor Red
      } else {
        $renames += [PSCustomObject]@{
          Original = $subfolder.FullName
          Target = $cleanPath
          Type = "Subfolder"
        }
        Write-Host "  $($versionFolder.Name)/$($subfolder.Name) -> $cleanName" -ForegroundColor Yellow
      }
    }
  }
}

# Summary
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Folders to rename: $($renames.Count)" -ForegroundColor $(if ($renames.Count -gt 0) { "Green" } else { "Gray" })
Write-Host "Conflicts detected: $($conflicts.Count)" -ForegroundColor $(if ($conflicts.Count -gt 0) { "Red" } else { "Gray" })

if ($conflicts.Count -gt 0) {
  Write-Host ""
  Write-Host "CONFLICTS DETECTED - Cannot proceed!" -ForegroundColor Red
  Write-Host "Manual intervention required:" -ForegroundColor Yellow
  foreach ($conflict in $conflicts) {
    Write-Host "  - $($conflict.Original)" -ForegroundColor Yellow
    Write-Host "    Target already exists: $($conflict.Target)" -ForegroundColor Yellow
  }
  exit 1
}

if ($renames.Count -eq 0) {
  Write-Host ""
  Write-Host "No timestamped folders found - all clean!" -ForegroundColor Green
  exit 0
}

# Execute renames
if (-not $DryRun) {
  Write-Host ""
  Write-Host "Executing renames..." -ForegroundColor Cyan

  foreach ($rename in $renames) {
    try {
      Move-Item -LiteralPath $rename.Original -Destination $rename.Target -Force
      Write-Host "  Renamed: $($rename.Type) - $(Split-Path $rename.Original -Leaf) -> $(Split-Path $rename.Target -Leaf)" -ForegroundColor Green
    } catch {
      Write-Host "  FAILED: $($rename.Original)" -ForegroundColor Red
      Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    }
  }

  Write-Host ""
  Write-Host "Rename complete!" -ForegroundColor Green
} else {
  Write-Host ""
  Write-Host "Dry run complete. Run without -DryRun to execute renames." -ForegroundColor Yellow
}

# Generate report
if (-not $DryRun -and $renames.Count -gt 0) {
  $reportPath = Join-Path $SnapshotsRoot "rename-report-$(Get-Date -Format 'yyyyMMdd-HHmm').txt"
  $renames | ForEach-Object {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $($_.Type) | $($_.Original) -> $($_.Target)"
  } | Out-File -FilePath $reportPath -Encoding UTF8
  Write-Host "Report written: $reportPath" -ForegroundColor Gray
}
