param(
  [Parameter(Mandatory=$true)][string]$FromCsv,
  [Parameter(Mandatory=$true)][string]$ToCsv,
  [Parameter(Mandatory=$true)][string]$OutDir
)

$ErrorActionPreference = "Stop"

Write-Host "=== Hash Comparison & Change Categorization ===" -ForegroundColor Cyan
Write-Host "Purpose: Compare file hashes between versions and categorize changes" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $FromCsv)) {
  throw "FromCsv not found: $FromCsv"
}

if (-not (Test-Path $ToCsv)) {
  throw "ToCsv not found: $ToCsv"
}

# Import hash data
Write-Host "Loading hash data..." -NoNewline
$from = Import-Csv $FromCsv
$to   = Import-Csv $ToCsv
Write-Host " Done" -ForegroundColor Green
Write-Host "  From version: $($from[0].Version) ($($from.Count) files)" -ForegroundColor Gray
Write-Host "  To version: $($to[0].Version) ($($to.Count) files)" -ForegroundColor Gray
Write-Host ""

# Build indexes for fast lookup
Write-Host "Building indexes..." -NoNewline
$idxFrom = @{}
$from | ForEach-Object { $idxFrom[$_.Path] = $_ }

$idxTo = @{}
$to | ForEach-Object { $idxTo[$_.Path] = $_ }
Write-Host " Done" -ForegroundColor Green
Write-Host ""

# Detect changes
Write-Host "Detecting changes..." -ForegroundColor Cyan
$allChanges = @()
$managedChanged = @()
$nativeChanged = @()
$configChanged = @()
$otherChanged = @()

$addedCount = 0
$removedCount = 0
$changedCount = 0

# Get all unique paths across both versions
$allPaths = ($idxFrom.Keys + $idxTo.Keys) | Sort-Object -Unique

foreach ($path in $allPaths) {
  $fromFile = $idxFrom[$path]
  $toFile = $idxTo[$path]

  $status = $null
  $changeType = $null

  if (-not $fromFile -and $toFile) {
    # File added in new version
    $status = 'ADDED'
    $addedCount++
    $changeType = $toFile
  } elseif ($fromFile -and -not $toFile) {
    # File removed in new version
    $status = 'REMOVED'
    $removedCount++
    $changeType = $fromFile
  } elseif ($fromFile.SHA256 -ne $toFile.SHA256) {
    # File changed (different hash)
    $status = 'CHANGED'
    $changedCount++
    $changeType = $toFile
  }

  # If there's a change, record it
  if ($status) {
    $change = [pscustomobject]@{
      Path       = $path
      Status     = $status
      FromSHA    = if ($fromFile) { $fromFile.SHA256 } else { '' }
      ToSHA      = if ($toFile) { $toFile.SHA256 } else { '' }
      FromSize   = if ($fromFile) { $fromFile.Size } else { 0 }
      ToSize     = if ($toFile) { $toFile.Size } else { 0 }
      Extension  = if ($toFile) { $toFile.Extension } elseif ($fromFile) { $fromFile.Extension } else { '' }
      IsManaged  = if ($changeType) { $changeType.IsManaged } else { 'False' }
      IsNative   = if ($changeType) { $changeType.IsNative } else { 'False' }
      IsConfig   = if ($changeType) { $changeType.IsConfig } else { 'False' }
    }

    $allChanges += $change

    # Categorize by file type
    if ($change.IsManaged -eq 'True') {
      $managedChanged += $path
    } elseif ($change.IsNative -eq 'True') {
      $nativeChanged += $path
    } elseif ($change.IsConfig -eq 'True') {
      $configChanged += $path
    } else {
      $otherChanged += $path
    }
  }
}

Write-Host "  Total changes detected: $($allChanges.Count)" -ForegroundColor Green
Write-Host "    - Added: $addedCount" -ForegroundColor Gray
Write-Host "    - Removed: $removedCount" -ForegroundColor Gray
Write-Host "    - Changed: $changedCount" -ForegroundColor Gray
Write-Host ""

# Ensure output directory exists
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Export comprehensive change list
$allChangesCsv = Join-Path $OutDir "all-changes.csv"
Write-Host "Exporting all changes..." -NoNewline
$allChanges | Sort-Object Path | Export-Csv -Path $allChangesCsv -NoTypeInformation -Encoding UTF8
Write-Host " $allChangesCsv" -ForegroundColor Green

# Export categorized change lists (plain text, one path per line)
$managedChangedTxt = Join-Path $OutDir "managed-changed.txt"
Write-Host "Exporting managed assembly changes..." -NoNewline
$managedChanged | Sort-Object | Out-File -FilePath $managedChangedTxt -Encoding UTF8
Write-Host " $managedChangedTxt" -ForegroundColor Green

$nativeChangedTxt = Join-Path $OutDir "native-changed.txt"
Write-Host "Exporting native binary changes..." -NoNewline
$nativeChanged | Sort-Object | Out-File -FilePath $nativeChangedTxt -Encoding UTF8
Write-Host " $nativeChangedTxt" -ForegroundColor Green

$configChangedTxt = Join-Path $OutDir "config-changed.txt"
Write-Host "Exporting config/content changes..." -NoNewline
$configChanged | Sort-Object | Out-File -FilePath $configChangedTxt -Encoding UTF8
Write-Host " $configChangedTxt" -ForegroundColor Green

if ($otherChanged.Count -gt 0) {
  $otherChangedTxt = Join-Path $OutDir "other-changed.txt"
  Write-Host "Exporting other file changes..." -NoNewline
  $otherChanged | Sort-Object | Out-File -FilePath $otherChangedTxt -Encoding UTF8
  Write-Host " $otherChangedTxt" -ForegroundColor Green
}

# Generate summary report
$summaryTxt = Join-Path $OutDir "change-summary.txt"
Write-Host "Generating summary report..." -NoNewline

$fromVersion = $from[0].Version
$toVersion = $to[0].Version

@"
====================================
Change Detection Summary
====================================
From Version: $fromVersion
To Version: $toVersion
Comparison Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

====================================
Overall Statistics
====================================
Total files in $fromVersion`: $($from.Count)
Total files in $toVersion`: $($to.Count)
Files changed: $($allChanges.Count)
  - Added: $addedCount
  - Removed: $removedCount
  - Modified: $changedCount

====================================
Changes by Category
====================================
Managed Assemblies (.NET DLLs/EXEs):
  Count: $($managedChanged.Count)
  Action: Requires decompilation for code diff
  File: managed-changed.txt

Native Binaries (Native DLLs/EXEs):
  Count: $($nativeChanged.Count)
  Action: Hash comparison only (no decompilation)
  File: native-changed.txt

Config/Content Files:
  Count: $($configChanged.Count)
  Action: Direct file diff (configs, JS, ASPX, etc.)
  File: config-changed.txt

Other Files:
  Count: $($otherChanged.Count)
  File: other-changed.txt

====================================
Decompilation Optimization
====================================
Total managed assemblies in both versions: $(($from | Where-Object { $_.IsManaged -eq 'True' }).Count + ($to | Where-Object { $_.IsManaged -eq 'True' }).Count)
Managed assemblies requiring decompilation: $($managedChanged.Count)
Decompilation reduction: $([math]::Round((1 - ($managedChanged.Count / (($from | Where-Object { $_.IsManaged -eq 'True' }).Count + ($to | Where-Object { $_.IsManaged -eq 'True' }).Count + 1))) * 100, 1))%

====================================
Output Files
====================================
All changes (CSV): all-changes.csv
Managed changes (TXT): managed-changed.txt
Native changes (TXT): native-changed.txt
Config changes (TXT): config-changed.txt
$(if ($otherChanged.Count -gt 0) { "Other changes (TXT): other-changed.txt" } else { "" })

====================================
Next Steps
====================================
1. Review change-summary.txt (this file)
2. Decompile only assemblies listed in managed-changed.txt
3. Generate direct diffs for files in config-changed.txt
4. Review native-changed.txt for binary-level changes
====================================
"@ | Out-File -FilePath $summaryTxt -Encoding UTF8

Write-Host " $summaryTxt" -ForegroundColor Green
Write-Host ""

# Display summary to console
Write-Host "=== Change Detection Complete ===" -ForegroundColor Cyan
Write-Host "Changes by category:" -ForegroundColor Green
Write-Host "  - Managed assemblies: $($managedChanged.Count)" -ForegroundColor Yellow
Write-Host "  - Native binaries: $($nativeChanged.Count)" -ForegroundColor Gray
Write-Host "  - Config/content: $($configChanged.Count)" -ForegroundColor Gray
if ($otherChanged.Count -gt 0) {
  Write-Host "  - Other files: $($otherChanged.Count)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Decompilation optimization: Only $($managedChanged.Count) assemblies need decompilation" -ForegroundColor Green
Write-Host "Output directory: $OutDir" -ForegroundColor Gray
