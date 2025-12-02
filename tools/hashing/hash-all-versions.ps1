param(
  [string]$SnapshotsRoot = "$(Join-Path $PSScriptRoot '..\..\snapshots_raw')",
  [string]$OutDir = "$(Join-Path $PSScriptRoot '..\..\artifacts\file-hashes')"
)

if (-not (Test-Path $SnapshotsRoot)) {
  throw "SnapshotsRoot does not exist: $SnapshotsRoot"
}

Write-Host "Hashing ALL files for all versions in: $SnapshotsRoot" -ForegroundColor Cyan
Write-Host "Output directory: $OutDir" -ForegroundColor Gray
Write-Host ""

# Auto-detect version directories
# Support both flat (v1, v2, v3) and nested (SERVER/v1_DATE) structures
$versionDirs = Get-ChildItem $SnapshotsRoot -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^v\d+' } |
  Sort-Object Name

if ($versionDirs.Count -eq 0) {
  Write-Host "No version directories found (expected v1, v2, v3, etc.)"
  exit 0
}

Write-Host "Found $($versionDirs.Count) version(s): $($versionDirs.Name -join ', ')"

# Ensure output directory exists
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# Hash each version
$hashFiles = @()
foreach ($ver in $versionDirs) {
  $versionName = $ver.Name
  $versionPath = $ver.FullName
  $hashCsv = Join-Path $OutDir "$versionName.csv"

  Write-Host "Hashing $versionName..." -ForegroundColor Cyan

  # Call hash-all-files.ps1 for this version
  & "$PSScriptRoot\hash-all-files.ps1" -SnapshotDir $versionPath -OutCsv $hashCsv
  Write-Host ""

  if (Test-Path $hashCsv) {
    $hashFiles += [PSCustomObject]@{
      Version = $versionName
      CsvPath = $hashCsv
    }
  }
}

# Generate comparison reports for adjacent version pairs
if ($hashFiles.Count -lt 2) {
  Write-Host "Only one version found - no comparisons to generate"
  exit 0
}

Write-Host "Generating change detection reports..." -ForegroundColor Cyan
Write-Host ""

for ($i = 0; $i -lt $hashFiles.Count - 1; $i++) {
  $from = $hashFiles[$i]
  $to = $hashFiles[$i + 1]

  $comparisonName = "$($from.Version)-to-$($to.Version)"
  $comparisonDir = Join-Path $OutDir $comparisonName

  Write-Host "Comparing $($from.Version) -> $($to.Version)..." -ForegroundColor Yellow

  & "$PSScriptRoot\compare-all-hashes.ps1" `
    -FromCsv $from.CsvPath `
    -ToCsv $to.CsvPath `
    -OutDir $comparisonDir

  Write-Host ""
}

Write-Host "=== File Hashing Complete ===" -ForegroundColor Cyan
Write-Host "Hash CSVs written to: $OutDir" -ForegroundColor Green
Write-Host "Comparison reports in: $OutDir\{version}-to-{version}\" -ForegroundColor Green
Write-Host ""
