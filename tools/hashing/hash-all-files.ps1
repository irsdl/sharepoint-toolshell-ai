param(
  [Parameter(Mandatory=$true)][string]$SnapshotDir,
  [string]$OutCsv = "$(Join-Path $PSScriptRoot '..\..\artifacts\file-hashes\hashes.csv')"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Hash All Files Utility ===" -ForegroundColor Cyan
Write-Host "Purpose: Hash ALL files in snapshot for comprehensive change detection" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $SnapshotDir)) {
  throw "SnapshotDir does not exist: $SnapshotDir"
}

function Test-IsManaged {
  param([string]$Path)
  try {
    [void][Reflection.AssemblyName]::GetAssemblyName($Path)
    return $true
  } catch {
    return $false
  }
}

# Ensure output directory exists
New-Item -ItemType Directory -Path (Split-Path $OutCsv) -Force | Out-Null

# Extract version info from path
$version = (Split-Path $SnapshotDir -Leaf)
Write-Host "Snapshot: $version" -ForegroundColor Green
Write-Host "Output: $OutCsv" -ForegroundColor Gray
Write-Host ""

# Define file categories by extension
$managedExtensions = @('.dll', '.exe')
$configExtensions = @('.config', '.xml', '.json', '.aspx', '.ascx', '.master', '.cshtml', '.svc', '.asmx', '.xaml', '.xamlx', '.xoml', '.ashx', '.axd', '.soap', '.js', '.html', '.htm', '.ps1', '.psm1', '.psd1', '.resx', '.xslt', '.css', '.ts', '.jsx', '.tsx', '.vue')

Write-Host "Scanning files..." -NoNewline
$allFiles = Get-ChildItem $SnapshotDir -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object {
    # Exclude metadata directories created by snapshot script
    $_.FullName -notmatch '\\_WSP-|\\_WSP\\|\\_REG-|\\_REG\\|\\_INVENTORY-|\\_INVENTORY\\|\\_SINGLEFILES-|\\_SINGLEFILES\\' -and
    # Exclude script-generated log files and artifacts
    $_.Name -notmatch '^robocopy-.*\.log$' -and
    $_.Name -notmatch '^decompile-.*\.log$' -and
    $_.Name -notmatch '^decompile-summary-.*\.txt$' -and
    $_.Name -ne 'path-mappings.csv' -and
    $_.Name -ne 'source-path.txt' -and
    $_.Name -notmatch '^rename-report-.*\.txt$'
  }

Write-Host " Found $($allFiles.Count) files" -ForegroundColor Green
Write-Host "Computing hashes and categorizing..." -ForegroundColor Cyan

$progressCount = 0
$results = foreach ($file in $allFiles) {
  $progressCount++
  if ($progressCount % 500 -eq 0) {
    Write-Host "  Progress: $progressCount / $($allFiles.Count) files processed..." -ForegroundColor Gray
  }

  # Compute SHA256 hash
  try {
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName -ErrorAction Stop).Hash
  } catch {
    Write-Warning "Failed to hash: $($file.FullName) - $_"
    continue
  }

  # Get extension
  $ext = $file.Extension.ToLower()

  # Categorize file type
  $isManaged = $false
  $isNative = $false
  $isConfig = $false

  if ($ext -in $managedExtensions) {
    # Check if it's a managed assembly
    $isManaged = Test-IsManaged $file.FullName
    if (-not $isManaged) {
      # It's a DLL/EXE but not managed, so it's native
      $isNative = $true
    }
  } elseif ($ext -in $configExtensions) {
    $isConfig = $true
  } else {
    # Other file types (images, fonts, etc.) - not categorized but still hashed
    $isConfig = $false
  }

  # Build relative path (from snapshot root)
  $relativePath = $file.FullName.Substring($SnapshotDir.Length).TrimStart('\','/')

  [pscustomobject]@{
    Version        = $version
    Path           = $relativePath
    SHA256         = $sha
    Size           = $file.Length
    Extension      = $ext
    IsManaged      = $isManaged
    IsNative       = $isNative
    IsConfig       = $isConfig
    LastWriteTime  = $file.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
  }
}

# Export to CSV
Write-Host ""
Write-Host "Exporting to CSV..." -NoNewline
$results | Sort-Object Path | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host " Done" -ForegroundColor Green

# Statistics
$managedCount = ($results | Where-Object { $_.IsManaged -eq $true }).Count
$nativeCount = ($results | Where-Object { $_.IsNative -eq $true }).Count
$configCount = ($results | Where-Object { $_.IsConfig -eq $true }).Count
$otherCount = $results.Count - $managedCount - $nativeCount - $configCount

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Total files hashed: $($results.Count)" -ForegroundColor Green
Write-Host "  - Managed assemblies: $managedCount" -ForegroundColor Gray
Write-Host "  - Native binaries: $nativeCount" -ForegroundColor Gray
Write-Host "  - Config/content: $configCount" -ForegroundColor Gray
Write-Host "  - Other files: $otherCount" -ForegroundColor Gray
Write-Host "Output: $OutCsv" -ForegroundColor Gray
