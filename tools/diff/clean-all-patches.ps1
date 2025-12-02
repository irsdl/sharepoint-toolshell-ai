param(
  [string]$ArtifactsDir = "$(Join-Path $PSScriptRoot '..\..\artifacts')",
  [switch]$InPlace  # If set, overwrites original .patch files; otherwise creates .clean.patch
)

if (-not (Test-Path $ArtifactsDir)) {
  Write-Host "Artifacts directory does not exist: $ArtifactsDir"
  exit 0
}

Write-Host "Cleaning patch files in: $ArtifactsDir"
Write-Host "Mode: $(if ($InPlace) {'In-place (overwrite)'} else {'Create .clean.patch files'})"

# Find all .patch files recursively
$patchFiles = Get-ChildItem $ArtifactsDir -Recurse -Filter *.patch -File -ErrorAction SilentlyContinue

if ($patchFiles.Count -eq 0) {
  Write-Host "No .patch files found"
  exit 0
}

Write-Host "Found $($patchFiles.Count) patch file(s)"

$cleaned = 0
foreach ($patch in $patchFiles) {
  Write-Host "  Processing: $($patch.Name)"

  if ($InPlace) {
    # Create temp file, clean it, then replace original
    $tempFile = "$($patch.FullName).tmp"
    & "$PSScriptRoot\clean-patch.ps1" -PatchFile $patch.FullName -OutFile $tempFile
    if (Test-Path $tempFile) {
      Move-Item -LiteralPath $tempFile -Destination $patch.FullName -Force
      $cleaned++
    }
  } else {
    # Create .clean.patch file alongside original
    $outFile = [System.IO.Path]::ChangeExtension($patch.FullName, "clean.patch")
    & "$PSScriptRoot\clean-patch.ps1" -PatchFile $patch.FullName -OutFile $outFile
    if (Test-Path $outFile) {
      $cleaned++
    }
  }
}

Write-Host "`nCleaned $cleaned patch file(s)"
