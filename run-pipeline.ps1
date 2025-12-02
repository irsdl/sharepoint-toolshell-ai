param(
  [string]$RepoRoot = "$PSScriptRoot",
  [switch]$SkipValidation,
  [switch]$Force  # Re-run steps even if output exists
)

$ErrorActionPreference = "Stop"

Write-Host "=== SharePoint AI Research - Pipeline Orchestrator ===" -ForegroundColor Cyan
Write-Host ""

# Step 0: Validate environment
if (-not $SkipValidation) {
  Write-Host "Step 0: Validating environment..." -ForegroundColor Cyan
  & "$RepoRoot\tools\validate-environment.ps1" -RepoRoot $RepoRoot
  if ($LASTEXITCODE -ne 0) {
    Write-Host "`nEnvironment validation failed. Fix issues and try again." -ForegroundColor Red
    exit 1
  }
  Write-Host ""
}

# Discover available versions
$snapshotsRoot = Join-Path $RepoRoot "snapshots_raw"
$versions = Get-ChildItem $snapshotsRoot -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^v\d+' } |
  Sort-Object Name

if ($versions.Count -eq 0) {
  Write-Host "ERROR: No version directories found in snapshots_raw/" -ForegroundColor Red
  Write-Host "Please populate snapshots_raw with at least one version (v1, v2, v3, etc.)" -ForegroundColor Yellow
  exit 1
}

Write-Host "Detected versions: $($versions.Name -join ', ')" -ForegroundColor Green
Write-Host ""

$startTime = Get-Date

# Step 1: Normalize configs
Write-Host "Step 1: Normalizing configs..." -ForegroundColor Cyan
$snapshotsNorm = Join-Path $RepoRoot "snapshots_norm"

if ((Test-Path $snapshotsNorm) -and -not $Force) {
  Write-Host "  snapshots_norm/ already exists - SKIPPING (use -Force to re-run)" -ForegroundColor Yellow
} else {
  $step1Start = Get-Date
  & "$RepoRoot\tools\normalize\normalize-configs.ps1" `
    -InputRoot $snapshotsRoot `
    -OutputRoot $snapshotsNorm
  $step1Duration = (Get-Date) - $step1Start
  Write-Host "  Completed in $([math]::Round($step1Duration.TotalSeconds, 1)) seconds" -ForegroundColor Gray
}
Write-Host ""

# Step 2: Hash ALL files (managed, native, config)
Write-Host "Step 2: Hashing all files and detecting changes..." -ForegroundColor Cyan
$hashDir = Join-Path $RepoRoot "artifacts\file-hashes"

if ((Test-Path $hashDir) -and -not $Force) {
  Write-Host "  artifacts/file-hashes/ already exists - SKIPPING (use -Force to re-run)" -ForegroundColor Yellow
} else {
  $step2Start = Get-Date
  & "$RepoRoot\tools\hashing\hash-all-versions.ps1" `
    -SnapshotsRoot $snapshotsRoot `
    -OutDir $hashDir
  $step2Duration = (Get-Date) - $step2Start
  Write-Host "  Completed in $([math]::Round($step2Duration.TotalSeconds, 1)) seconds" -ForegroundColor Gray
}
Write-Host ""

# Step 3: Decompile ONLY changed managed assemblies (optimized)
Write-Host "Step 3: Decompiling changed managed assemblies..." -ForegroundColor Cyan
$snapshotsDecompiled = Join-Path $RepoRoot "snapshots_decompiled"

if ((Test-Path $snapshotsDecompiled) -and -not $Force) {
  Write-Host "  snapshots_decompiled/ already exists - SKIPPING (use -Force to re-run)" -ForegroundColor Yellow
} else {
  $step3Start = Get-Date

  # Build unified change list across all version pairs
  $allChangedPaths = @{}

  if ($versions.Count -ge 2) {
    for ($i = 0; $i -lt $versions.Count - 1; $i++) {
      $fromVer = $versions[$i].Name
      $toVer = $versions[$i + 1].Name
      $comparisonDir = Join-Path $hashDir "$fromVer-to-$toVer"
      $managedChangedFile = Join-Path $comparisonDir "managed-changed.txt"

      if (Test-Path $managedChangedFile) {
        $changedPaths = Get-Content $managedChangedFile | Where-Object { $_.Trim() -ne '' }
        foreach ($path in $changedPaths) {
          $allChangedPaths[$path] = $true
        }
      }
    }
  }

  if ($allChangedPaths.Count -gt 0) {
    # Create temporary unified change list
    $unifiedChangeList = Join-Path $RepoRoot "artifacts\temp-unified-changes.txt"
    New-Item -ItemType Directory -Path (Split-Path $unifiedChangeList) -Force | Out-Null
    $allChangedPaths.Keys | Out-File -FilePath $unifiedChangeList -Encoding UTF8

    Write-Host "  Total unique changed assemblies across all versions: $($allChangedPaths.Count)" -ForegroundColor Yellow
    Write-Host "  Decompiling only changed assemblies (optimized mode)" -ForegroundColor Green

    & "$RepoRoot\tools\decompile\decompile-all.ps1" `
      -RawRoot $snapshotsRoot `
      -OutRoot $snapshotsDecompiled `
      -ChangeListFile $unifiedChangeList

    # Clean up temp file
    Remove-Item $unifiedChangeList -Force -ErrorAction SilentlyContinue
  } else {
    Write-Host "  No change lists found - decompiling all assemblies (fallback mode)" -ForegroundColor Yellow
    & "$RepoRoot\tools\decompile\decompile-all.ps1" `
      -RawRoot $snapshotsRoot `
      -OutRoot $snapshotsDecompiled
  }

  $step3Duration = (Get-Date) - $step3Start
  Write-Host "  Completed in $([math]::Round($step3Duration.TotalSeconds, 1)) seconds" -ForegroundColor Gray
}
Write-Host ""

# Step 4: Generate diffs
Write-Host "Step 4: Generating diffs..." -ForegroundColor Cyan

if ($versions.Count -lt 2) {
  Write-Host "  Only one version available - no diffs to generate" -ForegroundColor Yellow
} else {
  # Generate diffs for each adjacent pair
  for ($i = 0; $i -lt $versions.Count - 1; $i++) {
    $fromVer = $versions[$i].Name
    $toVer = $versions[$i + 1].Name

    # Content diffs (outputs to diff_reports/ by default)
    $diffReportsDir = Join-Path $RepoRoot "diff_reports"
    $contentPatch = Join-Path $diffReportsDir "$fromVer-to-$toVer.content.patch"
    Write-Host "  Diffing content (excludes managed DLLs): $fromVer -> $toVer" -ForegroundColor Gray

    if ((Test-Path $contentPatch) -and -not $Force) {
      Write-Host "    Already exists - SKIPPING" -ForegroundColor Yellow
    } else {
      $fromPath = Join-Path $snapshotsNorm $fromVer
      $toPath = Join-Path $snapshotsNorm $toVer

      if ((Test-Path $fromPath) -and (Test-Path $toPath)) {
        & "$RepoRoot\tools\diff\make-diff-content.ps1" `
          -FromDir $fromPath `
          -ToDir $toPath `
          -ExcludeManagedDlls
      } else {
        Write-Host "    Missing normalized snapshots - skipping" -ForegroundColor Yellow
      }
    }

    # Decompiled code diffs (outputs to diff_reports/ by default)
    $decompPatch = Join-Path $diffReportsDir "$fromVer-to-$toVer.decompiled.patch"
    Write-Host "  Diffing decompiled code: $fromVer -> $toVer" -ForegroundColor Gray

    if ((Test-Path $decompPatch) -and -not $Force) {
      Write-Host "    Already exists - SKIPPING" -ForegroundColor Yellow
    } else {
      $fromDecompPath = Join-Path $snapshotsDecompiled $fromVer
      $toDecompPath = Join-Path $snapshotsDecompiled $toVer

      if ((Test-Path $fromDecompPath) -and (Test-Path $toDecompPath)) {
        & "$RepoRoot\tools\diff\make-diff-decompiled.ps1" `
          -FromDir $fromDecompPath `
          -ToDir $toDecompPath
      } else {
        Write-Host "    Missing decompiled snapshots - skipping" -ForegroundColor Yellow
      }
    }
  }
}
Write-Host ""

# Step 5: Clean patches
Write-Host "Step 5: Cleaning patches..." -ForegroundColor Cyan
$diffReportsDir = Join-Path $RepoRoot "diff_reports"

if (Test-Path $diffReportsDir) {
  $step5Start = Get-Date
  & "$RepoRoot\tools\diff\clean-all-patches.ps1" `
    -ArtifactsDir $diffReportsDir `
    -InPlace
  $step5Duration = (Get-Date) - $step5Start
  Write-Host "  Completed in $([math]::Round($step5Duration.TotalSeconds, 1)) seconds" -ForegroundColor Gray
} else {
  Write-Host "  No diff_reports directory - nothing to clean" -ForegroundColor Yellow
}
Write-Host ""

# Summary
$totalDuration = (Get-Date) - $startTime
Write-Host "=== Pipeline Complete ===" -ForegroundColor Cyan
Write-Host "Total time: $([math]::Round($totalDuration.TotalMinutes, 1)) minutes" -ForegroundColor Green
Write-Host ""
Write-Host "Output locations:" -ForegroundColor Cyan
Write-Host "  - Normalized configs:   $snapshotsNorm" -ForegroundColor Gray
Write-Host "  - Decompiled sources:   $snapshotsDecompiled" -ForegroundColor Gray
Write-Host "  - File hashes:          $hashDir" -ForegroundColor Gray
Write-Host "  - Change reports:       $hashDir\{version}-to-{version}\" -ForegroundColor Gray
$diffReportsDir = Join-Path $RepoRoot "diff_reports"
Write-Host "  - Diffs:                $diffReportsDir\" -ForegroundColor Gray
Write-Host ""
Write-Host "Key files for AI analysis:" -ForegroundColor Cyan
if ($versions.Count -ge 2) {
  for ($i = 0; $i -lt $versions.Count - 1; $i++) {
    $fromVer = $versions[$i].Name
    $toVer = $versions[$i + 1].Name
    $comparisonDir = Join-Path $hashDir "$fromVer-to-$toVer"
    $summaryFile = Join-Path $comparisonDir "change-summary.txt"
    if (Test-Path $summaryFile) {
      Write-Host "  - $fromVer -> $toVer summary: $summaryFile" -ForegroundColor Yellow
    }
  }
}
Write-Host ""
Write-Host "Ready for AI experiment!" -ForegroundColor Green
