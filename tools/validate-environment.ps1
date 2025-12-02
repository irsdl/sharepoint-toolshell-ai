param(
  [string]$RepoRoot = "$PSScriptRoot\.."
)

Write-Host "=== SharePoint AI Research - Environment Validation ===" -ForegroundColor Cyan
Write-Host ""

$issues = @()
$warnings = @()

# Check PowerShell version
Write-Host "[1/6] Checking PowerShell version..." -NoNewline
if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1) {
  Write-Host " OK (v$($PSVersionTable.PSVersion))" -ForegroundColor Green
  if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "           Note: PowerShell 7+ recommended for better performance" -ForegroundColor Gray
  }
} else {
  Write-Host " FAIL" -ForegroundColor Red
  $issues += "PowerShell 5.1+ required (found v$($PSVersionTable.PSVersion))"
}

# Check Git
Write-Host "[2/6] Checking Git..." -NoNewline
$git = Get-Command git -ErrorAction SilentlyContinue
if ($git) {
  $gitVersion = (& git --version 2>&1) -replace 'git version ', ''
  Write-Host " OK ($gitVersion)" -ForegroundColor Green
} else {
  Write-Host " FAIL" -ForegroundColor Red
  $issues += "Git not found - required for diff generation"
}

# Check ILSpy
Write-Host "[3/6] Checking ILSpy..." -NoNewline
$ilspyPath = Join-Path $RepoRoot "tools\decompile\ILSpyCmd\ilspycmd.exe"
if (Test-Path $ilspyPath) {
  Write-Host " OK" -ForegroundColor Green
  Write-Host "           Path: $ilspyPath" -ForegroundColor Gray
} else {
  Write-Host " FAIL" -ForegroundColor Red
  $issues += "ILSpy command-line tool not found at: $ilspyPath"
  Write-Host "           Download from: https://github.com/icsharpcode/ILSpy/releases" -ForegroundColor Yellow
}

# Check snapshots_raw directory and versions
Write-Host "[4/6] Checking snapshot versions..." -NoNewline
$snapshotsRoot = Join-Path $RepoRoot "snapshots_raw"
if (-not (Test-Path $snapshotsRoot)) {
  Write-Host " FAIL" -ForegroundColor Red
  $issues += "snapshots_raw directory not found: $snapshotsRoot"
} else {
  $versions = Get-ChildItem $snapshotsRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^v\d+' } |
    Sort-Object Name

  if ($versions.Count -eq 0) {
    Write-Host " WARNING" -ForegroundColor Yellow
    $warnings += "No version directories found in snapshots_raw/ (expected v1, v2, v3, etc.)"
    Write-Host "           No snapshots populated yet" -ForegroundColor Yellow
  } else {
    Write-Host " OK" -ForegroundColor Green
    Write-Host "           Found $($versions.Count) version(s): $($versions.Name -join ', ')" -ForegroundColor Gray

    # Check if each version has files
    foreach ($ver in $versions) {
      $fileCount = (Get-ChildItem $ver.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
      $sizeGB = [math]::Round((Get-ChildItem $ver.FullName -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum / 1GB, 2)

      if ($fileCount -eq 0) {
        $warnings += "$($ver.Name) directory is empty"
        Write-Host "           $($ver.Name): EMPTY" -ForegroundColor Yellow
      } else {
        Write-Host "           $($ver.Name): $fileCount files, $sizeGB GB" -ForegroundColor Gray
      }
    }

    # Check for timestamped folder names (version folders use _ or -, subfolders use -)
    $timestampedVersions = $versions | Where-Object { $_.Name -match '[-_]\d{8}-\d{4}$' }
    $timestampedSubfolders = @()
    foreach ($ver in $versions) {
      $subfolders = Get-ChildItem $ver.FullName -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^_(REG|INVENTORY|WSP|SINGLEFILES)-\d{8}-\d{4}$' }
      if ($subfolders) {
        $timestampedSubfolders += [PSCustomObject]@{
          Version = $ver.Name
          Subfolders = $subfolders.Name
        }
      }
    }

    if ($timestampedVersions.Count -gt 0 -or $timestampedSubfolders.Count -gt 0) {
      $warnings += "Timestamped folders detected - use rename-snapshots.ps1 to normalize"
      Write-Host "           WARNING: Timestamped folders found:" -ForegroundColor Yellow
      foreach ($tv in $timestampedVersions) {
        Write-Host "             - $($tv.Name) (version folder)" -ForegroundColor Yellow
      }
      foreach ($ts in $timestampedSubfolders) {
        Write-Host "             - $($ts.Version): $($ts.Subfolders -join ', ')" -ForegroundColor Yellow
      }
      Write-Host "           Run: powershell -File tools/normalize/rename-snapshots.ps1 -SnapshotsRoot snapshots_raw" -ForegroundColor Cyan
    }

    if ($versions.Count -lt 2) {
      $warnings += "Only $($versions.Count) version(s) available - need at least 2 for diff comparison"
    }
  }
}

# Check disk space
Write-Host "[5/6] Checking disk space..." -NoNewline
try {
  $drive = (Get-Item $RepoRoot).PSDrive
  $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
  $requiredGB = 20

  if ($freeSpaceGB -ge $requiredGB) {
    Write-Host " OK ($freeSpaceGB GB free)" -ForegroundColor Green
  } else {
    Write-Host " WARNING" -ForegroundColor Yellow
    $warnings += "Low disk space: $freeSpaceGB GB free (recommended: at least $requiredGB GB)"
  }
} catch {
  Write-Host " SKIP" -ForegroundColor Gray
  Write-Host "           Could not determine disk space" -ForegroundColor Gray
}

# Check required tools scripts exist
Write-Host "[6/6] Checking pipeline scripts..." -NoNewline
$requiredScripts = @(
  "tools\snapshot\snapshot-sp.ps1",
  "tools\normalize\normalize-configs.ps1",
  "tools\hashing\hash-native.ps1",
  "tools\hashing\compare-native-hashes.ps1",
  "tools\decompile\decompile-all.ps1",
  "tools\diff\make-diff-content.ps1",
  "tools\diff\make-diff-decompiled.ps1",
  "tools\diff\clean-patch.ps1"
)

$missingScripts = @()
foreach ($script in $requiredScripts) {
  $scriptPath = Join-Path $RepoRoot $script
  if (-not (Test-Path $scriptPath)) {
    $missingScripts += $script
  }
}

if ($missingScripts.Count -eq 0) {
  Write-Host " OK" -ForegroundColor Green
} else {
  Write-Host " FAIL" -ForegroundColor Red
  $issues += "Missing $($missingScripts.Count) pipeline script(s): $($missingScripts -join ', ')"
}

# Summary
Write-Host ""
Write-Host "=== Validation Summary ===" -ForegroundColor Cyan

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
  Write-Host "All checks passed! Environment is ready." -ForegroundColor Green
  exit 0
}

if ($issues.Count -gt 0) {
  Write-Host ""
  Write-Host "CRITICAL ISSUES ($($issues.Count)):" -ForegroundColor Red
  foreach ($issue in $issues) {
    Write-Host "  - $issue" -ForegroundColor Red
  }
}

if ($warnings.Count -gt 0) {
  Write-Host ""
  Write-Host "WARNINGS ($($warnings.Count)):" -ForegroundColor Yellow
  foreach ($warning in $warnings) {
    Write-Host "  - $warning" -ForegroundColor Yellow
  }
}

Write-Host ""
if ($issues.Count -gt 0) {
  Write-Host "Please resolve critical issues before running the pipeline." -ForegroundColor Red
  exit 1
} else {
  Write-Host "Ready to proceed (with warnings noted above)." -ForegroundColor Yellow
  exit 0
}
