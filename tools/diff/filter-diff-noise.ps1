param(
  [Parameter(Mandatory=$true)][string]$InputFile,
  [string]$OutputFile = "",
  [string]$RulesFile = ""
)

# Filter out decompiler-generated noise from diff files using patterns from rules file
# Patterns are loaded from diff-noise-rules.txt (or custom file via -RulesFile parameter)
# This filters non-security-related noise like timestamps, version numbers, compiler-generated attributes

if ([string]::IsNullOrEmpty($OutputFile)) {
  $OutputFile = $InputFile -replace '\.patch$', '.filtered.patch'
}

# Default rules file location
if ([string]::IsNullOrEmpty($RulesFile)) {
  $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
  $RulesFile = Join-Path $scriptRoot "diff-noise-rules.txt"
}

# Load filter patterns from rules file
$filterPatterns = @()
if (Test-Path $RulesFile) {
  Get-Content $RulesFile -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    # Skip comments and empty lines
    if ($line.Length -gt 0 -and -not $line.StartsWith('#')) {
      $filterPatterns += $line
    }
  }
  Write-Host "Loaded $($filterPatterns.Count) filter patterns from: $RulesFile"
} else {
  Write-Warning "Rules file not found: $RulesFile - no patterns will be filtered"
}

Write-Host "Filtering diff noise from: $InputFile"
Write-Host "Output: $OutputFile"

$content = Get-Content $InputFile -Encoding UTF8
$filtered = @()
$linesRemoved = 0
$inNoiseBlock = $false

for ($i = 0; $i -lt $content.Length; $i++) {
  $line = $content[$i]
  $skip = $false

  # Skip source-path.txt file chunks entirely
  if ($line -match '^diff --git.*source-path\.txt') {
    $inNoiseBlock = $true
    $skip = $true
  }

  # Exit noise block when we hit next file
  if ($inNoiseBlock -and $line -match '^diff --git') {
    $inNoiseBlock = $false
  }

  if ($inNoiseBlock) {
    $skip = $true
  }

  # Filter individual noise patterns from rules file
  if (-not $skip) {
    foreach ($pattern in $filterPatterns) {
      if ($line -match $pattern) {
        $skip = $true
        break
      }
    }
  }

  if ($skip) {
    $linesRemoved++
  } else {
    $filtered += $line
  }
}

Write-Host "Filtered $linesRemoved lines of noise"
Write-Host "Original: $($content.Length) lines, Filtered: $($filtered.Length) lines"

$filtered | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Filtered diff saved to: $OutputFile"
