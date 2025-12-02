param(
  [Parameter(Mandatory=$true)][string]$InputRoot,
  [Parameter(Mandatory=$true)][string]$OutputRoot,
  [switch]$DryRun
)

if (-not (Test-Path $InputRoot)) {
  throw "InputRoot does not exist: $InputRoot"
}

Write-Host "Normalizing configs: $InputRoot -> $OutputRoot"

# Copy entire tree from InputRoot to OutputRoot (preserves immutable source)
if (-not $DryRun) {
  Write-Host "Copying files from $InputRoot to $OutputRoot..."
  if (-not (Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
  }
  # Use robocopy for efficient tree copy (Windows)
  $robocopyArgs = @(
    $InputRoot,
    $OutputRoot,
    '/E',          # copy subdirectories including empty ones
    '/NFL',        # no file list
    '/NDL',        # no directory list
    '/NJH',        # no job header
    '/NJS',        # no job summary
    '/NC',         # no class
    '/NS',         # no size
    '/NP'          # no progress
  )
  $result = & robocopy @robocopyArgs
  # Robocopy exit codes: 0-7 are success (8+ are errors)
  if ($LASTEXITCODE -ge 8) {
    throw "Robocopy failed with exit code $LASTEXITCODE"
  }
  Write-Host "Copy complete."
} else {
  Write-Host "[DryRun] Would copy $InputRoot -> $OutputRoot"
}

# Now normalize files in OutputRoot
Write-Host "Normalizing XML and config files..."

# XML & .config
Get-ChildItem $OutputRoot -Recurse -Include *.config,*.xml -File -ErrorAction SilentlyContinue |
  ForEach-Object {
    try {
      $content = Get-Content -LiteralPath $_.FullName -Raw
      [xml]$x = $content
      if (-not $DryRun) {
        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.Indent = $true
        $settings.NewLineChars = "`r`n"
        $settings.NewLineHandling = "Replace"
        $settings.Encoding = New-Object System.Text.UTF8Encoding($false)
        $writer = [System.Xml.XmlWriter]::Create($_.FullName, $settings)
        $x.Save($writer); $writer.Close()
      }
    } catch { Write-Host "  XML normalize skipped: $($_.FullName)" }
  }

# JSON
Get-ChildItem $OutputRoot -Recurse -Include *.json -File -ErrorAction SilentlyContinue |
  ForEach-Object {
    try {
      $raw = Get-Content -LiteralPath $_.FullName -Raw
      $j = $raw | ConvertFrom-Json -Depth 100
      if (-not $DryRun) {
        ($j | ConvertTo-Json -Depth 100) | Out-File -FilePath $_.FullName -Encoding utf8
      }
    } catch { Write-Host "  JSON normalize skipped: $($_.FullName)" }
  }

Write-Host "Normalization complete: $OutputRoot"
