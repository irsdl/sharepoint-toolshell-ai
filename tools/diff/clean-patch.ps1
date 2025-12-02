param(
  [Parameter(Mandatory=$true)][string]$PatchFile,
  [string]$OutFile
)

if (-not (Test-Path $PatchFile)) { throw "Patch not found: $PatchFile" }
if (-not $OutFile) { $OutFile = [System.IO.Path]::ChangeExtension($PatchFile, ".clean.patch") }

$lines = Get-Content -LiteralPath $PatchFile

$removeIfStartsWith = @(
  "diff --git ",
  "index ",
  "new file mode ",
  "deleted file mode ",
  "old mode ",
  "new mode ",
  "similarity index ",
  "rename from ",
  "rename to "
)

$filtered = foreach ($l in $lines) {
  $skip = $false
  foreach ($p in $removeIfStartsWith) { if ($l.StartsWith($p)) { $skip = $true; break } }
  if (-not $skip) { $l }
}

$filtered | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "Clean patch written: $OutFile"
