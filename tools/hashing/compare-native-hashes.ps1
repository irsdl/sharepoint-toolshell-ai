param(
  [Parameter(Mandatory=$true)][string]$FromCsv,
  [Parameter(Mandatory=$true)][string]$ToCsv,
  [string]$OutReport = "$(Join-Path $PSScriptRoot '..\..\diff_reports\native-hash-diff.csv')"
)

$from = Import-Csv $FromCsv
$to   = Import-Csv $ToCsv

# key = relative Path
$idxFrom = @{}; $from | ForEach-Object { $idxFrom[$_.Path] = $_ }
$idxTo   = @{}; $to   | ForEach-Object { $idxTo[$_.Path]   = $_ }

$allPaths = ($idxFrom.Keys + $idxTo.Keys) | Sort-Object -Unique

$rows = foreach ($p in $allPaths) {
  $a = $idxFrom[$p]; $b = $idxTo[$p]
  if (-not $a) {
    [pscustomobject]@{ Path=$p; Status='ADDED';  FromSHA='';         ToSHA=$b.SHA256 }
  } elseif (-not $b) {
    [pscustomobject]@{ Path=$p; Status='REMOVED';FromSHA=$a.SHA256; ToSHA='' }
  } elseif ($a.SHA256 -ne $b.SHA256) {
    [pscustomobject]@{ Path=$p; Status='CHANGED';FromSHA=$a.SHA256; ToSHA=$b.SHA256 }
  }
}

New-Item -ItemType Directory -Path (Split-Path $OutReport) -Force | Out-Null
$rows | Export-Csv -Path $OutReport -NoTypeInformation
Write-Host "Native hash diff written: $OutReport"
