param(
  [Parameter(Mandatory=$true)][string]$SnapshotDir,   # e.g. snapshots_raw\SERVERA\v1_YYYY...
  [string]$OutCsv = "$(Join-Path $PSScriptRoot '..\..\inventories\native-hashes.csv')"
)

function Test-IsManaged {
  param([string]$Path)
  try { [void][Reflection.AssemblyName]::GetAssemblyName($Path); return $true } catch { return $false }
}

New-Item -ItemType Directory -Path (Split-Path $OutCsv) -Force | Out-Null

$server  = (Split-Path (Split-Path $SnapshotDir -Parent) -Leaf)
$version = (Split-Path $SnapshotDir -Leaf)

Get-ChildItem $SnapshotDir -Recurse -Include *.dll,*.exe -File -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\_WSP-|\\_REG-|\\_INVENTORY-|\\_SINGLEFILES'
  } |
  Where-Object { -not (Test-IsManaged $_.FullName) } |
  ForEach-Object {
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
    [pscustomobject]@{
      Server   = $server
      Version  = $version
      Path     = $_.FullName.Substring($SnapshotDir.Length).TrimStart('\','/')
      SHA256   = $sha
      Size     = $_.Length
      LastWriteTime = $_.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
  } | Sort-Object Path | Export-Csv -Path $OutCsv -NoTypeInformation
Write-Host "Native hash CSV written: $OutCsv"
