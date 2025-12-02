param(
  [Parameter(Mandatory=$true)][string]$RootDir,
  [int]$MaxPathLength = 250
)

# Rename files with paths longer than MaxPathLength to MD5 hashes of original name
# This preserves the data while making paths accessible to git and Windows

$renamed = 0
$errors = 0

Write-Host "Scanning for files with paths longer than $MaxPathLength characters..."

Get-ChildItem $RootDir -Recurse -ErrorAction SilentlyContinue | Where-Object {
  $_.FullName.Length -gt $MaxPathLength
} | ForEach-Object {
  $file = $_
  $pathLen = $file.FullName.Length
  $originalName = $file.Name
  $dir = $file.Directory.FullName

  # Create MD5 hash of original name (keep extension)
  $ext = [System.IO.Path]::GetExtension($originalName)
  $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($originalName)

  $md5 = [System.Security.Cryptography.MD5]::Create()
  $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($nameWithoutExt))
  $hashString = [System.BitConverter]::ToString($hash).Replace("-", "").Substring(0, 16)

  $newName = "$hashString$ext"
  $newPath = Join-Path $dir $newName

  # Create mapping file in same directory
  $mappingFile = Join-Path $dir "long-path-mappings.txt"
  "$newName -> $originalName" | Out-File -Append -FilePath $mappingFile -Encoding UTF8

  try {
    Rename-Item -Path $file.FullName -NewName $newName -ErrorAction Stop
    Write-Host "Renamed: $originalName -> $newName (was $pathLen chars)"
    $renamed++
  } catch {
    Write-Host "ERROR renaming $originalName : $_" -ForegroundColor Red
    $errors++
  }
}

Write-Host "`nRenamed $renamed files, $errors errors"
