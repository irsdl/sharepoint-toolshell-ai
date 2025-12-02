param(
  [string]$RawRoot = "$(Join-Path $PSScriptRoot '..\..\snapshots_raw')",
  [string]$OutRoot = "$(Join-Path $PSScriptRoot '..\..\snapshots_decompiled')",
  [string]$Ilspy  = $null,
  [int]$MaxParallel = 6,
  [string[]]$Versions = @(),
  [string]$ChangeListFile = $null  # Optional: Path to file containing list of changed DLL paths (one per line)
)

# --- Create a short, deterministic folder name from a path ---
function Get-ShortFolderName {
  param(
    [string]$SubPath,
    [string]$AssemblyName
  )
  
  try {
    # Use SubPath for hashing (excludes snapshots_raw\v1\ part)
    $pathToHash = $SubPath.ToLowerInvariant()
    
    # Compute MD5 and SHA1 hashes
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    
    $md5Hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($pathToHash))
    $sha1Hash = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($pathToHash))
    
    # First 8 chars of MD5 and SHA1
    $md5Str = [System.BitConverter]::ToString($md5Hash).Replace('-','').Substring(0,8).ToLower()
    $sha1Str = [System.BitConverter]::ToString($sha1Hash).Replace('-','').Substring(0,8).ToLower()
    
    # First 10 chars of assembly name (sanitized)
    $asmPrefix = $AssemblyName -replace '[^a-zA-Z0-9._-]', '_'
    if ($asmPrefix.Length -gt 10) {
      $asmPrefix = $asmPrefix.Substring(0, 10)
    }
    
    # Format: first10chars-md5(8)-sha1(8)
    # Total max length: 10 + 1 + 8 + 1 + 8 = 28 characters
    $shortName = "${asmPrefix}-${md5Str}-${sha1Str}"
    
    # Safety check: ensure total path won't exceed Windows limit
    # Reserve 100 chars for OutRoot + version + file extensions
    if ($shortName.Length -gt 150) {
      Write-Warning "Generated short name is unusually long: $shortName"
    }
    
    return $shortName
    
  } catch {
    Write-Error "Failed to generate short name for $SubPath : $_"
    # Fallback to just hash if something goes wrong
    return [System.Guid]::NewGuid().ToString("N").Substring(0,16)
  }
}

# --- Resolve ILSpy command ---
function Resolve-Ilspy {
  param([string]$UserProvided)
  if ($UserProvided) {
    if (Test-Path $UserProvided) { return (Resolve-Path $UserProvided).Path }
    if (Get-Command $UserProvided -ErrorAction SilentlyContinue) { return $UserProvided }
    throw "Specified ILSpy not found: $UserProvided"
  }

  $defaultRel = Join-Path $PSScriptRoot 'ILSpyCmd\ilspycmd.exe'
  if (Test-Path $defaultRel) { return (Resolve-Path $defaultRel).Path }

  $cmd = Get-Command ilspycmd.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Path }
  $cmd2 = Get-Command ilspycmd -ErrorAction SilentlyContinue
  if ($cmd2) { return $cmd2.Path }

  throw "ilspycmd not found. Place ILSpy in tools\decompile\ILSpyCmd\ or add to PATH, or pass -Ilspy."
}

$IlspyPath = Resolve-Ilspy -UserProvided $Ilspy

function Test-IsManaged {
  param([string]$Path)
  try { 
    [void][Reflection.AssemblyName]::GetAssemblyName($Path)
    return $true 
  } catch { 
    return $false 
  }
}

Write-Host "======================================"
Write-Host "Decompile-All.ps1"
Write-Host "======================================"
Write-Host " - RawRoot      = $RawRoot"
Write-Host " - OutRoot      = $OutRoot"
Write-Host " - ILSpy        = $IlspyPath"
Write-Host " - MaxParallel  = $MaxParallel"
Write-Host "======================================"

# Discover assemblies under snapshots_raw\<VERSION>\...
Write-Host "Scanning for assemblies..."
$assemblies = Get-ChildItem $RawRoot -Recurse -Include *.dll,*.exe -File -ErrorAction SilentlyContinue |
  Where-Object {
    $_.FullName -notmatch '\\_WSP-|\\_REG-|\\_INVENTORY-|\\_SINGLEFILES'
  } | ForEach-Object {
    $rel = $_.FullName.Substring((Resolve-Path $RawRoot).Path.Length).TrimStart('\','/')
    $parts = $rel -split '[\\/]', 2
    [PSCustomObject]@{
      File = $_.FullName
      Version = if ($parts.Length -ge 1) { $parts[0] } else { "" }
      SubPath = if ($parts.Length -ge 2) { $parts[1] } else { "" }
    }
  }

Write-Host "Found $($assemblies.Count) total assemblies"

if ($Versions) { 
  $assemblies = $assemblies | Where-Object { $Versions -contains $_.Version }
  Write-Host "Filtered to $($assemblies.Count) assemblies for versions: $($Versions -join ', ')"
}

# Filter to MANAGED assemblies only
Write-Host "Filtering managed assemblies..."
$managed = $assemblies | Where-Object { Test-IsManaged $_.File }
Write-Host "Found $($managed.Count) managed assemblies total"

# Further filter by change list if provided
if ($ChangeListFile) {
  if (-not (Test-Path $ChangeListFile)) {
    throw "ChangeListFile not found: $ChangeListFile"
  }

  Write-Host "Loading change list from: $ChangeListFile" -ForegroundColor Cyan
  $changedPaths = Get-Content $ChangeListFile | Where-Object { $_.Trim() -ne '' }
  Write-Host "  Change list contains $($changedPaths.Count) paths" -ForegroundColor Gray

  # Normalize paths for comparison (handle both forward and back slashes)
  $changedPathsNormalized = $changedPaths | ForEach-Object { $_.Replace('/', '\') }

  # Filter managed assemblies to only those in the change list
  $managedBeforeFilter = $managed.Count
  $managed = $managed | Where-Object {
    $normalizedSubPath = $_.SubPath.Replace('/', '\')
    $changedPathsNormalized -contains $normalizedSubPath
  }

  Write-Host "  Filtered to $($managed.Count) changed assemblies (excluded $($managedBeforeFilter - $managed.Count) unchanged)" -ForegroundColor Yellow

  if ($managed.Count -eq 0) {
    Write-Host ""
    Write-Host "No changed managed assemblies to decompile. All assemblies are unchanged!" -ForegroundColor Green
    Write-Host "Exiting early - nothing to do." -ForegroundColor Green
    exit 0
  }
} else {
  Write-Host "  No change list provided - will decompile all managed assemblies" -ForegroundColor Gray
}

Write-Host "Total assemblies to decompile: $($managed.Count)" -ForegroundColor Green

if ($managed.Count -eq 0) {
  Write-Warning "No managed assemblies found to decompile. Exiting."
  exit 0
}

# Initialize path mapping and collision detection
$pathMappings = @{}
$shortNameCollisions = @{}

# Build decompilation plan
Write-Host "Building decompilation plan..."
$plan = foreach ($a in $managed) {
  $asmName = [System.IO.Path]::GetFileNameWithoutExtension($a.File)
  
  # Create short folder name using SubPath
  $shortName = Get-ShortFolderName -SubPath $a.SubPath -AssemblyName $asmName
  
  # Detect collisions (same short name for different paths)
  $collisionKey = "$($a.Version)|$shortName"
  if ($shortNameCollisions.ContainsKey($collisionKey)) {
    if ($shortNameCollisions[$collisionKey] -ne $a.SubPath) {
      Write-Warning "COLLISION DETECTED: $shortName"
      Write-Warning "  Path 1: $($shortNameCollisions[$collisionKey])"
      Write-Warning "  Path 2: $($a.SubPath)"
    }
  } else {
    $shortNameCollisions[$collisionKey] = $a.SubPath
  }
  
  # Build output directory: OutRoot\Version\ShortName\
  $outDir = Join-Path (Join-Path $OutRoot $a.Version) $shortName
  
  # Track mapping for this version
  if (-not $pathMappings.ContainsKey($a.Version)) {
    $pathMappings[$a.Version] = @()
  }
  $pathMappings[$a.Version] += [PSCustomObject]@{
    ShortName = $shortName
    RelativePath = $a.SubPath
    AssemblyName = $asmName
  }
  
  # Return plan item
  [PSCustomObject]@{
    SourceFile = $a.File
    Version = $a.Version
    SubPath = $a.SubPath
    ShortName = $shortName
    OutDir = $outDir
    AssemblyName = $asmName
  }
}

# Write path mappings BEFORE starting jobs
New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
foreach ($version in $pathMappings.Keys) {
  $versionDir = Join-Path $OutRoot $version
  New-Item -ItemType Directory -Path $versionDir -Force | Out-Null
  
  $mappingFile = Join-Path $versionDir "path-mappings.csv"
  $pathMappings[$version] | 
    Sort-Object ShortName | 
    Export-Csv -Path $mappingFile -NoTypeInformation -Encoding UTF8
  Write-Host "Created mapping: $mappingFile"
}

# Queue decompilation jobs
Write-Host "`nStarting decompilation with $MaxParallel parallel jobs..."
$jobs = @()
$completed = 0
$total = $plan.Count

foreach ($item in $plan) {
  # Create output directory
  New-Item -ItemType Directory -Path $item.OutDir -Force | Out-Null
  
  # Wait for available slot
  while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxParallel) {
    Start-Sleep -Milliseconds 400
    # Clean up completed jobs to track progress
    $finishedJobs = @($jobs | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' })
    if ($finishedJobs.Count -gt $completed) {
      $completed = $finishedJobs.Count
      Write-Host "Progress: $completed / $total completed"
    }
  }

  # Start job
  $job = Start-Job -ScriptBlock {
    param($Ilspy, $AsmPath, $OutDir, $SubPath)
    try {
      # Build ILSpy arguments
      $ilspyArgs = @(
        '-p'
        '-o', $OutDir
        '--no-dead-code'
        '--nested-directories'
        $AsmPath
      )
      
      & $Ilspy $ilspyArgs 2>&1 | Out-Null
      
      # Only create source-path.txt on SUCCESS
      $sourcePathFile = Join-Path $OutDir "source-path.txt"
      @"
Original DLL Path:
$AsmPath

Relative Path (from version root):
$SubPath

Decompiled: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@ | Out-File -FilePath $sourcePathFile -Encoding UTF8
      
      [pscustomobject]@{ 
        Assembly = $AsmPath
        Ok = $true
        Msg = ""
      }
    } catch {
      [pscustomobject]@{ 
        Assembly = $AsmPath
        Ok = $false
        Msg = $_.Exception.Message
      }
    }
  } -ArgumentList $IlspyPath, $item.SourceFile, $item.OutDir, $item.SubPath
  
  $jobs += $job
}

Write-Host "`nWaiting for all jobs to complete..."
if ($jobs.Count -gt 0) { 
  Wait-Job -Job $jobs | Out-Null 
  $results = Receive-Job -Job $jobs -Keep
  Remove-Job -Job $jobs -Force | Out-Null
} else {
  $results = @()
}

# Write decompilation summary
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$summary = Join-Path $OutRoot "decompile-summary-$timestamp.txt"
$successCount = @($results | Where-Object { $_.Ok }).Count
$failCount = @($results | Where-Object { -not $_.Ok }).Count

@"
====================================
Decompilation Summary
====================================
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Total Assemblies: $($results.Count)
Successful: $successCount
Failed: $failCount

Results:
====================================
"@ | Out-File -FilePath $summary -Encoding UTF8

$results | Sort-Object Assembly | ForEach-Object {
  "{0}  {1}{2}" -f ($(if($_.Ok){"OK  "}else{"FAIL"})), $_.Assembly, $(if($_.Msg){"  :: " + $_.Msg}else{""})
} | Out-File -FilePath $summary -Encoding UTF8 -Append

Write-Host "`n======================================"
Write-Host "Decompilation Complete!"
Write-Host "======================================"
Write-Host "Total:      $($results.Count)"
Write-Host "Successful: $successCount" -ForegroundColor Green
Write-Host "Failed:     $failCount" -ForegroundColor $(if($failCount -gt 0){'Red'}else{'Green'})
Write-Host "Summary:    $summary"
Write-Host "======================================"