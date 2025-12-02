<#
  SharePoint / IIS code+config snapshot for diffing
  - Copies only code/config-oriented extensions
  - Excludes static assets & noisy folders (Style Library, ClientBin, images, css, fonts, media, etc.)
  - Inventories IIS, SharePoint solutions, and GAC

  -- v1.1
  -- Created by ChatGPT 5 Thinking
#>

param(
  [string]$DestRoot
)

# --- Ask for destination if not supplied; default on empty/Enter ---
if (-not $DestRoot) {
  $inputPath = Read-Host 'Enter destination root folder [C:\temp\sp-copy\]'
  if ([string]::IsNullOrWhiteSpace($inputPath)) {
    $DestRoot = 'C:\temp\sp-copy\'
  } else {
    $DestRoot = $inputPath
  }
}

$destRoot = $DestRoot  # keep using $destRoot below
$stamp    = Get-Date -Format 'yyyyMMdd-HHmm'
$logFile  = Join-Path $destRoot "robocopy-$stamp.log"

# --- Keep only these extensions (code + config oriented) ---
$ext = @(
  '*.dll','*.exe','*.config','*.xml','*.aspx','*.ascx','*.master','*.cshtml',
  '*.svc','*.asmx','*.xaml','*.xamlx','*.xoml','*.ashx','*.axd','*.soap',
  '*.js','*.html','*.htm',
  # extra useful stuff:
  '*.ps1','*.psm1','*.psd1','*.wsp','*.xsn','*.resx','*.xslt','*.json',
  '*.cmd','*.bat','*.snk'
)

# --- Source roots (only ones that exist will be processed) ---
$paths = @(
  'C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions',
  'C:\Program Files\Microsoft Office Servers\16.0',
  'C:\Program Files\Microsoft Office Servers\15.0',
  'C:\Program Files\Microsoft Office Servers\14.0',
  'C:\inetpub\wwwroot\wss\VirtualDirectories',
  'C:\Windows\System32\inetsrv\config',
  'C:\Windows\Microsoft.NET\assembly'
) | Where-Object { Test-Path $_ }

# --- Exclude folders that are mostly/static assets or noise ---
# (Robocopy treats names in /XD as folder-name matches anywhere in the tree.)
$excludeDirs = @(
  # SharePoint site-level asset buckets
  'Style Library','_catalogs','ClientBin',
  # Common static asset names
  'content','contents','style','styles','css','img','imgs','image','images',
  'font','fonts','media','videos','video','audio','uploads','upload','docs','documents',
  # Build / tooling noise if present
  'node_modules','dist','coverage',
  # Typical ASP.NET Core/WWWROOT asset folders (harmless if not present)
  'wwwroot\images','wwwroot\css','wwwroot\fonts','wwwroot\media'
)

# --- Exclude static file types (non-executed) ---
$excludeFiles = @(
  # images
  '*.png','*.jpg','*.jpeg','*.gif','*.svg','*.ico','*.bmp','*.webp','*.tif','*.tiff',
  # styles
  '*.css','*.less','*.scss','*.sass',
  # fonts
  '*.woff','*.woff2','*.ttf','*.eot','*.otf',
  # media
  '*.mp3','*.wav','*.ogg','*.mp4','*.webm','*.mov','*.avi','*.mkv',
  # maps & docs
  '*.map','*.pdf',
  # Silverlight client packages (noise) + other web client bins
  '*.xap'
)

# Ensure destination exists
New-Item -ItemType Directory -Path $destRoot -Force | Out-Null

# --- Function to run robust robocopy with proper argument splitting ---
function Copy-Tree {
  param([string]$Src)

  $rel = ($Src -replace "[:\\]", '_').Trim('_')
  $dst = Join-Path $destRoot $rel
  New-Item -ItemType Directory -Path $dst -Force | Out-Null

  # Core robocopy switches for reliable, diff-friendly snapshots
  $common = @(
    '/E',              # recurse incl. empty subdirs
    '/XJ',             # skip junctions
    '/R:0','/W:0',     # no retries
    '/COPY:DAT',       # data + attributes + timestamps
    '/DCOPY:T',        # preserve dir timestamps
    '/FFT',            # 2-sec time granularity tolerance
    '/MT:32',          # multithreaded
    '/NFL','/NDL','/NP','/ETA',  # quieter output
    "/LOG+:$logFile"   # append to one rolling log
  )

  # Turn exclusions into proper /XD and /XF args
  $xd = @()
  foreach ($d in $excludeDirs) { $xd += '/XD'; $xd += $d }

  $xf = @()
  foreach ($f in $excludeFiles) { $xf += '/XF'; $xf += $f }

  # Build full argument array: src, dst, each filespec as its own arg, then switches
  $args = @("`"$Src`"","`"$dst`"") + $ext + $common + $xd + $xf

  Write-Host "Copying $Src -> $dst"
  Start-Process -FilePath robocopy.exe -ArgumentList $args -NoNewWindow -Wait
}

# --- Execute for each path ---
$paths | ForEach-Object { Copy-Tree $_ }

# --- Save key single files that might be missed by include rules ---
$singleFiles = @(
  'C:\Windows\System32\inetsrv\config\applicationHost.config'
) | Where-Object { Test-Path $_ }

foreach ($f in $singleFiles) {
  $target = Join-Path $destRoot ("_SINGLEFILES\" + ($f -replace "[:\\]", '_'))
  New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
  Copy-Item $f $target -Force
}

# --- Export registry hives (IIS + SharePoint server keys) ---
$regOut = Join-Path $destRoot "_REG"
New-Item -ItemType Directory -Path $regOut -Force | Out-Null
$regKeys = @(
  'HKLM\SOFTWARE\Microsoft\Office Server\16.0',
  'HKLM\SOFTWARE\Microsoft\Office Server\15.0',
  'HKLM\SOFTWARE\Microsoft\Office Server\14.0',
  'HKLM\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\16.0',
  'HKLM\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\15.0',
  'HKLM\SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0',
  'HKLM\SOFTWARE\Microsoft\InetStp'
)
foreach ($k in $regKeys) {
  $safe = ($k -replace '[\\/:*?"<>| ]','_')
  & reg.exe export $k (Join-Path $regOut "$safe.reg") /y | Out-Null
}

# --- Produce inventories useful for later diffing ---
$invDir = Join-Path $destRoot "_INVENTORY"
New-Item -ItemType Directory -Path $invDir -Force | Out-Null

# IIS sites & app pools (requires WebAdministration)
try {
  Import-Module WebAdministration -ErrorAction Stop
  Get-ChildItem IIS:\Sites | Select Name, State, PhysicalPath, Bindings |
    Export-Csv (Join-Path $invDir 'IIS-Sites.csv') -NoTypeInformation
  Get-ChildItem IIS:\AppPools | Select Name, State, managedRuntimeVersion, processModel |
    Export-Csv (Join-Path $invDir 'IIS-AppPools.csv') -NoTypeInformation
} catch {
  Write-Host "WebAdministration not available; skipping IIS inventory."
}

# Farm solutions and WSP capture
try {
  Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop
  Get-SPSolution | Select Name, Id, Deployed, Version, LastOperationResult |
    Export-Csv (Join-Path $invDir 'SP-Solutions.csv') -NoTypeInformation

  $wspOut = Join-Path $destRoot "_WSP"
  New-Item -ItemType Directory -Path $wspOut -Force | Out-Null
  Get-SPSolution | ForEach-Object {
    if ($_.SolutionFile -ne $null) {
      $path = Join-Path $wspOut ($_.Name)
      $_.SolutionFile.SaveAs($path)
    }
  }
} catch {
  Write-Host "SharePoint snapin not loaded; skipping SP inventory/WSP export."
}

# GAC inventory (what DLLs/versions were present)
Get-ChildItem 'C:\Windows\Microsoft.NET\assembly' -Recurse -Filter *.dll -ErrorAction SilentlyContinue |
  ForEach-Object {
    $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)
    [PSCustomObject]@{
      Path            = $_.FullName
      FileVersion     = $ver.FileVersion
      ProductVersion  = $ver.ProductVersion
      Company         = $ver.CompanyName
      Product         = $ver.ProductName
      FileDescription = $ver.FileDescription
    }
  } | Export-Csv (Join-Path $invDir 'GAC-Assemblies.csv') -NoTypeInformation
