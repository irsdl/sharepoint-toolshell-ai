> **🤖 AI ASSISTANT INSTRUCTIONS**
>
> These are the instructions for any AI assistant working in this repository. Always follow them throughout your entire session.

# AI Agent Guide for SharePoint Patch Analysis Pipeline

**Last Updated**: 2025-11-08
**Environment**: Windows, PowerShell 5.1+
**Purpose**: Guide for AI agents assisting with SharePoint security research

---

## ⚠️ CRITICAL RULES - READ FIRST ⚠️

### 1. **ALWAYS Git Commit After Changes**
- **ALWAYS commit changes to git after making modifications** to scripts, tools, or configuration files
- This allows easy rollback if something breaks
- Use descriptive commit messages that explain what was changed and why
- Commit before regenerating large files (diffs, decompiled code) so changes are tracked separately
- User can run `git log` and `git diff` to see what changed between sessions

### 2. **NEVER Delete Source Files**
- **NEVER delete files in `snapshots_norm/`** - This is the IMMUTABLE source of truth
- **NEVER delete files in `snapshots_decompiled/`** unless explicitly approved by user with clear explanation
- These directories contain valuable research data that cannot be easily regenerated
- If you think files need to be deleted, **ALWAYS ask the user first** with a detailed explanation of why

### 3. **Windows Environment Only**
- This project runs **ONLY on Windows**
- Use Windows-specific commands and paths
- Path separators: use backslash `\` or PowerShell-compatible forward slash `/`
- DO NOT suggest Linux/Mac commands (`ls`, `grep`, `find`, etc.)

### 4. **PowerShell 5.1 Compatibility**
- All scripts must work with **PowerShell 5.1** (Windows built-in)
- DO NOT use PowerShell 7+ specific features without user approval
- Test scripts are compatible with PS 5.1 before suggesting them
- If PS 7+ is required, user must approve as it requires environment changes

### 5. **Always Verify Diff Outputs**
- After generating diff files, **ALWAYS check they contain actual diffs**, not PowerShell errors
- Common issue: PowerShell error records instead of git output
- Check file sizes: 0-byte or tiny diffs (< 1KB) are usually errors
- Look for error messages like "Cannot find path" or "Exit code" in diff content
- If diffs are unexpectedly small/empty, investigate and fix the script

### 6. **Git Exit Codes Are Normal**
- Git returns exit code **1** when differences are found (this is expected!)
- Only exit codes 2+ indicate actual errors
- PowerShell interprets exit code 1 as an error - scripts must handle this
- Use `$ErrorActionPreference = 'Continue'` or `cmd /c` wrappers during git diff

### 7. **Path Length Limits**
- Windows has a 260-character path limit (legacy MAX_PATH)
- Decompilation scripts already mitigate this with short folder names
- If path issues occur, use `tools/cleanup/shorten-long-paths.ps1`
- DO NOT delete long-path files - rename them instead

### 8. **Managed DLL Exclusion in Content Patches**
- **Content patches (.content.patch) must exclude managed .NET DLLs**
- Managed DLLs are decompiled to C# source code (in .decompiled.patch)
- Including managed DLLs in content patches creates noise and duplication
- Scripts use `artifacts/file-hashes/*.csv` with `IsManaged` column to filter
- If you modify diff generation scripts, ensure managed DLL exclusion is preserved
- Common bug: Path normalization issues can break exclusion (use `Resolve-Path` + backslash normalization)

---

## 📁 Project Structure

```
sp-toolshell-ai-research/
├── snapshots_raw/              🗄️ Raw server captures (excluded from git)
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   └── v3/                     # Second patch
│
├── snapshots_norm/             📝 IMMUTABLE - Normalized configs for diffing
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   └── v3/                     # Second patch
│
├── snapshots_decompiled/       💎 IMMUTABLE - Decompiled C# sources
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   ├── v3/                     # Second patch
│   └── path-mappings.csv       # Maps short names → original paths
│
├── diff_reports/               📊 Generated patch files
│   ├── v1-to-v2.content.patch         # Web files only (78 MB)
│   ├── v1-to-v2.content.stat.txt      # Statistics
│   ├── v1-to-v2.decompiled.patch      # C# code only (52 MB)
│   ├── v1-to-v2.decompiled.stat.txt   # Statistics
│   ├── v1-to-v2.server-side.patch     # Combined C# + web + configs (42 MB)
│   ├── v1-to-v2.server-side.stat.txt  # Statistics
│   ├── v2-to-v3.content.patch         # Web files only (170 MB)
│   ├── v2-to-v3.content.stat.txt      # Statistics
│   ├── v2-to-v3.decompiled.patch      # C# code only (21 MB)
│   ├── v2-to-v3.decompiled.stat.txt   # Statistics
│   ├── v2-to-v3.server-side.patch     # Combined C# + web + configs (16 MB)
│   └── v2-to-v3.server-side.stat.txt  # Statistics
│
├── artifacts/                  🔨 Build artifacts (excluded from git)
│   ├── file-hashes/            # SHA256 hashes and change detection
│   └── path-mappings/          # Decompiled folder → original path maps
│
├── additional_resources/       📚 Research materials
│   ├── ms_advisories/          # Microsoft CSAF files
│   ├── previous_exploits_github_projects/  # Prior GitHub projects (git submodules)
│   ├── previous_sp_related_writeups/       # Prior research (HTML + assets)
│   ├── social_media/           # Social media posts
│   ├── zdi_pwn2own_announcement/  # ZDI Pwn2Own announcement
│   └── exploits/               # Exploits (HTTP requests or code)
│
├── additional_resources_text/  📄 Markdown conversions of HTML research
│   └── previous_sp_related_writeups/  # Clean markdown versions
│
├── experiments/                🧪 Isolated experiment environments
│   ├── README.md               # Experiment setup guide
│   ├── templates/              # Agent.md templates for experiments
│   ├── prompts/                # Experiment prompts (organized by type)
│   │   ├── 1.diff-triage/
│   │   ├── 2.static-analysis/
│   │   └── 3.dynamic-analysis/
│   ├── 1.1.diff-triage-v1/         # Populated by setup commands (excluded from git)
│   ├── 1.2.diff-triage-v2/         # Populated by setup commands (excluded from git)
│   ├── 1.3.diff-triage-v3/         # Populated by setup commands (excluded from git)
│   ├── 2.1.static-analysis/        # Populated by setup commands (excluded from git)
│   ├── 3.1.dynamic-analysis-v1/    # Populated by setup commands (excluded from git)
│   └── 3.2.dynamic-analysis-v2/    # Populated by setup commands (excluded from git)
│
├── ai_results/                 🤖 AI experiment outputs (excluded from git)
│
├── tools/                      🛠️ Automation scripts
│   ├── snapshot/              # Server capture
│   ├── normalize/             # Path/config normalization
│   ├── hashing/               # SHA256 + change detection
│   ├── decompile/             # ILSpy automation
│   ├── diff/                  # Patch generation
│   └── cleanup/               # HTML to Markdown conversion + path length fixes
│
├── .gitmodules                 📦 Git submodules configuration
├── .gitignore                  🚫 Excludes copyrighted/large files
├── readme.md                   📖 Project overview
├── agent.md                    🤖 This file
└── run-pipeline.ps1            ▶️ Main orchestrator
```

---

## 🎯 Context Building Order for AI Agents

When starting work on this project, read files in this order:

### Phase 1: Understand the Mission
1. **readme.md** - Project overview, research goals, vulnerability context
2. **This file (agent.md)** - Rules, constraints, how everything works

### Phase 2: Understand the Data
3. **snapshots_norm/** structure - Run `ls snapshots_norm/v1` to see directory layout
4. **snapshots_decompiled/v1/path-mappings.csv** - How short names map to original DLLs

### Phase 3: Understand the Pipeline
5. **run-pipeline.ps1** - High-level flow
6. **tools/decompile/decompile-all.ps1** - How decompilation works
7. **tools/diff/make-diff-server-side.ps1** - How patches are generated

### Phase 4: Analyze the Results
8. **diff_reports/v1-to-v2.server-side.patch** - C# + web changes (first vulnerability)
9. **diff_reports/v2-to-v3.server-side.patch** - C# + web changes (bypass fix)

---

## 🔄 Pipeline Execution Flow

### Stage 0: Environment Validation (Optional)
**Script**: `tools/validate-environment.ps1`

**Checks**:
- PowerShell version (5.1+ required, 7+ recommended)
- Git availability
- ILSpy CLI presence
- Disk space (15-20GB needed)
- Snapshot directories exist

**Run**:
```powershell
powershell -File tools/validate-environment.ps1
```

**Skip**: Use `-SkipValidation` flag on run-pipeline.ps1

---

### Stage 1: Normalization
**Script**: `tools/normalize/normalize-configs.ps1`

**Purpose**: Create stable, diff-friendly copies of snapshots

**What it does**:
- Normalize XML/JSON formatting (consistent indentation)
- UTF-8 encoding (no BOM), CRLF line endings
- Preserves immutable source

**Input**: Source snapshots
**Output**: `snapshots_norm/v1`, `v2`, `v3`

**Note**: Snapshots are already normalized in this repository.

---

### Stage 2: Decompilation
**Script**: `tools/decompile/decompile-all.ps1`

**Purpose**: Decompile .NET assemblies to C# using ILSpy

**Key Features**:
1. **Short Path Names**: Uses MD5+SHA1 hashing of **file path** → 28-char folder names (avoids Windows 260-char limit)
   - Format: `{first10chars}-{md5(8)}-{sha1(8)}`
   - Example: `Microsoft-12ab34cd-56ef78gh`
   - Hash is based on PATH, not file content

2. **Path Mappings**: Creates `path-mappings.csv` in each version directory
   - Maps short names → original DLL paths
   - **CRITICAL** for understanding diff output

3. **Source Tracking**: Each decompiled assembly gets `source-path.txt`
   - Original DLL path
   - Decompilation timestamp

4. **Parallel Execution**: 6 parallel jobs by default (adjust with `-MaxParallel`)

5. **Cross-Version Optimization** (Pipeline Mode):
   - When run via `run-pipeline.ps1`, only assemblies that **changed between versions** are decompiled
   - Uses `artifacts/file-hashes/*.csv` and `managed-changed.txt` change lists
   - Significantly reduces processing time and disk usage

⚠️ **Important: Duplicate Assemblies Within Same Version**
- The same DLL binary may exist in multiple locations (e.g., GAC, bin folders, shared libraries)
- Each location is decompiled **separately** - no within-version deduplication by file content
- **For exploit development**: When searching for available libraries:
  - The same assembly (e.g., `System.Web.dll`) may appear in multiple decompiled folders
  - Use `path-mappings.csv` to identify which original location each decompiled folder represents
  - Search by assembly name or class/namespace, not just folder names

**Output**:
- `snapshots_decompiled/v1`, `v2`, `v3`
- `path-mappings.csv` in each version directory
- `decompile-summary-{timestamp}.txt` - Success/failure report

**Note**: Decompiled sources are already available in this repository.

---

### Stage 3: Server-Side Combined Diffs
**Script**: `tools/diff/make-diff-server-side.ps1`

**Purpose**: Generate combined diffs with both C# code and SharePoint web files (ASPX, ASMX, SVC, etc.)

**Includes**:
- C# source from decompiled assemblies
- SharePoint web files (ASPX, ASCX, ASMX, SVC, CSHTML)
- Config files

**Output**:
- `diff_reports/v1-to-v2.server-side.patch` - Combined C# + web diff
- `diff_reports/v1-to-v2.server-side.stat.txt` - Statistics

**Run manually**:
```powershell
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v1 -ToDir snapshots_norm/v2
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v2 -ToDir snapshots_norm/v3
```

**Version Normalization**: All scripts strip timestamps from folder names
- `v1_20240115-1430` → `v1` (ensures consistent filenames across machines)

---

### Stage 4: Noise Filtering ⚠️ DEPRECATED - NOT RECOMMENDED

**Script**: `tools/diff/filter-diff-noise.ps1`

**Status**: ❌ **Deprecated** - Found to be inefficient after testing

**Performance Data** (from actual testing):
- **Runtime**: 3+ hours for large patch files
- **Reduction**: Only 2-4% of lines removed (e.g., 6,661 lines from 272,000 = 2.4%)
- **Cost/Benefit**: Not worth the time investment

**Why Deprecated**:
- Minimal noise reduction doesn't justify 3+ hour runtime
- Manual filtering or AI context management is more efficient
- Modern AI models handle decompiler noise well without pre-filtering

**Filters Out** (for reference):
- Decompilation timestamps: `// Decompiled: 2025-11-07 18:46:39`
- Assembly version attributes: `[assembly: AssemblyVersion("16.0.10417.20027")]`
- `source-path.txt` file chunks
- GeneratedCode/CompilerGenerated/DebuggerNonUserCode attributes
- EditorBrowsable attributes
- PackageProperty metadata

**If You Must Use It** (not recommended):
```powershell
powershell -File tools/diff/filter-diff-noise.ps1 -InputFile diff_reports/v1-to-v2.decompiled.patch -OutputFile filtered.patch
```

**Recommendation**: Skip this stage entirely. Use unfiltered patches directly.

---

## 🛠️ Complete Script Reference

### Snapshot Capture (Run on SharePoint Server)
**Script**: `tools/snapshot/snapshot-sp.ps1`

**Purpose**: Capture SharePoint server state

**Usage**: Run ON SharePoint server, then copy to research machine
```powershell
powershell -File snapshot-sp.ps1 -DestRoot "C:\SharePointSnapshot"
# Then copy entire DestRoot to snapshots_raw/v1 (or v2, v3)
```

**What It Captures**:
- SharePoint binaries (.dll, .exe)
- Config files (.config, .xml, .aspx, etc.)
- IIS applicationHost.config
- Registry hives (SharePoint keys)
- WSP solutions
- GAC assemblies

**Excluded** (to save space):
- Images: .png, .jpg, .gif, .svg, .ico
- Styles: .css, .less, .scss
- Fonts: .woff, .ttf, .eot
- Static content

---

### Pre-Pipeline Utilities

#### Remove Timestamps from Folder Names
**Script**: `tools/normalize/rename-snapshots.ps1`

**Problem**: Timestamped folders break cross-machine diffing
```
BAD:  snapshots_raw/v1_20240115-1430/
GOOD: snapshots_raw/v1/
```

**Usage**:
```powershell
# Preview changes
powershell -File tools/normalize/rename-snapshots.ps1 -SnapshotsRoot snapshots_raw -DryRun

# Execute renames
powershell -File tools/normalize/rename-snapshots.ps1 -SnapshotsRoot snapshots_raw
```

**When to Use**: After copying snapshots from servers, before running pipeline

---

#### Normalize Version Folder Numbers
**Script**: `tools/normalize/normalize-version-folders.ps1`

**Problem**: SharePoint versions have build numbers in folder names that change between patches
```
BEFORE:  v1/.../LAYOUTS/16.0.10417.20018/
         v2/.../LAYOUTS/16.0.10417.20027/

AFTER:   v1/.../LAYOUTS/BUILD_VERSION/
         v2/.../LAYOUTS/BUILD_VERSION/
```

**Usage**:
```powershell
# Preview with details
powershell -File tools/normalize/normalize-version-folders.ps1 -SnapshotsRoot snapshots_raw -DryRun -ShowDetails

# Execute
powershell -File tools/normalize/normalize-version-folders.ps1 -SnapshotsRoot snapshots_raw
```

**When to Use**: If you see version number mismatches in folder names before diffing

---

#### Fix Long Path Names
**Script**: `tools/cleanup/shorten-long-paths.ps1`

**Problem**: Windows 260-char path limit causes git/tools to fail

**Solution**: Renames files using MD5 hash, preserves extension, creates mapping file

**Usage**:
```powershell
powershell -File tools/cleanup/shorten-long-paths.ps1 -RootDir snapshots_decompiled/v1 -MaxPathLength 250
```

**Output**: Creates `long-path-mappings.txt` in affected directories

**When to Use**: Rarely needed (decompile-all.ps1 already prevents this), but use if path errors occur

---

## 📊 Key Output Files & How to Use Them

### Path Mappings (Essential for Understanding Diffs!)
**File**: `snapshots_decompiled/v1/path-mappings.csv`

**Format**: CSV with columns `ShortName`, `RelativePath`, `AssemblyName`

**Purpose**: Maps cryptic short folder names → original DLL paths

**Example**:
```csv
ShortName,RelativePath,AssemblyName
Microsoft-12ab34cd-56ef78gh,C__Program Files_Common Files_Microsoft Shared_Web Server Extensions\14\ISAPI\Microsoft.SharePoint.dll,Microsoft.SharePoint
```

**Use**: When reading decompiled diffs, look up the short name to find which DLL the code came from

---

### Source Path Metadata
**File**: `snapshots_decompiled/v1/{ShortName}/source-path.txt`

**Contains**:
- Original DLL absolute path
- Relative path from version root
- Decompilation timestamp

**Example**:
```
d:\Code\GitHubRepos\sp-toolshell-ai-research\snapshots_raw\v1\C__Program Files_Common Files_Microsoft Shared_Web Server Extensions\14\ISAPI\Microsoft.SharePoint.dll
C__Program Files_Common Files_Microsoft Shared_Web Server Extensions\14\ISAPI\Microsoft.SharePoint.dll
2025-11-07 18:46:39
```

---

## 🚨 Common Issues & Solutions

### Issue 1: Content Diffs Are 0 Bytes
**Symptom**: `diff_reports/v1-to-v2.content.patch` is 0 bytes

**Root Cause**: PowerShell pipeline stops when git returns exit code 1 (which means "differences found" - not an error!)

**Solution**: Scripts already handle this with:
```powershell
$ErrorActionPreference = 'Continue'
$output = & git diff --no-index ... 2>&1 | Out-String
$ErrorActionPreference = 'Stop'
```

**If Still Broken**: Check if script is using `cmd /c` wrapper or `2>nul` redirection (these can cause output capture failures)

**Fix**: Update to use `Out-String` method shown above

---

### Issue 2: Diff Files Contain PowerShell Errors
**Symptom**: Diff file is tiny (< 1KB) and contains text like:
```
Cannot find path 'D:\...' because it does not exist.
```

**Root Cause**: Script failed before git could run, but error was redirected to output file

**Solution**:
1. Check directory paths are correct
2. Verify git is in PATH: `git --version`
3. Look for actual error in PowerShell console output
4. Re-run with verbose output: `powershell -File script.ps1 -Verbose`

---

### Issue 3: Timestamped Folders Breaking Diffs
**Symptom**: Diffs show every file as changed, even when content is identical

**Root Cause**: Folder names include timestamps:
```
snapshots_raw/v1_20240115-1430/
snapshots_raw/v2_20240116-0900/
```

**Solution**:
```powershell
powershell -File tools/normalize/rename-snapshots.ps1 -SnapshotsRoot snapshots_raw
```

**Prevention**: Always rename immediately after copying snapshots from servers

---

### Issue 4: Version Folder Number Mismatches
**Symptom**: Diffs show file moves/renames for folders like:
```
- a/v1/.../LAYOUTS/16.0.10417.20018/file.js
+ b/v2/.../LAYOUTS/16.0.10417.20027/file.js
```

**Root Cause**: SharePoint build numbers change between patches

**Solution**:
```powershell
powershell -File tools/normalize/normalize-version-folders.ps1 -SnapshotsRoot snapshots_raw
```

**When to Use**: Before Stage 1 if you notice version folder mismatches

---

### Issue 5: "Path Too Long" Errors
**Symptom**: Errors like:
```
The specified path, file name, or both are too long. The fully qualified file name must be less than 260 characters.
```

**Solution**: Decompilation scripts already prevent this with short folder names. If still occurring:
```powershell
powershell -File tools/cleanup/shorten-long-paths.ps1 -RootDir {problematic_directory}
```

**⚠️ WARNING**: This renames files - check `long-path-mappings.txt` to recover original names

---

### Issue 6: Git Not Found
**Symptom**: `Git is required. Install Git and try again.`

**Solution**:
1. Install Git for Windows: https://git-scm.com/download/win
2. Verify: `git --version`
3. Restart PowerShell after installation

---

### Issue 7: ILSpy Not Found
**Symptom**: `ILSpy CLI not found at: tools\decompile\ILSpyCmd\ilspycmd.exe`

**Solution**:
1. Download from: https://github.com/icsharpcode/ILSpy/releases
2. Look for `ilspycmd-*-net8.0.zip`
3. Extract to `tools/decompile/ILSpyCmd/`
4. Verify: `.\tools\decompile\ILSpyCmd\ilspycmd.exe --version`

---

## ✅ Success Verification Checklist

After running the pipeline, verify:

### Stage 1: Normalization
```powershell
# Check snapshots_norm exists
Test-Path snapshots_norm/v1, snapshots_norm/v2, snapshots_norm/v3

# Count files
(Get-ChildItem snapshots_norm/v1 -Recurse -File).Count
```

### Stage 2: Decompilation
```powershell
# Check decompiled folders exist
Test-Path snapshots_decompiled/v1, snapshots_decompiled/v2, snapshots_decompiled/v3

# Read decompilation summary
Get-Content snapshots_decompiled/decompile-summary-*.txt

# Verify path mappings
Import-Csv snapshots_decompiled/v1/path-mappings.csv | Select -First 5
```

### Stage 3: Diff Generation
```powershell
# List diff files
Get-ChildItem diff_reports/*.patch | Select Name, @{N='Size(MB)';E={[math]::Round($_.Length/1MB,2)}}

# Check for errors in diffs (should return nothing)
Select-String -Path diff_reports/*.patch -Pattern "Cannot find path|Exit code" | Select -First 5
```

### Expected File Sizes
```
v1-to-v2.server-side.patch   ~varies  (C# + web + config changes)
v2-to-v3.server-side.patch   ~varies  (C# + web + config changes)
```

**⚠️ If any .patch file is 0 bytes or < 1KB**: There's a problem! Check Issue #1 or #2 above.

---

## 🔍 Data Flow Visualization

```
┌─────────────────┐
│ snapshots_norm/ │ 🔒 IMMUTABLE SOURCE
│  v1, v2, v3     │ (Normalized configs, web files)
└────────┬────────┘
         │
         │
┌────────┴────────┐
│ snapshots_      │ 🔒 IMMUTABLE SOURCE
│  decompiled/    │ (Decompiled C# sources)
│  v1, v2, v3     │
└────────┬────────┘
         │
         └──► Stage 3: make-diff-server-side.ps1
              ▼
             ┌─────────────┐
             │ diff_reports│ (Combined patches)
             │ *.server-   │ (C# + web + config)
             │   side.patch│
             └─────────────┘
```

---

## 🎓 Tips for AI Agents

### 1. Use path-mappings.csv to Understand Diffs
When you see a diff like:
```diff
diff --git a/Microsoft-12ab34cd-56ef78gh/Class1.cs b/Microsoft-12ab34cd-56ef78gh/Class1.cs
```

Look up `Microsoft-12ab34cd-56ef78gh` in `path-mappings.csv` to find:
- Original DLL path
- Assembly name
- Context about what this code does

### 2. Look for Security-Relevant Patterns
When analyzing diffs, look for:
- Authentication/authorization logic changes
- Deserialization code (`BinaryFormatter`, `JavaScriptSerializer`, etc.)
- Input validation changes
- Access control modifications
- Cryptographic operations

### 3. Use Git Blame Context
The patch files show context lines (lines starting with space, not +/-). Use these to understand:
- What code surrounds the change
- What class/method the change is in
- The broader logic flow

### 4. Cross-Reference Multiple Patches
- v1→v2 patch shows: Incomplete fix (still vulnerable)
- v2→v3 patch shows: Bypass was fixed (complete patch)
- Comparing both reveals: What the bypass was!

### 5. PowerShell 5.1 Syntax Reference
Common PowerShell 5.1 compatible patterns:
```powershell
# File operations
Get-ChildItem -Path $dir -Recurse -File
Test-Path $file
Get-Content $file
Copy-Item -Path $src -Destination $dst -Recurse

# String operations
$str -match 'pattern'
$str -replace 'old', 'new'
$str.Split(',')
$str.Trim()

# Arrays
$arr = @()
$arr += $item
$arr | Where-Object { $_.Property -eq 'value' }
$arr | ForEach-Object { $_ }

# Hash tables
$hash = @{}
$hash['key'] = 'value'
$hash.ContainsKey('key')

# Error handling
try { ... } catch { Write-Host $_.Exception.Message }
$ErrorActionPreference = 'Continue'  # Don't stop on errors
```

**Avoid** (PowerShell 7+ only):
- Ternary operator: `$x = $condition ? $a : $b`
- Pipeline chain operators: `$x && $y`
- Null-coalescing: `$x ?? $y`

---

## 📝 Quick Command Reference

### Run Full Pipeline
```powershell
powershell -File run-pipeline.ps1
```

### Run Individual Stages
```powershell
# Stage 3: Generate server-side diffs
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v1 -ToDir snapshots_norm/v2
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v2 -ToDir snapshots_norm/v3
```

### Verify Outputs
```powershell
# List generated diffs with sizes
Get-ChildItem diff_reports/*.patch | Select Name, Length

# Count decompiled files
(Get-ChildItem snapshots_decompiled/v1 -Recurse -File -Filter *.cs).Count
```

### Troubleshooting
```powershell
# Check Git version
git --version

# Check ILSpy
.\tools\decompile\ILSpyCmd\ilspycmd.exe --version

# Find long paths
Get-ChildItem snapshots_decompiled/v1 -Recurse | Where-Object { $_.FullName.Length -gt 250 }
```

---

## 📞 Getting Help

If you encounter issues:

1. **Check this guide first** - Most common issues are documented above
2. **Read error messages carefully** - PowerShell errors usually explain the problem
3. **Verify prerequisites** - Run `tools/validate-environment.ps1`
4. **Check file sizes** - 0-byte diffs indicate errors
5. **Ask the user** - When in doubt, ask before making changes (especially deletions!)

---

## 🔄 Version History

- **2025-11-08**: Initial creation
  - Documented all pipeline stages
  - Added critical rules based on user feedback
  - Included PowerShell 5.1 compatibility notes
  - Added comprehensive troubleshooting guide

---

**Remember**: This is a security research project analyzing real vulnerabilities. The goal is to understand how AI can discover n-day vulnerabilities from patch analysis. Approach the code changes with a security mindset!



