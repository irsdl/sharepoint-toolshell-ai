# ILSpy Decompilation Scripts

## Overview

This directory contains scripts for decompiling .NET assemblies using ILSpy.

## Files

- **decompile-all.ps1** - Main script to decompile all managed assemblies in the snapshots
- **test-decompile.ps1** - Test script to verify ILSpy works with a single DLL
- **ilspy.settings.json** - Reference settings (not used by ILSpy CLI, kept for documentation)
- **ILSpyCmd/** - ILSpy command-line tool directory

## Important Notes

⚠️ **ILSpy CLI does NOT accept a settings file** - settings must be passed as individual command-line flags.

## ILSpy Command-Line Flags Used

The scripts use these flags based on the desired decompilation settings:

```powershell
$ilspyArgs = @(
  '-p'                    # Create project files (.csproj)
  '-o', $OutputDir        # Output directory
  '--no-dead-code'        # Remove dead code (equivalent to removeDeadCode: true)
  '--nested-directories'  # Use nested directories for namespaces
  $DllPath                # Input assembly
)
```

## Testing

Before running the full decompilation, test with a single DLL:

```powershell
# Test with automatic DLL discovery
.\test-decompile.ps1

# Test with a specific DLL
.\test-decompile.ps1 -DllPath "C:\path\to\your.dll"

# Test with custom output directory
.\test-decompile.ps1 -DllPath "C:\path\to\your.dll" -OutputDir "C:\output"
```

Expected output:
```
Using test DLL: D:\...\admsoap.dll
OK: DLL is a managed assembly

Decompiling with ILSpy...
  ILSpy: D:\...\ilspycmd.exe
  DLL:   D:\...\admsoap.dll
  Output: D:\...\test-output

Running: ilspycmd.exe -p -o ... --no-dead-code --nested-directories ...
SUCCESS: Decompilation completed!

Output files:
  - admsoap.csproj
  - Admin.cs
  - AssemblyInfo.cs

Check output at: D:\...\test-output
```

## Running Full Decompilation

```powershell
# Decompile all versions with default settings
.\decompile-all.ps1

# Decompile specific version(s)
.\decompile-all.ps1 -Versions @('v1')

# Decompile with custom parallelism
.\decompile-all.ps1 -MaxParallel 4

# Decompile specific version with limited parallelism
.\decompile-all.ps1 -Versions @('v1', 'v2') -MaxParallel 2
```

## Parameters

### decompile-all.ps1

- **RawRoot** - Source directory containing assemblies (default: `..\..\snapshots_norm`)
- **OutRoot** - Output directory for decompiled code (default: `..\..\snapshots_decompiled`)
- **Ilspy** - Path to ILSpy executable (auto-detected if not provided)
- **MaxParallel** - Maximum parallel decompilation jobs (default: 6)
- **Versions** - Filter by version folders (e.g., @('v1', 'v2'))
- **ChangeListFile** - Optional path to file containing list of changed DLL paths (one per line) for cross-version optimization

## Understanding Decompilation Behavior

### Duplicate Assemblies

⚠️ **The same DLL binary may be decompiled multiple times if it exists in multiple locations**

The decompilation script:
- Creates folder names based on **file path**, not file content
- Does NOT deduplicate identical assemblies within the same version
- Each location gets its own decompiled output directory

**Example**:
If `System.Web.dll` (identical file) exists in both locations:
```
snapshots_norm/v1/GAC_MSIL/System.Web/System.Web.dll
snapshots_norm/v1/Program Files/App/bin/System.Web.dll
```

Both will be decompiled to separate directories:
```
snapshots_decompiled/v1/System.We-a1b2c3d4-e5f6g7h8/    (from GAC)
snapshots_decompiled/v1/System.We-x9y8z7w6-v5u4t3s2/    (from bin)
```

### Cross-Version Optimization (Pipeline Mode)

When using `-ChangeListFile` parameter (as done by `run-pipeline.ps1`):
- Only assemblies that **changed between versions** are decompiled
- Uses hash comparison from `artifacts/file-hashes/*.csv`
- Significantly reduces decompilation time
- Does NOT affect within-version duplicate handling

### Impact on Exploit Development

When searching for available libraries or dependencies:
- ✅ Use `path-mappings.csv` to find which original path each decompiled folder represents
- ✅ Search by assembly name, class name, or namespace
- ✅ Check `source-path.txt` in each decompiled folder to understand the original location
- ❌ Don't assume one decompiled folder = one unique assembly (duplicates exist)

## Output Structure

```
snapshots_decompiled/
  v1/
    <original-folder-structure>/
      <assembly-name>/
        <assembly>.csproj
        <decompiled-cs-files>
  v2/
    <original-folder-structure>/
      <assembly-name>/
        <assembly>.csproj
        <decompiled-cs-files>
  v3/
    <original-folder-structure>/
      <assembly-name>/
        <assembly>.csproj
        <decompiled-cs-files>
  decompile-summary-<timestamp>.txt
```

The output preserves the v1, v2, v3 version structure and maintains the original folder hierarchy. Each assembly is decompiled into its own folder named after the assembly.

**Example:**
```
snapshots_norm\v1\test\admsoap.dll
    ↓
snapshots_decompiled\v1\test\admsoap\
    ├── admsoap.csproj
    ├── Microsoft\
    │   └── ... (decompiled .cs files)
    └── Properties\
        └── AssemblyInfo.cs
```

## Available ILSpy Options

Run `ilspycmd.exe --help` to see all available options. Key flags:

- `-p` - Create compilable project
- `-o <dir>` - Output directory
- `--no-dead-code` - Remove dead code
- `--no-dead-stores` - Remove dead stores
- `--nested-directories` - Use nested directories for namespaces
- `-lv <version>` - C# language version
- `-r <path>` - Reference path for dependencies
- `--use-varnames-from-pdb` - Use variable names from PDB

## Troubleshooting

### Error: "ilspycmd not found"
- Ensure ILSpyCmd is in the `ILSpyCmd/` subdirectory
- Or add ILSpy to your PATH
- Or use `-Ilspy` parameter to specify the path

### Error: "Not a managed .NET assembly"
- The DLL is a native (unmanaged) DLL
- Only .NET managed assemblies can be decompiled
- The script automatically filters out native DLLs

### Decompilation fails for specific assemblies
- Check the summary report in `snapshots_decompiled/decompile-summary-<timestamp>.txt`
- Failed assemblies will be marked with "FAIL" and include error messages

## Changes Made

1. **Removed settings file dependency** - ILSpy CLI doesn't support `--settings` flag
2. **Added individual CLI flags** - Settings are now passed as separate command-line arguments
3. **Created test script** - `test-decompile.ps1` for quick validation
4. **Updated job script block** - Modified to use array of arguments instead of settings file
