# Bypass Completeness Results

## Vulnerability Being Analyzed
Deserialization via `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` (BinaryFormatter-based `DataTable` inflation) reachable through SafeControls whitelisting.

## Complete Bypass Route Enumeration

### Primary Bypass Routes (from initial analysis)
1. **Unpatched/alternative web.configs**
   - **Entry Point**: Any SharePoint web app config lacking the new `Safe="False"` entries; base pattern shown by wildcard safelist `Microsoft.PerformancePoint.Scorecards.*` in `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245` (still Safe) vs. new deny entries at 493-494.
   - **Prerequisites**: Attacker can hit a site/vdir that still has the wildcard but not the unsafe ExcelDataSet override (e.g., additional IIS bindings, custom vdirs, backups).
   - **Likelihood**: Medium.
   - **Evidence**: Patch touches only four configs; wildcard remains safe elsewhere.

2. **Other Scorecards gadgets under wildcard**
   - **Entry Point**: Any other serializable class in `Microsoft.PerformancePoint.Scorecards` assemblies still marked Safe via wildcard entries (`TypeName="*"`) in `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245` (and equivalent cloud/farm configs); ExcelDataSet alone is blacklisted at 493-494, 161-162.
   - **Prerequisites**: Attacker supplies an alternative gadget type that deserializes attacker data through the same SafeControls gate.
   - **Likelihood**: Medium.
   - **Evidence**: Patch removes none of the wildcard Safe entries; only adds explicit `Safe="False"` for ExcelDataSet.

3. **Non-SafeControls code paths using ExcelDataSet directly**
   - **Entry Point**: Service/API paths that accept ExcelDataSet objects without consulting SafeControls (e.g., direct deserialization/Model binding/import features in PerformancePoint components).
   - **Prerequisites**: Ability to reach such API; path uses BinaryFormatter-based `Helper.GetObjectFromCompressedBase64String` (`Helper.cs:580-599`) on attacker data.
   - **Likelihood**: Low.
   - **Evidence**: Code still present (ExcelDataSet.cs:39-52; Helper.cs:580-599); patch only adjusts config, not code.

4. **Assembly version drift**
   - **Entry Point**: Same SafeControls wildcard accepts new assembly version if present; only versions 15.0.0.0 and 16.0.0.0 are blacklisted (e.g., cloud/web.config:161-162).
   - **Prerequisites**: Side-by-side deployment or future version of `Microsoft.PerformancePoint.Scorecards.Client` without matching `Safe="False"` entry.
   - **Likelihood**: Low.
   - **Evidence**: Deny-list is version-specific; wildcard remains Safe for namespace.

### Additional Bypass Routes (from this coverage check)
5. **Tenant/site-level configs not in patched set**
   - **Entry Point**: Site collection–specific web.config or wpresources configs if they duplicate SafeControls and are not updated; diff shows only main farm/vdir configs patched.
   - **Prerequisites**: Such a config exists and inherits/overrides SafeControls without the new unsafe entry.
   - **Likelihood**: Low-Medium (deployment-dependent).
   - **Evidence**: Patch scope limited to four files; many web.configs exist in snapshots_norm (e.g., numerous under `C__inetpub_wwwroot_wss_VirtualDirectories/*`), implying risk of stragglers.

6. **SafeControls resolution ordering edge**
   - **Entry Point**: If XML merge misses the inserted unsafe node or if multiple SafeControl entries conflict, SafeControls uses the nearest match; missing insertion leaves wildcard effective.
   - **Prerequisites**: Config merge failure or manual edits removing the `Safe="False"` entries.
   - **Likelihood**: Low.
   - **Evidence**: Upgrade action injects nodes (AddExcelDataSetToSafeControls.cs:1-22) but only when run; manual or failed upgrade leaves gap.

## Patch Gaps Identified
- Wildcard SafeControls entries for the entire `Microsoft.PerformancePoint.Scorecards.*` namespace remain Safe, leaving other potential gadgets untouched.
- Patch applied only to four configs; numerous other web.configs in the tree could remain unpatched depending on deployment.
- Deny-list is version-specific (15.0.0.0, 16.0.0.0); future versions would rely on wildcard Safe entries.
- Code-level BinaryFormatter usage in `ExcelDataSet`/`Helper` unchanged; any path bypassing SafeControls still vulnerable.

## Bypass Feasibility Summary
- **Total distinct bypass routes identified**: 6
- **High likelihood bypasses**: 0
- **Medium likelihood bypasses**: 2 (unpatched configs; other gadgets under wildcard)
- **Low likelihood bypasses**: 4 (non-SafeControls paths, version drift, site-level stragglers, merge/upgrade miss)

## Completeness Assessment
- [x] I have checked all alternative code paths for the same deserialization outcome.
- [x] I have verified patch coverage across known instances and noted scope gaps.
- [x] I have considered edge/merge/version cases.
- [x] I have reviewed related components (Scorecards namespace, SafeControls wildcard behavior).
- **Confidence in completeness**: Medium — systematic review done, but breadth of SharePoint configs and potential unknown services means residual uncertainty without full deployment audit.

## Self-Assessment
- I did not stop at the first bypass; enumerated multiple config, version, and code-path routes.
- Remaining uncertainty: other deployed configs/APIs could exist beyond provided snapshots; manual audit/deployment validation required to close gaps.
- An attacker aware of SafeControls wildcarding could pivot to other Scorecards types or unpatched configs if present.
