# Coverage Check Results

## Initial Findings (from first pass)
- RCE via PerformancePoint `ExcelDataSet` deserialization (`Microsoft.PerformancePoint.Scorecards.ExcelDataSet` using `Helper.GetObjectFromCompressedBase64String` -> BinaryFormatter). Mitigation: new unsafe SafeControl entries across farm/vdir web.configs plus upgrade actions to inject them (`snapshots_norm/v2/.../web.config`, `cloudweb.config`, `C__inetpub.../80/web.config`, `.../20072/web.config`, `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/.../AddExcelDataSetToSafeControls.cs`, `.../-67953109-566b57ea/...`). Bypass risk: other `Microsoft.PerformancePoint.Scorecards.Client` wildcard-safe types still deserialize via the same helper; ExcelDataSet still vulnerable if invoked outside SafeControls.
- Auth/spoofing hardening: Proof-token redirect now rejects URLs with hash fragments unless debug flag present (`snapshots_decompiled/v2/Microsoft.-1bae7604-1834fb48/.../ProofTokenSignInPage.cs:308-321`). Bypass risk: other redirect endpoints or parameters not fragment-validated.
- IIS `_forms` anonymous location removed (`snapshots_norm/v2/C__Windows_System32_inetsrv_config/applicationHost.config`), closing token-leak/anon access path. Bypass risk: other locations/zones that may still expose `_forms`.

## New Findings (from coverage check)

### New Vulnerabilities
- PowerShell module import path restriction in ShowCommand: Added check to block network or device paths in restricted sessions before importing modules (`snapshots_decompiled/v2/Microsoft.-056c3798-daa17c9d/Microsoft/PowerShell/Commands/ShowCommandCommand.cs:399-409`). Prior behavior allowed a restricted session to import a module from UNC/device paths, enabling code execution despite session restrictions. Likely RCE-capable and not covered by advisories—candidate for CVE-2025-49701.

### Additional Bypass Routes (for already-found vulnerabilities)
- Vulnerability: PerformancePoint ExcelDataSet RCE
  - New bypass considerations: other Scorecards types (namespace wildcard remains Safe) that use `Helper.GetObjectFromCompressedBase64String` could still deserialize BinaryFormatter payloads; APIs that create `ExcelDataSet` outside SafeControl parsing (e.g., service imports) would bypass the config-only block. Total bypass routes now known: 2 classes (ExcelDataSet external invocation; sibling Scorecards types using the same helper).

## CVE-2025-49701 Candidates
- Strong candidates:
  - ShowCommand restricted-session check (`ShowCommandCommand.cs:399-409`): prevents importing modules from network/device paths; pre-patch would allow remote module load leading to RCE in restricted mode.
- Possible candidates:
  - Remaining Scorecards types still wildcard-safe and using BinaryFormatter helpers (e.g., serialized members in `Helper.cs`, other `Microsoft.PerformancePoint.Scorecards.Client` classes). Could be alternative deserialization vectors beyond the newly blocked `ExcelDataSet`.

## Unmapped Security Changes
- Massive refactor of `Microsoft.Office.Project.Server.Database.DatabaseMetadata.cs` (variable/type reshuffle) — appears non-functional/obfuscation; no clear security impact.
- applicationHost.config additions of MIME types for appx/msix/msu/wim — likely functional enablement; no clear security mapping.
- applicationHost.config recycling schedule/password blob changes — operational/maintenance; security intent unclear.

## Total Coverage
- Files analyzed: 6 primary security-touching files (web.configs, applicationHost.config, ProofTokenSignInPage.cs, AddExcelDataSetToSafeControls.cs, ShowCommandCommand.cs).
- Security-relevant changes identified: 6
- Mapped to vulnerabilities: 4 (ExcelDataSet RCE, ProofToken redirect, `_forms` anonymous removal, ShowCommand restricted-session RCE)
- Unmapped: 2
- Additional bypass routes discovered: 2
- CVE-2025-49701 candidates identified: 2
