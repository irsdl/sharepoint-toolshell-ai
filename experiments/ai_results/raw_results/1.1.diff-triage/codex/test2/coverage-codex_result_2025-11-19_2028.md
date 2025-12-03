# Coverage Check Results

## Initial Findings (from first pass)
- **ProofTokenSignIn fragment hardening** – `snapshots_decompiled/v2/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:317-327` now rejects redirect URIs containing fragments unless debug flag 53020 is enabled. The v1 code (`.../v1/.../ProofTokenSignInPage.cs:315-323`) only validated the host. This maps directly to the previously reported open redirect / proof-token exfiltration issue (high severity, CWE-601/CWE-345).

## New Findings (from coverage check)
- **ExcelDataSet safe-control lockdown** (Confidence: Medium)
  - **Files/Changes**: `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config:161-162`, `.../cloudweb.config:161-162`, `.../VirtualDirectories/80/web.config:493-494` now add `<SafeControl ... TypeName="ExcelDataSet" Safe="False" ... SafeAgainstScript="False" />` entries for both v15 and v16 assemblies. A new upgrade action `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs:1-28` forces these entries into every farm web.config.
  - **Hypothesized vulnerability**: Prior builds apparently lacked an explicit entry overriding wildcard-safe registrations for `Microsoft.PerformancePoint.Scorecards.*`. That meant the `ExcelDataSet` control—which opens arbitrary Excel workbooks and can reach back-end data sources—was implicitly trusted and could be instantiated by page authors or attackers who controlled page markup. Registering it as unsafe plus shipping an upgrade routine suggests Microsoft was blocking uncontrolled use, likely to stop server-side request forgery or arbitrary file access via crafted workbooks. Breaking this implicit trust prevents low-privilege users from loading the control and abusing its data-connection capabilities.

## Unmapped Security Changes
- **SharePointSearchRuntime highlight XML fallback** – `snapshots_decompiled/v2/Microsoft.-b3970a17-9bc74dbc/Microsoft/Office/Server/Search/Query/SharePointSearchRuntime.cs:1189-1210` includes a new try/catch that logs malformed hit-highlight snippets and falls back to `SecurityElement.Escape` before emitting them. The diff indicates security-motivated sanitization, but the older build for this exact binary is not present in `snapshots_decompiled/v1`, so I cannot conclusively state what vulnerability (e.g., XSS via crafted highlight metadata) was being patched.

## Total Coverage
- Files analyzed: 5 (ProofTokenSignInPage.cs, three farm web.config variants, AddExcelDataSetToSafeControls.cs, SharePointSearchRuntime.cs)
- Security-relevant changes identified: 2
- Mapped to known vulnerabilities: 1
- Unmapped: 1
