Agent: Codex-GPT5
Timestamp: 2025-11-20 00:57:01
Duration: 00:08

# Coverage Check Results

## Initial Findings (from first pass)
- **ExcelDataSet SafeControl RCE (CWE-502, High confidence)** – Multiple SharePoint web.configs now add explicit `<SafeControl>` entries that mark `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` as unsafe (e.g., `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:493-495`, `.../20072/web.config:494-495`, `.../16/CONFIG/web.config:161-162`, `.../16/CONFIG/cloudweb.config:161-162`). Upgrade actions (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/.../AddExcelDataSetToSafeControls.cs:6-27` and the duplicate under `Microsoft.-67953109-566b57ea`) ensure these entries are injected automatically, closing the declarative deserialization vector described earlier.
- **Show-Command remote import bypass (CWE-284/427, High)** – `WaitForWindowClosedOrHelpNeeded` now normalizes the pending module path and blocks UNC/device imports whenever `Utils.IsSessionRestricted` is true, throwing `HelpErrors.NoNetworkCommands` instead of blindly invoking the import (`snapshots_decompiled/v2/Microsoft.-056c3798-daa17c9d/Microsoft/PowerShell/Commands/ShowCommandCommand.cs:387-407`).
- **ProofTokenSignIn open redirect/token leak (CWE-601, High)** – `ShouldRedirectWithProofToken` rejects any redirect URI containing a fragment unless kill switch 53020 is enabled, logging the attempt and avoiding downstream token leakage (`snapshots_decompiled/v2/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:317-329`).

## New Findings (from coverage check)
- **Anonymous `_forms` virtual directory exposure (CWE-284, Low confidence)** – The IIS configuration no longer creates a physical `/ _forms` virtual directory nor a `<location path="SharePoint - 80/_forms">` block that forced anonymous authentication and long-lived caching (`snapshots_norm/v1/C__Windows_System32_inetsrv_config/applicationHost.config:353` and `:28667` vs. absence in v2). This likely mitigates unauthenticated downloads or tampering with Forms auth assets by requiring requests to hit the secured 16-hive handlers instead of a writable IIS folder.

## Unmapped Security Changes
- **Project Server `DatabaseMetadata` security function reshuffle (unknown vulnerability)** – The massive refactor in `snapshots_decompiled/v2/Microsoft.-024f053c-222dada5/Microsoft/Office/Project/Server/Database/DatabaseMetadata.cs` (stat file shows ~42k changed lines) replaces numerous `FunctionDefinition` entries for the `MSP_WEB_FN_SEC_*` family with new resource IDs and parameter arrays (e.g., around lines 13316-17970). This appears security-motivated—possibly tightening dependency lists or parameterization for the Project Server security catalog—but the patch alone does not reveal the exact issue. Hypotheses include closing privilege-escalation paths when evaluating category membership or ensuring instrumentation wrappers are called consistently.

## Total Coverage
- Files analyzed: 10
- Security-relevant changes identified: 9
- Mapped to vulnerabilities: 8
- Unmapped: 1
