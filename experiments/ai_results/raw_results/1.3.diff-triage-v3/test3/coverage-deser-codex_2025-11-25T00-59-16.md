# Coverage Check Results

## Initial Findings (from first pass)
- Deserialization RCE via `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` reachable through ToolPane import; patch marks SafeControl entries as `Safe="False"` in multiple `web.config` files and adds upgrade action `Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs` to push the block. Bypass route (v1): POST to `/_layouts/15/ToolPane.aspx` importing a web part referencing `ExcelDataSet` with DataSet/XamlReader gadget; executes as farm account.
- Auth bypass enabling unauth ToolPane access: anonymous `_forms` location and signout-based skip in `SPRequestModule`; patch removes `_forms` anonymous location/virtual directory and adds ToolPane-specific signout detection in `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs`. Bypass route (v1): use signout referrer + `_forms` to reach ToolPane pre-auth.
- Possible secondary RCE hardening: removal of `System/Management/Automation/StringToBase64Converter.cs` (CliXml base64 deserialization helper) suggesting prior attacker-controlled deserialization surface.

## New Findings (from coverage check)

### New Vulnerabilities
- JobSourceAdapter loading hardening (likely RCE prevention): `System/Management/Automation/JobManager.cs` gains adapter name filtering (`CheckTypeNames`), stricter resolution (`AssertAndReturnJobSourceAdapter`), and guarded module import when adapters are missing. Previously, arbitrary adapter type names could be accepted without validation, potentially allowing attacker-influenced adapter selection/instantiation leading to code execution. **Confidence: medium**. **CVE candidate: 49701**.

### Additional Bypass Routes (for already-found vulnerabilities)
- None newly identified; existing bypasses remain: ToolPane import chain (ExcelDataSet deserialization) and signout/`_forms` pre-auth path.

### CVE-2025-49701 Candidates
- **Strong candidates:**
  - JobManager adapter type validation (`System.Management.Automation/JobManager.cs`): new checks on adapter names and guarded module import reduce attacker-controlled adapter resolution → RCE potential if unvalidated.
- **Possible candidates:**
  - Removal of CliXml Base64 deserializer (`StringToBase64Converter.cs`): eliminates an accessible XML deserialization helper that could be invoked with attacker-controlled base64 payloads.
  - WCF `[XmlSerializerFormat]` attribute churn across service contracts (multiple Microsoft.* assemblies): may switch serializers to close type-confusion/deserialization gadgets; unclear entrypoints.

## Unmapped Security Changes
- Numerous `[XmlSerializerFormat]` additions/removals in service contracts (e.g., Microsoft.ProjectServer ServerProxy classes) indicating serializer selection hardening; vulnerability type not confirmed.
- Large schema/column definition shifts in `Microsoft.Office.Project.Server.Database/DatabaseMetadata.cs` including TypeName column type adjustments; likely non-security but unconfirmed.
- Addition of new MIME mappings in `applicationHost.config` (`.appx`, `.msix`, `.wim`, etc.) appears operational; no clear security implication.

## Total Coverage
- Files analyzed: ~8 key areas (web.config variants, applicationHost.config, SPRequestModule.cs, AddExcelDataSetToSafeControls.cs, StringToBase64Converter removal, JobManager.cs, XmlSerializerFormat changes, DatabaseMetadata.cs overview).
- Security-relevant changes identified: 6
- Mapped to vulnerabilities: 3 (ExcelDataSet deserialization RCE, ToolPane auth bypass, CliXml/base64 hardening tentative)
- Unmapped: 3
- Additional bypass routes discovered: 0
- CVE-2025-49701 candidates identified: 2
