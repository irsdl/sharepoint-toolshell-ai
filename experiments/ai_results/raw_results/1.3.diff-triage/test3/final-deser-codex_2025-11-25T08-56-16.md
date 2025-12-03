# Final Verification Results

## Vulnerability 1: ToolPane authentication bypass (CVE-2025-49706)
- **Diff evidence:** `diff_reports/v1-to-v2.server-side.patch`, `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs` hunk around lines ~2720:
  ```diff
  -		if (IsShareByLinkPage(context) || IsAnonymousVtiBinPage(context) || IsAnonymousDynamicRequest(context) || context.Request.Path.StartsWith(signoutPathRoot) ... || (uri != null && (SPUtility.StsCompareStrings(uri.AbsolutePath, signoutPathRoot) || ... )))
  +		bool flag8 = uri != null && (SPUtility.StsCompareStrings(uri.AbsolutePath, signoutPathRoot) || ...);
  +		if (IsShareByLinkPage(context) ... || flag8)
  		{
  			flag6 = false;
  			flag7 = true;
  +			bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
  +			bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
  +			if (flag9 && flag8 && flag10)
  +			{
  +				flag6 = true;
  +				flag7 = false;
  +				ULS.SendTraceTag(... "signout with ToolPane.aspx detected");
  +			}
  		}
  ```
- **V1 behavior:** In v1 this branch disabled authentication (`flag6=false`) whenever the request path or referrer matched signout/start pages, covering ToolPane.aspx implicitly. ToolPane.aspx (`snapshots_norm/v1/.../ToolPane.aspx`) is a Web Part import UI; with `flag6=false` the module skipped auth and set `flag7=true`, allowing anonymous handling. Combined with `applicationHost.config` v1 `location path="SharePoint - 80/_forms"` (anonymous enabled, removed in v2), an unauthenticated client could reach `/layouts/15/ToolPane.aspx` after a signout referrer.
- **Input → sink:** Untrusted HTTP request to ToolPane.aspx; SPRequestModule bypassed auth; ToolPane loads Web Part definitions (including potentially dangerous types) without verifying identity. Missing check: ToolPane requests from signout path were not re-authenticated.
- **Impact:** Anonymous user could reach ToolPane import surface that normally requires authentication, enabling further RCE chaining (per social “ToolShell”).
- **Patch effect:** v2 detects ToolPane.aspx specifically when referrer is signout and re-enables auth (`flag6=true`, `flag7=false`) plus logs, and removes the anonymous `_forms` location. This blocks the documented pre-auth path. Other endpoints remain guarded; no alternate anonymous paths identified.
- **Bypass completeness:** Only validated one bypass route (signout-referrer + anonymous `_forms`). No other pre-auth paths found in SPRequestModule; feasibility high in v1, closed in v2.
- **Confidence:** **High** (explicit auth logic change and anonymous config removal).

## Vulnerability 2: PerformancePoint ExcelDataSet deserialization exposure via SafeControls (CVE-2025-49704)
- **Diff evidence:** SafeControls additions marking ExcelDataSet unsafe
  - `16/CONFIG/web.config` & `cloudweb.config` hunks:
    ```diff
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
    ```
  - New upgrade action: `Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs` creates the same entries if missing.
- **V1 behavior:** Site web.configs (`snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config` and `20072/web.config`) already include SafeControls allowing the entire `Microsoft.PerformancePoint.Scorecards` namespace and `Scorecards.Client` assembly with `TypeName="*"` (Safe by default). ToolPane import honors SafeControls: ExcelDataSet Web Parts were permitted. ExcelDataSet (in Scorecards client assembly) deserializes attacker-supplied DataSet XML; historical writeups show gadget chains via `System.Data.Services.Internal.ExpandedWrapper` → `System.Windows.Data.ObjectDataProvider` → `System.Windows.Markup.XamlReader.Parse` leading to RCE. Missing check: no restriction on ExcelDataSet usage or deserialized types.
- **Input → sink:** Untrusted Web Part definition uploaded via ToolPane includes a type reference to `Microsoft.PerformancePoint.Scorecards.ExcelDataSet,...` and attacker-controlled DataSet XML. Because the namespace was Safe, SharePoint instantiated the control, reaching the deserialization sink and executing payload (RCE).
- **Patch effect:** Global configs now explicitly mark ExcelDataSet as `Safe="False" SafeAgainstScript="False"`; upgrade action propagates to site configs. This blocks Web Part instantiation even if other entries allow the namespace, cutting off the ToolPane deserialization path. Effectiveness depends on all farms applying the upgrade; alternative types in the namespace could still be risky.
- **Bypass completeness:** Dangerous type enumerated: `ExcelDataSet` (uses DataSet/XML deserialization). Related gadget types for exploit: `ExpandedWrapper`, `ObjectDataProvider`, `XamlReader.Parse`. No additional dangerous Scorecards types confirmed from code. Alternative endpoints: other SafeControls on `Microsoft.PerformancePoint.Scorecards.*` remain; they may need separate review. Feasibility in v1 high; v2 blocks this type but not necessarily others.
- **Confidence:** **Medium** (SafeControl evidence is strong; exact ExcelDataSet sink not present in provided code but consistent with known Scorecards gadget behavior).

## Candidate Vulnerability 3: PowerShell adapter/type hardening (possible CVE-2025-49701)
- **Diff evidence:** `System/Management/Automation/JobManager.cs` added adapter name validation and guarded resolution (hunks ~762300+):
  ```diff
  + private bool CheckTypeNames(JobSourceAdapter sourceAdapter, string[] jobSourceAdapterTypes) { ... WildcardPattern.IsMatch(adapterName) }
  + private JobSourceAdapter AssertAndReturnJobSourceAdapter(string adapterTypeName) { if (!_sourceAdapters.TryGetValue(adapterTypeName)) throw InvalidOperationException(...); }
  + GetJobSourceAdapter(...) now loads modules only if needed and throws JobSourceAdapterNotFound when unresolved.
  ```
  Removed helper `StringToBase64Converter.cs` (hunk ~773321) that decoded attacker-controlled base64 to `Deserializer` (CliXml) arguments.
- **V1 behavior (JobManager):** Not present—job adapter lookup likely accepted arbitrary adapter names without verification and could import modules implicitly, potentially enabling attacker-chosen adapter instantiation. Lack of filtering/validation creates a surface for code execution if user input controls adapter type names.
- **Impact hypothesis:** Malicious adapter type selection via management APIs could lead to executing adapter code (RCE). Removal of CliXml helper reduces another deserialization surface. Evidence is indirect; no direct entrypoint shown.
- **Patch effect:** Enforces adapter existence, filters by name patterns, and limits auto-import. Eliminating CliXml helper removes a generic deserialization utility.
- **Confidence:** **Low/Unproven** (code suggests hardening; vulnerable entrypoint not demonstrated in provided sources).

## Bypass Validation Summary
- CVE-2025-49706 (auth bypass): **Confirmed 1 distinct bypass** (signout-referrer + anonymous `_forms`). Feasibility high in v1, blocked in v2.
- CVE-2025-49704 (deserialization): **Validated 1 dangerous type path** (ExcelDataSet via ToolPane import). Other Scorecards controls remain unreviewed; additional dangerous types may exist. Feasibility high in v1, blocked for ExcelDataSet in v2.
- CVE-2025-49701 (unknown): Candidates identified (JobManager adapter hardening, CliXml helper removal) but **Unproven**; no concrete exploit path validated.

## Coverage Check (unmapped security-relevant changes)
- `[XmlSerializerFormat]` attribute churn across service contracts (multiple Microsoft.* assemblies). Mechanically switches serializer decoration; likely deserialization hardening. **Unmapped; unknown if security-motivated.** Potentially related to 49701 or additional RCE surface.
- Large modifications in `Microsoft.Office.Project.Server.Database/DatabaseMetadata.cs` (column definitions, parameter changes). Mechanically schema adjustments; no clear security linkage. **Unmapped; probably non-security.**
- MIME map additions in `applicationHost.config` (`.appx`, `.msix`, `.wim`, etc.) and recycled schedule tweaks. Operational; not tied to documented vulns. **Unmapped; likely non-security.**
- Removal of `_forms` virtual directory/anonymous `location` in `applicationHost.config` maps directly to the documented auth bypass fix (CVE-2025-49706) and is already covered.

## Confidence and Status
- ToolPane auth bypass: **Confirmed (High)**
- ExcelDataSet SafeControl block: **Confirmed but mechanism partially inferred (Medium)**
- JobManager/adapter hardening & CliXml helper removal: **Uncertain/Unproven (Low)**

