# Diff-Driven Triage Report

## Metadata
- Agent: Codex (GPT-5)
- Timestamp: 2025-11-20 13:29:38 UTC
- Duration: 01:25

## 1. Vulnerability Discovery
| ID | Title | Type | Severity | Summary |
| --- | --- | --- | --- | --- |
| V1 | ExcelDataSet Safe Control enables unsafe DataTable deserialization | Deserialization / Serialization | High | The `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` control is marked safe for all page authors and lazily deserializes attacker-supplied Base64 payloads into `DataTable` objects via `BinaryFormatter`, allowing low-privileged authors to feed crafted serialized payloads that execute server-side. |
| V2 | ProofTokenSignIn open redirect via URL fragment | Authentication | High | `ProofTokenSignIn.aspx` accepted `redirect_uri` values containing URL fragments, so an attacker could point the fragment to `AppRedirect.aspx` (or similar relay pages) and cause users to be redirected to attacker-controlled origins immediately after SharePoint minted proof tokens. |
| V3 | Show-Command imports untrusted modules in restricted sessions | Authorization / Access Control | High | The Show-Command UI blindly executed `Import-Module` requests even when the module path resolved to a UNC share or device path, letting restricted PowerShell sessions load arbitrary code from network locations. |
| V4 | ToolPane reachable after logout via signout bypass | Authorization / Access Control | High | `SPRequestModule` skipped the anonymous-access block whenever the referrer or path matched `SignOut.aspx`, which let unauthenticated users call `_layouts/ToolPane.aspx` right after a forced logout and upload arbitrary `MSOTlPn_DWP` markup that SharePoint instantiates server-side. |

## 2. Root Cause Analyses
### V1 – ExcelDataSet deserialization surface
- `ExcelDataSet` (`snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs:7-103`) exposes `CompressedDataTable`, which simply Base64-decodes attacker input and passes it to `Helper.GetObjectFromCompressedBase64String` (`Helper.cs:580-599`).
- The helper inflates the blob and feeds it into `System.Data.BinarySerialization.Deserialize` (`System/Data/BinarySerialization.cs:8-62`), which is a thin wrapper over `BinaryFormatter`. Even though it restricts to `DataTable`/`DataSet`, those types themselves are known gadget surfaces.
- Web.configs ship with `<SafeControl ... Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />` (e.g., `snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:468-495`), so any page author can drop `<Scorecards:ExcelDataSet>` markup and supply arbitrary compressed payloads. That lets an editor trigger server-side BinaryFormatter deserialization without farm admin review.

### V2 – ProofTokenSignIn fragment abuse
- `ProofTokenSignIn.aspx` uses `RedirectUri` to decide where to send the browser after issuing proof tokens. Before the patch, `ShouldRedirectWithProofToken` only called `IsAllowedRedirectUrl` based on host/subscription and returned true even if `RedirectUri.Fragment` was set.
- Attackers could craft URLs such as `/_layouts/15/ProofTokenSignIn.aspx?redirect_uri=https://tenant/_layouts/15/AppRedirect.aspx#redirect_uri=https://evil`, so the host check succeeds (domain is tenant), but client-side script in `AppRedirect.aspx` later reads the fragment and navigates to `https://evil`, carrying fresh auth cookies or tokens.
- This allows phishing/open-redirect chains immediately after authentication, and any tokens appended to the redirect target are disclosed to the attacker-controlled final endpoint.

### V3 – Show-Command unrestricted module import
- When the Show-Command WPF window needs additional metadata it sets `showCommandProxy.ParentModuleNeedingImportModule` and fires `ImportModuleNeeded`. The handler (pre-patch) simply called `InvokeScript(Import-Module ...)` regardless of the module path.
- In constrained or restricted sessions (`Utils.IsSessionRestricted`), admins expect UNC paths and device paths (e.g., `\\attacker\mod\evil.psm1` or `\\?\GLOBALROOT\...`) to be blocked. The missing guard meant those paths were imported verbatim, running arbitrary module initialization scripts with current privileges.

### V4 – ToolPane access after logout
- `SPRequestModule.PostAuthenticateRequestHandler` toggles `flag6`/`flag7` to skip `SPSecurity.CookieWssKeepSessionAuthenticated` enforcement for special pages like `SignOut.aspx` and `_layouts/start.aspx`. Before the fix it treated any request whose referrer matched SignOut as safe, even if the target path ended in `ToolPane.aspx`.
- `_layouts/ToolPane.aspx` (`ToolPane.cs:523-548`) reads `MSOTlPn_Uri` and `MSOTlPn_DWP` from the POST body, instantiates the referenced WebPart markup, and processes it without additional authentication gates. If an attacker forced a victim through `SignOut.aspx?Source=/_layouts/15/ToolPane.aspx...`, the subsequent ToolPane request bypassed the anonymous block, letting unauthenticated callers submit arbitrary markup and potentially get SharePoint to deserialize or execute it.

## 3. Patch Analyses
### V1 – ExcelDataSet
- Added explicit `<SafeControl ... TypeName="ExcelDataSet" Safe="False" ... />` entries in every relevant configuration (`cloudweb.config`, farm `web.config`, and each IIS web.config under `VirtualDirectories/80` & `/20072`).
- Added an upgrade action `AddExcelDataSetToSafeControls` (`snapshots_decompiled/v2/.../Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs:1-28`) that injects the unsafe entry for both v15 and v16 assemblies.
- No code change to the control itself, so the mitigation relies entirely on preventing untrusted markup from instantiating the class.

### V2 – ProofTokenSignIn
- `ShouldRedirectWithProofToken` now inspects `RedirectUri.Fragment` and refuses to redirect if any fragment is present, unless the farm-specific kill switch 53020 is flipped (`snapshots_decompiled/v2/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:317-329`).
- This halves the exploit chain by preventing attackers from smuggling extra semantics to client-side redirectors via `#`.

### V3 – Show-Command
- `WaitForWindowClosedOrHelpNeeded` now normalizes the module path and, when `Utils.IsSessionRestricted` returns true, throws a terminating error if the path is a UNC share or device path (`snapshots_decompiled/v2/Microsoft.-056c3798-daa17c9d/.../ShowCommandCommand.cs:391-407`).
- This bounds the Show-Command surface to local filesystem modules under constrained sessions, aligning it with other remote-blocking policies.

### V4 – ToolPane signout bypass
- Within `SPRequestModule.PostAuthenticateRequestHandler`, the special-casing block now re-enables the cookie check (`flag6 = true`, `flag7 = false`) when the referer was SignOut and the current path ends in `ToolPane.aspx` and the farm kill switch 53506 is not set (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/.../SPRequestModule.cs:2708-2734`).
- A high-level trace (`ULS.SendTraceTag(505264341u, ...)`) warns if someone attempts this path, and AccessDenied is triggered instead of silently allowing the request.

## 4. Bypass Hypotheses
### V1 – ExcelDataSet
- **High:** Other `[Serializable]` Scorecards controls (e.g., `TransformerConfigurationRecord`, still covered by the `TypeName="*"` safe entry) may expose similar BinaryFormatter helpers; attackers could pivot to them now that ExcelDataSet is blocked.
- **Medium:** Existing pages that already contain `<Scorecards:ExcelDataSet>` markup might continue to run if their pages live in site collections where admins re-enabled the control via custom safe-control entries.
- **Low:** A malicious solution package could register its own SafeControl entry for ExcelDataSet (or a subclass) in a web application's web.config before the upgrade action runs, undoing the mitigation.

### V2 – ProofTokenSignIn fragment check
- **High:** Client-side redirectors that parse regular query parameters (instead of fragments) can still be abused. Example: `redirect_uri=https://tenant/_layouts/15/AppRedirect.aspx?redirect_uri=https://evil` bypasses the new fragment check.
- **Medium:** If attackers URL-encode `#` (`%23`) inside the `redirect_uri`, .NET may decode it only after the fragment scan, depending on how `Uri` parses the string. That could reintroduce the fragment semantics.
- **Low:** Other authentication pages (e.g., `_layouts/start.aspx`) that later process fragments were not patched; abusing them might still permit post-login open redirects.

### V3 – Show-Command import restrictions
- **High:** Attackers can still drop malicious modules on a local path they control (e.g., `%TEMP%`) and point Show-Command there; the new check only blocks network/device prefixes.
- **Medium:** Other cmdlets that auto-import modules (e.g., implicit remoting) might lack the new path restrictions, letting attackers bypass policy without using Show-Command.
- **Low:** UNC paths disguised as `file://server/share/module.psm1` might slip past `PathIsNetworkPath` depending on how `NormalizePath` canonicalizes URIs.

### V4 – ToolPane bypass
- **High:** Other sensitive pages reachable through SignOut (e.g., `/_layouts/15/Start.aspx` or custom tool panes) are still caught by the `flag6=false` branch; attackers could repeat the bypass with those surfaces.
- **Medium:** Administrators can toggle kill switch 53506 to disable the fix (the code explicitly checks `SPFarm.CheckFlag((ServerDebugFlags)53506)`), reopening the bypass.
- **Low:** If an attacker can directly set `UrlReferrer` to the SignOut paths using a proxy or local tooling, they might not need to rely on legit logout flows to trigger the risky condition.

## 5. Coverage Check Results
- **Initial Findings:** V1–V4 listed above.
- **New Findings from Coverage Check:** None.
- **Unmapped Security-Relevant Changes:**
  - `Microsoft.Office.Project.Server.Database.DatabaseMetadata.cs` (42980-line diff) and `IBecWebService.cs` (3896-line diff) appear to be regenerated metadata/FaultContract declarations. Reviewed representative sections and found only type swaps and attribute reordering; no security impact identified but verification is brittle due to size.
- **Files Classified as Non-Security (Confident):**
  - Hundreds of `Properties/AssemblyInfo.cs` files only bumped `AssemblyFileVersion` (`diff_reports/...stat.txt`).
  - `ApplicationHost.config` edits were limited to encrypted password blobs, recycle schedules, and MIME mappings.
  - `AppCacheManifestPage.cs` and `MDSStartAppCacheManifestPage.cs` only updated manifest version strings.
  - Removal of `<customErrors mode="Off" />` in the LAYOUTS web.configs (`snapshots_norm/.../TEMPLATE/LAYOUTS/web.config`) matches the experiment note about user-added debugging flags.
- **Total Coverage:**
  - Files analyzed in detail: 18 (including all `.config` diffs and the `.cs` files listed above).
  - `.cs` / `.config` files requiring per-hunk review: 11 (ExcelDataSet, Helper, BinarySerialization, ProofTokenSignInPage, ShowCommandCommand, ToolPane, SPRequestModule, AddExcelDataSetToSafeControls (x2 assemblies), plus each patched web.config).
  - Security-relevant changes flagged: 4 (mapped to V1–V4).
  - Security-relevant changes mapped to earlier findings: 4.
  - New vulnerabilities discovered during coverage: 0.
  - Unmapped-but-possible items still under review: 0 (not counting the large auto-generated files noted above, which currently look mechanical).

## 6. Overall Assessment & Recommendations
- The patch primarily hardens SharePoint against unsafe server-side deserialization (ExcelDataSet), open redirects immediately after proof-token issuance, and two privilege escalation paths (Show-Command and ToolPane). Each issue enables high-impact exploitation against farm services and therefore deserves urgent deployment.
- Follow-up actions:
  1. Audit all Scorecards-namespace safe controls for other serialization helpers and consider tightening their SafeControl entries as well.
  2. Extend the ProofToken fix to sanitize both fragments and query parameters, ensuring no downstream page can reinterpret attacker-provided navigation hints.
  3. Review other automation cmdlets that launch `Import-Module` behind the scenes, adding the same `PathIsNetworkPath` guard.
  4. Confirm kill switches 53020 and 53506 remain off in production; document processes so they are not re-enabled inadvertently.
