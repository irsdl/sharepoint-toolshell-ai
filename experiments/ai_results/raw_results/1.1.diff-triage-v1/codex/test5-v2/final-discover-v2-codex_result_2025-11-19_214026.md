Agent: Codex (GPT-5)
Timestamp: 2025-11-19 21:40:26
Duration: 08:00

## Verified Vulnerabilities

### V1 – ToolPane anonymous bypass (Authorization / Access Control)
1. **Diff evidence** – `diff_reports/v1-to-v2.server-side.patch`, hunk `@@ -2720,10 +2720,19 @@ public sealed class SPRequestModule : IHttpModule`:
   ```diff
-                if (IsShareByLinkPage(context) ... || (uri != null && (SPUtility.StsCompareStrings(uri.AbsolutePath, signoutPathRoot) ... )))
+                bool flag8 = uri != null && (SPUtility.StsCompareStrings(uri.AbsolutePath, signoutPathRoot) ...);
+                if (IsShareByLinkPage(context) ... || flag8)
                 {
                     flag6 = false;
                     flag7 = true;
+                    bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
+                    bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
+                    if (flag9 && flag8 && flag10)
+                    {
+                        flag6 = true;
+                        flag7 = false;
+                        ULS.SendTraceTag(... "Risky bypass limited ... ToolPane.aspx ...");
+                    }
                 }
   ```
2. **V1 behavior** – `snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs:2700-2767`:
   - Untrusted input: the current request path and `UrlReferrer` (client-provided headers) (lines 2712-2734).
   - Flow: when any of the `StartsWith(signoutPath*)` conditions or referrer matches the sign-out paths, the code sets `flag6=false` and `flag7=true` (lines 2722-2732). Later, when the user is unauthenticated, the branch that would send `AccessDenied` is skipped because it requires `flag6==true` and `flag7==false` (lines 2758-2767).
   - Missing check: there is no exception for sensitive resources like `/_layouts/15/ToolPane.aspx`; any request that spoofs the referrer as a sign-out URL clears `flag6`.
   - Impact: unauthenticated attackers can reach ToolPane, which exposes web-part configuration and allows edits. Reading and posting ToolPane parameters leaks data and enables stored XSS or configuration tampering.
3. **V2 mitigation** – `snapshots_decompiled/v2/.../SPRequestModule.cs:2700-2750`:
   - Introduces `flag8` to detect sign-out referrers and immediately adds a carve-out: if the request path ends with `ToolPane.aspx` and kill switch 53506 is not set, `flag6` is restored to `true` and `flag7` to `false`, forcing the downstream auth check to run and resulting in `AccessDenied` for unauthenticated users.
4. **Confidence**: **High** – the control flow clearly skipped authorization for any page when the referrer spoof matched sign-out, and the patch directly reinstates the check solely for ToolPane.

### V2 – Show-Command restricted-session escape (Authorization / Access Control)
1. **Diff evidence** – `diff_reports/.../ShowCommandCommand.cs`, hunk `@@ -399,6 +399,12 @@ public class ShowCommandCommand`:
   ```diff
+            string path = FileSystemProvider.NormalizePath(base.SessionState.Path.GetUnresolvedProviderPathFromPSPath(showCommandProxy.ParentModuleNeedingImportModule));
+            if (Utils.IsSessionRestricted(base.Context) && (FileSystemProvider.NativeMethods.PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
+            {
+                ErrorRecord errorRecord = ...;
+                ThrowTerminatingError(errorRecord);
+            }
             string importModuleCommand = showCommandProxy.GetImportModuleCommand(showCommandProxy.ParentModuleNeedingImportModule);
   ```
2. **V1 behavior** – `snapshots_decompiled/v1/Microsoft.-056c3798-daa17c9d/.../ShowCommandCommand.cs:389-414`:
   - Untrusted input: `showCommandProxy.ParentModuleNeedingImportModule` is derived from UI interactions (module selection) and ultimately resolves to a filesystem path that may point to attacker-controlled locations.
   - Flow: during `WaitForWindowClosedOrHelpNeeded`, when the UI requests a module import (`case 2`), the code immediately builds a script via `GetImportModuleCommand(...)` and executes it with `InvokeScript(...)` (lines 403-411). No validation is performed even if `Utils.IsSessionRestricted` is true, meaning constrained runspaces will happily import modules from UNC paths or device namespaces.
   - Missing check: no restriction on remote paths despite the presence of a restricted session indicator.
   - Impact: an attacker who can influence `ParentModuleNeedingImportModule` (e.g., via module metadata or by luring an admin to browse a malicious module manifest) can execute arbitrary scripts hosted on network shares even in constrained sessions, bypassing WL restrictions.
3. **V2 mitigation** – `snapshots_decompiled/v2/.../ShowCommandCommand.cs:399-416` now normalizes the path and explicitly blocks imports when `Utils.IsSessionRestricted` and the path is a network/device path, throwing `CommandNameNotAllowed` before any script executes.
4. **Confidence**: **High** – the unsafe behavior is explicit in v1 (no checks) and v2 adds a targeted guard tied to the restricted-session flag.

### V3 – ProofToken redirect hash smuggling (Input Validation)
1. **Diff evidence** – `diff_reports/.../ProofTokenSignInPage.cs`, hunks `@@ -32,6 +32,8 @@` and `@@ -318,6 +320,11 @@`:
   ```diff
+    private const int RevertRedirectFixinProofTokenSigninPage = 53020;
@@
         if (null != RedirectUri)
         {
             result = IsAllowedRedirectUrl(RedirectUri);
+            if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+            {
+                ULS.SendTraceTag(... "Hash parameter is not allowed.");
+                result = false;
+            }
         }
   ```
2. **V1 behavior** – `snapshots_decompiled/v1/.../ProofTokenSignInPage.cs:40-87, 317-328`:
   - Untrusted input: `RedirectUri` is constructed from the `redirect_uri` query parameter, optionally decoded via flags (lines 45-70).
   - Flow: `FormActionValue` uses `RedirectUri.OriginalString` whenever `ShouldRedirectWithProofToken()` returns true (lines 72-88). In v1, `ShouldRedirectWithProofToken` simply called `IsAllowedRedirectUrl` (lines 317-323) and never examined fragments.
   - Missing check: the code ensures only that the host resolves to the current subscription; it does not reject `RedirectUri` values that append arbitrary `#fragment`. `silentsignin.aspx` posts directly to `FormActionValue` and the browser immediately follows the resulting URL (see `snapshots_norm/v1/.../silentsignin.aspx:24-48`). Therefore, an attacker can supply `/sites/portal/_layouts/15/start.aspx#https://evil.example/`—after the token exchange, the browser loads `start.aspx` and then automatically navigates to the fragment URL, carrying fresh cookies.
   - Impact: phishing or token exfiltration: the fragment is attacker-controlled and executed client-side after authentication.
3. **V2 mitigation** – `snapshots_decompiled/v2/.../ProofTokenSignInPage.cs:33-36, 317-330` introduces a kill-switch constant and rejects any `RedirectUri` with a non-empty `Fragment` unless admins explicitly enable switch 53020, logging the attempt and setting `result=false` so the final redirect reverts to a safe default.
4. **Confidence**: **High** – the parameter source, missing fragment validation, and the browser behavior in `silentsignin.aspx` provide a complete exploit path, and the patch directly blocks URIs containing fragments.

## Coverage Check – Unmapped Security-Relevant Changes
1. **SafeControl additions** – Several web.configs (`diff_reports/.../16/CONFIG/web.config`, `cloudweb.config`, virtual directory configs) gained SafeControl entries for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` with `Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False"` (see lines 22-36, 122-136 of the patch). *Mechanical change*: registering additional controls with explicit safety flags. **Unknown if security-motivated.**
2. **Upgrade helper** – New file `Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs` (patch lines ~73146) introduces code to insert those SafeControl entries during upgrade. *Mechanical change*: new upgrade step ensuring the SafeControl registration exists. **Unknown if security-motivated.**
3. **applicationHost.config adjustments** – `diff_reports/.../applicationHost.config` modifies application pool credentials/schedules and removes the `<virtualDirectory path="/_forms" ...>` plus the `<location path="SharePoint - 80/_forms">` block that previously enabled anonymous access (patch hunks `@@ -350,7 +350,6 @@` and `@@ -28664,17 +28669,4 @@`). *Mechanical change*: `_forms` mapping removed and anonymous handler section deleted. **Unknown if security-motivated.**

## Confirmation Status
- **V1 ToolPane bypass** – **Confirmed** (code shows the unauthenticated bypass and the fix directly addresses ToolPane requests).
- **V2 Show-Command escape** – **Confirmed** (v1 executes unvalidated module imports; v2 blocks network/device paths in restricted sessions).
- **V3 ProofToken redirect hash smuggling** – **Confirmed** (v1 trusts fragments; v2 rejects them unless a kill switch is set).

All other apparently security-related changes remain unmapped because the patch mechanics do not reveal the underlying vulnerability.
