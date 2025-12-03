Agent: Codex (GPT-5)  
Timestamp: 2025-11-19 22:28:51 UTC  
Duration: 35:00  

## 1. Vulnerability Verification

### V1 – `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` exposed as a safe control
1. **Diff evidence**  
   File: `C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config` (method: N/A – safe control list)  
   ```
   @@
         <SafeControl Assembly="Microsoft.Office.Server.Search, Version=16.0.0.0, ..." TypeName="SearchFarmDashboard" ... />
   +     <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
   +     <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
         </SafeControls>
   ```  
   Identical hunks exist for every web.config variant plus the new upgrade job (`Microsoft/.../AddExcelDataSetToSafeControls.cs`).

2. **V1 behavior**  
   - `webconfig.pps.xml` registers the entire `Microsoft.PerformancePoint.Scorecards` namespace as safe (`snapshots_norm/v1/.../webconfig.pps.xml:4-9`), so a page author can instantiate the `ExcelDataSet` control in markup.  
   - `ExcelDataSet.DataTable` lazily deserializes the `CompressedDataTable` string by calling `Helper.GetObjectFromCompressedBase64String` (`snapshots_decompiled/v1/.../ExcelDataSet.cs:38-78`).  
   - `Helper.GetObjectFromCompressedBase64String` simply Base64-decodes the user-provided string and passes the resulting stream to `BinarySerialization.Deserialize` (BinaryFormatter) without enforcing the `ExpectedSerializationTypes` whitelist (`snapshots_decompiled/v1/.../Helper.cs:560-599`).  
   - An attacker with page-edit rights can therefore craft markup that sets `CompressedDataTable` to an arbitrary BinaryFormatter payload. When the control renders, the payload is deserialized with full trust, enabling remote code execution in the w3wp process.

3. **V2 behavior**  
   - The diff injects explicit `<SafeControl ... TypeName="ExcelDataSet" Safe="False">` entries into every farm web.config so that this control is disallowed in page markup.  
   - The new `AddExcelDataSetToSafeControls` upgrade action iterates through IIS `web.config` files and adds the blocking entry if it is missing, guaranteeing existing deployments pick up the restriction. With the control no longer marked safe, untrusted markup cannot instantiate it, eliminating the deserialization vector.

4. **Confidence**: **High** – The vulnerable code path is fully visible (BinaryFormatter on user-controlled markup), and the patch directly revokes the control’s safe status.

---

### V2 – `ShowCommandCommand` importing modules from UNC/device paths inside restricted sessions
1. **Diff evidence**  
   File: `Microsoft/PowerShell/Commands/ShowCommandCommand.cs` — method `WaitForWindowClosedOrHelpNeeded`  
   ```
   @@
               case 0:
                   return;
               }
   +           string path = FileSystemProvider.NormalizePath(base.SessionState.Path.GetUnresolvedProviderPathFromPSPath(showCommandProxy.ParentModuleNeedingImportModule));
   +           if (Utils.IsSessionRestricted(base.Context) && (FileSystemProvider.NativeMethods.PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
   +           {
   +               ErrorRecord errorRecord = new ErrorRecord(new ArgumentException(HelpErrors.NoNetworkCommands, "Name"), "CommandNameNotAllowed", ErrorCategory.InvalidArgument, null);
   +               ThrowTerminatingError(errorRecord);
   +           }
               string importModuleCommand = showCommandProxy.GetImportModuleCommand(showCommandProxy.ParentModuleNeedingImportModule);
               Collection<PSObject> collection;
   ```

2. **V1 behavior**  
   - When the Show-Command WPF window signals `ImportModuleNeeded`, `showCommandProxy.ParentModuleNeedingImportModule` contains a module path derived from the user’s GUI choice. V1 immediately built a script command and executed it (`snapshots_decompiled/v1/.../ShowCommandCommand.cs:390-415`) without validating where the module resides.  
   - In constrained or JEA sessions, `Utils.IsSessionRestricted(base.Context)` should block risky operations, but nothing prevented a user from pointing the GUI to `\\attacker\share\evil.psm1` or `\\.\pipe\evil`. The cmdlet would run `Import-Module` on that UNC/device path, executing untrusted code despite session restrictions.  
   - This undermines the integrity guarantees of restricted language modes or remote runspaces because network-delivered modules run with the user’s privileges.

3. **V2 behavior**  
   - The patched method normalizes the resolved filesystem path, and whenever the session is restricted it rejects both network (`PathIsNetworkPath`) and device (`PathIsDevicePath`) paths with a terminating `CommandNameNotAllowed` error before importing anything.  
   - Only local filesystem modules remain loadable under restriction, restoring the policy expectation that constrained sessions cannot execute code directly from attacker-controlled shares or device aliases.

4. **Confidence**: **High** – The susceptible code path (automatic import followed by remote execution) and the hardening logic (explicit path validation) are clear in the source.

---

### V3 – `ProofTokenSignInPage` fragment rejection
1. **Diff evidence**  
   File: `Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs` — method `ShouldRedirectWithProofToken`  
   ```
   @@
           if (null != RedirectUri)
           {
               result = IsAllowedRedirectUrl(RedirectUri);
   +           if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
   +           {
   +               ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
   +               result = false;
   +           }
           }
   ```

2. **V1 behavior**  
   - `RedirectUri` is read directly from the `redirect_uri` query string (`snapshots_decompiled/v1/.../ProofTokenSignInPage.cs:45-66`). The page later issues an HTTP redirect to `RedirectUri.OriginalString` (`lines 244-252`).  
   - In v1, fragments (`#...`) were preserved inside `RedirectUri` and ultimately sent back to the browser. However, the v1 code base provided does not show any consumer of the fragment data—`IsAllowedRedirectUrl` only checks the site subscription, and the server never parses the hash. Without visibility into the target page, there is no direct evidence that the fragment creates an exploit condition (for example, an open redirect or injection).  

3. **V2 behavior**  
   - V2 introduces a kill-switch-controlled block that rejects any redirect URI containing a fragment, logging “Hash parameter is not allowed.”  
   - While this certainly hardens the input, the repository lacks code demonstrating how an attacker could leverage the fragment in v1, so the exact security impact cannot be confirmed.

4. **Confidence**: **Low / Unproven** – The diff suggests a security motivation, but the provided sources do not show a concrete exploit path involving fragments, so the original vulnerability remains speculative.

---

### V4 – Removal of IIS `/ _forms` virtual directory
1. **Diff evidence**  
   File: `C__Windows_System32_inetsrv_config/applicationHost.config` (IIS configuration)  
   ```
   @@
           <virtualDirectory path="/_windows" physicalPath="C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\template\identitymodel\windows" />
   -       <virtualDirectory path="/_forms" physicalPath="C:\inetpub\wwwroot\wss\VirtualDirectories\80\_forms" />
         </application>
   ...
   -  <location path="SharePoint - 80/_forms">
   -    <system.webServer>
   -      <handlers accessPolicy="Read, Execute, Script" />
   -      <security>
   -        <authentication>
   -          <anonymousAuthentication enabled="true" />
   -        </authentication>
   -      </security>
   -      <staticContent>
   -        <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="365.00:00:00" />
   -      </staticContent>
   -    </system.webServer>
   -  </location>
   ```

2. **V1 behavior**  
   - IIS exposed `/_forms` as a separate virtual directory mapped to `C:\inetpub\wwwroot\wss\VirtualDirectories\80\_forms` with anonymous access and `Read, Execute, Script` permissions (`snapshots_norm/v1/.../applicationHost.config:332-354` and `28667-28679`).  
   - The files shipped in `_forms` normally host SharePoint’s legacy login pages, and the configuration alone does not indicate that untrusted users can place new code there. Without such write capability, no clear exploit emerges from the configuration as provided.

3. **V2 behavior**  
   - The diff deletes both the virtual directory and the dedicated `<location>` block, so `/ _forms` requests must now flow through the main SharePoint application.  
   - While this reduces attack surface, the repository contains no evidence that the old configuration was exploitable (e.g., via writable directories or bypassed modules).

4. **Confidence**: **Low / Unproven** – The change appears security-motivated, but there is no demonstrable vulnerability in the provided materials.

## 2. Unmapped Security-Relevant Changes
The following modifications appear security related but are not tied to a confirmed vulnerability above:
1. **ProofTokenSignInPage fragment check**  
   - Mechanical change: added fragment rejection and kill-switch constant `RevertRedirectFixinProofTokenSigninPage`.  
   - Status: **Unknown if security-motivated** – No observable exploit path from the available code.
2. **Removal of IIS `/ _forms` mapping**  
   - Mechanical change: deleted the `/ _forms` virtual directory and its anonymous access `<location>` override from `applicationHost.config`.  
   - Status: **Unknown if security-motivated** – Lacking evidence that the directory was attacker-writable or bypassed authentication.

## 3. Final Assessment

| ID | Status after verification | Rationale |
| --- | --- | --- |
| V1 | **Confirmed** | Direct BinaryFormatter deserialization on untrusted safe control input and explicit configuration block in patch. |
| V2 | **Confirmed** | Clear restricted-session bypass in v1 and explicit UNC/device path guard in v2. |
| V3 | **Uncertain** | Fragment rejection added, but the repo lacks proof that fragments enabled an attack. |
| V4 | **Uncertain** | `/ _forms` mapping removal appears hardening, yet no exploit is evident from provided files. |

Only V1 and V2 can be conclusively tied to real vulnerabilities based on the available evidence; V3 and V4 remain speculative without further context.
