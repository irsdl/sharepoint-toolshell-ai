Agent: Codex-GPT5
Timestamp: 2025-11-20 01:05:00
Duration: 00:08

# Final Verification Results

## 1. ExcelDataSet SafeControl / Deserialization RCE
**Diff evidence**
```
diff_reports/v1-to-v2.server-side.patch:18-37
+      <SafeControl ... Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
+      <SafeControl ... Version=16.0.0.0 ... TypeName="ExcelDataSet" Safe="False" ... />
```
(added under every farm-level web.config); identical additions appear for site web.configs and an upgrade class `snapshots_decompiled/v2/.../AddExcelDataSetToSafeControls.cs:6-27`.

**V1 vulnerable behavior**
- V1 web.configs allowed *any* type in `Microsoft.PerformancePoint.Scorecards` (`snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:236-245`), so page authors could instantiate `ExcelDataSet` from declarative markup.
- `ExcelDataSet` lazily deserializes `CompressedDataTable` using `Helper.GetObjectFromCompressedBase64String` (`snapshots_decompiled/v1/.../ExcelDataSet.cs:39-67`), which in turn decompresses attacker-provided base64 and feeds it directly into `BinarySerialization.Deserialize` without an allow list (`snapshots_decompiled/v1/.../Helper.cs:556-599`).
- Because page content is editable by site designers, they can supply arbitrary base64 payloads in markup; when SharePoint renders the control, it instantiates the object and deserializes the payload, leading to BinaryFormatter gadget execution under the web app identity (RCE).

**V2 mitigation**
- The patch explicitly marks `ExcelDataSet` as `Safe="False"` in every SafeControls list and ships an upgrade step that inserts these entries at runtime. SharePoint refuses to load unsafe controls from untrusted markup, so the low-privilege invocation path is blocked. Existing server-side usages (trusted code) remain but no longer run attacker-supplied markup.

**Confidence**: **High** – We can trace untrusted page markup → SafeControls wildcard → `ExcelDataSet` BinaryFormatter invocation, and the patch plainly revokes the SafeControl permission.

## 2. Show-Command Network Module Import
**Diff evidence**
```
diff_reports/v1-to-v2.server-side.patch:53200-53208
+            string path = FileSystemProvider.NormalizePath(...);
+            if (Utils.IsSessionRestricted(...) && (PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
+            {
+                ThrowTerminatingError(... "NoNetworkCommands" ...);
+            }
             string importModuleCommand = showCommandProxy.GetImportModuleCommand(...);
```

**V1 vulnerable behavior**
- `WaitForWindowClosedOrHelpNeeded` reacts to UI events, and when `ImportModuleNeeded` fires it unconditionally grabbed the module command and executed it via `InvokeScript` (`snapshots_decompiled/v1/Microsoft.-056c3798-daa17c9d/.../ShowCommandCommand.cs:387-414`).
- User input (`showCommandProxy.ParentModuleNeedingImportModule`) comes from the Show-Command UI, which in turn reflects the `-Module` name the remoting client requested. Constrained sessions restrict UNC/device imports elsewhere, but this helper bypassed those checks because it ran inside w3wp with full language mode.
- Thus a restricted remote user could request a module located on `\\attacker\share\evil.psm1`; the helper would import and execute it, yielding code execution in the SharePoint Management Shell host.

**V2 mitigation**
- Before importing, v2 resolves the module path and, when the session advertises `IsSessionRestricted`, rejects network/device paths by raising the same terminating error other cmdlets use (`HelpErrors.NoNetworkCommands`). Only local modules survive to the import step, closing the policy bypass.

**Confidence**: **High** – The control flow is explicit, the new guard is directly on the untrusted path, and the change precisely enforces an existing policy.

## 3. ProofTokenSignIn Redirect Fragment Leak
**Diff evidence**
```
diff_reports/v1-to-v2.server-side.patch (ProofTokenSignInPage.cs)
@@ -318,6 +320,11 @@ protected bool ShouldRedirectWithProofToken()
         if (null != RedirectUri)
         {
             result = IsAllowedRedirectUrl(RedirectUri);
+            if ((!((SPPersistedObject)SPFarm.Local != null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+            {
+                ... "Hash parameter is not allowed." ...
+                result = false;
+            }
         }
```

**V1 vulnerable behavior**
- ProofTokenSignIn uses `redirect_uri` query input to decide where to post proof/identity tokens after issuance. `ShouldRedirectWithProofToken` only invoked `IsAllowedRedirectUrl` (subscription comparison) before returning true (`snapshots_decompiled/v1/.../ProofTokenSignInPage.cs:317-327`).
- Attackers could supply URLs such as `https://tenant/_layouts/15/redirect.aspx#https://evil.example`. The host portion (before `#`) passes `IsAllowedRedirectUrl`, but client-side redirect pages read `location.hash` and forward the browser (and the freshly generated tokens) to the attacker, enabling token theft/open redirect.

**V2 mitigation**
- V2 rejects any redirect URI containing a fragment (unless a farm-level kill switch is set) and logs the attempt (`snapshots_decompiled/v2/.../ProofTokenSignInPage.cs:317-329`). Without approval, ProofTokenSignIn will not proceed, so the token issuance flow never posts to pages with fragments and the leakage path closes.

**Confidence**: **High** – The vulnerable logic and its intended fix are both clearly present in the code, and the attack surface (redirects driven by unvalidated fragments) is straightforward.

## 4. Coverage Check – Unmapped Security-Relevant Changes
1. **`applicationHost.config` removal of `_forms` overrides** (diff lines 74-111): the `/ _forms` virtual directory and location block (allowing anonymous auth and long-lived caching) were deleted. This likely tightens access but the precise vulnerability is unknown.
2. **`Microsoft.Office.Project.Server/Database/DatabaseMetadata.cs` mass updates**: the stats file shows ~42k changed lines, mostly redefined `FunctionDefinition` entries for `MSP_WEB_FN_SEC_*`. Mechanical description: parameter lists, resource IDs, and dependency arrays were rewritten; unknown if security-motivated.

## 5. Final Assessment
- **ExcelDataSet SafeControl RCE** – **Confirmed** (direct evidence of unsafe BinaryFormatter usage gated solely by SafeControls, and the patch revokes that access).
- **Show-Command remote import bypass** – **Confirmed** (v1 executed user-chosen module paths without restriction; v2 adds the missing restriction logic).
- **ProofTokenSignIn redirect leak** – **Confirmed** (v1 ignored fragments; v2 explicitly blocks them, closing the described attack).

No previous claim required rejection or downgrade.
