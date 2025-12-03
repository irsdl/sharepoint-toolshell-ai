# Final Verification

## Vulnerability 1: Unrestricted BinaryFormatter Deserialization in Ssdqs (CVE-2025-49704)
- Diff evidence: `diff_reports/v1-to-v2.server-side.patch` hunk for `Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/NoneVersionSpecificSerializationBinder.cs` shows type gating added:
```
-           value = Type.GetType(typeName + ", " + assemblyName);
+           value = TypeProcessor.LoadType(assemblyName, typeName);
+           if (value == null)
+           {
+               throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.InDeny);
+           }
+           if (TypeProcessor.IsTypeExplicitlyDenied(value))
+           {
+               throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.InDeny);
+           }
+           if (!TypeProcessor.IsTypeExplicitlyAllowed(value))
+           {
+               throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.NotInAllow);
+           }
```
- v1 vulnerable behavior (source: `snapshots_decompiled/v1/.../NoneVersionSpecificSerializationBinder.cs`): `BindToType` directly used `Type.GetType(typeName + ", " + assemblyName)` without restrictions. All Ssdqs entry points that deserialize blobs set `BinaryFormatter.Binder = NoneVersionSpecificSerializationBinder.Instance` (see `snapshots_decompiled/v1/Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/SerializationUtility.cs:144-182`). Untrusted input: SQLBytes/byte[] returned from DB or wire; flow: stored procs and service clients call `ConvertBytesToObject` → new BinaryFormatter().Deserialize with permissive binder → attacker-chosen type instantiated. Missing check: no allow/deny; outcome: arbitrary gadget activation ⇒ RCE.
- Bypass/completeness: Only one attack path validated (arbitrary type in BinaryFormatter payload). TypeProcessor still auto-allows arrays/enums/interfaces and any Microsoft.Ssdqs.* types; if a malicious type exists inside Ssdqs, payload could execute (feasibility medium). No evidence of other entry points bypassing the binder in v2; all known deserializers in Ssdqs proxies use this binder. Edge cases: allowed-type abuse remains possible; denylist may miss future gadgets.
- v2 mitigation: Binder now blocks `System.Type` outright, loads via `TypeProcessor` which enforces allowlist/denylist (see new files `TypeProcessor.cs`, `BlockedTypeException.cs`, `BlockReason.cs`), and throws on unknown types. `ChunksExportSession.ByteArrayToObject` switched to `SerializationUtility.ConvertBytesToObject` instead of raw BinaryFormatter, so export paths also enforced. This prevents arbitrary external types; remaining risk is allowed Ssdqs types/arrays. Bypass coverage: only one validated bypass path; other Ssdqs gadgets not assessed.
- Confidence: **High** that v1 was vulnerable and v2 mitigates arbitrary-type deserialization; residual allowed-type risk remains.

## Vulnerability 2: SafeControl Restriction for PerformancePoint ExcelDataSet (CVE-2025-49701 candidate)
- Diff evidence: `diff_reports/v1-to-v2.server-side.patch` web.config hunks (`C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config` and `20072/web.config`):
```
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0,..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0,..." Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" ... />
```
- v1 behavior (source: `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs`): class serializes/deserializes `DataTable` via BinaryFormatter inside `Helper.GetObjectFromCompressedBase64String`, which calls `BinarySerialization.Deserialize` (BinaryFormatter with limited allowed types, but still DataTable). With SafeControl not present/blocked, site authors could add this control to pages; attacker with author/Site Owner control of markup could embed crafted compressed payloads leading to deserialization of attacker-influenced data. Missing check: SafeControl permit allowed it to be loaded; DataTable deserialization risks gadget abuse or resource consumption.
- Bypass/completeness: Only route noted is page markup instantiation. Other PerformancePoint controls were not changed; risk confined to ExcelDataSet. Feasibility: requires author/Site Owner privileges to add control.
- v2 mitigation: SafeControl explicitly marks ExcelDataSet as Safe="False" (both v15/v16 assemblies), preventing it from loading in content pages; blocks the instantiation route. Other instantiation vectors (code-behind/server deployment) remain but are admin-only. No other bypass routes identified.
- Confidence: **Medium**; evidence shows intentional block, but exact exploitability (RCE) depends on DataTable payload gadget availability.

## Vulnerability 3: Anonymous Access to /_forms (CVE-2025-49706)
- Diff evidence: `diff_reports/v1-to-v2.server-side.patch` for `C__Windows_System32_inetsrv_config/applicationHost.config`:
```
-          <virtualDirectory path="/_forms" physicalPath="C:\inetpub\wwwroot\wss\VirtualDirectories\80\_forms" />
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
- v1 behavior: Dedicated virtual directory and location for `/_forms` with `anonymousAuthentication enabled="true"`; attackers could access form resources unauthenticated (confidentiality/integrity risk, potential token exposure). Entry is IIS-level config; any request to `/_forms/*` bypassed auth.
- Bypass/completeness: Only identified route is this explicit anonymous location; no other anonymous overrides seen in patch. Feasibility high for unauthenticated HTTP clients.
- v2 mitigation: Removal of virtual directory and anonymous `<location>` causes `/_forms` to inherit normal SharePoint/IIS authentication. No alternative anon paths identified in diff.
- Confidence: **High** that v1 allowed anonymous `/_forms` and v2 closes it.

## Coverage Check of Patch
- Security-relevant changes mapped: (1) Ssdqs deserialization allow/deny (NoneVersionSpecificSerializationBinder + TypeProcessor + ChunksExportSession), (2) SafeControl ExcelDataSet entries, (3) removal of `/_forms` anonymous access. All correspond to documented vulnerabilities above.
- No additional security-focused hunks found in scan; MIME additions/recycling schedule and assembly version bumps appear non-security. Unknown if security-motivated: none observed beyond mapped items.

## Conclusions & Confidence
- Ssdqs deserialization RCE: **Confirmed**; v1 unrestricted BinaryFormatter with custom binder, v2 enforces allow/deny. Bypass routes: only validated arbitrary-type payload path; allowed-type/array edge remains (feasibility medium). Additional gadgets inside Ssdqs not assessed.
- ExcelDataSet SafeControl (CVE-2025-49701 candidate): **Confirmed as intentional block**, exploitability for RCE is plausible but not fully proven (confidence medium); no other candidates found.
- /_forms anonymous access (CVE-2025-49706): **Confirmed**; v1 allowed anon, v2 removes it.
- Bypass validation summary: Ssdqs – only one concrete bypass path validated; others may exist via allowed-type abuse. /_forms – only one path, now removed. ExcelDataSet – single instantiation path via SafeControl; other bypasses not identified.
