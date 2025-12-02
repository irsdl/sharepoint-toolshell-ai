# Final Verification Results

## Verified Vulnerability 1: Unsafe BinaryFormatter deserialization in Microsoft.Ssdqs (CVE-2025-49704/RCE; candidate also for CVE-2025-49701)

### 1) Evidence in diff
- File: diff_reports/v1-to-v2.server-side.patch @ NoneVersionSpecificSerializationBinder
```
@@
-            value = Type.GetType(typeName + ", " + assemblyName);
+            value = TypeProcessor.LoadType(assemblyName, typeName);
+            if (value == null)
+            {
+                throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.InDeny);
+            }
+            if (TypeProcessor.IsTypeExplicitlyDenied(value))
+            {
+                throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.InDeny);
+            }
+            if (!TypeProcessor.IsTypeExplicitlyAllowed(value))
+            {
+                throw new BlockedTypeException(typeName + ", " + assemblyName, BlockReason.NotInAllow);
+            }
```
- New files added: `Microsoft/Ssdqs/Infra/Utilities/TypeProcessor.cs`, `BlockedTypeException.cs`, `BlockReason.cs` (allow/deny enforcement and exception signaling).

### 2) Vulnerable v1 behavior
- v1 binder (`snapshots_decompiled/v1/Microsoft.-b23f4965-73cc7a11/.../NoneVersionSpecificSerializationBinder.cs`):
```
value = Type.GetType(typeName + ", " + assemblyName);
_sTypeNamesCache.Add(key, value);
return value;
```
- BinaryFormatter call sites (e.g., `SerializationUtility.ConvertSqlBytesToObject/ConvertBytesToObject`) set `BinaryFormatter.Binder = NoneVersionSpecificSerializationBinder.Instance`, then deserialize arbitrary blobs from SQL or byte arrays. These blobs originate from database fields populated from client inputs across many Ssdqs entry points and SQLCLR stored procedures (e.g., `PersistentCache.TryGetEntry`, numerous stored procedures and proxy clients call `SerializationUtility.ConvertSqlBytesToObject`).
- Missing check: binder blindly resolves attacker-controlled type names embedded in BinaryFormatter payloads. No allow/deny list and no null guard. Result: attacker supplying serialized data can resolve and instantiate arbitrary types (including framework gadgets such as `System.Configuration.Install.AssemblyInstaller`, remoting sinks, etc.), enabling gadget-based RCE under the SharePoint service account. Preconditions match advisory: authenticated user (Site Owner) can cause server-side deserialization of provided blobs.

### 2.5) Bypass routes and completeness
- Primary route: framework gadget types in BinaryFormatter payload (explicitly denied in v2). Feasibility: High; BinaryFormatter gadget chains are well-known and binder accepted any type.
- Potential residual route: any `Microsoft.Ssdqs.*` type remains auto-allowed in `TypeProcessor.IsTypeExplicitlyAllowed`—if such types contain dangerous serialization callbacks, they could still be abused. Feasibility: Medium (requires internal gadget in Ssdqs assembly). Only one validated route (framework gadgets); internal gadget route noted but not demonstrated. CVE-2025-49706 (auth bypass) not implicated here.
- Dangerous elements explicitly blocked in v2 (illustrative list from deny set): `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, remoting formatter sinks, `System.Configuration.Install.AssemblyInstaller`, `System.Web.UI.ObjectStateFormatter`, `System.Management.Automation.PSObject`, `System.Windows.Markup.XamlReader`, `System.Xml.XmlDocument`, etc.; generic blocks for `SortedDictionary<>`, `SortedSet<>`.

### 3) Patched v2 behavior
- Binder now delegates to `TypeProcessor.LoadType`, throws `BlockedTypeException` if type is null or explicitly denied or not explicitly allowed. It also short-circuits `System.RuntimeType/System.Type` to null before resolution.
- `TypeProcessor` enforces:
  - Allowlist: primitives, benign generics (Nullable, List, Dictionary, etc.), `Microsoft.Ssdqs.*` assemblies, globalization types, arrays/enums/interfaces/abstract types.
  - Denylist: extensive list of high-risk gadget types plus disallowed generics.
- Effect: attacker-supplied payloads resolving to denied or non-allowed types now fail with `BlockedTypeException`; generic parsing uses guarded loader. This blocks the arbitrary type resolution that enabled RCE in v1.
- Completeness: Blocks known framework gadget types; still allows all Ssdqs types, so fix is strong against generic framework gadgets but may not cover internal gadget classes. No other endpoints using this binder were altered separately; protection is centralized in the binder/TypeProcessor.

### 4) Confidence
- **High**: Direct code evidence of unsafe type resolution in v1 and strict allow/deny enforcement in v2. RCE vector via BinaryFormatter gadgets is a well-established consequence of unconstrained binders. Residual risk of Ssdqs-internal gadgets noted but does not negate primary vulnerability.

## Coverage / Unmapped Security-Relevant Changes
- SafeControl additions in multiple web.configs (`cloudweb.config`, `CONFIG/web.config`, `VirtualDirectories/80/web.config`, `VirtualDirectories/20072/web.config`): added `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` (versions 15.0.0.0 and 16.0.0.0) marked `Safe="False"`. Mechanically adds explicit unsafe declaration; likely to prevent automatic SafeControl loading of that control. Purpose unclear—could be hardening against control activation/XSS/RCE. Candidate for CVE-2025-49701 or separate hardening, but vulnerability type cannot be determined from code alone. Marked **unknown if security-motivated**.
- IIS `applicationHost.config` changes: password blob and recycle schedule adjusted. Operational; no direct security behavior change evident.
- Search-related BinaryFormatter binder usages (CookieAuthData, CTSDocument, UrlMapping) only show namespace qualification or added binder instances identical to existing behavior—no logic change; not mapped as new security fixes.

## Confirmation Status
- Unsafe Ssdqs BinaryFormatter deserialization: **Confirmed** (CVE-2025-49704; also plausible for CVE-2025-49701).
- SafeControl ExcelDataSet change: **Uncertain** (security intent plausible but not evidenced as a specific vulnerability).
- No evidence found to confirm CVE-2025-49706 (auth bypass); not addressed in observed diffs.

## Bypass Validation Summary
- Ssdqs deserialization: **Confirmed 1 distinct validated bypass route** (arbitrary framework gadget types). Potential additional route via Ssdqs-internal gadgets remains unvalidated—others may exist. Feasibility: High for framework gadgets; Medium for internal gadgets (requires gadget presence).
- CVE-2025-49706: No bypass routes identified; not validated.
- CVE-2025-49701 candidates: Ssdqs binder hardening (High confidence); SafeControl ExcelDataSet hardening (Medium/Uncertain).
- Coverage statement: I may have missed alternative bypass routes within Ssdqs-specific types because the allowlist permits all `Microsoft.Ssdqs.*` types; only the framework gadget path was validated.

