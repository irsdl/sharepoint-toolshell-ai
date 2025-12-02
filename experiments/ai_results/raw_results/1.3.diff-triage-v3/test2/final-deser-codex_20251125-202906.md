# Final Verification

## 1) Vulnerability: Unsafe type resolution in Ssdqs BinaryFormatter binder (RCE risk, CVE-2025-49701 candidate)

**Patch hunk (diff_reports/v1-to-v2.server-side.patch)**  
File: `Microsoft/Ssdqs/Infra/Utilities/NoneVersionSpecificSerializationBinder.cs`, method `BindToType`  
Key changes: adds allow/deny checks and TypeProcessor; blocks System.Type/RuntimeType; raises `BlockedTypeException`.  
```diff
@@ public override Type BindToType(string assemblyName, string typeName)
-            value = Type.GetType(typeName + ", " + assemblyName);
+            value = TypeProcessor.LoadType(assemblyName, typeName);
+            if (value == null) { throw new BlockedTypeException(..., BlockReason.InDeny); }
+            if (TypeProcessor.IsTypeExplicitlyDenied(value)) { throw new BlockedTypeException(..., BlockReason.InDeny); }
+            if (!TypeProcessor.IsTypeExplicitlyAllowed(value)) { throw new BlockedTypeException(..., BlockReason.NotInAllow); }
```
New file added: `Microsoft/Ssdqs/Infra/Utilities/TypeProcessor.cs` defining allow/deny lists (includes DataSet, ObjectDataProvider, XamlReader, BinaryFormatter/SoapFormatter, ClaimsIdentity/Principal, Hashtable, ResourceDictionary/ResX, JavaScriptSerializer, ObjectStateFormatter, etc.).

**V1 behavior (snapshots_decompiled/v1/Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/NoneVersionSpecificSerializationBinder.cs)**  
```csharp
// BindToType in v1
value = Type.GetType(typeName + ", " + assemblyName);
_sTypeNamesCache.Add(key, value);
return value;
```
No validation of requested type; any type name in the serialized stream is resolved.

**Untrusted input path (snapshots_decompiled/v1/Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/SerializationUtility.cs)**  
```csharp
public static object ConvertBytesToObject(byte[] input) {
    using Stream serializationStream = new MemoryStream(input);
    return new BinaryFormatter { Binder = NoneVersionSpecificSerializationBinder.Instance }.Deserialize(serializationStream);
}
```
`ConvertBytesToObject` and `ConvertSqlBytesToObject` accept arbitrary byte arrays/SqlBytes (potentially attacker-controlled if persisted from user input) and deserialize them with the binder that resolves any type.

**Attack flow (v1)**
- Untrusted bytes provided to `ConvertBytesToObject` → BinaryFormatter invoked.
- Binder resolves arbitrary `typeName` from the payload via `Type.GetType` with no allow/deny.
- Classic gadget types (e.g., `System.Data.DataSet`, `System.Windows.Markup.XamlReader`, `System.Windows.Data.ObjectDataProvider`, `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`, etc.) can be instantiated during deserialization.
- Outcome: arbitrary code execution in the process context (standard .NET BinaryFormatter gadget RCE) assuming an attacker can supply the serialized bytes (e.g., via persisted data that flows through these helpers).

**Patched behavior (v2)**
- Binder now rejects System.Type/RuntimeType and defers to TypeProcessor.
- TypeProcessor enforce allowlist primitives/collections and denies high-risk gadget types; throws BlockedTypeException otherwise.
- This blocks arbitrary gadget selection through the binder, preventing code execution via unsafe types when deserializing untrusted bytes.

**Bypass/Completeness**
- Other BinaryFormatter call sites may exist; only the binder-enforced paths (ConvertBytesToObject/ConvertSqlBytesToObject) gain protection. If any BinaryFormatter use omits this binder, RCE remains possible there (not covered by this change).
- Edge cases: payloads using only allowed primitive/collection types still deserialize; gadget types in the deny list are blocked. No evidence of an alternate type resolver in this component.

**Confidence:** Medium. Code clearly shows unvalidated type resolution fixed to an allow/deny model. Exploitability depends on attacker influence over the serialized bytes; such influence is plausible but not proven from these files alone.

---

## 2) Vulnerability: ToolPane signout-path handling (authentication bypass) — Uncertain

**Patch hunk**  
File: `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs`, method `PostAuthenticateRequestHandler` (around line ~2720).  
```diff
@@
-                if (IsShareByLinkPage(...) || ... || context.Request.Path.StartsWith(signoutPathCurrent) || (uri != null && (... signout...)))
+                bool flag8 = uri != null && (... signout...);
+                if (IsShareByLinkPage(...) || ... || context.Request.Path.StartsWith(signoutPathCurrent) || context.Request.Path.StartsWith(startPathCurrent) || flag8)
                 {
                     flag6 = false;
                     flag7 = true;
+                    bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
+                    bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
+                    if (flag9 && flag8 && flag10) {
+                        flag6 = true;
+                        flag7 = false;
+                        ULS.SendTraceTag(... "signout with ToolPane.aspx detected. request path: '{0}'.", context.Request.Path);
+                    }
                 }
```

**V1 behavior (from same file, pre-diff)**  
Condition sets `flag6=false`/`flag7=true` for signout/start paths; no special case for `ToolPane.aspx`. The module therefore treated signout-path requests to ToolPane the same as other signout URLs (exact security semantics of `flag6/flag7` not visible here, but the patch treats it as “risky bypass limited”).

**Attack hypothesis (v1)**
- If signout-path requests were exempted from normal auth handling (flag6/flag7 toggles), an attacker could issue a signout-pattern URL ending with `ToolPane.aspx` to reach ToolPane without full auth.
- ToolPane pages load web parts and parse user-supplied parameters (`MSOTlPn_*` fields) that can include serialized markup; reaching it unauthenticated could enable further exploitation.
- This is inferred from the new “Risky bypass limited” log tag; exact bypass mechanics are not fully visible in the diff.

**Patched behavior (v2)**
- Adds explicit block for signout-path + `ToolPane.aspx` when debug flag not set: resets `flag6=true`/`flag7=false` and logs.
- This prevents the special signout handling from applying to ToolPane requests, implying the prior behavior was unsafe.

**Bypass/Completeness**
- Only `ToolPane.aspx` gets this guard. Other design-time endpoints are not covered; potential residual bypasses are unverified.
- Lacking full context of `flag6/flag7`, exploitability cannot be conclusively proven.

**Confidence:** Low/Uncertain. Patch intent suggests an auth bypass fix, but without full module semantics the bypass path is not conclusively demonstrated.

---

## 3) Vulnerability: URL mapping BinaryFormatter deserialization (RCE risk) — Uncertain

**Patch hunk**  
File: `Microsoft/Office/Server/Search/Query/UrlMapping/UrlMappingCache.cs` (method added `DeserializeMappingTables`).  
```diff
+    private void DeserializeMappingTables()
+    {
+        if (urlMappingBytes == null) { return; }
+        MemoryStream stream = new MemoryStream(urlMappingBytes);
+        using GZipStream serializationStream = new GZipStream(stream, CompressionMode.Decompress);
+        BinaryFormatter binaryFormatter = new BinaryFormatter();
+        binaryFormatter.Binder = new Microsoft.Office.Server.Security.SafeSerialization.ExplicitReferenceSerializationBinder<Dictionary<string, string>>("DeserializeMappingTables");
+        forwardUrlMapping = (Dictionary<string, string>)binaryFormatter.Deserialize(serializationStream);
+        reverseUrlMapping = new Dictionary<string, string>(forwardUrlMapping.Count);
+        ...
+    }
```
No binder in v1 (method absent), implying prior deserialization of `urlMappingBytes` with BinaryFormatter lacked type restrictions.

**V1 behavior (inferred)**
- URL mapping cache stored compressed BinaryFormatter bytes (`urlMappingBytes`). Deserialization would reconstruct objects without a validating binder, allowing arbitrary type instantiation if an attacker could influence the bytes.
- Actual v1 method is not present for comparison in the diff; thus behavior is inferred from the addition.

**Attack hypothesis (v1)**
- If `urlMappingBytes` can be influenced (e.g., via stored data in the search DB), an attacker could supply a BinaryFormatter gadget payload, leading to code execution when the cache is rebuilt.
- Input control is not proven from available code.

**Patched behavior (v2)**
- Introduces `ExplicitReferenceSerializationBinder<Dictionary<string,string>>`, constraining deserialization to the expected dictionary type.

**Bypass/Completeness**
- Only this mapping cache path is bounded. Other BinaryFormatter uses in Search may remain unbounded.
- Because input control is not evidenced, treat as speculative.

**Confidence:** Low/Uncertain. Addition is clearly defensive, but exploitability cannot be established from available code.

---

## Coverage of security-relevant changes

- `NoneVersionSpecificSerializationBinder` + `TypeProcessor` (mapped to RCE fix above).
- `SPRequestModule` ToolPane signout handling (mapped to auth bypass hypothesis).
- `UrlMappingCache` binder addition (mapped to speculative RCE via BinaryFormatter).
- Numerous framework/crypto/HMAC/X509 changes and added URL mapping constants — security relevance unclear for the targeted CVEs.  
- `16/TEMPLATE/LAYOUTS/web.config` removal of `<customErrors mode="Off" />` (info-disclosure hardening) — not mapped to CVEs; likely general hardening.

Unmapped but possibly security-related:
- Framework crypto/HMAC/X509 updates (mscorlib* files) — unknown if security-motivated.
- Added `UrlMappingConstants.cs` — mechanical addition; no direct security impact seen.

---

## Verification conclusions

- Unsafe type resolution in Ssdqs binder (CVE-2025-49701 candidate): **Confirmed (Medium confidence)** — clear code change from unrestricted `Type.GetType` to allow/deny model; RCE risk via BinaryFormatter if attacker controls serialized bytes.
- ToolPane signout-path handling (CVE-2025-49706 hypothesis): **Uncertain (Low confidence)** — patch implies a bypass fix, but exploit path not fully proven from available code.
- URL mapping BinaryFormatter deserialization (RCE hypothesis, CVE-2025-49704-related): **Uncertain (Low confidence)** — binder addition suggests prior unsafe deserialization; attacker control of input not demonstrated.

## Bypass validation summary

- Ssdqs binder RCE: Only the previously unbounded type resolution path validated; other BinaryFormatter sites may remain. **Only validated one path; others may exist.** Feasibility: Medium (requires control of serialized bytes).
- ToolPane auth: **Only one path examined (ToolPane.aspx + signout)**; other design-time endpoints could exist. Feasibility: Unclear without full module semantics.
- URL mapping deserialization: **Speculative**; feasibility Low until input control is shown.

## Final stance

- CVE-2025-49701: strong candidate in Ssdqs binder/type restrictions — confirmed as addressed in patch.
- CVE-2025-49706: not conclusively proven; patch suggests intent, but evidence insufficient.
- CVE-2025-49704: deserialization binders added in Search components; without showing attacker-controlled inputs, classification remains uncertain.
