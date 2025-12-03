# Final Verification Results

## Vulnerability 1: Authentication bypass allowing pre-auth ToolPane access (CVE-2025-49706)

**Diff evidence (patched):** `diff_reports/v1-to-v2.server-side.patch` → `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs`, method `PostAuthenticateRequestHandler`:
```
- if (... || (uri != null && (SPUtility.StsCompareStrings(uri.AbsolutePath, signoutPathRoot) ...)))
+ bool flag8 = uri != null && (...signoutPath...);
+ if (... || flag8)
  {
    flag6 = false; flag7 = true;
+   bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
+   bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
+   if (flag9 && flag8 && flag10)
+   {
+     flag6 = true; flag7 = false;
+     ULS.SendTraceTag(..., "[SPRequestModule.PostAuthenticateRequestHandler]Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected...", context.Request.Path);
+   }
  }
```

**V1 vulnerable behavior:** same method lacked the `flag10` block. Untrusted HTTP requests whose Referrer matched `SignOut.aspx` (or start paths) set `flag6=false`/`flag7=true`, skipping auth and avoiding Access Denied even when `context.User.Identity.IsAuthenticated` was false. ToolPane path `/ _layouts/15/ToolPane.aspx` therefore ran unauthenticated because the code never re-enabled the check.
- Input: attacker supplies request path `/ _layouts/15/ToolPane.aspx` with `Referer` = `/ _layouts/15/SignOut.aspx`.
- Flow: referrer triggers the signout condition ⇒ `flag6=false` (no cookie check) and `flag7=true` (anonymous allowed) ⇒ request proceeds unauthenticated.
- Missing check: no path-based exclusion for ToolPane in v1.
- Outcome: unauthenticated user reaches ToolPane page lifecycle, enabling further exploitation (see Vuln 2).

**Bypass routes validated:**
- Route A (primary): `/ _layouts/15/ToolPane.aspx` with referrer to any signout variant (`signoutPathRoot/Previous/Current`).
- Route B (kill-switch): even on v2, toggling `ServerDebugFlags` 53506 would disable the new block, restoring route A. Other endpoints still enjoy the signout/start exemption (no ToolPane-specific fix) but were not shown to lead to RCE in this patch.
Feasibility: High (simple crafted HTTP request; no auth needed in v1; relies on public endpoints). Preconditions: none beyond anonymous network access.

**Patched behavior:** v2 detects ToolPane paths when signout referrer is present and, unless debug flag set, resets `flag6=true`/`flag7=false` and logs, forcing AccessDenied for unauthenticated users. Blocks route A when kill-switch is off. Other signout/start exemptions remain; only ToolPane is covered.

**Confidence:** High (explicit diff plus v1/v2 logic comparison).

## Vulnerability 2: ToolPane WebPart import deserialization leading to RCE (CVE-2025-49704; pre-auth when chained with Vuln 1)

**Code evidence (v1):** `snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/ToolPane.cs`
- `SelectedAspWebPart` getter (~lines 520-560) in custom toolpane mode pulls untrusted form params:
  - `frontPageUri = new Uri(SPRequestParameterUtility.GetValue<string>(Page.Request, "MSOTlPn_Uri", ...))`
  - `MSOTlPn_DWP` passed to `GetPartPreviewAndPropertiesFromMarkup(..., SPRequestParameterUtility.GetValue<string>(Page.Request, "MSOTlPn_DWP", ...), ... , ref frontPageWebPart, ...)`
- `GetPartPreviewAndPropertiesFromMarkup` (~712-840) creates `XmlReader` over attacker markup and calls `WebPartImporter.Import(...)`, producing a WebPart instance whose properties (e.g., `DataSourcesString`) are deserialized using LosFormatter/BinaryFormatter gadget chains (e.g., `DataFormWebPart`, `AggregateDataSource`, `DataViewWebPart`). No form-digest verification occurs when the request is not treated as a postback.

**Vulnerable behavior:**
- Input: attacker-provided web part markup in `MSOTlPn_DWP` including losformatter payload in a property like `DataSourcesString`.
- Flow: ToolPane page in custom mode reads the params, imports the WebPart, and executes deserialization of the provided data during import/property handling.
- Missing check: no authentication (due to Vuln 1) and no form digest or payload validation before import; dangerous types allowed.
- Outcome: code execution in the SharePoint app pool via standard DataSet/ObjectDataProvider gadgets (or similar LosFormatter gadgets).

**Bypass routes validated:**
- Payload surfaces: any WebPart with losformatter-backed properties accepted by `WebPartImporter` (e.g., `DataFormWebPart`, `AggregateDataSource`, `DataViewWebPart`). Multiple assemblies share `SPRequestModule`, so both sites are exposed in v1.
- Alternate endpoints: only ToolPane import flow is evidenced here; other pages not shown to import WebParts from request in this patch set.
Feasibility: High once ToolPane is reachable; requires crafting known SharePoint losformatter gadget payloads.

**Patched behavior:** No functional change within ToolPane; the mitigation is gating access via Vuln 1 fix. v2 blocks unauthenticated access to ToolPane (unless kill-switch set). Authenticated site owners (PR:L) can still submit payloads; RCE surface remains for authenticated attackers.

**Confidence:** High for the combined pre-auth RCE chain; medium for post-auth RCE persistence (no direct patch to deserialization itself).

## Vulnerability 3: Proof token redirect fragment rejection (spoofing hardening)

**Diff evidence:** `diff_reports/v1-to-v2.server-side.patch` → `Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs`, method `IsAllowedRedirectUrl`:
```
+ if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020))
+     && !string.IsNullOrEmpty(RedirectUri.Fragment))
+ {
+   ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
+   result = false;
+ }
```

**V1 behavior:** `IsAllowedRedirectUrl` only checked allowlist logic; fragment (`#...`) was not rejected. An attacker controlling `wreply`/redirect could stash tokens or state in the fragment for spoofing/leakage.
- Input: redirect URL with fragment.
- Flow: passes allowlist; redirect proceeds with fragment preserved.
- Outcome: potential token spoofing/leak via fragment-based redirection.

**Patched behavior:** v2 rejects redirects containing fragments unless debug flag 53020 is set, logging the event. Blocks fragment-based misuse; other redirect vectors unaffected.

**Confidence:** Medium (security intent clear; impact limited to fragment misuse).

## Vulnerability 4: BinaryFormatter type resolution hardening (candidate CVE-2025-49701)

**Diff evidence:** New file `Microsoft/Ssdqs/Infra/Utilities/TypeProcessor.cs` and binder changes in `NoneVersionSpecificSerializationBinder.cs`:
```
+ public static HashSet<string> DisallowedTypesForDeserialization { get; } = BuildDisallowedTypesForDeserialization();
+ public static HashSet<string> DisallowedGenericsForDeserialization { get; } = BuildDisallowedGenerics();
... LoadType(...) now enforces IsTypeExplicitlyDenied/Allowed and throws BlockedTypeException when not allowed.
```
And `ChunksExportSession.cs`:
```
- BinaryFormatter binaryFormatter = new BinaryFormatter(); ... return binaryFormatter.Deserialize(memoryStream);
+ return SerializationUtility.ConvertBytesToObject(arrBytes);
```

**V1 vulnerable behavior:**
- Binder (`NoneVersionSpecificSerializationBinder`) resolved arbitrary types via `Type.GetType(typeName + ", " + assemblyName)` without deny/allow checks.
- `ChunksExportSession.ByteArrayToObject` directly deserialized attacker-influenced bytes with `BinaryFormatter.Deserialize`.
- Inputs: any binary payload accepted by Ssdqs components that use the binder or chunk export cache.
- Missing checks: no type allowlist/denylist; generic types unguarded; raw BinaryFormatter sink in export.
- Outcome: potential RCE via standard .NET gadget types (DataSet, XamlReader, etc.).

**Patched behavior:**
- TypeProcessor enforces explicit allowlist/denylist (includes dangerous types such as `System.Data.DataSet`, `System.Windows.Markup.XamlReader`, ClaimsIdentity, BinaryFormatter itself) and blocks disallowed generics.
- Binder now calls `TypeProcessor` and throws if not allowed.
- Export helper uses a sanitized conversion utility instead of raw BinaryFormatter.

**Confidence:** Medium (clear hardening; exact exploitation path in Ssdqs not fully mapped from provided code, but changes are RCE-preventive).

## Coverage Scan for Other Security-Relevant Changes
- Reviewed `diff_reports/v1-to-v2.server-side.stat.txt` for large functional diffs. Security-significant changes align with the four items above. Other modifications (variable renames, attribute order changes, cosmetic metadata) do not alter security behavior based on provided code.
- No additional unmapped security fixes were evident beyond Ssdqs hardening and ProofToken/ToolPane changes.
- Unmapped security changes: none identified; if present, purpose is **unknown if security-motivated**.

## Confirmation Status
- Auth bypass → ToolPane: **Confirmed** (high confidence; direct logic change).
- ToolPane import deserialization RCE: **Confirmed (pre-auth chain)**; post-auth RCE surface remains (no direct fix), so exploitation by authenticated users persists.
- ProofToken fragment rejection: **Confirmed** (medium confidence impact).
- Ssdqs BinaryFormatter hardening (CVE-2025-49701 candidate): **Confirmed as security hardening**, exact vulnerability details **Uncertain** (medium confidence).

## Bypass Validation Summary
- CVE-2025-49706 (auth bypass): **Confirmed 1 distinct path** (ToolPane with signout referrer); fix gated by kill-switch 53506. Other signout/start exemptions remain but no evidence of RCE there in this patch.
  - Feasibility: High in v1; mitigated in v2 unless kill-switch set.
- CVE-2025-49704 (deserialization via ToolPane import): **Validated primary payload surface** (WebPartImporter with losformatter-backed parts such as DataForm/AggregateDataSource/DataView). Additional gadgets may exist; not exhaustively enumerated.
  - Feasibility: High when ToolPane reachable; remains for authenticated users in v2.
- CVE-2025-49701 candidates: TypeProcessor/binder/ChunksExportSession hardening.
  - Feasibility pre-patch: Medium/High in principle (BinaryFormatter gadgets); exact ingress points in Ssdqs not fully shown.

**Coverage statement:** Auth bypass and ToolPane chain are comprehensively evidenced for the primary path. Deserialization gadget variety was not exhaustively cataloged; only representative losformatter paths were validated. Ssdqs RCE hardening is acknowledged with medium confidence due to limited contextual code.
