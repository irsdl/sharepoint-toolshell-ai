# Coverage Check Results

## Initial Findings (from first pass)
- **ToolPane auth bypass (CVE-2025-49706):** `SPRequestModule.PostAuthenticateRequestHandler` now blocks signout-path requests ending in `ToolPane.aspx`, removing the legacy anonymous window used in the “ToolShell” chain (snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs:2720).
- **Search deserialization RCE (CVE-2025-49704):** Multiple BinaryFormatter sinks now use validating binders:
  - `CookieAuthData` Base64 cookies → `ExplicitReferenceSerializationBinder<Cookie>` (…/Search/Administration/CookieAuthData.cs).
  - `ContentPushStore.DbSerializer` dictionary payloads → `InheritIDictionaryBinder` (…/Search/Analytics/ContentPushStore/DbSerializer.cs; InheritIDictionaryBinder.cs).
  - URL mapping cache → `ExplicitReferenceSerializationBinder<Dictionary<string,string>>` (…/Search/Query/UrlMapping/UrlMappingCache.cs).
- **Type resolution RCE (CVE-2025-49701 candidate, bonus):** `NoneVersionSpecificSerializationBinder` now defers to `TypeProcessor` allow/deny lists (…/Ssdqs/Infra/Utilities/TypeProcessor.cs), explicitly banning classic gadgets (DataSet, ObjectDataProvider, ResourceDictionary, XamlReader, BinaryFormatter/SoapFormatter, ClaimsIdentity/Principal, Hashtable, ResourceSet/ResX, JavaScriptSerializer, ObjectStateFormatter, etc.).

## New Findings (from coverage check)

### New Vulnerabilities
- **Info-leak hardening in LAYOUTS web.config:** `customErrors mode="Off"` removed from `.../16/TEMPLATE/LAYOUTS/web.config`; `compilation debug` remains `false`. This reduces error detail exposure for all LAYOUTS pages (confidentiality). **Mapped?** Unmapped to earlier findings; likely general hardening.
- **Additional BinaryFormatter gate in search URL mapping** (already noted) confirmed as covering both forward and reverse mapping reconstruction (…/Search/Query/UrlMapping/UrlMappingCache.cs). No new vuln type, but broadens RCE surface previously unmentioned (mapping cache load path).

### Additional Bypass Routes (for already-found vulnerabilities)
- **Search deserialization RCE:** Beyond cookies, content push, and URL mapping, the binder additions imply any BinaryFormatter paths without `SafeSerialization` remain potential bypasses. Stat file shows other BinaryFormatter usages untouched (e.g., analytics/document processing). Potential bypass: locate remaining BinaryFormatter calls lacking binders and feed crafted gadgets (DataSet/XamlReader) via other search ingestion inputs (not patched in this diff).
- **ToolPane auth bypass:** Only `ToolPane.aspx` is explicitly checked. Other design-time pages (`*_ToolPane.aspx` variations or custom toolpane endpoints) are not guarded here. Potential alternative bypass: similar signout-path trick against other LAYOUTS endpoints that invoke deserialization (requires further hunting).

### CVE-2025-49701 Candidates
- **Strong candidates**
  - `TypeProcessor` + updated `NoneVersionSpecificSerializationBinder` (…/Ssdqs/Infra/Utilities): Newly enforced allow/deny lists for BinaryFormatter targets, explicitly blocking high-risk gadget types. Prior behavior accepted arbitrary `Type.GetType` resolution → RCE-capable.
- **Possible candidates**
  - Unbindered BinaryFormatter sites in Search/Analytics hinted by stat output (other BinaryFormatter occurrences unchanged). If any accept attacker-controlled data, they could represent residual CVE-2025-49701 paths.
  - Removal of `customErrors Off` could be tied to an input-validation flaw where verbose errors aided exploitation; speculative and low confidence.

## Unmapped Security Changes
- `.../16/TEMPLATE/LAYOUTS/web.config`: removal of `<customErrors mode="Off" />` (info disclosure hardening). Vulnerability class uncertain; likely defensive.
- Large assemblies (mscorlib*, cryptography updates) show SHA/HMAC reworks; appear non-SharePoint specific. No clear mapping to the targeted CVEs; security motivation possible but uncertain.

## Total Coverage
- Files analyzed: Targeted security-relevant sections (auth pipeline, LAYOUTS config, Search BinaryFormatter sites, Ssdqs binder). Full hunk-by-hunk review infeasible due to 6k+ files; focused on all BinaryFormatter, auth, and config changes surfaced by stat/rg.
- Security-relevant changes identified: 7 (auth guard, three Search binder sites, TypeProcessor/binder, web.config hardening, potential residual BinaryFormatter sites).
- Mapped to vulnerabilities: 4 (CVE-2025-49706, CVE-2025-49704 ×3 sinks, CVE-2025-49701 candidate via TypeProcessor/binder).
- Unmapped: 2 (web.config hardening; broad framework crypto edits).
- Additional bypass routes discovered: 2 (other unguarded BinaryFormatter sinks; ToolPane-specific guard not applied to other design-time endpoints).
- CVE-2025-49701 candidates identified: 1 strong, 2 possible.
