# Coverage Check Results

## Initial Findings (from first pass)
- **Auth bypass via signout referrer to ToolPane.aspx** – `SPRequestModule.PostAuthenticateRequestHandler` skipped auth when referrer matched signout/start, letting unauth reach `/_layouts/ToolPane.aspx`; v2 adds ToolPane-specific block/trace (e.g., `...ApplicationRuntime/SPRequestModule.cs:2729`).
- **Deserialization RCE chain (ToolShell) once ToolPane exposed** – Multiple search/analytics BinaryFormatter paths hardened with explicit binders/denylists, implying gadget injection via ToolPane forms (consistent with CVE-2025-49704/chain). 
- **Type allow/deny enforcement** – SafeSerialization denylist improvements signaling broader BinaryFormatter/NetDataContract mitigation; suspected link to RCE (possibly CVE-2025-49701/49704) even for authenticated users.

## New Findings (from coverage check)

### New Vulnerabilities / Security-Relevant Changes
- **ProcessingDocument deserialization binder** (Mapped to deserialization RCE): new `InheritIDictionaryBinder` enforced for BinaryFormatter deserializing `Document.Values` in content push (`diff_reports` chunk around `ProcessingDocument.Deserialize`; new file `Microsoft.Office.Server.Search.Analytics.ContentPushStore.InheritIDictionaryBinder`). Reduces gadget surface; v1 accepted arbitrary IDictionary types.
- **CTSDocument BinaryFormatter binder strengthening** (Mapped): `Microsoft.Office.Server.Search.Feeding.CTSDocument` now binds deserialization of variant property dictionary via `ExplicitReferenceSerializationBinder<Dictionary<string, VariantProperties>>`; previously generic BinaryFormatter (prevents gadget types in feed ingestion).
- **UrlMapping BinaryFormatter gate** (Unmapped candidate): New `Microsoft.Office.Server.Search.Query.UrlMapping.UrlMapping` class uses BinaryFormatter + GZip to (de)serialize URL maps with explicit binder `ExplicitReferenceSerializationBinder<Dictionary<string,string>>`. New surface; if v1 URL mapping used looser deserialization, could be RCE or corruption vector. Candidate for CVE-2025-49701.
- **TypeProcessor denylist/allowlist logic** (Unmapped candidate): New `Microsoft.Ssdqs.Infra.Utilities.TypeProcessor` enforces explicit allow/deny for deserialization type resolution (with disallowed types: DataSet, ObjectDataProvider, XamlReader, remoting formatters, etc.). Indicates a previously unsafe type loader—likely RCE defense, potential CVE-2025-49701 alignment.
- **SafeSerialization disallowed type expansion** (Mapped): `SafeSerialization` gains `DisallowedTypesForDeserialization` with extensive blocklist (BinaryFormatter, NetDataContractSerializer, XamlReader, DataSet, ClaimsIdentity, etc.) and `IsTypeExplicitlyDenied` path. Closes gadget vectors beyond ToolShell. 
- **UrlMappingConstants (new)**: ancillary to UrlMapping; not security by itself.

### Additional Bypass Routes (for already-found vulnerabilities)
- **Auth bypass**: Signout/start referrer exemption still applies to other `_layouts` endpoints; only ToolPane got a special-case denial. Potential bypass: target other admin pages with same referrer trick. Total bypass routes known: 2 (ToolPane blocked; other Layouts with signout referrer possibly still reachable pre-auth).
- **Deserialization**: Even with new binders, remaining allowed types/generics could host gadgets (e.g., Nullable/List/Dictionary permitted). Alternate payloads could reach other BinaryFormatter users (e.g., UrlMapping, other search ingestion code) not covered by new blocklists.

### CVE-2025-49701 Candidates
- **Strong candidates:**
  - `Microsoft.Ssdqs.Infra.Utilities.TypeProcessor` allow/deny enforcement for type loading (indicates previously arbitrary NetDataContract/BinaryFormatter lookup).
- **Possible candidates:**
  - `Microsoft.Office.Server.Search.Query.UrlMapping.UrlMapping` BinaryFormatter (new) with binder; potential prior arbitrary deserialization if URL mapping bytes user-controlled.

## Unmapped Security Changes
- UrlMapping BinaryFormatter binder addition: security intent clear; exact vuln surface uncertain without call graph.
- TypeProcessor denylist/allowlist: clearly defensive, but precise consuming feature not seen; likely RCE hardening.

## Total Coverage
- Files analyzed: ~7 security-relevant files (SPRequestModule, CTSDocument, ProcessingDocument/InheritIDictionaryBinder, SafeSerialization/TypeProcessor, UrlMapping, CookieAuthData context, stats scan).
- Security-relevant changes identified: 6
- Mapped to vulnerabilities: 3 (auth bypass -> CVE-2025-49706; CTSDocument/ContentPushStore/SafeSerialization -> CVE-2025-49704 or chain)
- Unmapped: 3 (TypeProcessor, UrlMapping, residual SafeSerialization scope)
- Additional bypass routes discovered: 1 (other _layouts pages still riding signout referrer logic)
- CVE-2025-49701 candidates identified: 2
