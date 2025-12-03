# Coverage Check Results

## Initial Findings (from first pass)
- **Auth bypass → ToolPane pre-auth reachability (CVE-2025-49706)**: `SPRequestModule.PostAuthenticateRequestHandler` (Microsoft.-52195226-3676d482 and -67953109-566b57ea) skipped auth when referrer/start/signout paths matched, letting unauthenticated POSTs hit `/_layouts/15/ToolPane.aspx`. Patch adds ToolPane path + kill-switch 53506 check to force AccessDenied and log ULS 505264341.
- **ToolPane WebPart import deserialization RCE (CVE-2025-49704; pre-auth when chained)**: `ToolPane.cs` pulls `MSOTlPn_DWP` markup and feeds `WebPartImporter`/`GetPartPreviewAndPropertiesFromMarkup` without digest when not a postback; DataForm/AggregateDataSource `DataSourcesString` losformatter/DataSet gadgets enable code execution. Pre-auth when combined with the bypass above; PR:L otherwise.
- **ProofToken redirect hardening (spoofing adjunct)**: `ProofTokenSignInPage.IsAllowedRedirectUrl` now rejects redirect URLs containing `#` unless debug flag 53020 set, blocking fragment-based token leak/redirect abuse.
- **BinaryFormatter type gate (candidate CVE-2025-49701)**: New `TypeProcessor` + allow/deny lists in `Microsoft.Ssdqs.Infra.Utilities` and binder enforcement in `NoneVersionSpecificSerializationBinder` prevent dangerous type resolution during BinaryFormatter deserialization.

## New Findings (from coverage check)

### New Vulnerabilities
- **BinaryFormatter de-serialization safer wrapper** (possible RCE fix): `Microsoft.-a453c131-bab0bdc4/Microsoft/Ssdqs/Core/Service/Export/ChunksExportSession.cs` replaces direct `BinaryFormatter.Deserialize` with `SerializationUtility.ConvertBytesToObject`. This removes a raw deserialization sink for Excel chunk export caches; likely part of the same RCE hardening (CVE-2025-49701 class).

### Additional Bypass Routes (for already-found vulnerabilities)
- **Auth bypass scope**: The signout/start referrer logic still disables auth checks for other endpoints; only ToolPane gets special casing. Alternative pages under `/_layouts/15/` (or other content) could still be reachable with crafted referrers. Kill-switch 53506 can re-open the ToolPane bypass entirely.
- **ToolPane payload variants**: Beyond `DataFormWebPart`, other importable parts with `DataSourcesString`/`Data` losformatter fields (e.g., `AggregateDataSource`, `DataViewWebPart`) remain usable. Multiple assemblies contain the same `SPRequestModule` logic, so both need the fix applied.
- Total new bypass considerations: 2 (referrer-based alternate endpoints; additional gadget families within ToolPane import).

### CVE-2025-49701 Candidates
- **Strong candidates (high confidence)**:
  - `Microsoft.Ssdqs.Infra.Utilities.TypeProcessor.cs` + `NoneVersionSpecificSerializationBinder.cs`: introduces explicit allowlist/denylist, disallowed generics, and controlled generic parsing for BinaryFormatter binding.
- **Possible candidates (medium confidence)**:
  - `Microsoft.Ssdqs.Core.Service.Export.ChunksExportSession.cs`: swap from `BinaryFormatter.Deserialize` to `SerializationUtility.ConvertBytesToObject`, eliminating a raw binary deserialization sink in export caching.

## Unmapped Security Changes
- None newly identified beyond the Ssdqs BinaryFormatter hardening; other touched files reviewed (SPRequestModule variable renames, cellstorage/cobalt flag renames, ToolPane/ProofToken minor ordering changes) appear cosmetic/non-security.

## Total Coverage
- Files analyzed: 5 (SPRequestModule in two assemblies, ToolPane.cs, ProofTokenSignInPage.cs, Ssdqs TypeProcessor/binder + ChunksExportSession).
- Security-relevant changes identified: 5.
- Mapped to vulnerabilities: 4 (auth bypass, ToolPane deserialization, ProofToken redirect, Ssdqs TypeProcessor class of fixes).
- Unmapped: 0 (post-analysis; Ssdqs changes mapped as CVE-2025-49701 candidates).
- Additional bypass routes discovered: 2.
- CVE-2025-49701 candidates identified: 2 (one strong, one possible).
