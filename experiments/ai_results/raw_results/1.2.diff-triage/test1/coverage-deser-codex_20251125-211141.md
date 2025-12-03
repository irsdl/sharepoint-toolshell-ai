# Coverage Check Results

## Initial Findings (from first pass)
- RCE via unsafe BinaryFormatter deserialization in Microsoft.Ssdqs (Data Quality Services) binder (`NoneVersionSpecificSerializationBinder`), fixed by new `TypeProcessor` allow/deny lists and `BlockedTypeException`; affects many Ssdqs callers that deserialize DB/user-provided blobs (Conversion helpers in `SerializationUtility`, SQLCLR stored procs, proxy clients). Bypass risk: any Ssdqs type remains implicitly allowed.
- Existing BinaryFormatter usage in Search components (CookieAuthData, UrlMapping, CTSDocument) already used validating binders; minor namespace qualification changes observed. No new behavior change noted there.

## New Findings (from coverage check)

### New Vulnerabilities
- None newly confirmed beyond initial Ssdqs deserialization issue.

### Additional Bypass Routes (for already-found vulnerabilities)
- Vulnerability: Ssdqs BinaryFormatter deserialization (CWE-94 / RCE)
  - New bypass thoughts: Because `TypeProcessor` auto-allows all `Microsoft.Ssdqs.*` types, any gadget inside that assembly remains a potential payload path. Attackers could search for dangerous serialization callbacks within Ssdqs types to bypass the new denylist. Total bypass routes now known: 2 (framework gadget path blocked by denylist; Ssdqs-internal gadget path possibly still open).

### CVE-2025-49701 Candidates
- Possible: Ssdqs binder hardening could also map to CVE-2025-49701 (authorization-angled RCE), since no other substantive security changes were found; same code path fits RCE with PR:L.
- Possible: SafeControl additions for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` marked `Safe="False"` (multiple web.configs) could represent an RCE/sandboxing fix for a web part control; medium confidence.

## Unmapped Security Changes
- SafeControl additions in `cloudweb.config`, `web.config`, and virtual directory web.configs (`.../80/web.config`, `.../20072/web.config`): added two entries for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` (versions 15.0.0.0 and 16.0.0.0) with `Safe="False"`. This appears security-motivated (explicitly marking the control unsafe), but the exact vulnerability type is unclear—could mitigate arbitrary control activation, XSS, or RCE via unsafe control loading.
- IIS `applicationHost.config` change adjusts app pool password and recycle schedule; likely operational, not security-significant (not mapped).

## Total Coverage
- Files analyzed: 6 primary security-relevant areas (Ssdqs binder files; Search binder callsites; SafeControl web.configs; IIS config; ContentPush serializer/binder; CTSDocument feeding deserialization).
- Security-relevant changes identified: 3 (Ssdqs binder overhaul; Search CookieAuth/Feeding/UrlMapping binder qualification; SafeControl additions for ExcelDataSet).
- Mapped to vulnerabilities: 1 (Ssdqs deserialization hardening → CVE-2025-49704, possibly CVE-2025-49701).
- Unmapped: 2 (SafeControl ExcelDataSet entries; minor binder namespace qualification—no behavior change).
- Additional bypass routes discovered: 1 (Ssdqs-internal gadget allowance via assembly-wide allowlist).
- CVE-2025-49701 candidates identified: 2 (Ssdqs binder hardening; ExcelDataSet SafeControl restrictions).
