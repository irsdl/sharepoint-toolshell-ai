# Coverage Check Results

## Initial Findings (from first pass)
- RCE via unsafe BinaryFormatter in Ssdqs `NoneVersionSpecificSerializationBinder` (now guarded by `TypeProcessor` allow/deny list). Exploit: craft BinaryFormatter payload (DataSet/ExpandedWrapper+ObjectDataProvider, LosFormatter/ObjectStateFormatter, XamlReader, Workflow ActivitySurrogateSelector, JavaScriptSerializer, ClaimsIdentity, etc.) delivered to Ssdqs SQLCLR/Proxy entry points. Patched with allow/deny and `BlockedTypeException`.
- Auth bypass to `/_layouts/15/ToolPane.aspx` via signout-referrer path in `SPRequestModule` (flag6 skip). Patch re-enables auth when path ends with `ToolPane.aspx` under signout referrer; logs “Risky bypass limited…” (CVE-2025-49706).
- Additional BinaryFormatter surface in search analytics ContentPush (`DbSerializer`/`InheritIDictionaryBinder`) now whitelists IDictionary types; pre-patch arbitrary IDictionary deserialization could yield RCE (candidate CVE-2025-49701).
- Dangerous type inventory (deny list) blocks classic gadget families; suspected v1 allowed all.

## New Findings (from coverage check)

### New Vulnerabilities
- **PowerShell command injection in Diagnostics ManagedHost** (`Microsoft.-aee71ebd-5bd2a0ca/Microsoft/Windows/Diagnosis/ManagedHost.cs`):
  - Added regex `s_ParameterValueRegex` to reject params containing `iex/icm/&/[system.`/quotes).
  - Added PowerShell proxy loader overriding `Invoke-Expression`/`Invoke-Command` with caller validation and escaping.
  - Previously concatenated untrusted parameters into PS command → RCE via crafted diagnostic parameters. Strong candidate for unknown RCE (CVE-2025-49701).

### Additional Bypass Routes (for already-found vulnerabilities)
- **BinaryFormatter RCE**: `CookieAuthData` deserialization now uses `ExplicitReferenceSerializationBinder<Cookie>`; v1 deserialized Base64 cookies with raw BinaryFormatter → another gadget ingress.
- **BinaryFormatter RCE**: Deny list explicitly adds SortedDictionary/SortedSet generic blocks, covering comparer gadget chains.
- **BinaryFormatter RCE**: ContentPush IDictionary binder restricts types; confirms alternative gadget delivery via `IDictionary<string, object>` in search ingestion.

### CVE-2025-49701 Candidates
- **Strong**: ManagedHost PowerShell parameter injection fix; ContentPush IDictionary binder hardening (if treated separately).
- **Possible**: CookieAuthData BinaryFormatter binder; other BinaryFormatter allow/deny additions in crawl/federated search auth data.

## Unmapped Security Changes
- applicationHost/web.config identity/password updates and AssemblyFileVersion bumps — likely environmental.
- Redirect fragment check in auth code (rejects fragment unless farm debug flag) — potential open-redirect/phishing hardening, unclear.
- CrawlRule authentication type validation tightening — likely robustness; vuln type uncertain.

## Total Coverage
- Files analyzed: 6 key security-touching files.
- Security-relevant changes identified: 6
- Mapped to vulnerabilities: 4
- Unmapped: 2 (minor auth/debug tweaks remain uncertain)
- Additional bypass routes discovered: 3
- CVE-2025-49701 candidates identified: 2
