# Coverage Check Results

## Initial Findings (from first pass)
- CVE-2025-49706 (auth bypass/spoofing):
  - `Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs`: `ShouldRedirectWithProofToken` now blocks any `redirect_uri` containing a fragment unless kill switch 53020 is set; prevents proof-token redirects that leak tokens via hash-based forwarding.
  - `Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs` (and mirrored assembly): PostAuthenticateRequest now re-enforces auth when the referrer is signout and target ends with `ToolPane.aspx`, unless kill switch 53506; closes signout→ToolPane anonymous access.
  - Bypass routes recorded: (1) fragment-bearing redirect URIs that forward tokens client-side; (2) signout/start flows pointing to `ToolPane.aspx` letting anonymous users reach the web part tool pane.
- RCE advisories (CVE-2025-49701/49704): Not mapped in first pass; no clear code-level hardening identified.

## New Findings (from coverage check)

### New Vulnerabilities
- Anonymous access removal for `_forms` path:
  - File: `diff_reports/.../applicationHost.config` (IIS config for SharePoint web app)
  - Change: Removed `<location path="SharePoint - 80/_forms">` block that explicitly enabled `anonymousAuthentication` with Execute/Script handlers and long client cache.
  - Hypothesis: Previously, `_forms` pages were executable anonymously across the farm, potentially allowing unauthenticated access to forms endpoints (login-related pages, custom form handlers). Removal forces normal authentication pipeline. Likely an auth-bypass/surface-hardening fix that complements CVE-2025-49706 but via configuration.
  - Status: UNMAPPED (not tied to CSAF IDs yet).

### Additional Bypass Routes (for already-found vulnerabilities)
- Vulnerability: CVE-2025-49706 auth bypass
  - New bypass consideration: `_forms` anonymous enablement could have provided an alternate unauthenticated entry to form handlers beyond `ToolPane.aspx` and proof-token redirects. With the location override removed, default auth applies. Total distinct bypass routes considered: 3 (hash redirect, signout→ToolPane, anonymous `_forms`).

### CVE-2025-49701 Candidates
- Possible candidates (medium confidence):
  - BCS/BDC service contract churn (`Microsoft.-52195226-3676d482/Microsoft/SharePoint/BusinessData/SharedService/IBdcServiceApplication.cs`, related parser/model files) shows reordered FaultContracts and client exception constraints but no functional guard changes visible; could relate to tightening XML/package handling for Site Owners (potential RCE vector) yet not clearly enforced here.
  - `IBecWebService.cs` FaultContract reshuffle adds more specific directory/identity faults to `ReadApplicationPasswords` and `DeleteApplicationPassword`; may signal hardened error handling to stop unintended execution paths. No direct RCE sink observed.
  - mscorlib cryptography updates (new CNG HMAC/ASN readers) across `mscorlib-*` assemblies could be servicing a crypto misuse issue leveraged for code execution; mapping uncertain.
- Strong candidates: None identified with high confidence.

## Unmapped Security Changes
- Removal of anonymous `_forms` location (IIS config) – likely auth hardening but CVE mapping unclear.
- WCF FaultContract additions/reordering in `IBdcServiceApplication.cs` and `IBecWebService.cs` – security intent unclear; could be robustness against malformed inputs or privilege misuse but no logic change evident.
- Extensive crypto code updates in `mscorlib-*` (HMAC/SHA managed classes, ASN parser) – likely platform hardening; exploit class uncertain from provided context.

## Total Coverage
- Files analyzed: ~8 focal files/areas (ProofTokenSignInPage.cs, SPRequestModule.cs in two assemblies, applicationHost.config/web.config blocks, IBecWebService.cs, IBdcServiceApplication.cs, BDC parser/model snippets, mscorlib crypto updates).
- Security-relevant changes identified: 5
- Mapped to vulnerabilities: 2 (CVE-2025-49706 routes)
- Unmapped: 3
- Additional bypass routes discovered: 1 (anonymous `_forms` access removal)
- CVE-2025-49701 candidates identified: 3 (medium/low confidence, none strong)
