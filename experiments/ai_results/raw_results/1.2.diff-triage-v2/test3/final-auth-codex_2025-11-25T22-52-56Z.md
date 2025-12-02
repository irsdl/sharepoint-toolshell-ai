# Final Verification Results

## Vulnerability 1: ProofTokenSignIn redirect fragment acceptance (CVE-2025-49706)
- **Diff hunk (evidence)** — `diff_reports/v1-to-v2.server-side.patch` lines ~53863:
  ```
  -         result = IsAllowedRedirectUrl(RedirectUri);
  +         result = IsAllowedRedirectUrl(RedirectUri);
  +         if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
  +         {
  +             ULS.SendTraceTag(505250142u, (ULSCatBase)(object)ULSCat.msoulscat_WSS_ApplicationAuthentication, (ULSTraceLevel)10, "[ProofTokenSignInPage] Hash parameter is not allowed.");
  +             result = false;
  +         }
  ```
- **V1 behavior (vulnerable path)** — `snapshots_decompiled/v1/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:315-322`: `ShouldRedirectWithProofToken` returned `IsAllowedRedirectUrl(RedirectUri)` with no fragment check. `RedirectUri` is populated directly from the user-supplied `redirect_uri` query param (via `SPRequestParameterUtility.GetValue`), then used in `OnLogOnRequestToAppWeb` to mint proof/identity tokens and auto-post them to the provided URI. Missing validation of the fragment portion lets an attacker supply `https://tenant/_layouts/15/appredirect.aspx#target=https://attacker/collect` so the server issues tokens, and the client-side hash gets forwarded to attacker-controlled code—token exfiltration (auth bypass/spoofing). Preconditions: none (AllowAnonymousAccess true), only needs a crafted `redirect_uri` containing `#...`. Exploit is feasible: SharePoint app redirect flows respect client-side fragments and the server does not strip them in v1.
- **Bypass routes / completeness**
  - Route 1: Hash-fragment pivot on ProofTokenSignIn redirect (validated).
  - Route 2: Admin/debug kill-switch `SPFarm.Local.ServerDebugFlags.Contains(53020)` can disable the fragment block in v2; if enabled in prod, the bypass reopens.
  - Other endpoints using `IsAllowedRedirectUrl` may still accept fragments (not changed here), but this page is the token issuer; primary route validated.
- **V2 behavior (mitigation)** — `snapshots_decompiled/v2/...ProofTokenSignInPage.cs:317-329`: rejects any non-empty `RedirectUri.Fragment` unless debug flag 53020 is set, returning `false` so the redirect flow does not run and tokens aren’t minted. This directly blocks the hash exfiltration route. Residual gaps: if the kill switch is set, the bypass remains; other redirect validators unchanged may still allow fragment abuse elsewhere.
- **Confidence:** High (direct code path from untrusted input to token issuance; fragment check added precisely in the vulnerable method).

## Vulnerability 2: Signout-driven anonymous ToolPane access (CVE-2025-49706)
- **Diff hunk (evidence)** — `diff_reports/v1-to-v2.server-side.patch` lines ~66318 (and duplicate in second assembly):
  ```
  +         if (flag9 && flag8 && flag10)
  +         {
  +             flag6 = true;
  +             flag7 = false;
  +             ULS.SendTraceTag(505264341u, ULSCat.msoulscat_WSS_ClaimsAuthentication, ULSTraceLevel.High, "[SPRequestModule.PostAuthenticateRequestHandler]Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected. request path: '{0}'.", context.Request.Path);
  +         }
  ```
- **V1 behavior (vulnerable path)** — `snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs:2708-2727`: when `flag6` (check auth cookies) was true, requests with referrers or paths matching signout/start pages (including `_layouts/SignOut.aspx`) set `flag6=false`/`flag7=true`, treating them as anonymous-safe and skipping auth enforcement. No exception for `_layouts/ToolPane.aspx`, so an unauthenticated request to ToolPane with `Referer: /_layouts/SignOut.aspx` bypassed auth and reached a layout page that can surface edit UI/actions—confidentiality/integrity impact.
- **Bypass routes / completeness**
  - Route 1: ToolPane.aspx + signout referrer (validated).
  - Route 2: Other `_layouts` pages still covered by the signout/start anonymous carve-out remain potentially bypassable; fix is scoped to ToolPane only. These are unvalidated but plausible.
- **V2 behavior (mitigation)** — `snapshots_decompiled/v2/...SPRequestModule.cs:2708-2735`: adds `flag9` (!ServerDebugFlags 53506) and `flag10` (path endswith ToolPane.aspx) to re-enable auth checks (`flag6=true`, `flag7=false`) and log. This blocks the ToolPane-specific bypass but leaves other signout-carved pages unchanged, so additional paths may remain.
- **Confidence:** High for ToolPane route (explicit code path and targeted fix). Medium for broader bypass risk (other pages not fixed).

## Bypass Validation Summary
- CVE-2025-49706 (auth bypass):
  - Confirmed 2 distinct bypass considerations: (1) redirect fragment pivot; (2) signout→ToolPane anonymous handling. A third risk is the 53020 kill switch re-opening bypass (config-dependent).
  - Feasibility: High for both confirmed routes (no auth required; relies on crafted request data).
  - Coverage: Fragment check only in ProofTokenSignIn; ToolPane guard is path-specific—other endpoints may still be exposed.
- CVE-2025-49704 (RCE):
  - No direct evidence in inspected server-side code; no dangerous type list identified. Unproven.
- CVE-2025-49701 (unknown, RCE-capable):
  - Candidates only (unproven): large BCL crypto/ASN parsing and packaging/compression changes; possible hardening against malicious certificates/packages. Confidence Low without deeper reverse-engineering.

## Coverage Check of Security-Relevant Changes
- Mapped to above vulns:
  - ProofToken fragment rejection hunk.
  - SPRequestModule ToolPane-specific auth enforcement hunk (both assemblies).
- Unmapped but security-relevant (possible CVE-2025-49701 or other fixes):
  - BCL crypto/ASN refactors (`System/Security/Cryptography/*`, AsnDecoder/Reader, PKCS#12 helpers): mechanical changes add bounds/validation logic; likely hardening against malformed certs/tokens (could be RCE/DoS). Unknown if security-motivated specifics.
  - Packaging/compression changes (`System/IO/Packaging/Package.cs`, `System/IO/Compression/ZLibNative.cs`, `CompoundFileDeflateTransform.cs`): improved buffer/stream handling; possible crafted ZIP/OPC exploit mitigation. Unknown if security-motivated.
  - Path/serialization safety tweaks (`System/IO/Path.cs`, `UnmanagedMemoryStream.cs`, `Formatters/Binary/ObjectWriter.cs`): likely hardening against path traversal or serialization abuse; purpose not explicit.
  - These unmapped changes may correspond to CVE-2025-49701/49704 or separate hardening; evidence insufficient to assert.

## Final Judgments
- ProofToken redirect fragment bypass: **Confirmed** (CVE-2025-49706); 2 bypass considerations logged (fragment pivot, kill-switch risk).
- Signout→ToolPane anonymous bypass: **Confirmed** (CVE-2025-49706); path-specific fix, other carve-out pages remain potential gaps (unvalidated).
- CVE-2025-49704 (RCE): **Uncertain/Unproven** — no clear SharePoint-layer fix observed in analyzed areas.
- CVE-2025-49701 (unknown RCE-capable): **Uncertain/Unproven** — only candidate hardening in BCL crypto/packaging; no direct exploit path established.

I have not comprehensively exhausted all alternative bypass routes beyond the validated ones; other signout-carved pages and redirect validators may still harbor bypasses. Bypass feasibility for the validated routes is high; additional routes remain to be tested. No dangerous element list validated for CVE-2025-49704.
