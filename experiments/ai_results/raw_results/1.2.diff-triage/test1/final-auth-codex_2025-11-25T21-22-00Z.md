# Final Verification (evidence-based)

## CVE-2025-49706 – Authentication Bypass

### Evidence: Patch hunks
- File: `diff_reports/v1-to-v2.server-side.patch` → `Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs`
  - Hunk: `@@ -318,6 +320,11 @@ public class ProofTokenSignInPage : FormsSignInPage`
  - Patch snippet:
    ```diff
    -		if (null != RedirectUri)
    -		{
    -			result = IsAllowedRedirectUrl(RedirectUri);
    +		if (null != RedirectUri)
    +		{
    +			result = IsAllowedRedirectUrl(RedirectUri);
    +			if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
    +			{
    +				ULS.SendTraceTag(...,"[ProofTokenSignInPage] Hash parameter is not allowed.");
    +				result = false;
    +			}
    		}
    ```
- File: `diff_reports/v1-to-v2.server-side.patch` → `Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs`
  - Hunk: `@@ -2720,10 +2720,19 @@ public sealed class SPRequestModule : IHttpModule`
  - Patch snippet:
    ```diff
    -			if (... || (uri != null && (... signoutPath... )))
    -			{
    -				flag6 = false;
    -				flag7 = true;
    -			}
    +			bool flag8 = uri != null && (... signoutPath...);
    +			if (... || flag8)
    +			{
    +				flag6 = false;
    +				flag7 = true;
    +				bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
    +				bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
    +				if (flag9 && flag8 && flag10)
    +				{
    +					flag6 = true;
    +					flag7 = false;
    +					ULS.SendTraceTag(..., "Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected. request path: '{0}'.", context.Request.Path);
    +				}
    +			}
    ```
- Config: `diff_reports/v1-to-v2.server-side.patch` → `applicationHost.config` (IIS) near end
  - Patch snippet removing anonymous access override:
    ```diff
    -  <location path="SharePoint - 80/_forms">
    -    <system.webServer>
    -      <handlers accessPolicy="Read, Execute, Script" />
    -      <security>
    -        <authentication>
    -          <anonymousAuthentication enabled="true" />
    -        </authentication>
    -      </security>
    -      <staticContent>
    -        <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="365.00:00:00" />
    -      </staticContent>
    -    </system.webServer>
    -  </location>
    ```

### Vulnerable behavior in v1
- Proof token redirect (v1 code: `snapshots_decompiled/v1/.../ProofTokenSignInPage.cs` lines ~300–335): `ShouldRedirectWithProofToken` simply calls `IsAllowedRedirectUrl(RedirectUri)` and returns `true` for any same-subscription absolute URI, regardless of fragment. Untrusted input: query `redirect_uri` from HTTP request; `TryResolveRedirectUriUsingFlags` can decode Base64 and make it absolute. No checks for `RedirectUri.Fragment`. Outcome: proof/identity tokens are generated and posted to the `redirect_uri` (FormActionValue). An attacker controlling `redirect_uri` with a `#fragment` can send tokens to a page that forwards `location.hash` elsewhere, enabling token theft/spoofing without authentication (consistent with AV:N/PR:N/UI:N, C/I impact).
- Signout→ToolPane (v1 code: `snapshots_decompiled/v1/.../SPRequestModule.cs` lines ~2700–2735): when referrer URL matches signout paths or the current path starts with signout/start paths, code sets `flag6=false` and `flag7=true`, skipping auth enforcement for subsequent checks. No special case for ToolPane. Untrusted input: crafted signout URL with `Source=/.../ToolPane.aspx`; referrer check marks the request as signout-flow and bypasses auth, letting anonymous user reach ToolPane page (web part editing surface) with AccessDenied suppressed.
- `_forms` anonymous override (v1 config): Explicit `<location path=".../_forms">` enabled anonymous authentication with Execute/Script handlers, allowing unauthenticated execution of forms pages under `/ _forms`. This broad bypass of IIS auth could expose forms-handling endpoints to anonymous users.

### Attack feasibility and bypass routes
- Route A: Fragment-bearing proof-token redirect
  - Flow: unauthenticated request to ProofTokenSignIn with `redirect_uri` pointing to same-tenant page using `location.hash` forwarding (e.g., SPA router). v1 accepts, issues tokens, posts them to that page; client script can forward tokens to attacker. Preconditions: attacker can host/point to page in same subscription (or page accepting hash). Feasibility: High (no auth required, only same-subscription constraint).
- Route B: Signout→ToolPane
  - Flow: attacker triggers signout URL with `Source=/.../ToolPane.aspx`; request after signout has referrer = signout, path = ToolPane; v1 marks as signout flow and bypasses auth, enabling anonymous ToolPane access. Preconditions: ability to reach signout endpoint; ToolPane accessible path. Feasibility: Medium (depends on ToolPane availability but uses standard signout mechanism).
- Route C: Anonymous `_forms` block
  - Flow: IIS config allowed anonymous Execute/Script under `_forms`; attackers could hit form pages (login or custom handlers) without authentication. Specific exploit surface depends on page functionality (token issuance, data access). Feasibility: Medium (broad surface, but requires a sensitive `_forms` page to be reachable).
- Completeness: These three are distinct bypass vectors touching authentication/authorization surfaces. No other explicit auth-related code hunks observed in patch beyond these.

### Patched behavior (v2)
- Proof token redirect: Added fragment check rejects any `RedirectUri` with a hash unless kill switch 53020 is enabled. This blocks the hash-forwarding exfil route. Remaining requirement: same-subscription validation still applies.
- Signout→ToolPane: v2 detects signout referrer + ToolPane target and, unless kill switch 53506 set, restores `flag6=true/flag7=false`, forcing normal auth and emitting a high-level trace. This blocks the signout-based anonymous ToolPane access.
- `_forms` anonymous override removed: Without the `<location>` block, IIS inherits default auth config, disabling anonymous execution under `_forms` and closing that bypass route.
- Bypass completeness: The patch covers the specific fragment-based redirect and signout→ToolPane cases, plus the broad `_forms` anonymous override. Other signout/start targets remain whitelisted (ShareByLink, anonymous VTI, etc.), so additional bypass surfaces could exist but are unchanged; not evidenced in this patch.

### Confidence
- Fragment redirect bypass: **High** — direct code evidence, clear input flow, clear block in v2.
- Signout→ToolPane bypass: **High** — direct code evidence, clear referrer-based bypass and targeted block in v2.
- Anonymous `_forms` config bypass: **Medium** — removal of anonymous auth strongly suggests security intent; exact exploit depends on `_forms` content.

### Bypass validation summary
- Confirmed distinct bypass routes for CVE-2025-49706: 3 (hash redirect, signout→ToolPane, `_forms` anonymous override). Feasibility: High (A), Medium (B), Medium (C). Other bypasses may exist in untouched whitelisted paths; not validated.

## Other Security-Relevant Changes (unmapped)
- BDC/BCS service contract reordering (`.../BusinessData/SharedService/IBdcServiceApplication.cs`, `.../Parser/PackageContents.cs`, etc.): FaultContract and attribute reshuffles; no functional checks added. **Unknown if security-motivated**. Possible robustness/RCE hardening candidate (CVE-2025-49701) but unproven.
- `IBecWebService.cs` FaultContract additions/removals around `ReadApplicationPasswords`/`DeleteApplicationPassword`: improved error modeling; no logic change seen. **Unknown if security-motivated**; weak candidate for CVE-2025-49701.
- Large crypto additions in `mscorlib-*` (HMAC, ASN.1 readers, PBE/PKCS12 code): platform hardening but vulnerability class not inferable here. **Unknown if security-motivated**.
- SafeControl additions in web.config (PerformancePoint ExcelDataSet) and new MIME types: likely functionality, not security; no direct link to vulnerabilities.

## Coverage check against stat report
- Security-mapped changes: ProofTokenSignInPage fragment block (maps to route A); SPRequestModule ToolPane guard (route B); removal of `_forms` anonymous location (route C). These directly address documented bypasses.
- Unmapped changes listed above remain without vulnerability mapping; none contradict current findings.

## Conclusion per prior claims
- Fragment-based proof-token redirect bypass: **Confirmed** (CVE-2025-49706).
- Signout→ToolPane anonymous access: **Confirmed** (CVE-2025-49706 variant).
- Anonymous `_forms` override removal: **Confirmed as auth hardening**, CVE mapping uncertain (could be part of 49706 defense-in-depth).
- RCE (CVE-2025-49701/49704): **Unproven/speculative** — no concrete code evidence in reviewed patch hunks.

## Final bypass coverage statement
- CVE-2025-49706: Confirmed 3 distinct bypass routes addressed by patch. Other whitelisted paths remain; not exhaustively analyzed.
- CVE-2025-49704: No dangerous elements identified; not validated.
- CVE-2025-49701: No confirmed candidate; only speculative unmapped service/crypto changes.
