# Final Verification

## Vulnerability 1: Auth bypass via SignOut referrer → ToolPane
- **Diff hunk (evidence):** `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs` `PostAuthenticateRequestHandler` (lines ~2720). Patch adds ToolPane guard when the referrer matches signout paths:
  ```diff
  - if (IsShareByLinkPage(...) || ... || uri!=null && (StsCompareStrings(...signout...)))
  + bool flag8 = uri != null && ( ... signout... );
  + if ( ... || flag8)
    {
      flag6 = false;
      flag7 = true;
  +   bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
  +   bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", ...);
  +   if (flag9 && flag8 && flag10)
  +   {
  +     flag6 = true;
  +     flag7 = false;
  +     ULS.SendTraceTag(..."Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected."...);
  +   }
    }
  ```
- **V1 behavior:** In v1 (same file, lines ~2700), any request where either the request path starts with a signout/start path or the **Referrer.AbsolutePath** equals those paths sets `flag6=false; flag7=true;`. Later, when the user is unauthenticated, the code only sends a 401 if `!flag7` and claims auth is required. Because `flag7` is true, unauthenticated requests proceed without challenge. Untrusted input: attacker controls the request path (`/_layouts/15/ToolPane.aspx`) and the `Referer` header (`/_layouts/15/SignOut.aspx`). ToolPane.aspx (see layouts file) is under `_layouts`, so this code path is hit.
- **Why vulnerable:** With `flag7=true`, the module skips the claims 401 branch, leaving the request unauthenticated yet processed. ToolPane.aspx in `_layouts` loads WebPart infrastructure; GET does not require form digest. An attacker can therefore reach ToolPane pre-auth and trigger rendering/loading of web parts (a known RCE surface when malicious web parts/BDC payloads exist). Bad outcome: pre-auth access to privileged WebPart editing surface → potential RCE or data exposure.
- **Bypass routes identified:**
  1) `Referer` set to any signout path (`signoutPathRoot/Previous/Current`) with request path `/_layouts/15/ToolPane.aspx` (or build-version variant). This is the only concretely patched route.
  2) Patch introduces kill-switch 53506; if enabled, the bypass revives. (Operational bypass, not a code path.)
  No other endpoints were changed; thus only ToolPane was validated.
- **V2 prevention:** Added guard restores `flag6=true/flag7=false` when both `flag8` (signout referrer) and `flag10` (ToolPane path) are true (unless kill-switch set). That re-enables normal auth enforcement (401) for ToolPane requests with signout referrers and logs the attempt.
- **Bypass completeness:** Only the ToolPane+signout pattern is blocked. Other `_layouts` pages with signout referrers still set `flag7=true` and are not covered by the new check. However, the patch targets the observed exploit path; no evidence of other pre-auth surfaces was modified. Bypass feasibility: High for route #1 pre-patch; blocked in v2 unless kill-switch toggled.
- **Confidence:** **High** (direct code flow shows auth skip and targeted fix).

## Vulnerability 2: ProofToken redirect hash fragment acceptance
- **Diff hunk (evidence):** `IdentityModel/ProofTokenSignInPage.cs` `ShouldRedirectWithProofToken`:
  ```diff
  if (null != RedirectUri)
  {
    result = IsAllowedRedirectUrl(RedirectUri);
+   if ((!SPFarm.Local?.ServerDebugFlags.Contains(53020) ?? true) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+   {
+     ULS..."Hash parameter is not allowed.";
+     result = false;
+   }
  }
  ```
- **V1 behavior:** Same method (v1 lines ~308-330) only checks `IsAllowedRedirectUrl(RedirectUri)`; fragments (`#...`) are not rejected. `RedirectUri` is user-controlled (return URL parameter in proof-token sign-in). If accepted, the page issues identity/proof tokens and redirects.
- **Why vulnerable:** An attacker can supply a redirect URL with a fragment to a controlled domain. Fragments are not part of HTTP requests to the target server, so `IsAllowedRedirectUrl` validation may pass on the base URL, while the fragment can carry state/tokens client-side. This risks token leakage or redirect tampering in the OAuth proof-token flow (spoofing/CSRF-style redirect abuse).
- **Bypass routes identified:** Single route—use of any allowed RedirectUri containing a fragment. No other fragment checks were present.
- **V2 prevention:** v2 rejects any RedirectUri containing a fragment unless debug flag 53020 is set. This blocks the fragment-based abuse. If the flag is set, the bypass reopens.
- **Bypass completeness:** Only fragment-based misuse addressed; other redirect validation depends on `IsAllowedRedirectUrl`, unchanged. Feasibility: Medium (requires user-supplied return URL in proof-token flow; plausible in OAuth scenarios).
- **Confidence:** **Medium** (behavioral risk inferred from redirect logic; no explicit token exposure shown, but fragment acceptance is clearly newly blocked).

## Vulnerability 3 (speculative): JSON date deserialization length hardening
- **Diff hunk:** `System.Web/Script/Serialization/JavaScriptObjectDeserializer.cs` adds `DateTimeMaxLength=36`, gated by `AppSettings.JsonDeserializerLimitedDate`, and uses `_s.LimitedIndexOf` to cap search before regex. `JavaScriptString` gains `LimitedIndexOf`.
- **V1 behavior:** `DeserializeStringIntoDateTime` unconditionally calls `_s.IndexOf("\\/")` then regex on substring without length cap, allowing attacker-supplied JSON date strings of arbitrary length/complexity. This could enable Regex backtracking DoS or extremely large allocations.
- **V2 prevention:** Limits search length when the new app setting (default true) is enabled; long/odd strings skip the date parsing path.
- **Bypass completeness:** If the app setting is disabled, old behavior persists. No other JSON changes observed.
- **Confidence:** **Low / speculative** (security impact not explicit; likely DoS mitigation rather than direct RCE/bypass).

## Vulnerability 4 (speculative): Removal of PowerShell InternalDeserializer
- **Diff hunk:** Entire `System/Management/Automation/InternalDeserializer.cs` deleted (index -> empty file, minus 1406 lines).
- **V1 behavior:** File contained full CLI XML/PSObject deserializer used by `Deserializer`/`PSSerializer`. Untrusted input (XML/CLI streams) could be deserialized into .NET objects including ScriptBlock via helper methods (`DeserializeScriptBlock`, etc.). This is a known RCE vector when exposed.
- **V2 prevention:** Implementation removed entirely; calls likely fail or no-op, preventing deserialization of arbitrary types.
- **Bypass completeness:** Unknown—other deserialization paths may remain. Exposure path to untrusted users not visible in provided code.
- **Confidence:** **Low / speculative** (security motivation implied by full removal, but exploit surface not evidenced in this tree).

## Coverage / Unmapped Security-Relevant Changes
- **Mapped to Vuln 1:** SPRequestModule ToolPane guard—addresses the single documented bypass route (signout referrer + ToolPane). No other bypasses patched here.
- **Mapped to Vuln 2:** ProofToken fragment rejection—only fragment route addressed.
- **Unmapped:**
  - JSON date length cap (possible DoS hardening).
  - InternalDeserializer removal (possible RCE mitigation; could align with CVE-2025-49701 but unproven).
  - Numerous config/metadata/fault-contract edits (e.g., auth settings in web.config, BDC/Project stored procedure metadata) lack clear security effect → **unknown if security-motivated**.

## Confirmation Status
- Auth bypass (ToolPane): **Confirmed** (code flow and patch show exploit/fix). Bypass routes validated: 1 distinct path; kill-switch can re-enable.
- ProofToken fragment redirect: **Confirmed (behavioral change)** with **Medium** confidence; risk scenario plausible but not directly demonstrated.
- JSON deserializer hardening: **Unproven / speculative** (DoS mitigation); not tied to CVEs.
- InternalDeserializer removal: **Unproven / speculative** (possible CVE-2025-49701 candidate); no concrete exploit path shown in supplied materials.

## Bypass Validation Summary
- **CVE-2025-49706 (auth bypass)**: Confirmed 1 distinct bypass route (SignOut/Start referrer + ToolPane.aspx). Other auth bypasses not evidenced. Feasibility pre-patch: High; post-patch blocked unless kill-switch enabled.
- **CVE-2025-49704 (deserialization)**: Not directly patched; ToolPane still loads WebParts/BDC content post-auth. Dangerous types not enumerated here; only the pre-auth path was fixed. Coverage is incomplete.
- **CVE-2025-49701 candidate(s)**: InternalDeserializer removal (Low confidence), JSON date limit (very low confidence). No confirmed mapping.

## Final Answers
- I still believe: Auth bypass (ToolPane) is real and patched (**Confirmed**). ProofToken fragment handling is a real hardening change (**Confirmed, Medium confidence**). Other hypothesized vulnerabilities remain **Unproven / speculative**.
- Bypass exploration: Auth bypass—**only one validated route**. Deserialization—**not validated**; other gadget routes may exist. 
