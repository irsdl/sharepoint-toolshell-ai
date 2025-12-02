Agent: Codex (GPT-5)
Timestamp: 2025-11-20 00:27:00
Duration: 05:00

# Final Verification Report

## Verified Vulnerabilities

### 1. ProofTokenSignInPage fragment redirect / token leakage

**Diff evidence**  
`diff_reports/v1-to-v2.server-side.patch`, hunk for `Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs`:
```
@@ -32,6 +32,8 @@
-	private const int DisableFilterSilentRedirect = 53502;
+	private const int DisableFilterSilentRedirect = 53502;
+	private const int RevertRedirectFixinProofTokenSigninPage = 53020;
...
@@ -318,6 +320,11 @@
 	if (null != RedirectUri)
 	{
 		result = IsAllowedRedirectUrl(RedirectUri);
+		if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+		{
+			ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
+			result = false;
+		}
 	}
```

**V1 behavior**  
File: `snapshots_decompiled/v1/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs`
- `ShouldRedirectWithProofToken()` (lines 315-323) only did `result = IsAllowedRedirectUrl(RedirectUri);` and immediately returned that boolean, so any redirect URI pointing to a URL under the same site subscription was accepted without examining fragments.
- `SignInAppWeb()` (lines 475-493) then used `RedirectUri.OriginalString` verbatim: it parsed the `ProofToken`/`IdentityToken`, established a local session via `SetIdentityUsingProofToken`, and finally called `Redirect(originalString, SPRedirectFlags.DoNotEndResponse)`. No output encoding or fragment removal occurred.
- Because `redirect_uri` is taken directly from the user’s query string by `get RedirectUri()` (lines 45-74) and only validated for host membership, attackers could supply a URL like `https://tenant/_layouts/15/SPAppRedirect.aspx#https://attacker`. After tokens are generated, the browser is redirected to SharePoint’s built-in redirector, which processes the fragment client-side and forwards to the attacker while the proof token is still valid. This leaks proof/identity tokens (confidentiality loss) and enables impersonation.

**V2 protection**  
The new fragment check in `ShouldRedirectWithProofToken()` rejects any redirect that contains a fragment (`RedirectUri.Fragment`) unless farm debug flag 53020 is set. Returning `false` prevents `SignInAppWeb()` from ever running (`ShouldRedirectWithProofToken()` gates all downstream logic). Therefore the redirect never happens and tokens are not generated/sent when a fragment is present. Attackers can no longer use fragment-driven redirectors to exfiltrate proof tokens via client-side chaining.

**Confidence**: **High**. The code clearly shows untrusted `redirect_uri` flowing to a redirect without fragment validation in v1, and the v2 hunk explicitly blocks the fragment case.

## Security-Relevant Changes Not Mapped to Verified Vulnerabilities

1. **SafeControl entries for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet`** (multiple `web.config` files plus `Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs`). Mechanical change: added `<SafeControl ... Safe="False" ...>` elements and an upgrade action that injects them. Unknown if security-motivated (likely to disable a vulnerable control, but no further evidence in repo).

2. **Search WebControls / Query pipeline refactor** (files under `Microsoft.-b3970a17-9bc74dbc`, e.g., `SearchCommon.cs`, `CoreResultsWebPart.cs`, `SearchRssHiddenObject.cs`, `SharePointSearchRuntime.cs`, `Query/Gateway/XMLBuilder.cs`). Mechanical changes include new files and updated XML handling with `XmlDocumentFragment` and exception logging. Unknown if security-motivated; diffs alone do not reveal a concrete vulnerability.

## Status of Previous Claims
- **ProofTokenSignInPage fragment redirect** – **Confirmed** as detailed above.
- **ExcelDataSet SafeControl change (speculative in coverage check)** – **Uncertain**. While the patch clearly marks the control unsafe, the provided code does not show the underlying vulnerability, so the claim cannot be verified.

No other vulnerabilities were previously asserted.
