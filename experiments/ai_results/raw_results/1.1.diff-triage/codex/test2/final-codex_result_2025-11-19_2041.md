# Final Verification Results

## Verified Vulnerabilities

### 1. ProofTokenSignIn fragment-smuggling lets attackers steal proof/identity tokens
**Diff evidence**
```
diff --git a/.../ProofTokenSignInPage.cs b/.../ProofTokenSignInPage.cs
@@ -32,6 +34,7 @@ public class ProofTokenSignInPage : FormsSignInPage
-   private const int DisableFilterSilentRedirect = 53502;
+   private const int DisableFilterSilentRedirect = 53502;
+   private const int RevertRedirectFixinProofTokenSigninPage = 53020;
@@ -318,6 +323,11 @@ protected bool ShouldRedirectWithProofToken()
        if (null != RedirectUri)
        {
            result = IsAllowedRedirectUrl(RedirectUri);
+           if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
+           {
+               ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
+               result = false;
+           }
        }
```
(File: `diff_reports/v1-to-v2.server-side.patch`, method `ShouldRedirectWithProofToken`.)

**Vulnerable v1 flow**
1. `redirect_uri` arrives directly from the query string (`RedirectUri` property calls `SPRequestParameterUtility.GetValue` on the request; `snapshots_decompiled/v1/.../ProofTokenSignInPage.cs:45-65`). No filtering occurs beyond `Uri.TryCreate`.
2. `FormActionValue` (`same file:68-90`) simply returns `RedirectUri.OriginalString` whenever `ShouldRedirectWithProofToken` succeeds. No normalization removes URI fragments.
3. `ShouldRedirectWithProofToken` (lines 315-323) only checks `IsAllowedRedirectUrl`, which validates the *host* against the current subscription but has no awareness of fragments.
4. `silentsignin.aspx` (`snapshots_norm/v1/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/TEMPLATE/LAYOUTS/silentsignin.aspx:26-54`) renders `<form action="FormActionValue" ...>` with hidden `ProofToken` and `IdentityToken` values and auto-submits on load.
5. Because fragments are never sent to the server, `IsAllowedRedirectUrl` cannot vet them. An attacker can craft `redirect_uri=https://tenant/site/Relay.aspx#https%3a%2f%2fattacker` where the page code reads `window.location.hash` and reposts the hidden form contents to the attacker-controlled URL. The victim never sees the relay because the Post happens automatically, so the attacker obtains valid OAuth proof/identity tokens and can impersonate the user/app to SharePoint resources.

**Patched behavior**
Lines 317-328 in v2 add an explicit fragment check inside `ShouldRedirectWithProofToken`. Unless the diagnostic flag 53020 is enabled, any non-empty `RedirectUri.Fragment` forces `result=false` after logging. This means `FormActionValue` will no longer use fragment-bearing URLs because `ShouldRedirectWithProofToken` now fails, so `silentsignin.aspx` posts only to fragment-free targets that the server fully validated. Fragment-based second-hop smuggling (the only reason the attack worked) is therefore blocked.

**Confidence**: **High**. The vulnerable control path and its reliance on unvalidated fragments are visible in the v1 sources, and the patch directly addresses that gap. The exploit impact (token theft) follows deterministically from the code that blindly posts the proof/identity tokens to the attacker-controlled action URL.

## Security-Relevant Changes Without Verified Vulnerabilities
1. **ExcelDataSet SafeControl lockdown** – Cloud/farm web.config files (`diff_reports/v1-to-v2.server-side.patch` hunks near lines 22-123) now contain explicit `<SafeControl ... Safe="False" ...>` entries for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet`, and a new upgrade class (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/.../AddExcelDataSetToSafeControls.cs`) injects those entries. *Unknown if security-motivated beyond changing SafeControl metadata.*
2. **SharePointSearchRuntime highlight sanitization** – The patched `SharePointSearchRuntime.cs` (`snapshots_decompiled/v2/Microsoft.-b3970a17-9bc74dbc/...` around lines 1189-1210) now catches `XmlException` when parsing hit-highlight snippets and falls back to `SecurityElement.Escape`. The equivalent v1 binary is absent in `snapshots_decompiled/v1`, so the original behavior cannot be inspected. *Unknown if security-motivated.*

## Final Assessment of Previously Reported Issues
- ProofTokenSignIn fragment-smuggling: **Confirmed**.

No other vulnerabilities were claimed earlier, so nothing else to downgrade.
