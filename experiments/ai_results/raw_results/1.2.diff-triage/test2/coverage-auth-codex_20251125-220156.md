# Coverage Check Results

## Initial Findings (from first pass)
- Auth bypass (CVE-2025-49706): `Microsoft.SharePoint.ApplicationRuntime.SPRequestModule.PostAuthenticateRequestHandler` now blocks unauthenticated ToolPane.aspx when referrer is signout/start pages; prevents access-denied bypass via forged signout referrer. Applies to both GAC copies (`Microsoft.-52195226-3676d482` and `Microsoft.-67953109-566b57ea`).
- Auth/redirect bypass (CVE-2025-49706): `Microsoft.SharePoint.IdentityModel.ProofTokenSignInPage.ShouldRedirectWithProofToken` rejects redirect URIs containing fragments (`#`) before issuing proof/identity tokens, blocking token exfiltration via fragment-based redirects.
- Search rankdetail hardening (info disclosure): `Microsoft.Office.Server.Search.Administration.SearchServiceApplicationProxy.CheckIsRankDetailQuery` strips `rankdetail/bypasscheckadminaccess` unless tenant admin or flight, reducing unauthorized rank log access.

## New Findings (from coverage check)

### New Vulnerabilities
- Unsafe deserialization guard (RCE candidate): `Microsoft.Ssdqs.Infra.Utilities.NoneVersionSpecificSerializationBinder` now routes type resolution through new `TypeProcessor` with explicit allow/deny lists and disallowed generic types (`TypeProcessor.cs`). Previously used `Type.GetType` with adjusted assembly name only, enabling arbitrary `BinaryFormatter` type resolution. Likely fixes a remote/low-priv authenticated deserialization RCE path (CVE-2025-49701 candidate). Files: `snapshots_decompiled/v2/Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/NoneVersionSpecificSerializationBinder.cs` & new `TypeProcessor.cs`.
- Cookie-based search auth data deserialization hardening (RCE/priv-esc candidate): New `Microsoft.Office.Server.Search.Administration.CookieAuthData` class adds BinaryFormatter deserialization with explicit safe binder (`ExplicitReferenceSerializationBinder<Cookie>`) and defensive logging; previously absent. Added KnownType attribute in related data contracts. Prevents arbitrary cookie payload from instantiating attacker-controlled types. Files: `snapshots_decompiled/v2/Microsoft.-b3970a17-9bc74dbc/Microsoft/Office/Server/Search/Administration/CookieAuthData.cs` and KnownType additions.

### Additional Bypass Routes (for already-found vulnerabilities)
- Auth bypass (SPRequestModule): No new routes observed beyond ToolPane.aspx+signout referrer; other bypass-whitelisted endpoints (share-by-link, anonymous VTI BIN, anonymous dynamic) remain unguarded—potential alternative paths still to test, but no code changes here.
- ProofTokenSignInPage: Fragment rejection covers inline/encoded `#` fragments; host/path manipulation without fragments remains a possible token-forwarding path (still open risk, not fixed).
- Rankdetail: New logic also clears `bypasscheckadminaccess`, preventing stored bypass flags. No additional bypass route identified beyond rank log access.

### CVE-2025-49701 Candidates
- Strong candidate: `NoneVersionSpecificSerializationBinder` + `TypeProcessor` allow/deny lists for BinaryFormatter type resolution in `Microsoft.Ssdqs.Infra` (potential deserialization RCE path; explicit blocklist of dangerous framework/SharePoint types and generic constraints).
- Possible candidate: `CookieAuthData` safe BinaryFormatter binder for cookie-based federated search auth data; mitigates deserialization of untrusted cookie blobs.

## Unmapped Security Changes
- The TypeProcessor/NoneVersionSpecificSerializationBinder and CookieAuthData changes appear security-motivated (deserialization hardening) but exact exposure path (network surface, privilege level) is not confirmed; mapped as RCE candidates but underlying trigger endpoint not identified in the provided diffs.

## Total Coverage
- Files analyzed: focused on high-signal security diffs (SharePoint runtime/auth, IdentityModel, Search admin, Ssdqs infra).
- Security-relevant changes identified: 5
- Mapped to vulnerabilities: 3 (auth bypass ToolPane, auth redirect fragment, rankdetail access)
- Unmapped (hypothesized RCE/priv-esc): 2
- Additional bypass routes discovered: 0 new confirmed (noting remaining open surfaces for testing)
- CVE-2025-49701 candidates identified: 2
