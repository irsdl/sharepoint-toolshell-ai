# Coverage Check Results

## Initial Findings (from first pass)
- Auth bypass in `Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs`: SignOut/Start referrer caused `flag6=false`/`flag7=true`, skipping auth. Bypass path: unauth `GET /_layouts/15/ToolPane.aspx` with `Referer` to SignOut/Start. Patch adds ToolPane-specific guard (kill-switch 53506) and logs risk.
- Proof token redirect hardening in `IdentityModel/ProofTokenSignInPage.cs`: Rejects redirect URLs containing fragments (`#...`) unless debug flag 53020 enabled; prevents token leak/spoof.
- ToolPane remains deserialization surface; RCE via malicious WebPart/BDC payload once reachable (primary chain for CVE-2025-49706 + CVE-2025-49704). Social intel: single-request “ToolShell” to ToolPane.aspx.

## New Findings (from coverage check)

### New Vulnerabilities
- **System.Web JSON date deserializer length check** (`System.Web/Script/Serialization/JavaScriptObjectDeserializer.cs`, `JavaScriptString.cs`, `AppContextDefaultValues.cs`): Added `JsonDeserializerLimitedDate` app-setting defaulting to true and a bounded `LimitedIndexOf` search (length 36) before parsing `\/Date(...)\/`. Mitigates overly long date strings/regex backtracking. Likely DoS or payload-smuggling reduction. Maps to deserialization hardening; not previously covered.
- **PowerShell CLI XML deserialization removal/neutralization** (`System.Management.Automation/InternalDeserializer.cs` and helpers are now zero-length/missing in v2 while references remain): Suggests deliberate removal of internal deserializer implementation to block XML/CLI deserialization gadgets (common PSObject RCE vector). This is a strong candidate for the unknown RCE (CVE-2025-49701) affecting low-priv authenticated users.

### Additional Bypass Routes (for already-found vulnerabilities)
- **Auth bypass (ToolPane)**: Kill-switch 53506 can re-enable the legacy bypass; any admin enabling it restores the pre-auth path. Other referrer-triggered paths (Start.aspx variants) remain guarded only by this logic; if new endpoints mimic SignOut/Start naming or if path comparison is case-insensitive, potential edge bypass remains. No new concrete endpoint beyond ToolPane, but note both SP foundation assemblies include identical patch; both must be updated.
- **Proof token redirect**: Fragment check gated by debug flag 53020; enabling it reopens the redirect-based spoof/leak. Alternate vector: similar checks may be absent on other token issuance endpoints (not fixed here).
- **Deserialization surface**: Even after auth fix, ToolPane accepts persisted WebParts/BDC definitions; additional gadget paths (DataSet, TypeConverters, WorkflowCompiler) remain viable post-auth. RCE reachable with low-priv auth per CSAF; not closed by this patch.

### CVE-2025-49701 Candidates
- **Strong candidate:** Removal/neutralization of `InternalDeserializer` (System.Management.Automation) — mitigates CLI XML/PowerShell object deserialization RCE reachable to authenticated low-priv users (PR:L matches CSAF). 
- **Possible candidate:** JSON date deserializer length cap — less likely RCE; more of a DoS/validation fix.

## Unmapped Security Changes
- `applicationHost.config`/web.config toggles (`anonymousAuthentication enabled="true"` removed): security posture change but likely environment/local; not mapped to CVE.
- Large reorder/metadata changes in BDC service contracts (fault contracts/constraints) appear non-security or cosmetic; no clear vulnerability mapping.
- Project Server database metadata version bumps (validate/read procs) — unclear security impact.

## Total Coverage
- Files analyzed: ~12 security-relevant targets (SPRequestModule, ProofTokenSignInPage, ToolPane.aspx, SPUtility, System.Web serialization, System.Management.Automation deserialization, selected configs/BDC metadata).
- Security-relevant changes identified: 4 (ToolPane auth guard, proof-token fragment check, JSON date limit, PowerShell deserializer removal).
- Mapped to vulnerabilities: 3 (auth bypass -> CVE-2025-49706; ToolPane deserialization chain -> CVE-2025-49704; proof-token redirect -> auxiliary spoofing). 
- Unmapped: 1 primary (PowerShell deserializer removal) + minor config/fault-contract tweaks.
- Additional bypass routes discovered: 2 (kill-switch toggles re-open fixes; post-auth deserialization gadgets remain).
- CVE-2025-49701 candidates identified: 1 strong, 1 possible.
