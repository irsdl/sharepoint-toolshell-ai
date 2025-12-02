Agent: Codex (GPT-5)
Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Duration: N/A

# Vulnerability Discovery
1. **ExcelDataSet Safe-Control Hardening** – *Deserialization / Serialization*, **High**
   - `snapshots_norm/v1/.../web.config:230-245` exposed the entire `Microsoft.PerformancePoint.Scorecards` namespace as safe controls. Anyone with page editing rights could instantiate `ExcelDataSet`, whose `CompressedDataTable` getter deserializes attacker-controlled binary data through `Helper.GetObjectFromCompressedBase64String` → `BinarySerialization.Deserialize`. Added `<SafeControl ... TypeName="ExcelDataSet" Safe="False">` entries in every scope now block this vector.
2. **ProofTokenSignInPage Fragment Acceptance** – *Input Validation*, **High**
   - `silentsignin.aspx` relied on `ShouldRedirectWithProofToken` to vet redirect URIs but ignored fragments. Attackers could supply `redirect_uri=/.../AppRedirect.aspx#@https://evil` to leak proof/identity tokens via AppRedirect's documented `#@` behavior. The patch rejects any fragment unless kill switch 53020 is enabled and logs the attempt.
3. **Show-Command Remote Module Import** – *Authorization / Access Control*, **High**
   - In constrained sessions the `ShowCommandCommand` GUI imported whatever module path the UI provided, including UNC/device paths, allowing arbitrary remote module execution. New logic normalizes the path and blocks UNC/device inputs when `Utils.IsSessionRestricted` holds, throwing `CommandNameNotAllowed` before import.

# Root Cause Analysis
- **ExcelDataSet**: wildcard safe controls + eager BinaryFormatter deserialization comprised a textbook gadget loading surface (C/I/A impact).
- **ProofTokenSignInPage**: validation only examined scheme/host while the browser reinterprets the fragment client-side, so `#@` rewrites allowed redirection to untrusted origins after token issuance (C/I impact).
- **Show-Command**: session restrictions were never re-applied in the import loop, so GUI-driven imports bypassed PowerShell constrained language (I impact).

# Patch Analysis
- **ExcelDataSet**: explicit `Safe="False"` entries for both v15/v16 assemblies added to `web.config`, `cloudweb.config`, and every IIS virtual directory, ensuring markup can no longer instantiate the type.
- **ProofTokenSignInPage**: fragment-aware check inside `ShouldRedirectWithProofToken`; rejects and logs unless server debug flag 53020 is set.
- **Show-Command**: guard code in `WaitForWindowClosedOrHelpNeeded` normalizes `ParentModuleNeedingImportModule`, rejects UNC/device paths in restricted sessions, and stops execution.

# Bypass Hypotheses
- **ExcelDataSet**
  1. Medium – other Scorecards types (e.g., `TransformerConfigurationRecord`) remain safe; review for BinaryFormatter usage.
  2. Medium – APIs or services that ingest `ExcelDataSet` outside the safe-control system may still deserialize attacker input.
  3. Low – administrators could reintroduce Safe="True" entries or custom mappings.
- **ProofTokenSignInPage**
  1. Medium – percent-encoded fragments (`%23@`) may evade the new `Uri.Fragment` check while browsers still honor the decoded fragment.
  2. Medium – alternative redirectors (e.g., malicious `RedirectUriFlags` or other `_layouts` pages) might still forward tokens.
  3. Low – enabling kill switch 53020 restores the vulnerable behavior.
- **Show-Command**
  1. Medium – map a UNC share to a drive letter or use `subst` so `PathIsNetworkPath` no longer detects it.
  2. Medium – abuse NTFS reparse points/symlinks to point local-looking paths at network locations.
  3. Low – if restricted sessions allow other PSProviders (e.g., `http:`) the guard may be bypassed.

# Coverage Check
- `.config` files (cloud/web configs, IIS applicationHost) reviewed; only ExcelDataSet entries were security-relevant. Added MIME maps / schedule changes classified as non-security.
- `.cs` files: besides three vulnerabilities, other changes were assembly version bumps or mechanical refactors. `Microsoft.Office.Project.Server.Database.DatabaseMetadata.cs` regenerated entirely; no clear security intent inferred – marked **Security-relevant (Possible)** and **UNMAPPED**.
- Totals: 5,744 `.cs` diffs, 6 `.config`. Security-relevant changes = 4 (3 definite, 1 possible). Mapped to findings = 3. New coverage findings = 0. Unmapped = 1.

# Overall Assessment
SharePoint v2 mitigates three impactful bugs: safe control tightening prevents BinaryFormatter gadget abuse, ProofTokenSignInPage clamps proof-token redirects, and Show-Command again honors constrained language policies. The fixes appear narrowly targeted; adjacent areas (other Scorecards classes, encoded fragments, path tricks) warrant further review.
