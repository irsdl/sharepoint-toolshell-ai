Agent: Codex (GPT-5)
Timestamp: 2025-11-26 16:46:28
Duration: 00:14

# Final Verification – Deserialization Patch (ExcelDataSet)

## Part 1: Validate the Vulnerability Understanding

### v1 Vulnerability Evidence
- SafeControls implicitly allowed the whole PerformancePoint client namespace, letting `ExcelDataSet` load in page/viewstate contexts: `snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245` (`TypeName="*"`, SafeControls for `Microsoft.PerformancePoint.Scorecards.Client`).
- Dangerous type: `[Serializable] Microsoft.PerformancePoint.Scorecards.ExcelDataSet` deserializes attacker-controlled compressed payloads with BinaryFormatter:
  - `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs:20-76` (property `CompressedDataTable` toggles `Helper.GetObjectFromCompressedBase64String` on access).
  - `Helper.GetObjectFromCompressedBase64String` calls BinaryFormatter without caller-supplied allowlist: `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/Helper.cs:580-599`.
  - Binder allows `DataSet/DataTable`: `snapshots_decompiled/v1/Microsoft.-52195226-3676d482/System/Data/BinarySerialization.cs:14-55`.

### Attack Flow (v1)
1) Attacker provides a PerformancePoint payload or viewstate that references `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` and supplies a crafted Base64 `CompressedDataTable`.  
2) SafeControls wildcard treats the type as safe, allowing page/control loading.  
3) Accessing `ExcelDataSet.DataTable` triggers `Helper.GetObjectFromCompressedBase64String`, which decompresses and BinaryFormatter-deserializes the attacker blob using the permissive binder.  
4) A malicious DataSet/DataTable gadget yields server-side code execution.  
Prereqs: ability to supply or persist a payload processed under SafeControls (e.g., PerformancePoint content), and BinaryFormatter gadget chain via DataSet/DataTable.

Validation: Confirmed with explicit code and config evidence (High).

### Patch Evidence & Mechanism (v2)
- Diff hunk adding explicit unsafe entries:  
  - `diff_reports/v1-to-v2.server-side.patch` shows additions to configs:  
    ```
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
    ```
- These entries appear in v2 configs:  
  - `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config:150-163` and `cloudweb.config:150-163`.  
  - Site web.configs (e.g., `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:490-495`).  
- Upgrade action to insert unsafe entries: `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs:7-35`.

Patch mechanism: Mark `ExcelDataSet` unsafe in SafeControls (versions 15/16), so the control is blocked from loading/deserializing in page contexts; upgrade hook enforces config insertion.

Effectiveness Rating: Partial. It blocks the primary SafeControls route but leaves code unchanged and relies on config coverage/precedence.

## Part 2: Validate Bypass Hypotheses

### Hypothesis 1 – Template gap (provisioning)
- Type: Alternative attack path via unpatched template.
- Claim: `webconfig.pps.xml` template lacks the unsafe entry; new sites may omit the block if upgrade not applied.
- Evidence: `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/webconfig.pps.xml:3-9` shows only wildcard SafeControls, no `ExcelDataSet` unsafe entries.
- Attack path: Provision a web app/site from this template before upgrade action runs; SafeControls wildcard would allow `ExcelDataSet`.
- Patch coverage: Missed in template; relies on upgrade execution.
- Feasibility: Medium (deployment-dependent).
- Verdict: Uncertain (needs deployment/upgrade behavior to confirm).

### Hypothesis 2 – Wildcard precedence risk
- Type: Alternative attack path via config precedence.
- Claim: Wildcard SafeControls may override the explicit `Safe="False"` entries if precedence favors earlier entries.
- Evidence: Wildcards remain (`snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245`), while unsafe entries are later in the same block (`:490-495`).
- Attack path: If resolution chooses the first matching wildcard, `ExcelDataSet` might stay allowed.
- Patch coverage: Unsafe entries present; outcome depends on SafeControls resolution order (not visible statically).
- Feasibility: Medium (behavioral uncertainty).
- Verdict: Uncertain (requires runtime confirmation).

### Hypothesis 3 – Re-registration/version skew
- Type: Reintroduction of dangerous type.
- Claim: Adding a SafeControl with `Safe="True"` or a new assembly version (e.g., 17.0.0.0) would re-enable the gadget; patch only lists v15/v16.
- Evidence: Unsafe entries are version-specific (`snapshots_norm/v2/.../web.config:150-163`, `:490-495`) and code unchanged.
- Attack path: Admin/feature deploys a SafeControl for `ExcelDataSet` with a different version or overriding safety.
- Patch coverage: Not protective against future versions or re-additions.
- Feasibility: Medium (requires config change).
- Verdict: Uncertain (depends on future/admin actions).

### Hypothesis 4 – Alternate types in namespace using the helper
- Type: Other dangerous deserialization types.
- Claim: Another serializable type in the namespace could use `Helper.GetObjectFromCompressedBase64String` and remain allowed by wildcard.
- Evidence: Wildcard SafeControls remain (`web.config:240-245`); only `ExcelDataSet` observed calling the helper (`Helper.cs:580-599`).
- Attack path: Would require locating another type using the helper; not found in provided sources.
- Patch coverage: Not applicable if no such type exists.
- Feasibility: Low without evidence.
- Verdict: Rejected (no code evidence of another helper-using type).

### Hypothesis 5 – Non–SafeControl contexts
- Type: Alternative attack path outside SafeControls.
- Claim: Deserialization of `ExcelDataSet` in services/storage paths would bypass config.
- Evidence: Code unchanged; no v2 service endpoint found consuming `ExcelDataSet`.
- Attack path: Not demonstrated in provided sources.
- Patch coverage: Config-only; would not cover such a path if it existed.
- Feasibility: Low (no evidence).
- Verdict: Uncertain (insufficient evidence).

### Hypothesis 6 – Assembly version wildcarding not covered
- Type: Version skew.
- Claim: If deployed assembly has a different version string, the explicit unsafe entries miss it while wildcards might still allow.
- Evidence: Unsafe entries list only 15.0.0.0 and 16.0.0.0 (`web.config:150-163`, `:490-495`).
- Attack path: Use `ExcelDataSet` from an assembly with another version.
- Patch coverage: Not covering other versions.
- Feasibility: Low-to-Medium (depends on deployment).
- Verdict: Uncertain.

## Part 3: Completeness Assessment
- Total hypotheses evaluated: 6  
  - Confirmed: 0  
  - Uncertain: 5 (1,2,3,5,6)  
  - Rejected: 1 (4)

Patch assumptions: SafeControls precedence correctly honors explicit unsafe entries; upgrade action runs on all sites; assembly versions remain 15/16; no re-registration occurs. Edge cases (null/encoding) are irrelevant to SafeControl gating but unresolved for code-level deserialization because BinaryFormatter helper remains unchanged.

Coverage: Patch touches primary configs and adds upgrade action but leaves provisioning template wildcards and does not alter the vulnerable code.

Completeness statement: [x] Some hypotheses remain uncertain due to configuration/runtime behavior—would require deployment/runtime validation.

## Final Verdict
- Vulnerability in v1: Confirmed (code and config evidence).
- Patch addresses vulnerability: Partial (config-based, version-specific, assumes precedence and upgrade coverage).
- Evidence quality: Moderate (clear static evidence; runtime precedence not verified).

Bypass summary:
- Confirmed: None.
- Uncertain: Template gap; wildcard precedence; re-registration/version skew (including other versions); non–SafeControl contexts.
- Rejected: No alternate helper-using types found.

Key findings:
- Patch blocks ExcelDataSet via explicit unsafe SafeControls and upgrade action but relies on configuration order and completeness across provisioning.
- Highest-risk bypass remains configuration-dependent (template gap/precedence).
- Static analysis limitation: cannot prove SafeControls resolution or upgrade execution; no dynamic validation performed.
