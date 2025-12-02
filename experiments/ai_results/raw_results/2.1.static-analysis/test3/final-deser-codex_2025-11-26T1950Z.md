# Final Verification: CVE-2025-49704 (ExcelDataSet Deserialization)

## Part 1: Validate the Vulnerability Understanding

### 1) Vulnerability in v1 (evidence and attack flow)
- **Code location (v1):** `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs:39-52` deserializes attacker-provided base64 into a `DataTable` via BinaryFormatter: `dataTable = Helper.GetObjectFromCompressedBase64String(compressedDataTable, ExpectedSerializationTypes) as DataTable;` (`compressedDataTable` is settable via XML, lines 62-77). `Helper.GetObjectFromCompressedBase64String` uses BinaryFormatter without strict allow-listing (`snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/Helper.cs:580-599`), which calls `BinarySerialization.Deserialize` -> BinaryFormatter (`snapshots_decompiled/v1/Microsoft.-52195226-3676d482/System/Data/BinarySerialization.cs:54-62`).
- **Missing check:** No validation of the serialized payload beyond minimal type gating; BinaryFormatter over `DataTable` gadgets permits code execution when the object graph is hydrated.
- **Attack flow:**
  1. Attacker supplies crafted `CompressedDataTable` (base64) in content that is parsed as `ExcelDataSet` (e.g., via SafeControls-allowed markup or stored dashboard data).
  2. SharePoint instantiates `ExcelDataSet` because the namespace `Microsoft.PerformancePoint.Scorecards.*` is marked Safe via wildcard (`snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245`).
  3. Accessing the `DataTable` property triggers `Helper.GetObjectFromCompressedBase64String` → BinaryFormatter → gadget execution.
- **Prereqs:** Ability to inject/persist content that the SafeControls gate accepts (pages/web parts/dashboards using the Scorecards namespace) and cause property access (e.g., rendering). No additional server-side validation is present.
- **Validation:** Concrete code demonstrates unsafe BinaryFormatter deserialization reachable through SafeControls whitelisting. **Confidence: High.**

### 2) Patch effectiveness (what changed and why it blocks)
- **Diff hunk (config):** `diff_reports/v1-to-v2.server-side.patch` shows additions: `<SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ... TypeName="ExcelDataSet" Safe="False" ... />` and similarly for version 16.0.0.0 inserted at lines around 158-162 of cloud/web.config (e.g., `diff_reports/...cloudweb.config` hunk in the patch top section).
- **v2 state:** These unsafe entries exist in `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config:161-162`, `.../CONFIG/web.config:161-162`, and virtual directory configs `.../80/web.config:493-494`, `.../20072/web.config:494-495`.
- **Mechanism:** SafeControls resolution checks explicit type entries before wildcard namespaces. Marking ExcelDataSet as `Safe="False"` overrides the wildcard `TypeName="*"` Safe entries, preventing instantiation in SafeControls-governed paths and blocking the attack vector that depended on SafeControls approval.
- **Patch scope extension:** Upgrade action `AddExcelDataSetToSafeControls` inserts these unsafe entries if missing (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs:1-22`).
- **Assumptions/limits:** Assumes all relevant web.configs include these entries and that only SafeControls-governed paths instantiate ExcelDataSet; assumes assemblies stay at versions 15/16.
- **Effectiveness rating:** **Partial.** It blocks the SafeControls-based instantiation route, but leaves wildcard Safe entries and version scope narrow.

## Part 2: Validate Each Bypass Hypothesis

### Hypothesis 1: Unpatched/alternative web.configs lacking the unsafe entry
- **Type:** Alternative attack path (config coverage gap)
- **Claim:** Other sites/vdirs without the new `Safe="False"` entry still allow ExcelDataSet via wildcard.
- **Evidence:** Many web.configs exist; patch modifies only four. Example wildcard remains Safe in v2 at `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245`. If a different vdir lacks lines 493-494 (unsafe entry), the wildcard would allow the gadget.
- **Attack path:** Deliver payload to that unpatched site; SafeControls approves via wildcard; deserialization proceeds as in v1.
- **Blocking conditions:** Only if the specific web.config includes the new unsafe entry. No evidence all configs are patched.
- **Feasibility:** **Medium (Uncertain)** — code supports possibility; requires deployment gap.
- **Verdict:** Uncertain (coverage not provable with provided files, but plausible).

### Hypothesis 2: Other Scorecards gadgets under wildcard remain safe
- **Type:** Dangerous deserialization type (alternative gadget)
- **Claim:** Namespace-wide SafeControls entries still allow other serializable Scorecards types that might deserialize attacker data.
- **Evidence:** Wildcard Safe entries remain (`snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:240-245`). Only ExcelDataSet is explicitly unsafe (493-494). Other types not reviewed/removed.
- **Attack path:** Use another serializable class in the namespace that performs unsafe deserialization (not confirmed here).
- **Blocking conditions:** Requires such a gadget to exist and be reachable; not demonstrated in provided code.
- **Feasibility:** **Low-Medium (Uncertain)** — plausible but unconfirmed without identifying a specific gadget.
- **Verdict:** Uncertain.

### Hypothesis 3: Non-SafeControls code paths using ExcelDataSet directly
- **Type:** Alternative attack path (bypasses SafeControls)
- **Claim:** APIs that accept ExcelDataSet directly would still deserialize because code unchanged.
- **Evidence:** ExcelDataSet and Helper deserialization unchanged in v2 (same as v1 files). Patch only touches config.
- **Attack path:** Requires an API endpoint taking ExcelDataSet payload outside SafeControls. Not located in provided material.
- **Blocking conditions:** Absence of such API in the provided scope; SafeControls not involved.
- **Feasibility:** **Low (Uncertain)** — theoretical without identified entry.
- **Verdict:** Uncertain.

### Hypothesis 4: Assembly version drift (new version not blacklisted)
- **Type:** Alternative attack path (version gap)
- **Claim:** Only versions 15.0.0.0 and 16.0.0.0 are marked unsafe; new version would fall back to wildcard Safe.
- **Evidence:** Unsafe entries list those two versions (`...cloudweb.config:161-162`, etc.). Wildcard remains Safe.
- **Attack path:** Deploy newer `Microsoft.PerformancePoint.Scorecards.Client` version; SafeControls matches wildcard and allows instantiation.
- **Blocking conditions:** Requires new assembly version present.
- **Feasibility:** **Low (Uncertain)** — depends on future/new assemblies.
- **Verdict:** Uncertain.

### Hypothesis 5: Tenant/site-level configs not in patched set
- **Type:** Alternative attack path (config coverage gap)
- **Claim:** Site-specific web.configs could omit the unsafe entry.
- **Evidence:** Numerous web.configs exist; patch shows only four modified. No evidence of site-level insertion.
- **Attack path:** Use unpatched site-level config inheriting Safe wildcard; attack as v1.
- **Blocking conditions:** Only if such configs exist and lack the unsafe entry.
- **Feasibility:** **Low-Medium (Uncertain)** — deployment-dependent.
- **Verdict:** Uncertain.

### Hypothesis 6: SafeControls merge/upgrade miss
- **Type:** Alternative attack path (deployment/merge failure)
- **Claim:** If upgrade action fails or node merge skipped, unsafe entry absent.
- **Evidence:** Upgrade action exists (`AddExcelDataSetToSafeControls.cs:1-22`) but effectiveness depends on running upgrade; no guarantee across all sites.
- **Attack path:** Same as Hypothesis 1 when entry absent.
- **Blocking conditions:** Successful upgrade/merge.
- **Feasibility:** **Low (Uncertain)** — operational risk, not code-level.
- **Verdict:** Uncertain.

## Part 3: Completeness Assessment

- **Total hypotheses evaluated:** 6
  - **Confirmed:** 0
  - **Uncertain:** 6
  - **Rejected:** 0

### Patch assumption validation
- Assumes all relevant configs receive explicit unsafe entries; not verified across all web.configs.
- Assumes only versions 15/16 exist; newer versions would need entries.
- Assumes deserialization only reachable via SafeControls-governed instantiation.

### Alternative attack paths checked
- Looked for other dangerous types via wildcard: none confirmed.
- Considered non-SafeControls instantiation: no concrete entry found.

### Incomplete patch coverage
- Only four configs patched in provided material; many others exist.
- Wildcard Safe entries remain untouched, leaving potential for other gadgets or version drift.

### Honest completeness statement
- [ ] “I have comprehensively validated all bypass hypotheses with code evidence”
- [x] “Some hypotheses remain uncertain due to code complexity—may require dynamic testing”
- [ ] “I identified plausible bypasses but lack complete evidence to confirm they work”
- [ ] “All hypotheses were rejected; the patch appears to comprehensively address the vulnerability”

Chosen because all bypass routes hinge on deployment/config scenarios or unconfirmed gadgets; static evidence is insufficient to fully confirm or reject.

## Part 4: Optional Adjacent Security Edits
- None observed beyond the added SafeControl entries and upgrade action relevant to ExcelDataSet.

## Final Verdict
- **Disclosed vulnerability exists in v1:** Confirmed (strong code evidence).
- **Patch addresses the vulnerability:** Partially — blocks SafeControls-based instantiation of ExcelDataSet where applied, but leaves wildcard Safe entries and potential coverage gaps.
- **Evidence quality:** Moderate to strong for vulnerability and patch mechanism; weak for bypass confirmations (all uncertain).

### Bypass Summary
- **Working bypasses identified:** None confirmed.
- **Uncertain bypasses requiring testing:** Deployment coverage gaps; other Scorecards gadgets; version drift; non-SafeControls APIs.
- **Rejected bypasses:** None.

### Key Findings
- The patch’s effectiveness relies on the presence of explicit unsafe entries in every relevant web.config; only a subset is shown patched.
- Highest-confidence remaining risk is unpatched configs relying on the unchanged wildcard SafeControls entries.
- Static analysis limitation: cannot confirm presence/absence of additional gadgets or deployment coverage without runtime/system inventory.
