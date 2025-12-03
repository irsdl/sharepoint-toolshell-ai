# Final Verification

## Vulnerability 1: PerformancePoint ExcelDataSet unsafe deserialization (RCE)

- **Diff evidence (config + upgrade):**
  - `diff_reports/v1-to-v2.server-side.patch` (cloud/web configs) adds explicit unsafe SafeControls:
    ```xml
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
    +      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
    ```
  - Upgrade action added: `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs` (same in `...-67953109-566b57ea`): ensures those entries are injected if missing.

- **v1 vulnerable behavior:**
  - SafeControls (e.g., `snapshots_norm/v1/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config:242-245`) allow the entire namespace: `TypeName="*"` for `Microsoft.PerformancePoint.Scorecards.Client`/`Microsoft.PerformancePoint.Scorecards`. Thus pages can instantiate `ExcelDataSet`.
  - `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs`:
    ```csharp
    public DataTable DataTable {
        get {
            if (dataTable == null && compressedDataTable != null) {
                dataTable = Helper.GetObjectFromCompressedBase64String(compressedDataTable, ExpectedSerializationTypes) as DataTable;
            }
            return dataTable;
        }
        set { dataTable = value; compressedDataTable = null; }
    }
    ```
  - `Helper.GetObjectFromCompressedBase64String` (`Helper.cs:580`): Base64 decode → GZip → `BinarySerialization.Deserialize` (BinaryFormatter with limited binder) over attacker-controlled `compressedDataTable`.
  - **Flow:** Site Owner supplies `CompressedDataTable` in Scorecards content → SafeControls instantiate `ExcelDataSet` → getter deserializes untrusted payload via BinaryFormatter → attacker can embed malicious DataTable gadget → RCE under web app identity.

- **Bypass/completeness check (v1):**
  - Other `Microsoft.PerformancePoint.Scorecards.Client` types remain Safe (`TypeName="*"`). Several code paths use the same helper (e.g., `Helper.cs` for calculated members). These are potential alternate deserialization vectors.
  - `ExcelDataSet` could also be loaded by server APIs/imports that bypass SafeControls, since the class remains present.

- **v2 mitigation:**
  - SafeControl entries mark `ExcelDataSet` explicitly `Safe="False"` and upgrade seeds configs, so page parsing rejects the type even though the wildcard remains.
  - The code itself is unchanged (deserialization still present); protection is configuration-based.

- **Bypass/completeness (v2):**
  - Blocks instantiation via SafeControls but does **not** remove the class or change deserialization. Alternate invocation paths (service/import APIs) or other Scorecards types using the helper remain unblocked. Fix is partial.

- **Confidence:** High (direct code path to BinaryFormatter on user data; config change explicitly blocks the type).

## Vulnerability 2: ProofToken redirect fragment acceptance (auth redirect abuse / spoofing)

- **Diff evidence:**
  - `diff_reports/v1-to-v2.server-side.patch` for `ProofTokenSignInPage.cs` adds fragment rejection inside `ShouldRedirectWithProofToken`:
    ```csharp
    +            if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || !SPFarm.Local.ServerDebugFlags.Contains(53020)) && !string.IsNullOrEmpty(RedirectUri.Fragment))
    +            {
    +                ULS.SendTraceTag(..., "[ProofTokenSignInPage] Hash parameter is not allowed.");
    +                result = false;
    +            }
    ```

- **v1 vulnerable behavior:**
  - In v1 `ShouldRedirectWithProofToken` (same file):
    ```csharp
    if (null != RedirectUri) { result = IsAllowedRedirectUrl(RedirectUri); }
    ```
  - No check for `RedirectUri.Fragment`. A crafted URL with a `#fragment` can hide parameters from server-side parsing; client could follow fragment to attacker-controlled content with proof tokens or redirect targets, enabling token leakage/phishing-style spoofing. No privilege required beyond reaching the page.

- **Bypass/completeness (v1):**
  - Other redirect paths in the product are not shown; this page was permissive to fragments. Single validated path here.

- **v2 mitigation:**
  - Rejects any fragment unless debug flag is set; sets `result=false`, stopping redirect. Prevents fragment-based smuggling on this endpoint.

- **Bypass/completeness (v2):**
  - Only this method is hardened. Other endpoints could still allow fragment-bearing redirects; not assessed here. Within this method, the check is straightforward; no evident edge-case bypass besides setting debug flag (controlled by farm admins).

- **Confidence:** Medium (clear logic change; impact requires attacker leveraging fragments, but behavior is consistent with spoofing fix).

## Vulnerability 3: Anonymous access to `_forms` virtual directory (auth bypass)

- **Diff evidence:**
  - `diff_reports/v1-to-v2.server-side.patch` (applicationHost.config):
    ```xml
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

- **v1 vulnerable behavior:**
  - IIS location enabled `anonymousAuthentication` for `/SharePoint - 80/_forms`, exposing auth-related pages/assets without auth. Could allow token leakage, spoofing, or serving modified login resources to unauthenticated users.

- **Bypass/completeness (v1):**
  - Specific to this path; other locations might also allow anonymous, but this was explicitly configured.

- **v2 mitigation:**
  - Entire location block removed; `_forms` inherits default authentication (typically NTLM/claims), closing anonymous access.

- **Bypass/completeness (v2):**
  - If other zones/virtual directories reintroduce anonymous access, bypass remains; not seen in patch. Within this file, the path is closed.

- **Confidence:** Medium (clear config change removing anonymous access; exact exploit depends on served content, but risk is plausible).

## Vulnerability 4 (candidate CVE-2025-49701): Restricted PowerShell session importing modules from network/device paths (RCE)

- **Diff evidence:**
  - `diff_reports/v1-to-v2.server-side.patch` `ShowCommandCommand.cs`:
    ```csharp
    +            string path = FileSystemProvider.NormalizePath(base.SessionState.Path.GetUnresolvedProviderPathFromPSPath(showCommandProxy.ParentModuleNeedingImportModule));
    +            if (Utils.IsSessionRestricted(base.Context) && (FileSystemProvider.NativeMethods.PathIsNetworkPath(path) || Utils.PathIsDevicePath(path)))
    +            {
    +                ErrorRecord errorRecord = new ErrorRecord(new ArgumentException(HelpErrors.NoNetworkCommands, "Name"), "CommandNameNotAllowed", ErrorCategory.InvalidArgument, null);
    +                ThrowTerminatingError(errorRecord);
    +            }
    ```

- **v1 vulnerable behavior:**
  - Same code path existed without the above check; when `ShowCommand` auto-imported a module (`ParentModuleNeedingImportModule`), a restricted session could resolve a UNC/device path and import it. That allows executing module init code from network/device locations despite session restrictions → RCE.
  - Input source: module name/path passed to ShowCommand; in restricted session, user could request a module on a UNC path.

- **Bypass/completeness (v1):**
  - Other PowerShell cmdlets may also allow UNC imports; this fix is scoped to ShowCommand. Within ShowCommand, this was the missing guard.

- **v2 mitigation:**
  - In restricted sessions, if path is network/device, it throws terminating error before import. Blocks this path to load remote modules.

- **Bypass/completeness (v2):**
  - Local file imports still allowed; if attacker can place module locally, attack persists (expected). Other cmdlets might still allow UNC imports; this fix is narrow.

- **Confidence:** Medium (clear new guard; RCE feasible if restricted sessions previously forbade such loads by policy). Candidate for CVE-2025-49701.

## Coverage of security-relevant changes

- **Mapped to above vulns:**
  - SafeControl additions + upgrade actions → Vuln 1. They address the instantiation path; other deserialization vectors remain.
  - ProofToken fragment check → Vuln 2. Only covers this page; other redirect paths not covered.
  - `_forms` anonymous removal → Vuln 3. Specific path; other paths unknown.
  - ShowCommand restricted-path guard → Vuln 4 candidate.

- **Potentially security-related but unmapped:**
  - `applicationHost.config` new MIME types (.appx, .msix, .msu, .wim): functional addition; unknown if security-motivated.
  - Large refactor of `Microsoft.Office.Project.Server.Database.DatabaseMetadata.cs`: variable type reshuffle/renaming; no clear security effect.
  - AppCache manifest version bumps (`AppCacheManifestPage.cs`, `MDSStartAppCacheManifestPage.cs`): version string changes only; likely non-security.
  - AssemblyInfo version bumps: maintenance.

- **CVE-2025-49701 candidates:**
  - Strong: ShowCommand restricted-session UNC/device import guard (new RCE block).
  - Possible: Other `Microsoft.PerformancePoint.Scorecards` types using `Helper.GetObjectFromCompressedBase64String` remain allowed by wildcard SafeControls (not patched); could be additional deserialization RCE paths.

## Confidence and status

- ExcelDataSet deserialization RCE: **Confirmed**, confidence High. Patch blocks SafeControl instantiation but leaves other avenues.
- ProofToken fragment redirect abuse: **Confirmed**, confidence Medium. Patch explicitly rejects fragments; other endpoints unchecked.
- `_forms` anonymous access: **Confirmed**, confidence Medium. Config removal closes that path; exploit specifics depend on served content.
- ShowCommand restricted-session remote module import: **Confirmed (candidate CVE-2025-49701)**, confidence Medium. Clear new guard against UNC/device imports; other cmdlets may still allow similar behavior.

## Bypass validation summary

- CVE-2025-49704 (ExcelDataSet): Dangerous element identified: `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` BinaryFormatter deserialization. Additional potential vectors (other Scorecards types using the same helper) remain **unblocked**; only one explicit type was denied. Bypass feasibility: Medium (alternate types or non-SafeControl entry points could be abused). Not fully exhaustively explored → **Only validated one explicit path; others likely exist**.

- CVE-2025-49706 (auth/spoofing): Two distinct paths validated: (1) fragment-based redirect in ProofTokenSignInPage; (2) anonymous `_forms` exposure. Other auth bypass paths not examined → **Only two validated paths; others may exist**. Feasibility: High for fragment abuse with crafted URLs; Medium for `_forms` depending on content.

- CVE-2025-49701 (unknown RCE): Candidate ShowCommand UNC import blocked. Feasibility: Medium (requires restricted session context and ability to point to network/device module). Other deserialization candidates in Scorecards remain speculative; not validated.

- Overall bypass coverage: I have **not** comprehensively exhausted all alternative endpoints; fixes are narrow and other paths may remain.
