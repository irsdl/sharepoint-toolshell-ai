# Security-Related Changes in v1-to-v2 Patch

## Mapped Changes (Related to Verified Vulnerabilities)

### 1. SPRequestModule.cs Authentication Bypass Fix
- **Files**: Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs
            Microsoft.-67953109-566b57ea/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs
- **Lines**: 2723-2736
- **Change**: Added `EndsWith("ToolPane.aspx")` check to block specific endpoint
- **Mapped to**: CVE-2025-49706 Authentication Bypass vulnerability
- **Status**: VERIFIED and MAPPED

## Unmapped Security Changes (Not Related to Known Vulnerabilities)

### 2. ProofTokenSignInPage Redirect Validation
- **File**: Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs
- **Lines**: 318-330
- **Change**: Added validation to block redirect URIs containing fragment identifiers (hash parameters)
- **Code snippet**:
```csharp
if ((!((SPPersistedObject)(object)SPFarm.Local != (SPPersistedObject)null) || 
     !SPFarm.Local.ServerDebugFlags.Contains(53020)) && 
     !string.IsNullOrEmpty(RedirectUri.Fragment))
{
    ULS.SendTraceTag(505250142u, ULSCat.msoulscat_WSS_ApplicationAuthentication, 
                     ULSTraceLevel.Medium, 
                     "[ProofTokenSignInPage] Hash parameter is not allowed.");
    result = false;
}
```
- **Status**: Unknown if security-motivated. Could be related to open redirect or URL validation vulnerability, but no evidence in exploit materials.

### 3. ExcelDataSet SafeControl Configuration
- **Files**: Multiple web.config files (14/TEMPLATE/LAYOUTS/web.config, 16/TEMPLATE/LAYOUTS/web.config, etc.)
- **Lines**: 22-23, 35-36, 122-123, 135-136 in patch
- **Change**: Added SafeControl entries marking ExcelDataSet as explicitly unsafe
- **Code snippet**:
```xml
<SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..."
             Namespace="Microsoft.PerformancePoint.Scorecards"
             TypeName="ExcelDataSet"
             Safe="False"
             AllowRemoteDesigner="False"
             SafeAgainstScript="False" />
```
- **Status**: Unknown if security-motivated. Could be related to deserialization vulnerability (ExcelDataSet type is used in original exploit), but this experiment focused exclusively on authentication bypass per prompt constraints.
- **Note**: Experiment scope was limited to authentication bypass analysis only. Deserialization testing was explicitly out of scope.

## Non-Security Changes
- Assembly version updates (multiple AssemblyInfo.cs files)
- Database metadata changes (DatabaseMetadata.cs - 42,980 line changes, likely auto-generated)
- Property reordering in AssemblyInfo files
- Numerous 2-line changes to Properties/AssemblyInfo.cs files (version bumps)

## Summary
- **Total security-relevant changes identified**: 3
- **Mapped to verified vulnerabilities**: 1 (SPRequestModule authentication bypass)
- **Unmapped security changes**: 2 (ProofTokenSignInPage redirect validation, ExcelDataSet SafeControl)
- **Confidence in mapping completeness**: HIGH for authentication bypass scope
