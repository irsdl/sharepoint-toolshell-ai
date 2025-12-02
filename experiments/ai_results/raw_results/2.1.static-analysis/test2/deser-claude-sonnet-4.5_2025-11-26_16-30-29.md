# CVE-2025-49704 Deserialization Vulnerability - Patch Analysis

**Agent:** Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
**Timestamp:** 2025-11-26 16:30:29
**Experiment:** Static Analysis - Deserialization Patch Evaluation

---

## Executive Summary

This analysis evaluates the patch for CVE-2025-49704, a deserialization vulnerability in SharePoint Server. The vulnerability allows remote code execution (RCE) through unsafe deserialization of the `ExcelDataSet` type from the PerformancePoint Services assembly.

**Key Findings:**
- ✅ The patch successfully blocks direct exploitation of `ExcelDataSet`
- ⚠️ **Multiple high-likelihood bypass routes identified**
- ⚠️ Other dangerous PerformancePoint types remain in the allowlist
- ⚠️ Configuration-based bypass mechanisms still present

---

## Part 1: Root Cause Analysis

### 1.1 Vulnerability Location

The deserialization vulnerability exists in SharePoint's WebPart attached properties handling:

**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/WebPart.cs`
**Lines:** 1954, 1994

```csharp
// Line 1954
SPSerializationBinderBase binder = new SPSerializationBinder(manager);
ArrayList arrayList = (ArrayList)Utility.DeserializeStringToObject(binder, _serializedAttachedPropertiesShared);

// Line 1994
arrayList = (ArrayList)Utility.DeserializeStringToObject(binder, _serializedAttachedPropertiesShared);
```

### 1.2 Deserialization Chain

The complete attack flow:

1. **Entry Point:** WebPart serialized attached properties (`_serializedAttachedPropertiesShared` or `_serializedAttachedPropertiesUser`)
2. **Deserialization Path:**
   - `Utility.DeserializeStringToObject()` → Base64 decode
   - `Utility.DeserializeByteArrayToObject()` → Uses `SPObjectStateFormatter`
   - `SPObjectStateFormatter.Deserialize()` → Calls binder to validate types

**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/Utility.cs:295-304`

```csharp
internal static object DeserializeByteArrayToObject(SPSerializationBinderBase binder, byte[] bytes)
{
    if (bytes == null || bytes.Length == 0)
    {
        return null;
    }
    IFormatter formatter = new SPObjectStateFormatter();
    formatter.Binder = binder;
    return formatter.Deserialize(new MemoryStream(bytes));
}
```

### 1.3 Type Validation Mechanism

SharePoint uses `SPSerializationBinder` to validate types during deserialization:

**File:** `Microsoft.-67953109-566b57ea/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:26-48`

The validation logic (pseudo-code):
```
1. Check if type is in hardcoded allowList → ALLOW (bypass SafeControls)
2. Check if type is in customizedAllowList → ALLOW (bypass SafeControls)
3. Check SafeControls configuration (IsSafeControl):
   - If Safe="True" → ALLOW
   - If Safe="False" → BLOCK
   - If not listed → Check ControlCompatMode
4. If ControlCompatMode=true → ALLOW (compatibility mode)
5. Otherwise → BLOCK
```

### 1.4 Why ExcelDataSet is Dangerous

**Assembly:** `Microsoft.PerformancePoint.Scorecards.Client` (Version 15.0.0.0 and 16.0.0.0)
**Namespace:** `Microsoft.PerformancePoint.Scorecards`
**Type:** `ExcelDataSet`

#### Exploitation Mechanism

In v1, `ExcelDataSet` was **not listed** in SafeControls configuration, meaning:
- It was not explicitly allowed (Safe="True")
- It was not explicitly blocked (Safe="False")
- The default behavior depends on `ControlCompatMode` setting

When an attacker can control serialized WebPart data:
1. Craft malicious payload containing `ExcelDataSet` type
2. Serialize the payload and inject into WebPart attached properties
3. SharePoint deserializes the payload, instantiating `ExcelDataSet`
4. The type's deserialization constructor/methods execute attacker-controlled logic

#### Attack Prerequisites

- **Authentication:** Authenticated user with WebPart modification permissions
- **Permissions:** Ability to create/modify WebParts or inject serialized data
- **Target:** SharePoint farm with PerformancePoint Services installed
- **Impact:** Remote Code Execution (RCE) with application pool privileges

---

## Part 2: Patch Analysis

### 2.1 Changes Made (v1 → v2)

The patch **adds** `ExcelDataSet` to SafeControls configuration with `Safe="False"`:

**Files Modified:**
1. `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config`
2. `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config`
3. `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/20072/web.config`
4. `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config`

**Diff Evidence:** `diff_reports/v1-to-v2.server-side.patch` lines 22-23, 35-36, 122-123, 135-136

#### Exact Configuration Changes

**Added in cloudweb.config (line 161-162):**
```xml
<SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"
             Namespace="Microsoft.PerformancePoint.Scorecards"
             TypeName="ExcelDataSet"
             Safe="False"
             AllowRemoteDesigner="False"
             SafeAgainstScript="False" />
<SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c"
             Namespace="Microsoft.PerformancePoint.Scorecards"
             TypeName="ExcelDataSet"
             Safe="False"
             AllowRemoteDesigner="False"
             SafeAgainstScript="False" />
```

### 2.2 Upgrade Action

**New File:** `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs`

```csharp
[TargetSchemaVersion("16.0.26.16", FromBuild = "16.0.0.0", ToBuild = "17.0.0.0")]
internal class AddExcelDataSetToSafeControls : SPWebConfigIisSiteAction
{
    public override string Description =>
        "Adding Microsoft.PerformancePoint.Scorecards.ExcelDataSet to SafeControls in web.config as unsafe.";

    public override void Upgrade()
    {
        // Checks if ExcelDataSet already exists in SafeControls
        // If not, adds it with Safe="False"
    }
}
```

### 2.3 How the Patch Prevents ExcelDataSet Exploitation

The patch works by:

1. **Explicit Blacklisting:** `ExcelDataSet` is now in SafeControls with `Safe="False"`
2. **IsSafeControl Check:** Returns `false` for `ExcelDataSet`
3. **Blocking Logic:** In `SPSerializationBinder.IsAllowedType()`:
   - If not in allowList AND `IsSafeControl()` returns false
   - AND `ControlCompatMode=false`
   - → Throws `UnsafeControlException`

**File:** `Microsoft.-67953109-566b57ea/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:41-46`

---

## Part 3: Bypass Hypotheses

### Bypass #1: PerformancePoint Types in AllowList (HIGH LIKELIHOOD)

**Hypothesis:** Other PerformancePoint types in the hardcoded allowlist can be exploited for deserialization attacks.

**Evidence:**
**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationSafeControlsAllowList.cs:9-16`

The allowlist contains multiple PerformancePoint types that **bypass SafeControls checks entirely**:

```csharp
public static readonly HashSet<string> allowList = new HashSet<string>
{
    "Microsoft.PerformancePoint.Scorecards.ProviderConsumerTransformations",
    "Microsoft.PerformancePoint.Scorecards.TransformerConfigurationRecord",
    "Microsoft.PerformancePoint.Scorecards.TransformConditionalVisibilityRecord",
    "Microsoft.PerformancePoint.Scorecards.TransformProviderConsumerRecord",
    // ... plus List wrappers:
    "System.Collections.Generic.List`1[Microsoft.PerformancePoint.Scorecards.TransformProviderConsumerRecord]",
    // ... other types
};
```

**Why This Works:**
- These types are in the **hardcoded allowlist** (line 9-16 of SPSerializationSafeControlsAllowList.cs)
- The binder checks allowlist **before** checking SafeControls
- If a type is in the allowlist, it **completely bypasses** the ExcelDataSet blacklist
- The allowlist is **identical in v1 and v2** - it was **not updated by the patch**

**Attack Scenario:**
1. Attacker identifies exploitable gadget chains using allowlisted PerformancePoint types
2. Crafts payload using `TransformerConfigurationRecord` or `ProviderConsumerTransformations`
3. Payload bypasses ExcelDataSet blacklist because it uses allowlisted types
4. Achieves RCE through alternative PerformancePoint deserialization gadget

**Likelihood: HIGH** - These types explicitly bypass SafeControls and were not addressed by the patch.

---

### Bypass #2: ControlCompatMode Configuration Bypass (HIGH LIKELIHOOD)

**Hypothesis:** If `ControlCompatMode` is enabled, ExcelDataSet deserialization is still allowed.

**Evidence:**
**File:** `Microsoft.-67953109-566b57ea/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:41-46`

```csharp
if (!base.ControlCompatMode)
{
    ULS.SendTraceTag(3981590u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
        "Allowing ControlCompatMode=false object in ObjectFormatter. Type = {0}",
        type.AssemblyQualifiedName);
    throw new SafeControls.UnsafeControlException(/*...*/);
}
ULS.SendTraceTag(3981589u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
    "Allowing ControlCompatMode=true object in ObjectFormatter. Type = {0}",
    type.AssemblyQualifiedName);
```

**Why This Works:**
- When `ControlCompatMode=true`, the exception is **not thrown**
- The logging message says "Allowing ControlCompatMode=true object"
- This suggests compatibility mode **allows even unsafe types**
- `ControlCompatMode` is read from `SafeModeSettings.SafeModeDefaults`

**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationBinderBase.cs:27`

**Attack Scenario:**
1. Attacker identifies SharePoint farm with `ControlCompatMode=true`
2. Compatibility mode is often enabled for legacy WebPart support
3. ExcelDataSet deserialization proceeds despite Safe="False" setting
4. Original vulnerability remains exploitable

**Likelihood: HIGH** - The code explicitly allows types when ControlCompatMode is enabled.

---

### Bypass #3: Customized AllowList Farm Configuration (MEDIUM LIKELIHOOD)

**Hypothesis:** Administrators can add types to the customized allowlist, potentially re-enabling ExcelDataSet.

**Evidence:**
**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationSafeControlsAllowList.cs:18`

```csharp
public static ReadOnlyCollection<string> customizedAllowList =
    SPFarm.Local.GetGenericAllowedListValues(SPFarm.SPSerializationCustomizedAllowListListName);
```

**Why This Works:**
- There's a **customized allowlist** that can be configured at the farm level
- This allowlist also **bypasses SafeControls checks**
- Administrators might add ExcelDataSet to this list for "troubleshooting"
- Social engineering attack: convince admin that ExcelDataSet needs to be allowed

**Attack Scenario:**
1. Attacker gains administrative access or social engineers an admin
2. Admin adds ExcelDataSet to customized allowlist via farm configuration
3. ExcelDataSet now bypasses the Safe="False" blacklist
4. Original vulnerability re-enabled

**Likelihood: MEDIUM** - Requires administrative action but provides documented bypass mechanism.

---

### Bypass #4: Alternative Configuration Files Not Patched (MEDIUM LIKELIHOOD)

**Hypothesis:** Some web.config files in virtual directories may not receive the patch update.

**Evidence:**
The patch update class checks for existing entries but may fail if:
- Custom virtual directories exist that aren't updated by the upgrade action
- Configuration files are manually modified and lose the ExcelDataSet blacklist
- Restore operations from pre-patch backups

**File:** `Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs:16-22`

The upgrade action only updates if entries don't exist:
```csharp
XmlNode xmlNode2 = appWebConfig.SelectSingleNode(/* check for 15.0.0.0 */);
if (xmlNode2 == null)
{
    // Only adds if not present
}
```

**Attack Scenario:**
1. Identify SharePoint virtual directories not covered by standard upgrade
2. Target WebParts in those directories
3. Exploit ExcelDataSet deserialization in unpatched configurations

**Likelihood: MEDIUM** - Depends on deployment complexity and patch application thoroughness.

---

### Bypass #5: Type Confusion via Assembly Version Mismatch (LOW LIKELIHOOD)

**Hypothesis:** Loading ExcelDataSet from a different assembly version that isn't blacklisted.

**Evidence:**
The patch blacklists specific assembly versions:
- `Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0`
- `Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0`

**Potential Weakness:**
If other versions exist (e.g., 14.0.0.0, 17.0.0.0), they may not be blacklisted.

**Attack Scenario:**
1. Deploy older/newer version of PerformancePoint assembly with ExcelDataSet
2. Craft payload referencing non-blacklisted version
3. SharePoint loads from alternative assembly version
4. Bypasses version-specific blacklist

**Likelihood: LOW** - Requires specific version availability and may fail assembly loading.

---

### Bypass #6: Property Traversal or Nested Type Instantiation (LOW LIKELIHOOD)

**Hypothesis:** Instantiate ExcelDataSet indirectly through property setters or nested objects.

**Evidence:**
SafeControls checks only validate the directly deserialized type. The allowlist includes generic collections:
- `System.Collections.Generic.Dictionary`
- `System.Collections.Generic.List`

**Attack Scenario:**
1. Deserialize an allowed type (e.g., Dictionary) containing ExcelDataSet as a property
2. Type validation only checks the container, not contents
3. ExcelDataSet instantiated during property population

**Likelihood: LOW** - ObjectStateFormatter typically validates nested types, but implementation bugs are possible.

---

## Part 4: Comprehensive Evaluation

### 4.1 Patch Completeness Assessment

**Is the patch complete?**

❌ **NO** - The patch is **incomplete** for several reasons:

1. **Allowlist Not Updated:** The hardcoded allowlist still contains exploitable PerformancePoint types
2. **ControlCompatMode Bypass:** Compatibility mode completely bypasses the blacklist
3. **Single-Type Approach:** Only ExcelDataSet was addressed; related types remain exploitable
4. **No Allowlist Audit:** Dangerous types in the allowlist were not reviewed

**Coverage:**
- ✅ All four main configuration files were updated (cloudweb.config, web.config, both virtual directories)
- ✅ Both assembly versions (15.0.0.0 and 16.0.0.0) are blacklisted
- ✅ Upgrade action ensures consistent deployment
- ❌ Allowlist mechanism still bypasses SafeControls entirely
- ❌ ControlCompatMode still allows unsafe types

### 4.2 What Can an Attacker Still Do?

**Active Exploitation Routes:**

1. **HIGH SEVERITY:** Exploit allowlisted PerformancePoint types
   - `ProviderConsumerTransformations`
   - `TransformerConfigurationRecord`
   - `TransformProviderConsumerRecord`
   - `TransformConditionalVisibilityRecord`

2. **HIGH SEVERITY:** Target systems with ControlCompatMode enabled

3. **MEDIUM SEVERITY:** Social engineer customized allowlist additions

4. **LOW SEVERITY:** Type confusion or nested type attacks

**Impact:** All bypass routes achieve the same impact as the original vulnerability:
- **Remote Code Execution (RCE)**
- **Privilege Escalation** (if lower-privilege user exploits)
- **Data Exfiltration**
- **Lateral Movement** in SharePoint farms

### 4.3 Related Vulnerabilities

**Other Dangerous Types Still Present:**

The following types remain in SafeControls with `Safe="False"` but their risk level is lower:

1. **Data Source Types:** (Blacklisted in both v1 and v2)
   - `SqlDataSource` - SQL injection risk, blacklisted
   - `ObjectDataSource` - Object instantiation risk, blacklisted
   - `XmlDataSource` - XXE risk, blacklisted
   - `AccessDataSource` - File access risk, blacklisted

2. **Dangerous Controls:** (Blacklisted in both v1 and v2)
   - `DataViewWebPart` - XSLT injection risk, blacklisted
   - `CreateUserWizard`, `PasswordRecovery` - Authentication manipulation, blacklisted

**Note:** These types were already blacklisted in v1, so they are not new findings.

### 4.4 Recommendations

**Immediate Actions:**

1. **Remove PerformancePoint Types from AllowList**
   - Remove all four PerformancePoint types from hardcoded allowlist
   - If functionality breaks, implement safer alternatives

2. **Audit and Restrict ControlCompatMode**
   - Set `ControlCompatMode=false` by default
   - If compatibility mode needed, implement stricter type validation
   - Add explicit deny list that overrides ControlCompatMode

3. **Disable Customized AllowList or Add Validation**
   - Prevent runtime modification of customized allowlist
   - Implement approval workflow for allowlist changes
   - Log all allowlist modifications

4. **Comprehensive Type Audit**
   - Review all types in hardcoded allowlist for exploitability
   - Remove or replace dangerous types
   - Document security reasoning for each allowed type

**Defense-in-Depth Measures:**

5. **Implement Allowlist-by-Default**
   - Change model from "blacklist dangerous types" to "allowlist safe types"
   - Require explicit approval for any deserialization type

6. **Runtime Deserialization Monitoring**
   - Log all deserialization events with type information
   - Alert on attempts to deserialize PerformancePoint types
   - Monitor for ControlCompatMode usage

7. **Least Privilege for WebPart Modification**
   - Restrict WebPart creation/modification permissions
   - Implement approval workflow for custom WebParts
   - Audit WebPart property changes

8. **Code-Level Improvements**
   - Replace ObjectStateFormatter with safer serialization (JSON)
   - Implement type validation before deserialization attempt
   - Add security boundary checks in PerformancePoint types

---

## Conclusion

The CVE-2025-49704 patch **successfully blocks direct ExcelDataSet exploitation** but leaves **multiple high-likelihood bypass routes**. The most critical issues are:

1. **Allowlisted PerformancePoint types bypass the entire SafeControls mechanism**
2. **ControlCompatMode provides a configuration-based bypass**
3. **The patch follows a blacklist approach rather than allowlist-by-default**

**Risk Assessment:**
- **Direct ExcelDataSet Exploit:** Patched ✅
- **Alternative PerformancePoint Exploits:** HIGH RISK ⚠️
- **ControlCompatMode Bypass:** HIGH RISK ⚠️
- **Configuration-Based Bypasses:** MEDIUM RISK ⚠️

**Overall Assessment:** The patch is a **partial mitigation** that addresses the specific CVE but does not comprehensively solve the underlying deserialization vulnerability class. Additional hardening is strongly recommended.

---

## Appendix: Evidence Summary

### Key Files Analyzed

**Configuration Files:**
- `snapshots_norm/v1/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config`
- `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config`
- Corresponding web.config files in both versions

**Deserialization Code:**
- `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/Utility.cs:295-304`
- `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/WebPart.cs:1940-2019`
- `Microsoft.-67953109-566b57ea/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:26-48`

**Type Validation:**
- `Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SafeControls.cs:313-362`
- `Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationSafeControlsAllowList.cs:9-18`

**Patch Implementation:**
- `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs`
- `diff_reports/v1-to-v2.server-side.patch`

### Exploitation Path Diagram

```
User Input (Malicious Serialized Data)
    ↓
WebPart._serializedAttachedPropertiesShared
    ↓
Utility.DeserializeStringToObject()
    ↓
Utility.DeserializeByteArrayToObject()
    ↓
SPObjectStateFormatter.Deserialize()
    ↓
SPSerializationBinder.IsAllowedType()
    ↓
┌─────────────────────────────────────┐
│  1. Check allowList?                │ → YES → ALLOW (BYPASS!)
│  2. Check customizedAllowList?      │ → YES → ALLOW (BYPASS!)
│  3. Check IsSafeControl()?          │ → NO  → Check ControlCompatMode
│  4. ControlCompatMode enabled?      │ → YES → ALLOW (BYPASS!)
│                                     │ → NO  → BLOCK
└─────────────────────────────────────┘
```

---

**End of Analysis**
