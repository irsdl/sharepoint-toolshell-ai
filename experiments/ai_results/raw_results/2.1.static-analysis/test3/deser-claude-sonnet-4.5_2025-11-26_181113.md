# Deserialization Vulnerability Patch Analysis - CVE-2025-49704

**Metadata:**
- Agent: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
- Timestamp: 2025-11-26 18:11:13
- Experiment: Static Analysis - Deserialization Patch Evaluation

---

## Executive Summary

This analysis evaluates a security patch applied to SharePoint Server that addresses a .NET deserialization vulnerability involving the `ExcelDataSet` type from the PerformancePoint Scorecards component. The patch adds explicit blacklist entries marking `ExcelDataSet` as unsafe (`Safe="False"`) in SharePoint configuration files.

**Key Findings:**
- **Vulnerability Type:** .NET Binary Deserialization leading to Remote Code Execution
- **Root Cause:** `ExcelDataSet` type allowed in deserialization context without explicit restrictions
- **Patch Approach:** Configuration-based blacklisting via SafeControl entries
- **Effectiveness:** Partial - may be bypassable depending on ControlCompatMode setting
- **Risk Level:** High - other dangerous deserializable types remain in configuration

---

## Part 1: Root Cause Analysis

### 1.1 Vulnerability Mechanism

SharePoint uses .NET Binary Deserialization to serialize/deserialize web part and object state. The deserialization process is controlled by `SPSerializationBinder` which validates types before allowing deserialization.

**Key Components:**
- **SPSerializationBinder.cs** (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:26-48`)
- **SafeSerialization.cs** (`snapshots_decompiled/v2/Microsoft.-0dabac64-19146cec/Microsoft/Office/Server/Security/SafeSerialization.cs`)
- **SafeControls.cs** (`snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SafeControls.cs:313-362`)

### 1.2 ExcelDataSet as a Deserialization Gadget

`ExcelDataSet` is part of the Microsoft PerformancePoint Scorecards component (`Microsoft.PerformancePoint.Scorecards.Client` assembly). While the exact implementation of `ExcelDataSet` is not visible in the decompiled sources, its presence in a security patch blacklist strongly indicates it can be exploited as a .NET deserialization gadget.

**Why ExcelDataSet is Dangerous:**

1. **Assembly Context:** Located in `Microsoft.PerformancePoint.Scorecards.Client` - a legitimate Microsoft assembly with full trust
2. **Serializable Type:** Implicitly marked as serializable for web part state persistence
3. **Gadget Characteristics:** Types with complex deserialization logic, event handlers, or type converters can trigger arbitrary code execution during the deserialization process
4. **Presence in Patch:** The explicit blacklisting in `AddExcelDataSetToSafeControls.cs` (v2 only) confirms exploitation potential

### 1.3 Attack Flow

**Deserialization Entry Points:**

From `SPSerializationBinder.cs:26-48`, the validation logic is:

```csharp
protected override void IsAllowedType(Type type)
{
    if (!(null != type) || m_safeControls == null || type.IsEnum)
        return;

    string text = anonymousTypeRegex.Replace(type.ToString(), "<>f__AnonymousType`");
    bool flag = m_safeControls.IsSafeControl(m_isAppWeb, type, out unsafeErrorMessage);

    // Check against hardcoded allowlist
    if (!SPSerializationSafeControlsAllowList.allowList.Contains(text) &&
        (SPSerializationSafeControlsAllowList.customizedAllowList == null ||
         !SPSerializationSafeControlsAllowList.customizedAllowList.Contains(text)))
    {
        if (flag) // Type passed SafeControl check but not in allowlist
        {
            ULS.SendTraceTag(..., "Missed type in new allowlist. Type = {0}", text);
        }

        // CRITICAL: ControlCompatMode determines if type is blocked
        if (!base.ControlCompatMode)
        {
            // Block the deserialization
            throw new SafeControls.UnsafeControlException(...);
        }
        // If ControlCompatMode=true, type is ALLOWED (backward compatibility)
    }
}
```

**Attack Prerequisites:**

1. **Attacker Capability:** Ability to supply serialized data to SharePoint (e.g., via web part import, ViewState manipulation, or API endpoints accepting serialized objects)
2. **System Configuration:**
   - ExcelDataSet NOT in hardcoded allowlist (confirmed: `SPSerializationSafeControlsAllowList.cs:11-15` doesn't contain it)
   - ControlCompatMode=true (backward compatibility mode)
   - OR no explicit Safe="False" entry in web.config (v1 condition)

**Attack Scenario:**

```
1. Attacker crafts malicious serialized payload containing ExcelDataSet gadget chain
2. Payload submitted to SharePoint endpoint (e.g., web part import, ViewState)
3. SharePoint deserializes using BinaryFormatter with SPSerializationBinder
4. SPSerializationBinder.IsAllowedType() checks:
   - ExcelDataSet not in hardcoded allowlist ✓
   - Check IsSafeControl() from web.config
     * v1: No entry → returns false/null → uses default behavior
     * v2: Safe="False" → returns false
   - Check ControlCompatMode
     * If ControlCompatMode=true → ALLOWS deserialization (VULNERABLE)
     * If ControlCompatMode=false → BLOCKS deserialization (SECURE)
5. If allowed, ExcelDataSet deserialization triggers RCE gadget chain
6. Attacker achieves code execution in SharePoint app pool context
```

**Impact:** Remote Code Execution (RCE) with privileges of the SharePoint application pool identity (typically high-privileged service account).

---

## Part 2: Patch Analysis

### 2.1 Configuration Changes (v1 → v2)

**Files Modified:**
- `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config`
- `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config`
- `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/20072/web.config`
- `snapshots_norm/v2/C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config`

**Exact Changes (from `diff_reports/v1-to-v2.server-side.patch:21-23`):**

```xml
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="ExcelDataSet" Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
```

**Key Attributes:**
- `Safe="False"` - Marks type as explicitly unsafe
- `AllowRemoteDesigner="False"` - Prevents remote designer access
- `SafeAgainstScript="False"` - Prevents script access
- **Two entries:** Version 15.0.0.0 (SharePoint 2013 compatibility) and 16.0.0.0 (SharePoint 2016/2019)

### 2.2 Code Changes

**New Upgrade Action:**

File: `snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs`

```csharp
[TargetSchemaVersion("16.0.26.16", FromBuild = "16.0.0.0", ToBuild = "17.0.0.0")]
internal class AddExcelDataSetToSafeControls : SPWebConfigIisSiteAction
{
    public override string Description =>
        "Adding Microsoft.PerformancePoint.Scorecards.ExcelDataSet to SafeControls in web.config as unsafe.";

    public override void Upgrade()
    {
        // Adds Safe="False" entries for both v15 and v16 assemblies
    }
}
```

This upgrade action ensures that ExcelDataSet entries are added during SharePoint patch installation.

### 2.3 How the Patch Prevents ExcelDataSet Exploitation

**SafeControl Enforcement (from `SafeControls.cs:318-362`):**

```csharp
internal bool IsSafeControl(bool isAppWeb, Type type, out string unsafeErrorMessage)
{
    bool flag = false;
    SafeTypeData safeTypeData = FindTypeEntryInfo(type);  // Reads web.config SafeControl entries

    if (safeTypeData != null)
    {
        flag = safeTypeData.IsSafe;  // Gets the Safe="True/False" value
    }

    return flag;  // Returns false if Safe="False"
}
```

**Protection Mechanism:**

1. When deserialization attempts to load ExcelDataSet type
2. `SPSerializationBinder.IsAllowedType()` calls `IsSafeControl()`
3. `IsSafeControl()` finds SafeControl entry with `Safe="False"`
4. Returns `false`, indicating type is not safe
5. **Critical Caveat:** The blocking only occurs if:
   - ControlCompatMode=false, OR
   - Type validation is enforced elsewhere in the code path

### 2.4 Completeness Assessment

**What was patched:**
- ✅ ExcelDataSet v15.0.0.0 explicitly blacklisted
- ✅ ExcelDataSet v16.0.0.0 explicitly blacklisted
- ✅ Entries added to all relevant web.config files (root, virtual directories)

**What was NOT patched:**
- ❌ No code changes to SPSerializationBinder enforcement logic
- ❌ ControlCompatMode behavior unchanged (still allows non-allowlisted types if enabled)
- ❌ Other dangerous deserializable types remain with `Safe="False"` but same enforcement issues

---

## Part 3: Bypass Hypotheses

### 3.1 HIGH Likelihood: ControlCompatMode Bypass

**Hypothesis:** ExcelDataSet deserialization may still succeed if ControlCompatMode=true, despite Safe="False" configuration.

**Evidence:**

From `SPSerializationBinder.cs:35-47`:

```csharp
if (!SPSerializationSafeControlsAllowList.allowList.Contains(text) && ...)
{
    if (flag)  // IsSafeControl returned true
    {
        ULS.SendTraceTag(..., "Missed type in new allowlist. Type = {0}", text);
    }

    if (!base.ControlCompatMode)  // Only blocks if ControlCompatMode=false
    {
        throw new SafeControls.UnsafeControlException(...);
    }
    // If ControlCompatMode=true, execution continues without blocking
}
```

**Attack Scenario:**
1. Identify SharePoint instance with ControlCompatMode=true (backward compatibility enabled)
2. Craft ExcelDataSet deserialization payload
3. Submit payload via web part import or ViewState manipulation
4. Despite Safe="False" entry, type is deserialized due to ControlCompatMode bypass
5. RCE achieved via ExcelDataSet gadget chain

**Likelihood:** HIGH
- Evidence: Direct code analysis shows ControlCompatMode overrides SafeControl checks
- No diff between v1 and v2 SPSerializationBinder.cs (no enforcement improvement)
- ControlCompatMode likely enabled in many environments for backward compatibility

**Mitigation Required:** Ensure ControlCompatMode=false in all production environments, or modify SPSerializationBinder to enforce Safe="False" regardless of ControlCompatMode.

---

### 3.2 MEDIUM Likelihood: Alternative Dangerous Types

**Hypothesis:** Other types marked Safe="False" in the configuration could serve as alternative deserialization gadgets.

**Evidence from Configuration Files:**

File: `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config:42-52`

```xml
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="SqlDataSource" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="AdRotator" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="AccessDataSource" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="XmlDataSource" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="ObjectDataSource" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="Xml" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="RegularExpressionValidator" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="CreateUserWizard" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="PasswordRecovery" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="ChangePassword" Safe="False" ... />
<SafeControl Assembly="System.Web, Version=4.0.0.0, ..." TypeName="Substitution" Safe="False" ... />
```

File: `snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config:100-122`

```xml
<SafeControl Assembly="Microsoft.SharePoint, Version=15.0.0.0, ..." TypeName="DataViewWebPart" Safe="False" ... />
<SafeControl Assembly="Microsoft.SharePoint, Version=16.0.0.0, ..." TypeName="DataViewWebPart" Safe="False" ... />
<SafeControl Assembly="Microsoft.SharePoint.ApplicationPages, Version=16.0.0.0, ..." TypeName="SPThemes" Safe="False" ... />
```

**Known Dangerous Types:**

1. **ObjectDataSource** - Well-documented deserialization gadget in .NET, can invoke arbitrary methods
2. **XmlDataSource / SqlDataSource / AccessDataSource** - Data source controls with exploitable deserialization
3. **DataViewWebPart** - SharePoint web part with complex deserialization logic
4. **AdRotator** - Historically associated with XXE and deserialization issues

**Attack Scenario:**
1. Identify alternative gadget type from Safe="False" list
2. Research/develop exploitation chain (e.g., ObjectDataSource → arbitrary method invocation)
3. Craft payload using alternative gadget
4. If ControlCompatMode=true, bypass Safe="False" restriction
5. Achieve RCE via alternative gadget

**Likelihood:** MEDIUM
- Evidence: Multiple dangerous types present in configuration with same Safe="False" marking
- ObjectDataSource is a proven .NET deserialization gadget
- Same ControlCompatMode bypass applies to all types
- Exploitation requires gadget chain development

**Supporting Evidence:** Previous upgrade actions show pattern of blacklisting dangerous types:
- `MarkAdRotatorUnsafeInSafeControls.cs` (v16.0.26.10)
- `RestrictPasswordRecoveryFromSafeControls.cs` (v16.0.26.4)
- `AddExcelDataSetToSafeControls.cs` (v16.0.26.16) ← Current patch

This pattern suggests multiple types have been exploited in the wild or identified as high-risk.

---

### 3.3 MEDIUM Likelihood: Custom AllowList Manipulation

**Hypothesis:** If an attacker can modify the customized allowlist (`SPSerializationCustomizedAllowList`), they could re-enable dangerous types including ExcelDataSet.

**Evidence:**

From `SPSerializationSafeControlsAllowList.cs:18`:

```csharp
public static ReadOnlyCollection<string> customizedAllowList =
    SPFarm.Local.GetGenericAllowedListValues(SPFarm.SPSerializationCustomizedAllowListListName);
```

From `SPSerializationBinder.cs:35`:

```csharp
if (!SPSerializationSafeControlsAllowList.allowList.Contains(text) &&
    (SPSerializationSafeControlsAllowList.customizedAllowList == null ||
     !SPSerializationSafeControlsAllowList.customizedAllowList.Contains(text)))
{
    // Type is blocked (unless ControlCompatMode=true)
}
```

**Attack Scenario:**
1. Attacker gains access to modify SharePoint farm configuration (requires high privileges)
2. Add "Microsoft.PerformancePoint.Scorecards.ExcelDataSet" to `SPSerializationCustomizedAllowList`
3. Type now bypasses both hardcoded and SafeControl checks
4. ExcelDataSet can be deserialized freely
5. RCE via ExcelDataSet gadget

**Likelihood:** MEDIUM
- Prerequisites: Requires SharePoint farm administrator access or SQL database access
- Evidence: Custom allowlist explicitly checked before blocking
- If attacker has farm admin access, many easier attack paths exist
- Plausible in compromised environment for privilege escalation or persistence

---

### 3.4 LOW Likelihood: Assembly Version Bypass

**Hypothesis:** ExcelDataSet could be loaded from a different assembly version not explicitly blacklisted.

**Evidence:**

Patch blacklists only two versions:
- `Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0` (SharePoint 2013)
- `Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0` (SharePoint 2016/2019)

From `SafeControls.cs:578`:

```csharp
private SafeTypeData FindTypeEntryInfo(Type type)
{
    if (_safeControlsList.SafeAssemblyInfoDictionary.TryGetValue(type.Assembly.FullName, out var value))
    {
        result = value.FindTypeEntryInfo(type);
    }
}
```

The lookup uses `type.Assembly.FullName` which includes the version number, culture, and public key token.

**Attack Scenario:**
1. Identify an alternative assembly version (e.g., 14.0.0.0 for SharePoint 2010 compatibility, or hypothetical 17.0.0.0)
2. Ensure that version is present in GAC or application bin directory
3. Craft payload using alternative version
4. SafeControl check fails to find explicit Safe="False" entry for that version
5. Type allowed if ControlCompatMode=true
6. RCE via ExcelDataSet from alternative assembly version

**Likelihood:** LOW
- SharePoint 2013/2016/2019 are the primary target versions (covered by patch)
- SharePoint 2010 (v14) is out of support and less common
- Future versions (v17+) unlikely to exist in current deployments
- Assembly binding redirects may normalize versions
- Even if bypass works, requires specific assembly version to be present

---

### 3.5 LOW Likelihood: Type Name Obfuscation

**Hypothesis:** Slight variations in type name formatting could bypass SafeControl matching.

**Evidence:**

From `SPSerializationBinder.cs:32`:

```csharp
string text = anonymousTypeRegex.Replace(type.ToString(), "<>f__AnonymousType`");
```

The code normalizes anonymous types but performs exact string matching for other types.

**Attack Scenario:**
1. Attempt to use generic type instantiation: `ExcelDataSet<T>`
2. Use nested type path: `OuterClass+ExcelDataSet`
3. Rely on case sensitivity differences (unlikely in .NET)

**Likelihood:** LOW
- .NET type system is strict about type names and assembly qualified names
- SafeControl lookup uses Assembly.FullName which is normalized by .NET runtime
- No evidence of flexible matching or wildcard support in SafeControl code
- Type instantiation must match exactly for deserialization to succeed

---

## Part 4: Comprehensive Evaluation

### 4.1 Is the Patch Complete?

**Completeness by Objective:**

✅ **Removes all ExcelDataSet v15/v16 references:** YES
- Both assembly versions explicitly blacklisted
- Entries added to all configuration files

❌ **Prevents ExcelDataSet exploitation in all scenarios:** NO
- ControlCompatMode bypass remains viable
- No code-level enforcement improvement

❌ **Addresses root cause of deserialization vulnerability:** NO
- Other dangerous types remain exploitable
- Deserialization architecture unchanged
- BinaryFormatter still in use (inherently insecure)

**Configuration Coverage:**

| File | v1 State | v2 State | Status |
|------|----------|----------|--------|
| `/16/CONFIG/cloudweb.config` | No ExcelDataSet entry | Safe="False" added | ✅ Patched |
| `/16/CONFIG/web.config` | No ExcelDataSet entry | Safe="False" added | ✅ Patched |
| `/VirtualDirectories/20072/web.config` | No ExcelDataSet entry | Safe="False" added | ✅ Patched |
| `/VirtualDirectories/80/web.config` | No ExcelDataSet entry | Safe="False" added | ✅ Patched |

**Enforcement Coverage:**

| Protection Mechanism | v1 | v2 | Gap |
|---------------------|----|----|-----|
| Hardcoded allowlist | ❌ ExcelDataSet not included | ❌ Still not included | Should add ExcelDataSet to prevent any bypass |
| SafeControl blacklist | ❌ No entry | ✅ Safe="False" | Depends on ControlCompatMode enforcement |
| ControlCompatMode enforcement | ❌ Bypasses checks | ❌ Still bypasses checks | **CRITICAL GAP** |
| Deserialization Binder | ⚠️ Checks SafeControl | ⚠️ No change | No improvement in enforcement logic |

---

### 4.2 What Could an Attacker Still Do?

**Post-Patch Attack Scenarios (Ordered by Likelihood):**

1. **HIGH - ControlCompatMode Exploitation**
   - Target: Environments with ControlCompatMode=true
   - Method: ExcelDataSet or alternative gadget deserialization
   - Impact: RCE
   - Prerequisites: ControlCompatMode=true, ability to submit serialized data

2. **MEDIUM - Alternative Gadget Chains**
   - Target: ObjectDataSource, XmlDataSource, DataViewWebPart (all Safe="False")
   - Method: Develop exploitation chain for alternative type
   - Impact: RCE
   - Prerequisites: ControlCompatMode=true, gadget chain development

3. **MEDIUM - Farm Configuration Manipulation**
   - Target: SPSerializationCustomizedAllowList
   - Method: Add ExcelDataSet to custom allowlist
   - Impact: Re-enable ExcelDataSet deserialization
   - Prerequisites: Farm admin or database access

4. **LOW - Assembly Version Variation**
   - Target: Non-blacklisted assembly versions (v14, v17+)
   - Method: Load ExcelDataSet from alternative version
   - Impact: RCE
   - Prerequisites: Alternative assembly present, ControlCompatMode=true

**Attacker Decision Tree:**

```
Can attacker supply serialized data to SharePoint?
├─ YES → Is ControlCompatMode=true?
│         ├─ YES → Can use ExcelDataSet (HIGH risk) ✓
│         │        OR alternative gadget (MEDIUM risk) ✓
│         └─ NO → Blocked by SafeControl enforcement ✗
└─ NO → Cannot exploit deserialization ✗

Has attacker gained farm admin access?
├─ YES → Modify custom allowlist (MEDIUM risk) ✓
└─ NO → Limited to ControlCompatMode bypass ✓
```

---

### 4.3 Recommended Additional Patches

**Immediate Priority (Address Critical Gaps):**

1. **Enforce SafeControl Checks Regardless of ControlCompatMode**

   **Location:** `Microsoft.SharePoint.WebPartPages.SPSerializationBinder.IsAllowedType()`

   **Change:** Remove or restrict ControlCompatMode bypass for Safe="False" types

   ```csharp
   // CURRENT (VULNERABLE):
   if (!base.ControlCompatMode)
   {
       throw new SafeControls.UnsafeControlException(...);
   }
   // Type allowed if ControlCompatMode=true

   // RECOMMENDED:
   if (!base.ControlCompatMode || (safeTypeData != null && !safeTypeData.IsSafe))
   {
       throw new SafeControls.UnsafeControlException(...);
   }
   // Blocks Safe="False" types even when ControlCompatMode=true
   ```

2. **Add ExcelDataSet to Hardcoded Allowlist as Explicitly Denied**

   **Location:** `SPSerializationSafeControlsAllowList.cs`

   **Approach:** Create a hardcoded deny list that takes precedence over all other checks

   ```csharp
   public static readonly HashSet<string> denyList = new HashSet<string>
   {
       "Microsoft.PerformancePoint.Scorecards.ExcelDataSet",
       "System.Web.UI.WebControls.ObjectDataSource",
       // ... other dangerous types
   };
   ```

3. **Implement Deserialization Event Logging**

   **Location:** `SPSerializationBinder.IsAllowedType()`

   **Change:** Log all deserialization attempts for Safe="False" types (currently only logs when type is in SafeControl but not in allowlist)

**High Priority (Defense in Depth):**

4. **Blacklist Additional Dangerous Data Source Types**
   - `ObjectDataSource` (proven RCE gadget)
   - `XmlDataSource`
   - `SqlDataSource`
   - `AccessDataSource`

   **Note:** These already have Safe="False", but need code-level enforcement per recommendation #1

5. **Implement Assembly Version Wildcarding**

   **Location:** SafeControl matching logic

   **Change:** Support wildcard versions in SafeControl entries

   ```xml
   <!-- Block all versions of ExcelDataSet -->
   <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=*, ..."
                TypeName="ExcelDataSet" Safe="False" ... />
   ```

**Medium Priority (Long-term Security):**

6. **Deprecate BinaryFormatter**

   **Approach:** Migrate to safer serialization:
   - JSON serialization for web part properties
   - DataContractSerializer with known types for object graphs
   - Custom serialization with strict type validation

7. **Implement Serialization Firewall**

   **Approach:** Add an additional validation layer before BinaryFormatter:
   - Inspect serialized stream for type names
   - Block known dangerous types before deserialization
   - Log all deserialization attempts for security monitoring

8. **Remove ControlCompatMode or Make Opt-In Per-Type**

   **Current Risk:** ControlCompatMode=true creates blanket bypass

   **Recommendation:**
   - Remove ControlCompatMode entirely (breaking change)
   - OR make it opt-in per specific safe types rather than global setting

---

## Part 5: Additional Observations

### 5.1 Pattern of Incremental Blacklisting

Evidence of ongoing security issue discovery:

| Patch Version | Type Blacklisted | Class |
|--------------|------------------|-------|
| 16.0.26.4 | PasswordRecovery | `RestrictPasswordRecoveryFromSafeControls.cs` |
| 16.0.26.10 | AdRotator | `MarkAdRotatorUnsafeInSafeControls.cs` |
| **16.0.26.16** | **ExcelDataSet** | `AddExcelDataSetToSafeControls.cs` |

This pattern suggests:
- Reactive rather than proactive security approach
- Likely responding to vulnerability reports or exploitation attempts
- More dangerous types may be discovered in future
- Comprehensive review of all serializable types needed

### 5.2 Hardcoded AllowList Analysis

From `SPSerializationSafeControlsAllowList.cs:11-15`, the allowlist includes many PerformancePoint types:

```csharp
"Microsoft.PerformancePoint.Scorecards.ProviderConsumerTransformations"
"Microsoft.PerformancePoint.Scorecards.TransformerConfigurationRecord"
"Microsoft.PerformancePoint.Scorecards.TransformConditionalVisibilityRecord"
"Microsoft.PerformancePoint.Scorecards.TransformProviderConsumerRecord"
```

**Observation:** Other PerformancePoint.Scorecards types ARE in the allowlist, but ExcelDataSet is explicitly excluded. This suggests:
- ExcelDataSet has unique dangerous properties
- Other PerformancePoint types may have been vetted as safe
- OR other types may represent future vulnerability targets

**Recommendation:** Audit all allowlisted PerformancePoint types for deserialization safety.

### 5.3 Upgrade Action Reliability

The `AddExcelDataSetToSafeControls.cs` upgrade action includes version checking:

```csharp
XmlNode xmlNode = appWebConfig.SelectSingleNode(string.Format(
    "configuration/SharePoint/SafeControls/SafeControl[@Assembly='{0}'][@Namespace='{1}'][@TypeName='{2}']",
    "Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ...",
    "Microsoft.PerformancePoint.Scorecards",
    "ExcelDataSet"));

if (xmlNode == null)
{
    // Add the entry
}
```

**Potential Issue:** If an administrator manually adds an ExcelDataSet entry with different attributes (e.g., Safe="True"), the upgrade action will see the entry exists and skip adding the correct Safe="False" entry.

**Recommendation:** Modify upgrade action to:
1. Check if entry exists
2. If exists, verify Safe="False"
3. If Safe="True", update to Safe="False"
4. If missing, add new entry

---

## Conclusion

The ExcelDataSet deserialization patch represents a targeted fix for a specific exploitation vector, but leaves several critical gaps:

**Strengths:**
- ✅ Explicitly blacklists ExcelDataSet v15 and v16
- ✅ Comprehensive coverage across all configuration files
- ✅ Automated deployment via upgrade action

**Weaknesses:**
- ❌ ControlCompatMode bypass allows circumvention
- ❌ No code-level enforcement improvements
- ❌ Other dangerous types remain exploitable
- ❌ Reactive approach suggests more vulnerabilities exist

**Critical Recommendation:** Immediately deploy code-level enforcement of Safe="False" regardless of ControlCompatMode setting. The current configuration-only patch is insufficient to prevent exploitation in environments with backward compatibility enabled.

**Overall Risk Assessment:** While the patch addresses the specific ExcelDataSet vector, the underlying deserialization vulnerability architecture remains exploitable through multiple bypass techniques and alternative gadget types. A comprehensive remediation requires both eliminating ControlCompatMode bypasses and migrating away from BinaryFormatter-based serialization.

---

## Appendix: Evidence References

### Configuration File Locations

**v1 (Vulnerable):**
- `/snapshots_norm/v1/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config` - No ExcelDataSet entry
- `/snapshots_norm/v1/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config` - No ExcelDataSet entry

**v2 (Patched):**
- `/snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/cloudweb.config:161-162` - ExcelDataSet Safe="False"
- `/snapshots_norm/v2/C__Program Files_Common Files_Microsoft Shared_Web Server Extensions/16/CONFIG/web.config:161-162` - ExcelDataSet Safe="False"

### Code File Locations

**Deserialization Logic:**
- `/snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationBinder.cs:26-48` - Main validation logic
- `/snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SafeControls.cs:313-362` - IsSafeControl implementation
- `/snapshots_decompiled/v2/Microsoft.-0dabac64-19146cec/Microsoft/Office/Server/Security/SafeSerialization.cs:656-679` - BinaryFormatter usage

**Allowlists:**
- `/snapshots_decompiled/v1/Microsoft.-52195226-3676d482/Microsoft/SharePoint/WebPartPages/SPSerializationSafeControlsAllowList.cs:9-16` - Hardcoded allowlist

**Patch Implementation:**
- `/snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/Upgrade/AddExcelDataSetToSafeControls.cs` - Upgrade action

### Diff Report References

- `/diff_reports/v1-to-v2.server-side.patch:21-23` - cloudweb.config changes
- `/diff_reports/v1-to-v2.server-side.patch:35-36` - web.config changes
- `/diff_reports/v1-to-v2.server-side.patch:73146-73164` - AddExcelDataSetToSafeControls.cs addition

---

**Analysis Complete**
