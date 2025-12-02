# Final Verification: CVE-2025-49704 Patch Effectiveness and Bypass Validation

## Metadata
- **Agent**: Claude Sonnet 4.5 (claude-sonnet-4-5-20250929)
- **Timestamp**: 2025-11-26 15:44:12
- **Analysis Type**: Final Verification with Evidence-Based Validation
- **Vulnerability**: CVE-2025-49704 (ExcelDataSet Deserialization)
- **Previous Reports**:
  - Initial: deser-claude-sonnet-4.5_20251126-134939.md
  - Coverage: coverage-deser-claude-sonnet-4.5_20251126-152325.md

---

## Part 1: Validate the Vulnerability Understanding

### 1.1 Confirm the Vulnerability in v1

#### Evidence of Vulnerable Code (v1)

**File**: `snapshots_decompiled/v1/Microsoft.-89ead232-72556f65/Microsoft/PerformancePoint/Scorecards/ExcelDataSet.cs`

**Vulnerable Code** (lines 40-53):
```csharp
[XmlIgnore]
public DataTable DataTable
{
    get
    {
        if (dataTable == null && compressedDataTable != null)
        {
            dataTable = Helper.GetObjectFromCompressedBase64String(
                compressedDataTable, ExpectedSerializationTypes) as DataTable;
            if (dataTable == null)
            {
                compressedDataTable = null;
            }
        }
        return dataTable;
    }
    // ...
}
```

**Deserialization Method** (Helper.cs:580-599):
```csharp
public static object GetObjectFromCompressedBase64String(
    string base64String, Type[] ExpectedSerializationTypes)
{
    // ...
    byte[] buffer = Convert.FromBase64String(base64String);
    using MemoryStream memoryStream = new MemoryStream(buffer);
    memoryStream.Position = 0L;
    GZipStream gZipStream = new GZipStream(memoryStream, CompressionMode.Decompress);
    try
    {
        return BinarySerialization.Deserialize(
            (Stream)gZipStream,
            (XmlValidator)null,
            (IEnumerable<Type>)null);  // ← ExpectedSerializationTypes NOT USED!
    }
    // ...
}
```

**BinaryFormatter with Limited Type Checking** (System/Data/BinarySerialization.cs:17-18):
```csharp
internal LimitingBinder(IEnumerable<Type> extraTypes)
{
    _allowedTypeMap = new TypeMap();
    _allowedTypeMap.Add(typeof(DataSet));
    _allowedTypeMap.Add(typeof(DataTable));  // ← DataTable is allowed
    _allowedTypeMap.Add(typeof(SchemaSerializationMode));
    _allowedTypeMap.Add(typeof(Version));
    // ...
}
```

#### Attack Flow

**Stage 1: Get ExcelDataSet Instance into SharePoint**

1. **Entry Point**: WebPart deserialization endpoint (any page accepting WebPart XML/binary data)
2. **Untrusted Input**: Attacker-supplied WebPart containing ExcelDataSet instance
3. **v1 Configuration** (snapshots_norm/v1/.../80/web.config:244-245):
   ```xml
   <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..."
                Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />
   <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ..."
                Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />
   ```
   **Note**: No Safe attribute specified; no explicit ExcelDataSet block

4. **Security Check**: SPSerializationBinder.IsAllowedType() is called
5. **v1 Behavior**:
   - ExcelDataSet matches wildcard namespace entry
   - `m_safeControls.IsSafeControl()` checks the wildcard match
   - ExcelDataSet is NOT in hardcoded `SPSerializationSafeControlsAllowList`
   - If `ControlCompatMode=false` (default): Wildcard match + not in allowList = **BLOCKED** by default
   - If `ControlCompatMode=true`: Allows deserialization (bypass - see SPSerializationBinder.cs:41-46)

**Stage 2: Trigger Malicious Deserialization**

6. **Trigger**: SharePoint code accesses `ExcelDataSet.DataTable` property getter
7. **Malicious Payload**: `CompressedDataTable` contains gzip + base64 + BinaryFormatter-serialized DataTable with gadget chain
8. **Deserialization**: `Helper.GetObjectFromCompressedBase64String()` calls `BinarySerialization.Deserialize()`
9. **Type Restriction Bypass**: LimitingBinder allows DataTable (line 18 above)
10. **Gadget Chain Execution**: Malicious DataTable triggers known .NET deserialization gadgets (PSObject, TypeConverter, etc.)
11. **Outcome**: **Remote Code Execution** as SharePoint application pool identity

#### Prerequisites

1. **Ability to supply WebPart data** to SharePoint (typically requires authenticated user, but depends on endpoint)
2. **One of the following**:
   - `ControlCompatMode=true` in SafeModeConfiguration (allows Stage 1)
   - OR alternative deserialization path that bypasses SafeControls checks
3. **Code that accesses ExcelDataSet.DataTable property** (automatic if WebPart is rendered or processed)

#### Confidence Assessment: **HIGH**

**Evidence**:
- ✅ ExcelDataSet.cs exists in v1 with dangerous pattern
- ✅ Helper method calls BinarySerialization.Deserialize with null extraTypes
- ✅ LimitingBinder explicitly allows DataTable
- ✅ v1 config has wildcard entries for PerformancePoint.Scorecards
- ✅ No explicit ExcelDataSet Safe="False" block in v1

**Uncertainty**:
- ⚠️ Default value of `ControlCompatMode` not confirmed in code (assumed false)
- ⚠️ Exact WebPart deserialization endpoints not identified
- ⚠️ Attack requires `ControlCompatMode=true` OR alternative path (see bypass hypotheses)

---

### 1.2 Verify the Patch Effectiveness

#### Exact Diff Hunk

**File**: `diff_reports/v1-to-v2.server-side.patch`

**cloudweb.config change** (lines +22-23):
```diff
@@ -158,6 +158,8 @@
       <SafeControl Assembly="Microsoft.Office.Server.Search, Version=16.0.0.0, ..."
                    Namespace="Microsoft.Office.Server.Search.Internal.UI"
                    TypeName="SearchFarmDashboard" Safe="True" AllowRemoteDesigner="False" />
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0,
+                   Culture=neutral, PublicKeyToken=71e9bce111e9429c"
+                   Namespace="Microsoft.PerformancePoint.Scorecards"
+                   TypeName="ExcelDataSet"
+                   Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
+      <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0,
+                   Culture=neutral, PublicKeyToken=71e9bce111e9429c"
+                   Namespace="Microsoft.PerformancePoint.Scorecards"
+                   TypeName="ExcelDataSet"
+                   Safe="False" AllowRemoteDesigner="False" SafeAgainstScript="False" />
     </SafeControls>
```

**Identical changes applied to**:
1. `C:\Program Files\...\16\CONFIG\web.config`
2. `C:\inetpub\wwwroot\wss\VirtualDirectories\80\web.config`
3. `C:\inetpub\wwwroot\wss\VirtualDirectories\20072\web.config`

#### Patch Mechanism

**v2 Code Behavior**:
1. ExcelDataSet now has **specific** SafeControl entries with `Safe="False"`
2. Specific type entries take **precedence** over namespace wildcards (SafeAssemblyInfo.cs:358-360):
   ```csharp
   if (!TypeInfoDictionary.TryGetValue(typeFullName, out value))  // Check specific FIRST
   {
       WildCardNamespacesDictionary.TryGetValue(typeNamespace, out value);  // Then wildcard
   }
   ```
3. When SPSerializationBinder checks ExcelDataSet:
   - `IsSafeControl()` finds the specific entry with `Safe="False"`
   - Returns `flag=false` (SafeControls.cs:327)
4. ExcelDataSet is NOT in hardcoded allowList
5. Enters the check block (SPSerializationBinder.cs:35-47)
6. If `ControlCompatMode=false`: **Throws exception, blocks deserialization**
7. If `ControlCompatMode=true`: **Still allows it!** (line 46)

#### How Patch Blocks the Attack

**For ControlCompatMode=false (default)**:
- ✅ Stage 1 BLOCKED: ExcelDataSet cannot be deserialized into WebPart
- ✅ Stage 2 N/A: No ExcelDataSet instance to trigger property access
- ✅ Attack prevented

**For ControlCompatMode=true**:
- ❌ Stage 1 NOT BLOCKED: ExcelDataSet can still be deserialized (bypass!)
- ❌ Stage 2 proceeds: Malicious DataTable deserialization
- ❌ Attack succeeds

#### Patch Effectiveness Rating: **PARTIAL**

**Justification**:
- ✅ **Blocks default configuration**: If ControlCompatMode=false (assumed default), patch is effective
- ❌ **Does NOT block ControlCompatMode=true**: SPSerializationBinder logic unchanged (lines 41-46)
- ❌ **Does NOT block DataTable**: Second stage vulnerability remains (BinarySerialization.cs:18)
- ❌ **Incomplete file coverage**: webconfig.pps.xml and other fragments unpatched (see bypass hypotheses)

**Critical Assumption**: Patch assumes `ControlCompatMode=false` is the default/standard configuration. This assumption is **unverified** in available code.

---

## Part 2: Validate Each Bypass Hypothesis

### Bypass Hypothesis 1: ControlCompatMode Configuration Bypass

**Type**: Configuration-based security control bypass

**The Claim**: If ControlCompatMode is set to true, the Safe="False" patch is ineffective.

#### Evidence-Based Validation

**Code Evidence** (SPSerializationBinder.cs:41-46):
```csharp
if (!base.ControlCompatMode)
{
    ULS.SendTraceTag(3981590u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
        "Allowing ControlCompatMode=false object in ObjectFormatter. Type = {0}",
        type.AssemblyQualifiedName);
    throw new SafeControls.UnsafeControlException(
        SPResource.GetString("UnsafeControlPageParserFilterError",
        type.FullName, (unsafeErrorMessage == null) ? string.Empty : unsafeErrorMessage));
}
ULS.SendTraceTag(3981589u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
    "Allowing ControlCompatMode=true object in ObjectFormatter. Type = {0}",
    type.AssemblyQualifiedName);
```

**Attack Path Verification**:
1. ✅ Administrator sets ControlCompatMode=true in SafeModeConfiguration
2. ✅ Attacker sends WebPart with ExcelDataSet
3. ✅ SPSerializationBinder.IsAllowedType() is called
4. ✅ ExcelDataSet has Safe="False", so flag=false
5. ✅ ExcelDataSet NOT in hardcoded allowList, enters if block (line 35)
6. ✅ Line 41 checks `if (!base.ControlCompatMode)` → evaluates to FALSE
7. ✅ Skips the throw statement, logs "Allowing ControlCompatMode=true"
8. ✅ Method returns without throwing → ExcelDataSet is ALLOWED
9. ✅ Stage 2 proceeds with DataTable deserialization → RCE

**Patch Coverage Check**:
- ❌ SPSerializationBinder.cs is **UNCHANGED** between v1 and v2 (verified with diff)
- ❌ No mitigation for ControlCompatMode=true scenario
- ✅ ControlCompatMode NOT set in any v2 config files (grep returned no matches)

**Feasibility Assessment**: **HIGH**

**Blocking Conditions in v2**: NONE if ControlCompatMode=true

**Verdict**: **CONFIRMED BYPASS**

---

### Bypass Hypothesis 2: DataTable Gadget Chains (Direct Deserialization)

**Type**: Alternative dangerous type still allowed in deserialization

**The Claim**: DataTable can be exploited directly through gadget chains, bypassing the ExcelDataSet fix.

#### Evidence-Based Validation

**Code Evidence** (BinarySerialization.cs:17-18):
```csharp
internal LimitingBinder(IEnumerable<Type> extraTypes)
{
    _allowedTypeMap = new TypeMap();
    _allowedTypeMap.Add(typeof(DataSet));
    _allowedTypeMap.Add(typeof(DataTable));  // ← STILL ALLOWED in v2
    _allowedTypeMap.Add(typeof(SchemaSerializationMode));
    _allowedTypeMap.Add(typeof(Version));
    // ...
}
```

**Verification**: BinarySerialization.cs is **UNCHANGED** between v1 and v2 (verified with diff).

**Attack Path Verification**:
- ❌ **UNCERTAIN**: Requires finding a code path where attacker can supply raw DataTable for deserialization
- ❌ **NOT PROVEN**: Cannot trace complete attack path from user input to DataTable deserialization
- ⚠️ **SPECULATIVE**: Known .NET DataTable gadget chains exist (PSObject, TypeConverter), but entry point unclear

**Feasibility Assessment**: **MEDIUM**

**Blocking Conditions**:
- Requires identifying specific SharePoint endpoint that deserializes DataTable
- Would need to bypass WebPart-level SafeControls checks
- Likely requires special access/permissions

**Verdict**: **UNCERTAIN** - Plausible but lacks complete evidence of attack path

---

### Bypass Hypothesis 3: webconfig.pps.xml Configuration Fragment Unpatched

**Type**: Incomplete patch coverage - configuration file gap

**The Claim**: PerformancePoint configuration fragment was not patched and still contains wildcard entries.

#### Evidence-Based Validation

**Code Evidence**:
```bash
$ diff ./snapshots_norm/v1/C__Program\ Files_.../16/CONFIG/webconfig.pps.xml \
       ./snapshots_norm/v2/C__Program\ Files_.../16/CONFIG/webconfig.pps.xml
[NO OUTPUT - Files are IDENTICAL]
```

**File Contents** (v1 and v2 both, lines 3-9):
```xml
<add path="configuration/SharePoint/SafeControls" id="{A093E8C6-BA89-4811-A891-E63E3EEBB188}">
  <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, ..."
               Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />
  <SafeControl Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=15.0.0.0, ..."
               Namespace="Microsoft.PerformancePoint.Scorecards" TypeName="*" />
</add>
```

**Key Observations**:
- ✅ File exists in both v1 and v2
- ✅ File is byte-for-byte identical (diff returned no output)
- ✅ Contains wildcard entries for PerformancePoint.Scorecards namespace
- ✅ Does NOT contain ExcelDataSet Safe="False" entries

**Attack Path Verification**:
- ⚠️ **ASSUMPTION**: Configuration fragments are merged during feature activation/installation
- ⚠️ **UNKNOWN**: Merge order and whether fragments can override main web.config
- ⚠️ **UNCLEAR**: When/if webconfig.pps.xml is actually applied to running configuration

**Critical Gap**: Cannot verify configuration merge behavior from static code analysis.

**Feasibility Assessment**: **MEDIUM**

**Blocking Conditions**:
- Depends on SharePoint configuration merge semantics
- May only apply in specific deployment scenarios (PerformancePoint Services installed)
- Precedence rules may favor main web.config over fragments

**Verdict**: **UNCERTAIN** - Configuration gap confirmed, but exploitability depends on runtime behavior

---

### Bypass Hypothesis 4: PTCSerializationBinder Alternative Path

**Type**: Alternative deserialization binder with weaker checks

**The Claim**: PTCSerializationBinder only checks ControlCompatMode, not SafeControls.

#### Evidence-Based Validation

**Code Evidence** (PTCSerializationBinder.cs:13-22):
```csharp
protected override void IsAllowedType(Type type)
{
    if (base.ControlCompatMode)
    {
        ULS.SendTraceTag(3981574u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
            "PTC Serializer Allowing ControlCompatMode=true object...");
        return;  // ← ALLOWS EVERYTHING if ControlCompatMode=true
    }
    ULS.SendTraceTag(3981575u, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High,
        "PTC Serializer Allowing ControlCompatMode=false object...");
    throw new SafeControls.UnsafeControlException(...);  // ← BLOCKS EVERYTHING if false
}
```

**Key Differences from SPSerializationBinder**:
- ❌ Does NOT check hardcoded allowList
- ❌ Does NOT check SafeControls configuration
- ❌ Does NOT check individual type safety
- ⚠️ ONLY checks ControlCompatMode boolean

**Usage Context** (SPUserCodeWebPart.cs:600):
```csharp
IBinaryWebPartDatabaseSerializedData binaryWebPartDatabaseSerializedData =
    binaryWebPartSerializer.Serialize(mode, binaryWebPartSerializerFlags,
        new PTCSerializationBinder());  // ← Used in sandboxed solution context
```

**Attack Path Verification**:
- ✅ PTCSerializationBinder exists and is used
- ⚠️ Used for SPUserCodeWebPart (sandboxed solutions)
- ⚠️ **UNCLEAR**: Can attacker trigger deserialization through this path?
- ⚠️ **UNCLEAR**: Sandboxed solution deployment restrictions

**Feasibility Assessment**: **LOW-MEDIUM**

**Blocking Conditions**:
- Requires ability to deploy/modify sandboxed solutions
- Requires ControlCompatMode=true (same as Bypass #1)
- Sandboxed solutions have additional security restrictions

**Verdict**: **UNCERTAIN** - Alternative binder confirmed, but access path unclear

---

### Bypass Hypothesis 5: Alternative PerformancePoint.Scorecards Types

**Type**: Other dangerous types in same namespace

**The Claim**: Other [Serializable] types in PerformancePoint.Scorecards might have similar vulnerabilities.

#### Evidence-Based Validation

**Types Checked**:
- ProviderConsumerTransformations (lines 6-52)
- TransformerConfigurationRecord (lines 5-62)
- TransformConditionalVisibilityRecord
- TransformProviderConsumerRecord

**Analysis**:
```csharp
// Example: ProviderConsumerTransformations.cs
[Serializable]
public class ProviderConsumerTransformations
{
    private List<TransformProviderConsumerRecord> _records;

    public List<TransformProviderConsumerRecord> Records
    {
        get { return _records ?? new List<...>(); }  // ← No deserialization trigger
        set { _records = value; }
    }
    // ... simple getters/setters only
}
```

**Findings**:
- ✅ All checked types are simple data containers
- ✅ NO property getters that trigger deserialization (unlike ExcelDataSet.DataTable)
- ✅ NO calls to Helper.GetObjectFromCompressedBase64String()
- ✅ NO BinaryFormatter.Deserialize() calls

**Feasibility Assessment**: **LOW**

**Verdict**: **REJECTED** - No similar dangerous patterns found in related types

---

### Bypass Hypothesis 6: Alternative Deserialization Entry Points

**Type**: Other code paths using BinaryFormatter

**The Claim**: SharePoint has many other BinaryFormatter entry points that may not enforce SafeControls.

#### Evidence-Based Validation

**Files with BinaryFormatter.Deserialize**:
- Microsoft/SharePoint/Deployment/ImportObjectManager.cs
- Microsoft/SharePoint/Deployment/SPDeployment.cs
- Microsoft/Office/RecordsManagement/Reporting/ReportingGallery.cs
- Microsoft/Office/Access/Server/Query/Serialization/CustomBinaryFormatter.cs
- And 6+ more

**Analysis**: ⚠️ **INCOMPLETE** - Each file would need individual audit to:
- Identify if user-controlled data reaches deserialization
- Verify if SafeControls checks are applied
- Determine access requirements (admin-only vs. user-accessible)

**Feasibility Assessment**: **LOW-MEDIUM**

**Verdict**: **UNCERTAIN** - Alternative paths exist but not fully audited

---

### Bypass Hypothesis 7: Assembly Version Mismatch

**Type**: Using different assembly version to bypass blocklist

**The Claim**: Version 14.0.0.0 might bypass the patch which only blocks 15.0.0.0 and 16.0.0.0.

#### Evidence-Based Validation

**Binding Redirects** (web.config:1049-1050):
```xml
<dependentAssembly xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity name="Microsoft.PerformancePoint.Scorecards.Client"
                    publicKeyToken="71e9bce111e9429c" culture="neutral" />
  <bindingRedirect oldVersion="14.0.0.0-15.0.0.0" newVersion="16.0.0.0" />
</dependentAssembly>
```

**Effect**: Version 14.0.0.0 is redirected to 16.0.0.0, then blocked by Safe="False" entry.

**Feasibility Assessment**: **LOW**

**Verdict**: **REJECTED** - Mitigated by assembly binding redirects

---

### Bypass Hypothesis 8-10: Type Name Obfuscation, DisableSafeControlsCheck, etc.

**Type**: Various low-likelihood edge cases

**Analysis**: These require special conditions or are technically impractical:
- Type name obfuscation: .NET type system prevents this
- DisableSafeControlsCheck: No evidence of usage in normal scenarios
- Configuration merge timing: Unverifiable without runtime testing

**Verdict**: **REJECTED** (8, 10) / **UNCERTAIN** (9 - merge timing)

---

## Part 3: Completeness Assessment

### Bypass Enumeration Summary

**Total bypass hypotheses evaluated**: 10

**Confirmed (High confidence)**: 1
- ✅ **Bypass #1**: ControlCompatMode=true completely bypasses the patch

**Uncertain (Medium confidence)**: 4
- ⚠️ **Bypass #2**: DataTable gadget chains (lacks complete attack path)
- ⚠️ **Bypass #3**: webconfig.pps.xml unpatched (configuration merge unclear)
- ⚠️ **Bypass #4**: PTCSerializationBinder (access path unclear)
- ⚠️ **Bypass #6**: Alternative entry points (incomplete audit)

**Rejected (Low confidence / disproven)**: 5
- ❌ **Bypass #5**: Alternative PerformancePoint types (no dangerous patterns found)
- ❌ **Bypass #7**: Assembly version mismatch (mitigated by binding redirects)
- ❌ **Bypass #8**: Type name obfuscation (technically impractical)
- ❌ **Bypass #9**: Configuration merge timing (unverifiable statically)
- ❌ **Bypass #10**: DisableSafeControlsCheck (no evidence of usage)

### Critical Self-Assessment

#### 1. Patch Assumption Validation

**Assumption 1: ControlCompatMode defaults to false**
- ✅ ControlCompatMode NOT set in any v2 config files
- ⚠️ Default value not explicitly verified in code
- ⚠️ Administrators could enable it for "compatibility"
- **Status**: Likely true but unconfirmed

**Assumption 2: Specific type entries override wildcards**
- ✅ Confirmed in code (SafeAssemblyInfo.cs:358-360)
- ✅ TypeInfoDictionary checked before WildCardNamespacesDictionary
- **Status**: Verified

**Assumption 3: Configuration fragments don't override main config**
- ⚠️ Cannot verify from static analysis alone
- ⚠️ SharePoint configuration merge order is complex
- **Status**: Unknown - requires runtime testing

#### 2. Alternative Attack Paths

**For ExcelDataSet specifically**:
- ✅ SPSerializationBinder is the primary path (confirmed)
- ✅ PTCSerializationBinder is an alternative (confirmed but unclear access)
- ⚠️ Other paths may exist but not fully audited

**For deserialization generally**:
- ⚠️ 10+ files use BinaryFormatter.Deserialize
- ⚠️ Not all paths audited for SafeControls enforcement
- ⚠️ LosFormatter/ViewState separate attack surface

#### 3. Incomplete Patch Coverage

**Files Patched**: 4 configuration files
- ✅ C:\...\16\CONFIG\web.config
- ✅ C:\...\16\CONFIG\cloudweb.config
- ✅ C:\inetpub\...\80\web.config
- ✅ C:\inetpub\...\20072\web.config

**Files NOT Patched**:
- ❌ C:\...\16\CONFIG\webconfig.pps.xml (verified identical v1/v2)
- ❌ 20+ other configuration fragments not audited
- ❌ Other web.config files in different virtual directories

**Code Changes**: NONE
- ✅ SPSerializationBinder.cs unchanged
- ✅ PTCSerializationBinder.cs unchanged
- ✅ BinarySerialization.cs unchanged
- ✅ ExcelDataSet.cs unchanged
- ✅ Helper.cs unchanged

**Implication**: Patch is configuration-only, no code fixes.

### Honest Completeness Statement

☑ **"Some hypotheses remain uncertain due to code complexity—may require dynamic testing"**

**Explanation**:

**What I CAN confirm with high confidence**:
1. ✅ Vulnerability exists in v1 (ExcelDataSet.DataTable triggers dangerous deserialization)
2. ✅ Patch adds Safe="False" config entries for ExcelDataSet
3. ✅ Patch blocks ExcelDataSet when ControlCompatMode=false
4. ✅ **ControlCompatMode=true completely bypasses the patch** (confirmed with code evidence)
5. ✅ Configuration file webconfig.pps.xml was not patched
6. ✅ BinarySerialization still allows DataTable deserialization

**What remains UNCERTAIN**:
1. ⚠️ Default value of ControlCompatMode (assumed false but not verified)
2. ⚠️ Configuration merge behavior for fragments like webconfig.pps.xml
3. ⚠️ Complete audit of all BinaryFormatter entry points
4. ⚠️ Access paths for PTCSerializationBinder exploitation
5. ⚠️ DataTable gadget chain entry points in SharePoint

**Limitations of static analysis**:
- Cannot test runtime configuration merging
- Cannot verify default configuration values
- Cannot trace all possible code paths dynamically
- Cannot test actual exploit payloads

**Why not "comprehensive validation"**:
- Configuration runtime behavior unverifiable from code alone
- Some code paths require dynamic analysis to trace
- Multiple uncertainty areas prevent absolute certainty

**Why not "all hypotheses rejected"**:
- ControlCompatMode bypass is definitively confirmed
- webconfig.pps.xml gap is factually confirmed
- Multiple uncertain bypasses remain plausible

---

## Part 4: Adjacent Security Edits

**Searched**: Diff around ExcelDataSet changes in v1-to-v2.server-side.patch

**Finding**: Only change related to this vulnerability is the addition of SafeControl entries. No adjacent code changes observed.

**Other Changes in Diff** (from stat.txt):
- AddExcelDataSetToSafeControls.cs (new file added)
- SPRequestModule.cs (different vulnerability - authentication bypass)
- Multiple files with minor changes (whitespace, attributes reordering)

**None appear directly related to strengthening ExcelDataSet deserialization defenses.**

---

## Final Verdict

### Vulnerability Confirmation

**Disclosed vulnerability exists in v1**: **CONFIRMED**
- ExcelDataSet.DataTable property triggers BinaryFormatter deserialization
- Helper.GetObjectFromCompressedBase64String uses BinarySerialization.Deserialize
- LimitingBinder allows DataTable, enabling gadget chain execution
- v1 config has wildcard entries without ExcelDataSet block

**Patch addresses the vulnerability**: **PARTIALLY**
- ✅ Adds Safe="False" config entries for ExcelDataSet
- ✅ Blocks ExcelDataSet when ControlCompatMode=false (assumed default)
- ❌ Does NOT block if ControlCompatMode=true (confirmed bypass)
- ❌ Does NOT address DataTable gadget chains (second-stage vulnerability)
- ❌ Does NOT patch configuration fragments (webconfig.pps.xml confirmed unpatched)

**Evidence quality**: **STRONG**
- Vulnerability confirmed with exact code locations and line numbers
- Patch confirmed with exact diff hunks
- ControlCompatMode bypass confirmed with code logic trace
- webconfig.pps.xml gap confirmed with file comparison

### Bypass Summary

**Working bypasses identified (High confidence)**: 1
- ✅ **ControlCompatMode=true**: SPSerializationBinder.cs:41-46 allows all types when ControlCompatMode=true, completely bypassing Safe="False" patch

**Uncertain bypasses requiring testing (Medium confidence)**: 4
- ⚠️ DataTable gadget chains: Type is allowed but entry point unclear
- ⚠️ webconfig.pps.xml: File unpatched but merge behavior unclear
- ⚠️ PTCSerializationBinder: Weaker checks but access path unclear
- ⚠️ Alternative entry points: Multiple BinaryFormatter uses not fully audited

**Rejected bypasses (Disproven / Low confidence)**: 5
- ❌ Alternative PerformancePoint types: No dangerous patterns found
- ❌ Assembly version mismatch: Mitigated by binding redirects
- ❌ Type name obfuscation: Technically impractical
- ❌ Configuration merge timing: Cannot verify statically
- ❌ DisableSafeControlsCheck: No evidence of usage

### Key Findings

**Most critical finding about patch effectiveness**:
The patch is **configuration-only** and makes a **critical assumption** that ControlCompatMode=false. If ControlCompatMode=true, the patch is **completely ineffective** because SPSerializationBinder logic explicitly allows all types in that mode (lines 41-46), regardless of Safe="False" markings.

**Highest confidence bypass**:
**ControlCompatMode=true** - This is not a theoretical bypass; it is confirmed by code logic. If an administrator enables ControlCompatMode for backward compatibility, ExcelDataSet can still be deserialized, and the entire attack succeeds.

**Main limitation of this static analysis**:
1. Cannot verify runtime configuration merging behavior (webconfig.pps.xml scenario)
2. Cannot determine ControlCompatMode default value with absolute certainty
3. Cannot trace all dynamic code paths to identify every possible attack vector
4. Cannot test actual exploit payloads to confirm gadget chain effectiveness

**Confidence Assessment**:
- **HIGH** for vulnerability existence and ControlCompatMode bypass
- **MEDIUM** for configuration-based gaps (webconfig.pps.xml)
- **LOW-MEDIUM** for alternative deserialization entry points

---

## Recommendations

### Immediate Actions (CRITICAL)

1. **Verify ControlCompatMode is false**
   - Audit all SharePoint farms for ControlCompatMode setting
   - Document security implications of enabling ControlCompatMode
   - Consider removing or deprecating this feature

2. **Patch configuration fragments**
   - Add ExcelDataSet Safe="False" entries to webconfig.pps.xml
   - Audit all 25 configuration files with SafeControls
   - Ensure comprehensive coverage

3. **Remove DataTable from allowList**
   - Update BinarySerialization.LimitingBinder to restrict DataTable
   - Or implement gadget chain detection

### Long-term Hardening

4. **Refactor SPSerializationBinder logic**
   - Remove ControlCompatMode bypass (lines 41-46)
   - Make Safe="False" always enforced
   - Or make check independent of ControlCompatMode

5. **Migrate away from BinaryFormatter**
   - Use safer serialization formats
   - Implement explicit type allowlisting

---

## Appendix: Evidence Summary

### Files Analyzed

**v1 Vulnerable Code**:
- snapshots_decompiled/v1/.../ExcelDataSet.cs (dangerous property)
- snapshots_decompiled/v1/.../Helper.cs:580-599 (deserialization)
- snapshots_decompiled/v1/.../BinarySerialization.cs:17-18 (DataTable allowed)
- snapshots_norm/v1/.../80/web.config:244-245 (wildcard entries)

**v2 Patch**:
- diff_reports/v1-to-v2.server-side.patch (ExcelDataSet entries added)
- snapshots_norm/v2/.../web.config (Safe="False" entries)

**Unchanged Between v1/v2**:
- SPSerializationBinder.cs (identical - diff returned no output)
- PTCSerializationBinder.cs (identical - diff returned no output)
- BinarySerialization.cs (identical - DataTable still allowed)
- webconfig.pps.xml (identical - confirmed unpatched)

### Key Code References

**ControlCompatMode Bypass** (SPSerializationBinder.cs:41-46)
**Type Precedence** (SafeAssemblyInfo.cs:358-360)
**DataTable Allowed** (BinarySerialization.cs:18)
**Wildcard Entries** (v1 web.config:244-245)
**Safe="False" Patch** (diff_reports v1-to-v2.server-side.patch)

---

## Conclusion

The CVE-2025-49704 patch is **partially effective** but has critical gaps:

✅ **Effective against**: Default configuration attacks (if ControlCompatMode=false)
❌ **NOT effective against**: ControlCompatMode=true (confirmed bypass with code evidence)
⚠️ **Uncertain about**: Configuration fragments, alternative entry points

The patch is **configuration-only** with **NO code changes**, relying entirely on SafeControls enforcement. This approach is inherently limited by the ControlCompatMode bypass built into SPSerializationBinder.

**Overall Assessment**: The patch addresses the primary CVE-2025-49704 attack vector in default configurations, but leaves significant attack surface for:
1. Configurations with ControlCompatMode=true (confirmed bypass)
2. Deployments using unpatched configuration fragments (webconfig.pps.xml)
3. Alternative deserialization entry points (partially audited)

**Static analysis confidence**: HIGH for core findings, MEDIUM for configuration scenarios, requiring dynamic testing for complete validation.
