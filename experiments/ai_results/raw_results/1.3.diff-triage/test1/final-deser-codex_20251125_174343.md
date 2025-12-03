# Final Verification (evidence-based)

## 1) Authentication bypass: `ToolPane.aspx` (CVE-2025-49706)

**Diff hunk (patch)** – `Microsoft.SharePoint.ApplicationRuntime.SPRequestModule`, PostAuthenticateRequestHandler:
```
@@
-                if (IsShareByLinkPage(context) ... || flag8)
+                if (IsShareByLinkPage(context) ... || flag8)
                 {
                     flag6 = false;
                     flag7 = true;
+                    bool flag9 = !SPFarm.CheckFlag((ServerDebugFlags)53506);
+                    bool flag10 = context.Request.Path.EndsWith("ToolPane.aspx", StringComparison.OrdinalIgnoreCase);
+                    if (flag9 && flag8 && flag10)
+                    {
+                        flag6 = true;
+                        flag7 = false;
+                        ULS.SendTraceTag(... "[SPRequestModule.PostAuthenticateRequestHandler]Risky bypass limited (Access Denied) - signout with ToolPane.aspx detected. request path: '{0}'.", context.Request.Path);
+                    }
                 }
```

**V1 vulnerable behavior:** In v1, when referrer or path matched signout/start URLs, `flag6` (check auth cookie) was disabled (`flag6=false`) with no ToolPane exception. `ToolPane.aspx` lives under `/_layouts/15/`. An attacker could set `Referer` to signout URL and request `/_layouts/15/ToolPane.aspx`; the module skipped auth checks, treating the request as logout-related, allowing unauthenticated access to ToolPane processing.

**Flow:** Untrusted HTTP request -> SPRequestModule PostAuthenticateRequestHandler -> signout/referrer logic sets `flag6=false` -> auth not enforced -> ToolPane page executes downstream with request context unauthenticated. Missing check: no special-case to force auth on ToolPane when coming from signout flow.

**Outcome:** Unauth reachability of ToolPane endpoint, enabling chaining with deserialization RCE for full RCE.

**Bypass routes:** Only documented route is signout-referrer + ToolPane path. No evidence of alternate paths in this handler; other signout/start paths remain blocked by setting `flag6=false` intentionally. Feasibility: high (single request with crafted referrer).

**V2 prevention:** Adds ToolPane-specific guard: if referrer is signout (flag8) AND path endswith ToolPane.aspx AND farm not in debug, it re-enables auth (`flag6=true`, `flag7=false`) and logs. This blocks the unauth ToolPane access for the known bypass route. Other endpoints remain as before. Edge: if server debug flag (53506) set, guard disabled (intentionally for debug). Alternative endpoints: none evident in this handler.

**Confidence:** High (explicit logic change shows the bypass and the fix).

## 2) Deserialization RCE: Ssdqs BinaryFormatter allow/deny (CVE-2025-49704)

**Diff hunk (patch)** – `NoneVersionSpecificSerializationBinder.BindToType`:
```
@@
-            value = Type.GetType(typeName + ", " + assemblyName);
+            value = TypeProcessor.LoadType(assemblyName, typeName);
+            if (value == null) throw new BlockedTypeException(..., BlockReason.InDeny);
+            if (TypeProcessor.IsTypeExplicitlyDenied(value)) throw new BlockedTypeException(..., BlockReason.InDeny);
+            if (!TypeProcessor.IsTypeExplicitlyAllowed(value)) throw new BlockedTypeException(..., BlockReason.NotInAllow);
```
New file `TypeProcessor.cs` builds allow/deny lists including: `System.Data.DataSet`, `System.Web.UI.LosFormatter`, `System.Web.UI.ObjectStateFormatter`, `System.Windows.Markup.XamlReader`, `System.Windows.Data.ObjectDataProvider`, `System.Xml.XmlDocument/XmlDataDocument`, `System.Web.Script.Serialization.JavaScriptSerializer/SimpleTypeResolver`, `System.Workflow.ComponentModel.Serialization.ActivitySurrogateSelector`, `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ClaimsIdentity/WindowsIdentity/Principals`, `SortedDictionary<>/SortedSet<>`, `ResourceDictionary`, etc.

**V1 vulnerable behavior:** Binder resolved arbitrary `assemblyName/typeName` via `Type.GetType` without allow/deny checks. Used by `SerializationUtility.ConvertSqlBytesToObject`, `ConvertBytesToObject`, `ConvertSqlBytesToObject` (multiple SQLCLR stored procedures and Proxy entrypoints) to deserialize attacker-supplied `SqlBytes`/`byte[]`. Untrusted input: database varbinary or service payloads controlled by user (e.g., Data Quality Services input, BDC/Proxy calls). Missing control: no type restrictions, so BinaryFormatter payload can instantiate any gadget.

**Outcome:** RCE via classic gadgets (DataSet/ExpandedWrapper+ObjectDataProvider→XamlReader.Parse/Process.Start; LosFormatter/ObjectStateFormatter TypeConfuseDelegate; JavaScriptSerializer+SimpleTypeResolver; Workflow ActivitySurrogateSelector; XmlDocument-based gadgets; comparer gadgets in SortedDictionary/SortedSet). Confidentiality/integrity/availability all impacted.

**Bypass routes:** Multiple sinks—any call to `SerializationUtility.*Deserialize*` with untrusted bytes. Dangerous types enumerated in deny list above; v1 allowed all. Feasibility: high for authenticated site-owner (per CSAF PR:L). Alternative endpoints: numerous SQLCLR stored procedures (`MatchingStoredProcedures`, `ReferenceDataStoredProcedures`, etc.) that directly call `ConvertSqlBytesToObject`.

**V2 prevention:** Central binder enforces allow-list and deny-list; blocks on both explicit deny and not-in-allow. Throws `BlockedTypeException`, preventing gadget activation. Coverage: list includes major gadget families; still depends on allow-list completeness (not shown), but deny covers known RCE gadgets. Edge: if allow-list overly permissive or new gadget not denied, residual risk remains—cannot confirm completeness.

**Confidence:** High (clear unsafe deserialization path in v1, explicit allow/deny in v2).

## 3) Deserialization RCE: Search ContentPush IDictionary (candidate CVE-2025-49701 or adjunct)

**Diff hunk (patch)** – New `DbSerializer.Deserialize` and binder:
```
BinaryFormatter binaryFormatter = new BinaryFormatter();
binaryFormatter.Binder = inheritIDictionaryBinder;
IDictionary<string, object> values = (IDictionary<string, object>)binaryFormatter.Deserialize(serializationStream);
```
`InheritIDictionaryBinder` whitelists specific dictionary/Expando/ModelStateDictionary/RouteValueDictionary types.

**V1 vulnerable behavior:** No binder; deserialized arbitrary IDictionary-derived object from stored blob (`doc.Values`) in search analytics ContentPush pipeline. Untrusted input: processing documents built from external content feed. Missing control: no type restriction on BinaryFormatter → attacker could supply gadget (e.g., Hashtable, custom dictionary with malicious comparer, or any BinaryFormatter gadget).

**Outcome:** RCE in search analytics pipeline process under service account.

**Bypass routes:** Any ContentPush ingestion that accepts attacker-controlled serialized values. Alternative paths: none shown outside this serializer. Feasibility: medium (requires ability to feed crafted content into analytics ingestion).

**V2 prevention:** Binder restricts to known safe dictionary types; unknown types rejected by `ValidatingSerializationBinder`. Blocks gadget types not in list. Edge: if a dangerous gadget is in the whitelist (e.g., ModelStateDictionary is allowed but generally benign), residual risk minimal. Bypass completeness: other BinaryFormatter usages in search remain; this change only covers ContentPush store.

**Confidence:** Medium (logic clear; exploit path depends on controllability of ContentPush input).

## 4) Deserialization RCE: CookieAuthData (adjunct to CVE-2025-49704)

**Diff hunk (patch)** – `CookieAuthData` deserialization:
```
if (new BinaryFormatter
{
    Binder = new Microsoft.Office.Server.Security.SafeSerialization.ExplicitReferenceSerializationBinder<Cookie>("DeserializeCookieAuthData")
}.Deserialize(serializationStream) is Cookie cookie)
```

**V1 vulnerable behavior:** Previously: `BinaryFormatter binaryFormatter = new BinaryFormatter(); binaryFormatter.Deserialize(serializationStream);` on Base64 cookie values from untrusted `nameValuePairs` (from federated search auth data). Missing: binder/allow-list. Attacker controlling cookie values could inject BinaryFormatter payload.

**Outcome:** RCE via gadget payload inside cookie values when federated auth data is processed (likely by admin configuring/using federated locations; attack surface narrower).

**Bypass routes:** Each cookie value deserialized individually; any gadget type allowed in v1. Feasibility: medium/low (needs ability to set auth data).

**V2 prevention:** Uses ExplicitReferenceSerializationBinder<Cookie>, limiting to Cookie type; exceptions logged; prevents arbitrary gadget types. Blocks this path; other BinaryFormatter sites still separate.

**Confidence:** Medium (clear binder change; exploit requires config control).

## 5) PowerShell injection in Diagnostics ManagedHost (candidate CVE-2025-49701)

**Diff hunk (patch)** – `Microsoft/Windows/Diagnosis/ManagedHost.cs`:
```
private const string s_ParameterValueRegex = "(?i)(.*(invoke-expression|invoke-command|...|\"|')";
... Regex regex = new Regex(...);
if (regex.Matches(parameterValues[num]).Count > 0) Marshal.ThrowExceptionForHR(...);
parameterValues[num] = CodeGeneration.EscapeSingleQuotedStringContent(parameterValues[num]);
text = text + " -" + parameterNames[num] + " '" + parameterValues[num] + "'";
...
m_Ps.Commands = s_LoadPowershellCmdletProxiesCommand; ExecuteCommand(m_Ps);
```
Proxies override Invoke-Expression/Invoke-Command with caller validation (`Test-Caller`) blocking `<No file>` origins.

**V1 vulnerable behavior:** Built command string `& 'script' -param "value"` with unescaped parameter values; no regex check; no proxy overrides. Untrusted input: diagnostic script parameters (likely user-supplied via diagnostic host). Missing validation allows injection of `";iex ..."` or `&cmd` to achieve arbitrary command execution.

**Outcome:** RCE in diagnostic host context.

**Bypass routes:** Inject metacharacters in parameterValues; also direct use of Invoke-Expression/Invoke-Command inside scripts. Feasibility: high if attacker can invoke diagnostics with custom parameters.

**V2 prevention:** Regex rejects suspicious patterns; escapes single quotes; wraps params in single quotes; loads proxy functions that block Invoke-Expression/Invoke-Command unless called from a file, preventing inline misuse. Bypass completeness: regex could miss novel payloads; however proxy override further constrains. Alternative endpoints: other cmdlets not overridden could still be abused; coverage partial.

**Confidence:** Medium (clear injection prevention; exploitability depends on access to diagnostic host).

---

## Bypass and completeness validation
- **Auth bypass (ToolPane):** Validated 1 route (signout-referrer + ToolPane path). No other routes observed in code. Feasibility high. Coverage: only this path fixed.
- **RCE (CVE-2025-49704 dangerous types):** Deny list explicitly includes: DataSet, DataViewManager, ObjectDataProvider, XamlReader, ResourceDictionary, XmlDocument/XmlDataDocument, JavaScriptSerializer/SimpleTypeResolver, ActivitySurrogateSelector/Workflow Activity, BinaryFormatter/SoapFormatter/NetDataContractSerializer, LosFormatter/ObjectStateFormatter, ClaimsIdentity/ClaimsPrincipal/WindowsIdentity/GenericPrincipal, SortedDictionary/SortedSet, Hashtable, ResXResourceSet/ResourceReader, DirectoryInfo/FileSystemInfo, RolePrincipal, ObjectStateFormatter session, AxHost State, etc. These cover major gadget families. Additional routes documented: CookieAuthData deserialization, ContentPush IDictionary deserialization, generic Ssdqs SQLCLR proxies.
- **Bypass feasibility:** CookieAuthData (medium/low), ContentPush (medium), Ssdqs SQLCLR (high for authenticated user), ToolPane (high unauth with referrer), ManagedHost (medium-high if access).
- **Completeness:** Other BinaryFormatter usages may exist; binder change centralizes Ssdqs path but other assemblies may still deserialize (e.g., SPJobState already used binder). ContentPush change only covers that pipeline.

## Coverage scan (unmapped security-relevant changes)
- applicationHost.config processModel identity password changes: security posture change but unclear (unknown if security-motivated).
- Auth redirect fragment check (`if !ServerDebugFlags.Contains(53020) && !string.IsNullOrEmpty(RedirectUri.Fragment) throw/adjust`): likely anti-open-redirect hardening; not mapped to above vulns.
- CrawlRule authentication type validations: prevents invalid auth types for inclusion rules; could be spoofing/misconfig fix; unknown if security-driven.
- AssemblyVersion/Workflow version string bumps: likely build metadata.
These remain **unknown if security-motivated** and do not map to validated vulns.

## Confirmation status
- ToolPane auth bypass: **Confirmed** (high).
- Ssdqs BinaryFormatter allow/deny RCE: **Confirmed** (high).
- ContentPush IDictionary deserialization RCE: **Uncertain/Medium** (exploit depends on input control).
- CookieAuthData BinaryFormatter RCE: **Uncertain/Medium-Low** (narrow surface).
- ManagedHost PowerShell injection: **Uncertain/Medium** (clear fix, access assumptions).

## Bypass validation summary
- CVE-2025-49706: Confirmed 1 distinct bypass route (signout-referrer + ToolPane).
- CVE-2025-49704: Dangerous types enumerated above; multiple gadget families covered. Bypass routes via multiple deserialize sinks (SQLCLR, Proxy, CookieAuthData). Only validated conceptually; other sinks may exist.
- CVE-2025-49701 candidates: ManagedHost PowerShell injection (medium), ContentPush IDictionary binder (medium). 
- Coverage: may have missed alternate bypass routes; only validated main paths evidenced in diff.
