# SharePoint Security Writeups Summary

This document provides a comprehensive summary of all SharePoint security research documents, including exploited weaknesses, bypass techniques, tips, and achievement descriptions.

---

## Code Execution on Microsoft SharePoint through BDC Deserialization _ Trend Micro.md

**Weaknesses Exploited:**
- Business Data Connectivity (BDC) Service in SharePoint allows arbitrary deserialization of XmlSerializer streams due to arbitrary method parameter types in the definition of custom BDC models
- Type system allows specification of Microsoft.BusinessData.Runtime.DynamicType as parameter type, enabling caller flexibility to pass many different types which results in deserialization of arbitrary XmlSerializer stream

**Bypasses Used:**
- BDC model can be defined with a parameter of type Microsoft.BusinessData.Runtime.DynamicType, allowing attacker-controlled deserialization

**Tips and Useful Notes:**
- Administrator must define a custom BDC model and upload it via SharePoint Central Administration or PowerShell for exploitation
- Microsoft addressed the vulnerability in September patch by correcting how SharePoint checks the source markup of application packages

**Summary:** CVE-2019-1257 (ZDI-19-812) exploited arbitrary deserialization in SharePoint BDC Service to achieve RCE. By defining custom BDC models with Microsoft.BusinessData.Runtime.DynamicType parameters, attackers could execute code in the context of the SharePoint application pool and farm account.

---

## Investigating a SharePoint Compromise_ IR Tales from the Field _ Rapid7 Blog.md

**Weaknesses Exploited:**
- CVE-2024-38094 - Microsoft SharePoint Remote Code Execution vulnerability exploited for initial access
- Insufficient logging and event log tampering capabilities allowed attacker to disable system logging and clear event logs using Mimikatz

**Bypasses Used:**
- Exploitation of CVE-2024-38094 allowed dropping webshell (ghostfile93.aspx) on SharePoint server
- Installation of Horoung Antivirus to disable security tooling and bypass endpoint protection (Impairing Defenses T1562)

**Tips and Useful Notes:**
- POST requests to `/_vti_bin/client.svc/web/GetFolderByServerRelativeUrl('/BusinessDataMetadataCatalog/')` and `/_vti_bin/DelveApi.ashx/config/ghostfile93.aspx` are indicators of CVE-2024-38094 exploitation
- Fast Reverse Proxy (FRP) tool (msvrp.exe) can be used for persistence via scheduled tasks to maintain external access through NAT firewalls
- Various credential harvesting tools observed: Mimikatz (66.exe), ADExplorer64.exe, NTDSUtil.exe, Certify.exe (creates ADFS certificates), kerbrute_windows_amd64.exe

**Summary:** CVE-2024-38094 was exploited to achieve RCE on SharePoint, followed by lateral movement using compromised Exchange service account. Attacker maintained access for two weeks using webshells, disabled security products, dumped credentials with Mimikatz, and established persistence via FRP and scheduled tasks.

---

## ndss21.pdf_rag_clean.md

**Weaknesses Exploited:**
- Object Injection Vulnerabilities (OIVs) occur when untrusted data instantiates objects of arbitrary attacker-controlled types with attacker-chosen properties
- Deserialization processes in .NET can reconstruct object graphs from attacker-controlled serialized streams without proper type restrictions
- YamlDotNet library allows instantiation of arbitrary types via Activator.CreateInstance during deserialization with no type restrictions until after object creation

**Bypasses Used:**
- ObjectDataProvider gadget can be used with property setters to invoke arbitrary methods via reflection
- BinaryFormatter in Azure DevOps can be exploited through Wiki page content when Markdown parser throws exceptions, causing content to be stored as-is to indexes
- YamlDotNet deserialization in Azure DevOps YAML pipeline configurations allows RCE when combined with XSS to elevate privileges

**Tips and Useful Notes:**
- SerialDetector tool identifies OIV patterns through taint-based dataflow analysis from entry points to sensitive sinks (type creation) to attack triggers (method invocations)
- 123 different sensitive sinks were detected in .NET Framework that create objects of arbitrary types
- Look-ahead deserialization approach using SerializationBinder allows whitelisting safe types during BinaryFormatter deserialization

**Summary:** The paper presents SerialDetector, a systematic approach for detecting Object Injection Vulnerabilities in .NET applications. Three CVEs in Azure DevOps Server were discovered (CVE-2019-1306, CVE-2019-0866, CVE-2019-0872) by analyzing deserialization vulnerabilities in BinaryFormatter and YamlDotNet through various threat models.

---

## New Wine in Old Bottle - Microsoft Sharepoint Post-Auth Deserialization RCE (CVE-2022-29108) _ STAR Labs.md

**Weaknesses Exploited:**
- ChartAdminPageBase.get_currentWorkingSet() retrieves binary data from StateService and passes it directly to BinaryFormatter.Deserialize() without SerializationBinder validation
- State Service is not enabled by default, requiring manual configuration for exploitation
- Self-Service Site Creation feature must be enabled for normal users to create sub-sites

**Bypasses Used:**
- Similar to CVE-2022-22005, but uses ChartAdminPageBase.get_currentWorkingSet() instead of ChartPreviewImage.loadChartImage() as the sink
- Binary session data can be stored and replayed using InfoPath file upload mechanism

**Tips and Useful Notes:**
- CVE-2022-29108 is closely related to CVE-2022-22005 and was likely found during 1-day analysis
- Microsoft patched CVE-2022-22005 by adding SerializationBinder to prevent arbitrary data deserialization in ChartPreviewImage.loadChartImage()
- Exploit uses InfoPath to upload gadget chain as attachment, retrieves session IDs, and replays them to trigger deserialization

**Summary:** CVE-2022-29108 achieved post-auth RCE through BinaryFormatter deserialization in SharePoint 2019. The vulnerability uses ChartAdminPageBase.get_currentWorkingSet() to deserialize attacker-controlled data from State Service, bypassing the SerializationBinder fix applied to CVE-2022-22005.

---

## SharePoint and Pwn __ Remote Code Execution Against SharePoint Server Abusing DataSet.md

**Weaknesses Exploited:**
- CVE-2020-1147 - DataSet deserialization vulnerability allowing arbitrary XmlSerializer streams to execute code
- DataSet.ReadXml() calls XmlSerializer.Deserialize with schema types that can be overwritten by attacker-supplied data
- ContactLinksSuggestionsMicroView.GetDataSet() populates DataSet from user-controlled __SUGGESTIONSCACHE__ parameter without validation

**Bypasses Used:**
- ExpandedWrapper class can load two different types simultaneously for gadget chains
- LosFormatter.Deserialize can be used as attack trigger since the class contains no interface members
- DataSet schema can be overwritten at deserialization time using msdata:DataType attribute in XML

**Tips and Useful Notes:**
- Endpoints `/_layouts/15/quicklinks.aspx?Mode=Suggestion` and `/_layouts/15/quicklinksdialogform.aspx?Mode=Suggestion` are exploitable without creating custom pages
- SharePoint installer sets AllowInsecureGuestAuth registry value to 1, allowing anonymous SMB access for TypeConverter exploitation
- XamlReader.Load requires registry access which IUSR impersonation doesn't provide, necessitating alternative static methods like LosFormatter.Deserialize

**Summary:** CVE-2020-1147 exploited DataSet deserialization to achieve RCE on SharePoint. By manipulating XML schema in __SUGGESTIONSCACHE__ parameter via ContactLinksSuggestionsMicroView, attackers could inject arbitrary types using ExpandedWrapper and LosFormatter gadgets, executing code in SharePoint application pool context.

---

## Source Incite - CVE-2020-17120 SharePoint SPSqlDataSource Information Disclosure.md

**Weaknesses Exploited:**
- SPSqlDataSource class lacks proper validation of user-supplied ConnectionString property

**Tips and Useful Notes:**
- In some cases, attackers can leverage this vulnerability to disclose files in the context of Administrator

**Summary:** CVE-2020-17120 is an information disclosure vulnerability in SharePoint Server SPSqlDataSource class that allows authenticated remote attackers to disclose sensitive information by manipulating the ConnectionString property. Microsoft patched this in December 2020.

---

## Source Incite - CVE-2022-21968 SharePoint DNS Rebinding SSRF.md

**Weaknesses Exploited:**
- SPWebRequest SafeCreate API has time-of-check-time-of-use (TOCTOU) vulnerability when requesting IP addresses from DNS servers

**Bypasses Used:**
- DNS rebinding attack can bypass IP restrictions during server-side request forgery attacks

**Tips and Useful Notes:**
- Allows bypassing access IP restrictions on SharePoint Server

**Summary:** CVE-2022-21968 is a DNS rebinding SSRF vulnerability in SharePoint Server SPWebRequest SafeCreate API. The TOCTOU vulnerability allows authenticated attackers to bypass IP restrictions when performing server-side request forgery attacks through DNS rebinding techniques. Patched February 2022.

---

## Zero Day Initiative — CVE-2019-0604_ Details of a Microsoft SharePoint RCE Vulnerability.md

**Weaknesses Exploited:**
- EntityInstanceIdEncoder.DecodeEntityInstanceId() uses XmlSerializer with attacker-controlled type parameter derived from encodedId
- ItemPicker.ValidateEntity() calls EntityInstanceIdEncoder.DecodeEntityInstanceId() with user-controlled PickerEntity.Key property
- EntityEditor.ParseSpanData() processes hiddenSpanData from POST requests with minimal validation, allowing arbitrary data in PickerEntity.Key

**Bypasses Used:**
- Picker.aspx with PickerDialogType parameter accepts ItemPickerDialog types to instantiate EntityEditor controls

**Tips and Useful Notes:**
- Three .aspx files expose the vulnerable pattern: ActionRedirect.aspx, downloadexternaldata.aspx, and profileredirect.aspx (but use query strings which can hit length limits)
- Original patch only addressed Microsoft.SharePoint.BusinessData.Infrastructure.EntityInstanceIdEncoder but not Microsoft.Office.Server.ApplicationRegistry.Infrastructure.EntityInstanceIdEncoder, requiring re-release of CVE-2019-0604

**Summary:** CVE-2019-0604 achieved RCE through XmlSerializer deserialization in SharePoint. By controlling the PickerEntity.Key via hiddenSpanData in ItemPicker POST requests to `/_layouts/15/Picker.aspx`, attackers could specify arbitrary types for XmlSerializer.Deserialize(), executing code in SharePoint application pool context.

---

## Zero Day Initiative — CVE-2020-0932_ Remote Code Execution on Microsoft SharePoint Using TypeConverters.md

**Weaknesses Exploited:**
- WebPartPages.RenderWebPartForEdit allows arbitrary Type specifications in WebPart property XML without restriction
- System.Resources.ResXFileRef.Converter TypeConverter parses attacker-controlled resource file paths and type names
- System.Resources.ResourceSet constructor feeds Stream content to BinaryFormatter.Deserialize()

**Bypasses Used:**
- ResXFileRef TypeConverter can instantiate arbitrary types with Stream constructor argument from attacker-controlled SMB share
- SharePoint installer sets AllowInsecureGuestAuth=1 registry value, allowing anonymous SMB share access

**Tips and Useful Notes:**
- Default SharePoint configuration allows any authenticated user to create sites with "Add or Customize Pages" permissions
- Vulnerable entry point is `/_vti_bin/WebPartPages.asmx` web service accessible via HTTP
- .resources file can be generated using Visual Studio's Resource File Generator (Resgen.exe) with modified .resx file containing BinaryFormatter payload

**Summary:** CVE-2020-0932 exploited TypeConverter mechanism in SharePoint to achieve RCE. By specifying System.Resources.ResXFileRef type in WebPart properties via RenderWebPartForEdit method, attackers could load malicious .resources files from SMB shares, triggering BinaryFormatter deserialization in ResourceSet constructor.

---

## Zero Day Initiative — CVE-2020-1181_ SharePoint Remote Code Execution Through Web Parts.md

**Weaknesses Exploited:**
- WikiContentWebpart.CreateChildControls() calls Page.ParseControl() with attacker-controlled Directive and Content parameters
- SPPageParserFilter initialization treats "ghosted" pages (created via SharePoint web editor) as trusted sources with unrestricted compilation mode
- GetEffectivePageParserSettings() returns PageParserSettings.GhostedPageDefaultSettings with AllowUnsafeControls=true and AllowServerSideScript=true for ghosted pages

**Bypasses Used:**
- WikiContentWebpart allows inclusion of arbitrary ASP.NET markup that gets parsed with unrestricted PageParserSettings
- ObjectDataSource control with SelectMethod="Start" and TypeName="system.diagnostics.process" can execute OS commands

**Tips and Useful Notes:**
- Pages created via SharePoint Web Editor are treated as "ghosted" and excluded from safety restrictions
- No code blocks or file inclusion allowed in user pages, but web editor-created pages bypass these restrictions

**Summary:** CVE-2020-1181 achieved RCE through WikiContentWebpart in SharePoint. Ghosted pages created via web editor were incorrectly trusted, allowing arbitrary ASP.NET markup in WikiContentWebpart Content parameter. This enabled use of dangerous controls like ObjectDataSource to execute system commands via Process.Start.

---

## Zero Day Initiative — CVE-2021-26420_ Remote Code Execution in SharePoint via Workflow Compilation.md

**Weaknesses Exploited:**
- WorkflowCompilerInternal type is not blocked by authorizedTypes list but has same dangerous functionality as blocked WorkflowCompiler
- Workflow compilation accepts XOML files with embedded C# code when noCode flag is not specified
- AssociateWorkflowMarkup method from WebPartPages WebService allows associating workflows with arbitrary XOML and .rules files

**Bypasses Used:**
- Direct invocation of WorkflowCompilerInternal.Compile() bypasses authorizedTypes whitelist that blocks WorkflowCompiler
- XOML workflow can load arbitrary code from attacker-controlled SMB shares

**Tips and Useful Notes:**
- Requires "Manage Lists" permissions on SharePoint site (any authenticated user can create their own site with necessary permissions)
- Attacker needs to upload WF02.xoml, WF02.rules, and WF02config.xml files to SharePoint Documents folder
- Workflow execution is triggered by adding new item to target SharePoint list

**Summary:** CVE-2021-26420 achieved RCE through workflow compilation in SharePoint. By directly invoking WorkflowCompilerInternal instead of blocked WorkflowCompiler, attackers could compile arbitrary XOML workflows containing embedded .NET code, loading malicious code from SMB shares when workflow is associated and executed.

---

## Zero Day Initiative — CVE-2021-27076_ A Replay-Style Deserialization Attack Against SharePoint.md

**Weaknesses Exploited:**
- InfoPath DocumentSessionState serialization stores arbitrary object data in session state via BinaryFormatter
- Document.LoadFromSession() deserializes DocumentSessionState using BinaryFormatter.Deserialize() without type validation
- Session state keys (editingSessionId) can be influenced from client side, allowing replay of data across different contexts

**Bypasses Used:**
- Attachment upload stores arbitrary file content in session state with intent of attachment handling, but can be replayed as DocumentSessionState
- DocumentSessionState contains attachmentId which can be extracted and replayed into attachment mechanism to retrieve state key
- State key of attachment can be fed into undocumented client-side API to trigger deserialization in wrong context

**Tips and Useful Notes:**
- Replay attack involves creating InfoPath list, attaching malicious file, extracting state keys, and replaying across contexts
- FormServerAttachments.aspx endpoint allows replaying DocumentSessionState into attachment mechanism
- Seven-step exploit process: create InfoPath list, attach file with gadget, scrape document state key, feed to FormServerAttachments.aspx, extract attachment state key, feed to undocumented API, achieve RCE

**Summary:** CVE-2021-27076 achieved RCE through replay-style deserialization attack in SharePoint InfoPath. By manipulating session state keys across different contexts (DocumentSessionState vs attachment upload), attackers could store malicious BinaryFormatter payloads as attachments and replay them in deserialization context, bypassing intended usage restrictions.

---

## Zero Day Initiative — CVE-2021-28474_ SharePoint Remote Code Execution via Server-Side Control Interpretation Conflict.md

**Weaknesses Exploited:**
- EditingPageParser.VerifyControlOnSafeList() does not HTML-decode attribute values during verification, but TemplateParser.ProcessAttributes() does during processing
- Inconsistency between verification and processing allows runat="&#115;erver" to bypass safety checks but still execute as server-side control
- System.Web.UI.WebControls.Xml control marked as unsafe in web.config but can be instantiated via HTML entity encoding bypass

**Bypasses Used:**
- HTML entity encoding of "server" attribute value (&#115;erver) bypasses EditingPageParser verification
- Xml control's DocumentSource property can retrieve arbitrary XML files including web.config
- Extracted machineKey from web.config enables ViewState forgery for RCE via deserialization

**Tips and Useful Notes:**
- WebPartPagesWebService.ExecuteProxyUpdates at `/_vti_bin/WebPartPages.asmx` allows rendering ASPX markup with OuterHtml attribute
- Requires SPBasePermissions.ManageLists permissions (default for authenticated users creating their own sites)
- Chain combines Xml control information disclosure with ViewState deserialization for full RCE

**Summary:** CVE-2021-28474 achieved RCE through server-side control interpretation conflict in SharePoint. HTML entity encoding of runat attribute bypassed EditingPageParser safety checks, allowing instantiation of unsafe Xml control to extract web.config machineKey, which was then used to forge ViewState for deserialization-based RCE.

---

## Zero Day Initiative — CVE-2021-31181_ Microsoft SharePoint WebPart Interpretation Conflict Remote Code Execution Vulnerability.md

**Weaknesses Exploited:**
- EditingPageParser.VerifyControlOnSafeList() doesn't trim namespace attribute values, while TemplateParser.GetAndRemove() does trim them
- Trailing space in namespace attribute causes Type resolution failure during verification but succeeds during processing
- XmlDataSource control marked as unsafe can be instantiated via namespace with trailing space

**Bypasses Used:**
- Register directive with Namespace="System.Web.UI.WebControls " (trailing space) bypasses Type resolution during verification
- XsltListFormWebPart allows specifying XmlDataSource in DataSources element
- XmlDataSource XPath and datafile properties enable arbitrary XML file retrieval including web.config

**Tips and Useful Notes:**
- RenderWebPartForEdit WebAPI method at `/_vti_bin/WebPartPages.asmx` processes ASPX markup in Design mode
- Requires site webId and existing SPList title (easily obtained via `/_api/web/id` and `/_layouts/15/viewlsts.aspx`)
- Exploit chain: bypass safety check → extract machineKey → forge ViewState → RCE via deserialization

**Summary:** CVE-2021-31181 achieved RCE through WebPart interpretation conflict in SharePoint. Trailing space in namespace attribute bypassed EditingPageParser type validation, allowing instantiation of unsafe XmlDataSource control to extract web.config machineKey via XsltListFormWebPart, enabling ViewState forgery for deserialization-based RCE.

---

## Zero Day Initiative — CVE-2024-30043_ Abusing URL Parsing Confusion to Exploit XXE on SharePoint Server and Cloud.md

**Weaknesses Exploited:**
- BaseXmlDataSource.Execute() uses XmlTextReader with XmlSecureResolver but parameter entities are resolved before DTD prohibition check
- XmlReaderSettings.DtdProcessing=Prohibit blocks general entities but not parameter entities when XmlResolver is set
- SPXmlDataSource URL parsing differs from XmlSecureResolver parsing, allowing malformed URLs to bypass restrictions

**Bypasses Used:**
- Parameter entity-based XXE payload triggers HTTP requests even when DtdProcessing is set to Prohibit
- URL file://localhost\c$/sites/mysite/test.xml is parsed differently: SPXmlDataSource treats it as SharePoint path, XmlSecureResolver treats it as unrestricted file access
- URL parsing confusion gives unrestricted XmlSecureResolver policy while still retrieving attacker-controlled XML from SharePoint

**Tips and Useful Notes:**
- Three DataSource classes extend BaseXmlDataSource: SoapDataSource, XmlUrlDataSource, SPXmlDataSource
- HTTP-based sources (XmlUrlDataSource, SoapDataSource) have SSRF protections blocking local addresses
- .NET XXE protection settings are tricky - XmlTextReader vs XmlReaderSettings handle DTD prohibition differently

**Summary:** CVE-2024-30043 exploited XXE vulnerability in SharePoint through URL parsing confusion. By using malformed URL file://localhost\c$/sites/mysite/test.xml, attackers could upload malicious XML to SharePoint and trigger parameter entity-based out-of-band XXE for file disclosure and SSRF, bypassing both DTD prohibition and XmlSecureResolver restrictions.

---

## [P2O Vancouver 2023] SharePoint Pre-Auth RCE chain (CVE-2023–29357 & CVE-2023–24955) _ STAR Labs.md

**Weaknesses Exploited:**
- SPApplicationAuthenticationModule allows JWT tokens with "none" signing algorithm, completely skipping signature validation
- SPIdentityProofTokenHandler.ValidateTokenIssuer() skips issuer validation if ver field is set to "hashedprooftoken"
- DynamicProxyGenerator.GenerateProxyAssembly() has code injection in proxyNamespaceName parameter with no validation

**Bypasses Used:**
- JWT with alg="none" bypasses signature verification in JsonWebSecurityTokenHandler.ReadTokenCore()
- Setting ver="hashedprooftoken" and isloopback=true bypasses issuer validation and SSL requirement checks
- Malicious WebServiceProxyNamespace property allows arbitrary C# code injection during proxy assembly compilation
- BDCMetadata.bdcm file in /BusinessDataMetadataCatalog/ can be written to inject malicious LobSystem objects

**Tips and Useful Notes:**
- Authentication bypass works only for SharePoint API endpoints (`/_api/`, `/_vti_bin/client.svc`, etc.) but not regular pages
- Requires knowing valid SharePoint site username - can enumerate via `/my/_vti_bin/listdata.svc/UserInformationList` with authenticated users filter
- Code injection requires Microsoft.SharePoint.BusinessData.MetadataModel.ClientOM.Entity.Execute() accessible via `/_vti_bin/client.svc/ProcessQuery`

**Summary:** CVE-2023-29357 & CVE-2023-24955 achieved pre-auth RCE chain in SharePoint. Authentication bypass via JWT "none" algorithm and hashedprooftoken verification skip allowed impersonating any user. Combined with code injection in DynamicProxyGenerator through malicious BDCMetadata.bdcm file, attackers achieved full RCE by compiling and executing arbitrary .NET code in SharePoint context.

---

## Summary Statistics

**Total Documents Analyzed:** 15

**Vulnerability Type Breakdown:**
- Deserialization vulnerabilities: 10 (BinaryFormatter, XmlSerializer, DataSet, YamlDotNet)
- Code injection: 4 (Workflow compilation, DynamicProxyGenerator, WikiContentWebpart, ObjectDataSource)
- XXE: 1 (URL parsing confusion)
- Information disclosure: 1 (SPSqlDataSource)
- SSRF: 1 (DNS rebinding)
- Authentication bypass: 1 (JWT "none" algorithm)

**Common Attack Patterns:**
- SMB share abuse for loading malicious payloads
- ViewState forgery after extracting machineKey from web.config
- Session state replay attacks
- Type confusion and interpretation conflicts
- HTML entity encoding bypasses
- URL/path parsing inconsistencies
- Workflow and compilation mechanisms

**Recurring Entry Points:**
- `/_vti_bin/WebPartPages.asmx` (RenderWebPartForEdit, ExecuteProxyUpdates)
- `/_vti_bin/client.svc` (ProcessQuery)
- `/_layouts/15/` endpoints (Picker.aspx, quicklinks.aspx, etc.)
- BDCMetadata manipulation in `/BusinessDataMetadataCatalog/`
- InfoPath and State Service session management

**Key Defensive Gaps Identified:**
- Insufficient SerializationBinder usage in BinaryFormatter deserialization
- Inconsistent validation between security checks and actual processing
- Type whitelisting bypasses through internal/alternative classes
- Incomplete patches addressing only specific entry points
- Trusted page assumptions (ghosted pages, workflow files)
