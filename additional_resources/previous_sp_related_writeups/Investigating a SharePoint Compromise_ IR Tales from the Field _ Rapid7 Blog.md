---
title: "Investigating a SharePoint Compromise: IR Tales from the Field | Rapid7 Blog"
source: "https://www.rapid7.com/blog/post/2024/10/30/investigating-a-sharepoint-compromise-ir-tales-from-the-field/"
original_path: "Investigating a SharePoint Compromise_ IR Tales from the Field _ Rapid7 Blog.html"
generated: "2025-11-17T00:30:41.798703+00:00"
---

Rapid7 in the 2025 Gartner® Magic Quadrant™ for SIEM. Read now. 


Services 


Partners 

Company 

Request Demo 

Back to Blog 
Detection and Response 
Investigating a SharePoint Compromise: IR Tales from the Field 

Rapid7 

Oct 30, 2024 | Last updated on Oct 30, 2024 | 9 min read 


Executive summary 

Observed attacker behavior 

Rapid7 customers 

MITRE ATT&CK techniques 

Indicators of Compromise 

Executive summary 

Rapid7’s Incident Response team recently investigated a Microsoft Exchange service account with domain administrator privileges. Our investigation uncovered an attacker who accessed a server without authorization and moved laterally across the network, compromising the entire domain. The attacker remained undetected for two weeks. Rapid7 determined the initial access vector to be the exploitation of a vulnerability, CVE 2024-38094 , within the on-premise SharePoint server. 

Exploitation for initial access has been a common theme in 2024, often requiring security tooling and efficient response procedures to avoid major impact. The attacker’s tactics, techniques, and procedures (TTPs) are showcased in this blog, along with some twists and turns we encountered when handling the investigation. 

Observed attacker behavior 

Rapid7 began exploring suspicious activity that involved process executions tied to a Microsoft Exchange service account. This involved the service account installing the Horoung Antivirus (AV) software, which was not an authorized software in the environment. For context, Horoung Antivirus is a popular AV software in China that can be installed from Microsoft Store. Most notably, the installation of Horoung caused a conflict with active security products on the system. This resulted in a crash of these services. Stopping the system’s current security solutions allowed the attacker freedom to pursue follow-on objectives thus relating this malicious activity to Impairing Defenses (T1562). 

Zooming out from the specific event to look at the surrounding activity paints a clear picture of the attacker’s intended goal. Shortly before installing Horoung AV, the attacker used Python to install Impacket from GitHub and then attempted to execute it. Impacket is a collection of open-source Python scripts to interact with network protocols, typically utilized to facilitate lateral movement and other post-exploitation objectives. The system’s security tooling blocked the Impacket execution, which led to the download via browser and installation of this AV product to circumvent defenses. 

As with many incident response investigations, identified clues are not always chronological, thus requiring a timeline to be constructed to understand the narrative. We must attempt to discover how the attacker compromised the system or accessed the environment in the first place. In this specific investigation, the attacker had a dwell time of two weeks. The attacker’s actions are detailed chronologically in the figure below. 

A great resource for identifying lateral movement involves analysis of authentication event logs from the domain controllers, specifically event ID 4624. Evidence indicated that malicious activity for this compromised Exchange service account involved more than just this single system. The source of unauthorized activity went back a week prior on a domain controller. 

Analysis of the domain controller revealed that the attacker used this Exchange service account to authenticate via Remote Desktop Protocol (RDP). The attacker went on to disable Windows Defender Threat Detection (WDTD) on the system and added an exclusion for a malicious binary called msvrp.exe using the GUI. The malicious binary was placed in the C:\ProgramData\VMware\ folder but was not related to VMware. This binary is a tool called Fast Reverse Proxy (FRP), which allows external access to the system through a NAT-configured firewall. The FRP tool requires an .ini file to provide the necessary network configuration to establish an outbound connection. The .ini file’s external IP address has been provided in the Indicators of Compromise (IoCs) table in this blog post. Persistence was established for the FRP via scheduled tasks on the domain controller. Review of the C:\ProgramData\VMware\ folder used by the attacker revealed additional malicious binaries such as ADExplorer64.exe, NTDSUtil.exe, and nxc.exe. These tools were utilized to map the Active Directory environment, gather credentials, and scan systems. 

Further analysis of authentication events from the domain controller indicated this malicious activity was sourced from a public-facing SharePoint server. Evidence indicated that the attacker executed Mimikatz, and there were signs of log tampering on the SharePoint server. It also indicated that a majority of system logging was disabled, and several key event log sources were absent during the investigation timeframe. Mimikatz has the ability to clear event logs and disable system logging. These malicious executions were tied to the local administrator account on the system. This would provide the necessary privileges for log tampering on the SharePoint server. However, some logs were spared, such as RDP log evidence. This indicated all authentication for the local administrator account was sourced from the local system to the local system during the in-scope time frame. The authentication information indicated that the potential initial access vector (IAV) would be tied to this SharePoint server. In light of this evidence, Rapid7 dug deeper into potential exploitation of the SharePoint services for an answer. 

Rapid7 reviewed available SharePoint inetpub logs and identified the following GET and POST requests indicative of CVE-2024-38094 being exploited from the external IP address 18.195.61[.]200. 

POST /_vti_bin/client.svc/web/GetFolderByServerRelativeUrl('/BusinessDataMetadataC atalog/')/Files/add(url='/BusinessDataMetadataCatalog/BDCMetadata.bdcm 
 
POST /_vti_bin/DelveApi.ashx/config/ghostfile93.aspx 

This vulnerability allows for remote code execution (RCE) on systems running Microsoft SharePoint from an external source. The proof-of-concept (PoC) code identified here was observed in available SharePoint log evidence. A great resource that explains the PoC code on Github can be found here . Utilizing this vulnerability, the attacker dropped a webshell on the system. The webshell was called ghostfile93.aspx, which generated numerous HTTP POST requests from the same external IP address tied to the exploit string within log evidence. After several hours of using the webshell, the attacker authenticated into the system using the local administrator account. 

Initial access occurred two weeks prior to the start of the investigation. The attacker performed other notable TTPs during the dwell time. These TTPs involved utilizing several binaries to include everything.exe, kerbrute_windows_amd64.exe, 66.exe, Certify.exe, and attempts to destroy third-party backups. The binary everything.exe can index the NTFS file system for efficient searching across files, such as recently used files and network shares. Some of the most notable binaries include 66.exe, a renamed version of Mimikatz, and Certify.exe, which creates an ADFS certificate to utilize for elevated actions within the Active Directory environment. The remaining binary kerbrute_windows_amd64.exe has extensive capability for brute-forcing Active Directory Kerberos tickets. The attacker failed to compromise the third-party backup solution but attempted multiple methods, including access via the browser using compromised credentials and connecting over SSH. 

As discussed previously, the installation of external AV products to disable security tooling was an interesting TTP identified during this investigation. Shortly after being blocked for attempted Impacket execution, Rapid7 identified the attacker leveraging an installation batch script called hrsword install.bat. The contents of this script indicate that the Huorong AntiVirus (AV) security solution was being installed. This script involved a service creation called sysdiag to execute the driver file sysdiag_win10.sys, which creates a VBS script execution parameter to execute HRSword.exe. Rapid7 observed this installation causing errors for security products on the system, potentially leading to a scenario in which the service or application would crash. These install files and all IOCs identified during this investigation have been provided in the IOC table contained within this blog. 

Rapid7 customers 

InsightVM and Nexpose customers can assess their exposure to the Microsoft SharePoint CVE-2024-38094 with authenticated vulnerability checks added in the July 09, 2024 content release. 

Rapid7 used Velociraptor during this investigation to allow for remote triage and collection of forensic artifacts on the endpoint. A Velociraptor artifact has been created to hunt for strings related to the public PoC and log evidence identified during the investigation. The artifact can be found within the Rapid7 Labs VQL Repo here 

InsightIDR and Managed Detection and Response customers have existing detection coverage through Rapid7's expansive library of detection rules. Rapid7 recommends installing the Insight Agent on all applicable hosts to ensure visibility into suspicious processes and proper detection coverage. Below is a non-exhaustive list of detections that are deployed and will alert on behavior related to exploitation of this vulnerability. 
Suspicious Commands Launched by Webserver 
IIS Launching Discovery Commands 
IIS Spawns PowerShell 
Attacker Tool - Impacket 
Attacker Tool - MimiKatz 
Attacker Technique - Hash Dumping With NTDSUtil 
Attacker Technique - Clearing Event Logs 
Defense Evasion - Disabling Multiple Security or Backup Products 

Rapid7 also recommends ensuring that SharePoint is patched to the latest version. 

MITRE ATT&CK techniques 

Tactic 

Technique 

Details 

Initial Access 

Exploit Public-Facing Application (T1190) 

CVE-2024-38094: Microsoft SharePoint Remote Code Execution Vulnerability 

Defense Evasion 

Impair Defense (T1562) 

AV solution being utilized to disable or degrade security tools on systems. 

Discovery 

Account Discovery (T1087) 

Usage of AD enumeration tools 

Command and Control 

Proxy (T1090) 

Fast Reverse Proxy being used to establish outbound connection 

Discovery 

File and Directory Discovery (T1083) 

Everything.exe being observed on in-scope systems. 

Discovery 

Network Share Discovery (T1135) 

nxc.exe being observed on in-scope systems. 

Credential Access 

OS Credential Dumping (T1003) 

Various credential harvesting tools observed on in-scope systems 

Persistence 

Scheduled Task/Job (T1053) 

Scheduled tasks observed on in-scope systems to execute the FRP tool. 

Indicators of Compromise 

Attribute 

Value 

Description 

Filename and Path 

c:\users\Redacted\documents\everything-1.4.1.1024.x86\everything.exe 

Binary to locate files 

SHA256 

d3a6ed07bd3b52c62411132d060560f9c0c88ce183851f16b632a99b4d4e7581 

Hash for everything.exe 

Filename and Path 

c:\programdata\vmware\66.exe 

Renamed mimikatz.exe 

SHA256 

61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1 

Hash for mimikatz.exe 

Filename and Path 

c:\programdata\vmware\certify.exe 

Creates an ADFS certificate to utilize for elevated actions within the Active Directory environment. 

SHA256 

95cc0b082fcfc366a7de8030a6325c099d8012533a3234edbdf555df082413c7 

Hash for certify.exe 

Filename and Path 

c:\programdata\vmware\kerbrute_windows_amd64.exe 

Used to perform Kerberos pre-auth brute forcing. 

SHA256 

d18aa84b7bf0efde9c6b5db2a38ab1ec9484c59c5284c0bd080f5197bf9388b0 

Hash for kerbrute_windows_amd64.exe 

Filename and Path 

c:\programdata\vmware\msvrp.exe 

Fast Reverse Proxy tool for allowing external access to the system through a NAT configured firewall. 

SHA256 

f618b09c0908119399d14f80fc868b002b987006f7c76adbcec1ac11b9208940 

Hash for msvrp.exe 

Filename and Path 

c:\programdata\vmware\nxc.exe 

Newer version of the CrackMapExec Network Pentesting tool. 

SHA256 

95cc0b082fcfc366a7de8030a6325c099d8012533a3234edbdf555df082413c7 

Hash for nxc.exe 

Filename and Path 

c:\programdata\vmware\adexplorer64.exe 

Active Directory Enumeration Tool 

SHA256 

e451287843b3927c6046eaabd3e22b929bc1f445eec23a73b1398b115d02e4fb 

Hash for adexplorer64.exe 

Filename and Path 

c:\users\Redacted\documents\h\hrsword install.bat 

Component of Huorong AV 

SHA256 

1beec8cecd28fdf9f7e0fc5fb9226b360934086ded84f69e3d542d1362e3fdf3 

Hash for hrsword install.bat 

Filename and Path 

c:\users\Redacted\documents\h\hrsword.exe 

Component of Huorong AV 

SHA256 

6ce228240458563d73c1c3cbbd04ef15cb7c5badacc78ce331848f5431b406cc 

Hash for hrsword.exe 

Filename and Path 

c:\Windows\System32\drivers\sysdiag_win10.sys 

System driver component of Huorong AV 

SHA256 

acb5de5a69c06b7501f86c0522d10fefa9c34776c7535e937e946c6abfc9bbc6 

Hash for sysdiag_win10.sys 

Log-Based IOC 

POST /_vti_bin/client.svc/web/GetFolderByServerRelativeUrl('/BusinessDataMetadataC atalog/')/Files/add(url='/BusinessDataMetadataCatalog/BDCMetadata.bdcm 

POC code identified in SharePoint logs. 

Log-Based IOC 

POST /_vti_bin/DelveApi.ashx/config/ghostfile93.aspx 

Webshell identified within SharePoint logs. 

IP Address 

54.255.89[.]118 

IP address from .ini file for Fast Reverse Proxy tool 

IP Address 

18.195.61[.]200 

Source IP address from exploitation and webshell communications 

Article Tags 

Incident Response 

Managed Detection and Response (MDR) 

Detection and Response 

Rapid7 

Author Posts 

Related blog posts 

Detection and Response 

Introducing Enhanced Endpoint Telemetry (EET) in InsightIDR 

Margaret Wei 

Products and Tools 

Rapid7 Introduces “Active Response” for End-to-End Detection and Response 

Jake Godgart 

Detection and Response 


Command Platform 

Exposure Management 

MDR Services 

Take Action 

Start a Free Trial 

Take a Product Tour 

Get Breach Support 

Contact Sales 

Company 

About Us 

Leadership 

Newsroom 

Our Customers 

Partner Programs 

Investors 

Careers 

Stay Informed 


Emergent Threat Response 

Webinars & Events 

Rapid7 Labs Research 

Vulnerability Database 

Security Fundamentals 

For Customers 

Sign In 

Support Portal 

Product Documentation 

Extension Library 

Rapid7 Academy 

Customer Escalation Portal 

Contact Support 

+1-866-390-8113 

Follow Us 

LinkedIn 

X (Twitter) 

Facebook 

Instagram 

Bluesky 

© Rapid7 
Legal Terms Privacy Policy Export Notice Trust Cookie List Accessibility Statement Cookies Settings 

Privacy Preference Center 

When you visit any website, it may store or retrieve information on your browser, mostly in the form of cookies. This information might be about you, your preferences or your device and is mostly used to make the site work as you expect it to. The information does not usually directly identify you, but it can give you a more personalized web experience. Because we respect your right to privacy, you can choose not to allow some types of cookies. Click on the different category headings to find out more and change our default settings. However, blocking some types of cookies may impact your experience of the site and the services we are able to offer. 
More information 
Allow All 

Manage Consent Preferences 

Strictly Necessary Cookies 

Always Active 

These cookies are necessary for the website to function and cannot be switched off in our systems. They are usually only set in response to actions made by you which amount to a request for services, such as setting your privacy preferences, logging in or filling in forms. You can set your browser to block or alert you about these cookies, but some parts of the site will not then work. These cookies do not store any personally identifiable information. 

Cookies Details‎ 

Targeting Cookies 

Targeting Cookies 

These cookies may be set through our site by our advertising partners. They may be used by those companies to build a profile of your interests and show you relevant adverts on other sites. They do not store directly personal information, but are based on uniquely identifying your browser and internet device. If you do not allow these cookies, you will experience less targeted advertising. 

Cookies Details‎ 

Performance Cookies 

Performance Cookies 

These cookies allow us to count visits and traffic sources so we can measure and improve the performance of our site. They help us to know which pages are the most and least popular and see how visitors move around the site. All information these cookies collect is aggregated and therefore anonymous. If you do not allow these cookies we will not know when you have visited our site, and will not be able to monitor its performance. 

Cookies Details‎ 

Functional Cookies 

Functional Cookies 

These cookies enable the website to provide enhanced functionality and personalisation. They may be set by us or by third party providers whose services we have added to our pages. If you do not allow these cookies then some or all of these services may not function properly. 

Cookies Details‎ 

Cookie List 

Clear 

checkbox label label 

Apply Cancel 

Consent Leg.Interest 

checkbox label label 

checkbox label label 

checkbox label label 

Reject All Confirm My Choices
