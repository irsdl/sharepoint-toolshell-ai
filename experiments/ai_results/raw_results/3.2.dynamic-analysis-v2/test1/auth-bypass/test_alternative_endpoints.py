#!/usr/bin/env python3
# Purpose: Test alternative SharePoint endpoints for authentication bypass
# Outcome: Check if historical endpoints allow unauthenticated access
# Based on: Historical research patterns from summaries

import requests

target = "http://10.10.10.166"

# Historical endpoints from research
endpoints = [
    # CVE-2019-0604 deserialization endpoint
    ("/_layouts/15/Picker.aspx", "GET"),
    ("/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.Portal.WebControls.ItemPickerDialog", "GET"),
    
    # CVE-2020-1147 DataSet endpoints
    ("/_layouts/15/quicklinks.aspx?Mode=Suggestion", "GET"),
    ("/_layouts/15/quicklinksdialogform.aspx?Mode=Suggestion", "GET"),
    
    # CVE-2023-29357 API endpoints
    ("/_api/web/siteusers", "GET"),
    ("/_api/web/currentuser", "GET"),
    ("/_api/contextinfo", "POST"),
    
    # CVE-2023-24955 endpoints
    ("/_vti_bin/client.svc", "GET"),
    ("/_vti_bin/client.svc/web/GetFolderByServerRelativeUrl('/BusinessDataMetadataCatalog/')", "POST"),
    
    # CVE-2024-38094 mentioned in IR writeup
    ("/_vti_bin/DelveApi.ashx/config/", "GET"),
    
    # WebPart endpoints
    ("/_vti_bin/WebPartPages.asmx", "GET"),
    
    # User enumeration
    ("/my/_vti_bin/listdata.svc/UserInformationList", "GET"),
    
    # Other common layouts
    ("/_layouts/15/start.aspx", "GET"),
    ("/_layouts/SignOut.aspx", "GET"),
    ("/_layouts/15/settings.aspx", "GET"),
]

print("Testing alternative SharePoint endpoints for authentication requirements:\n")

for endpoint, method in endpoints:
    url = f"{target}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, allow_redirects=False, timeout=5)
        else:
            response = requests.post(url, allow_redirects=False, timeout=5)
        
        status = response.status_code
        
        # Determine if authentication is required
        if status == 401:
            auth_status = "🔒 AUTH REQUIRED"
        elif status == 403:
            auth_status = "🔒 FORBIDDEN"
        elif status == 302 or status == 301:
            location = response.headers.get('Location', '')
            if 'login' in location.lower() or 'auth' in location.lower():
                auth_status = "🔒 REDIRECT TO LOGIN"
            else:
                auth_status = f"↪️  REDIRECT to {location[:50]}"
        elif status == 200:
            auth_status = "✅ ACCESSIBLE"
        elif status == 404:
            auth_status = "❌ NOT FOUND"
        elif status == 500:
            auth_status = "⚠️  SERVER ERROR"
        else:
            auth_status = f"❓ {status}"
        
        print(f"{auth_status:30} | {method:4} | {endpoint}")
        
    except Exception as e:
        print(f"{'❌ ERROR':30} | {method:4} | {endpoint} ({str(e)[:30]})")

print("\n" + "="*80)
print("Legend: ✅ = No auth required, 🔒 = Auth required, ❌ = Not found/error")
