# Purpose: Test accessibility of SharePoint endpoints from historical research
# Outcome: Identify which endpoints bypass authentication

import requests

target_base = "http://10.10.10.166"

# Endpoints from historical research
endpoints = [
    # From CVE-2019-0604
    "/_layouts/15/Picker.aspx",
    "/_layouts/15/Picker.aspx?PickerDialogType=Microsoft.SharePoint.WebControls.ItemPickerDialog",
    # From CVE-2020-1147
    "/_layouts/15/quicklinks.aspx?Mode=Suggestion",
    "/_layouts/15/quicklinksdialogform.aspx?Mode=Suggestion",
    # From CVE-2020-0932/CVE-2020-1181
    "/_vti_bin/WebPartPages.asmx",
    # From CVE-2021-28474/31181
    "/_vti_bin/WebPartPages.asmx/RenderWebPartForEdit",
    "/_vti_bin/WebPartPages.asmx/ExecuteProxyUpdates",
    # OAuth endpoints (should allow OAuth auth)
    "/_vti_bin/client.svc",
    "/_vti_bin/listdata.svc",
    "/_vti_bin/sites.asmx",
    "/_vti_bin/ExcelRest.aspx",
    "/_vti_bin/DelveApi.ashx",
    "/_layouts/15/getpreview.ashx",
    "/_layouts/15/userphoto.aspx",
    "/_layouts/15/download.aspx",
    "/_layouts/15/doc.aspx",
    "/_layouts/15/WopiFrame.aspx",
    # Original exploit endpoint
    "/_layouts/15/ToolPane.aspx",
    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
    # Other potentially interesting endpoints
    "/_layouts/SignOut.aspx",
    "/_layouts/15/SignOut.aspx",
    "/_layouts/Authenticate.aspx",
    "/_layouts/15/Authenticate.aspx",
    "/_layouts/15/start.aspx",
    "/_layouts/15/error.aspx",
    "/_layouts/15/AccessDenied.aspx",
    # My Site endpoint from research
    "/my/",
    "/my/_vti_bin/listdata.svc/UserInformationList",
]

print("[*] Testing endpoint accessibility...")
print(f"[*] Target: {target_base}")
print("\n[Endpoints returning non-401 status:]")

for endpoint in endpoints:
    try:
        r = requests.get(f"{target_base}{endpoint}", timeout=10, allow_redirects=False)
        status = r.status_code
        
        if status != 401:
            body_preview = r.text[:80].replace('\n', ' ') if r.text else ""
            print(f"    {status}: {endpoint}")
            print(f"        Body: {body_preview}...")
            if r.headers.get('Location'):
                print(f"        Redirect: {r.headers['Location']}")
    except Exception as e:
        print(f"    ERROR: {endpoint} - {str(e)[:50]}")

print("\n[*] Testing POST requests to key endpoints...]")
post_endpoints = [
    ("/_layouts/15/Picker.aspx", {}),
    ("/_vti_bin/WebPartPages.asmx", {"Content-Type": "text/xml"}),
    ("/_layouts/15/ToolPane.aspx?DisplayMode=Edit", {"Content-Type": "application/x-www-form-urlencoded"}),
]

for endpoint, headers in post_endpoints:
    try:
        r = requests.post(f"{target_base}{endpoint}", headers=headers, data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    {r.status_code}: POST {endpoint}")
    except Exception as e:
        print(f"    ERROR: POST {endpoint} - {str(e)[:50]}")

print("\n[*] Endpoint accessibility test complete")
