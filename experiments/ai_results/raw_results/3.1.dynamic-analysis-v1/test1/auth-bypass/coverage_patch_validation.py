import requests

base_url = "http://10.10.10.166"
headers = {"User-Agent": "Mozilla/5.0", "Referer": "/_layouts/SignOut.aspx"}

# Test endpoints with similar names to ToolPane
similar_endpoints = [
    "ToolPane.aspx",  # Should be blocked
    "ToolPaneFrame.aspx",  # Might exist
    "ToolPaneView.aspx",  # Might exist
    "CustomToolPane.aspx",  # Might exist
    "ToolBox.aspx",  # Different name
    "WebPartPage.aspx",  # Known vulnerable
]

print("Testing patch specificity...")
for endpoint in similar_endpoints:
    url = f"{base_url}/_layouts/15/{endpoint}"
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        status_msg = "✗ BLOCKED" if resp.status_code == 401 else "✓ VULNERABLE" if resp.status_code == 200 else f"? {resp.status_code}"
        print(f"  {endpoint:30s} -> {status_msg}")
    except Exception as e:
        print(f"  {endpoint:30s} -> Error")
