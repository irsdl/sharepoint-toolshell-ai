import requests
from urllib.parse import urlparse

base_url = "http://10.10.10.166"
target_url = f"{base_url}/_layouts/15/WebPartPage.aspx"

headers = {
    "Host": "10.10.10.166",
    "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
    "Referer": "/_layouts/SignOut.aspx",
}

# Try GET instead of POST
response = requests.get(target_url, headers=headers)
print(f"[*] GET {target_url}")
print(f"[*] Status: {response.status_code}")
