#!/usr/bin/env bash
set -euo pipefail
FROM="$1"   # e.g. snapshots_raw/SERVERA/v1_...
TO="$2"     # e.g. snapshots_raw/SERVERB/v2_...
OUTDIR="${3:-diff_reports}"

INCLUDE_EXT=("*.config" "*.xml" "*.json" "*.aspx" "*.ascx" "*.master" "*.cshtml" \
             "*.svc" "*.asmx" "*.xaml" "*.xamlx" "*.xoml" "*.ashx" "*.axd" "*.soap" \
             "*.js" "*.html" "*.htm" "*.ps1" "*.psm1" "*.psd1" "*.resx" "*.xslt")
EXCLUDE_EXT=("*.dll" "*.exe" "*.pdb" "*.snk" "*.wsp" "*.xsn" "*.xap" "*.log")

mkdir -p "$OUTDIR"
TMP="$(mktemp -d)"
LEFT="$TMP/left"; RIGHT="$TMP/right"
mkdir -p "$LEFT" "$RIGHT"

copy_set () {
  local SRC="$1" DST="$2"
  while IFS= read -r -d '' f; do
    rel="${f#$SRC/}"
    mkdir -p "$(dirname "$DST/$rel")"
    cp -f "$f" "$DST/$rel"
  done < <(find "$SRC" -type f \( $(printf -- '-name %q -o ' "${INCLUDE_EXT[@]}" | sed 's/ -o $//') \) \
           ! \( $(printf -- '-name %q -o ' "${EXCLUDE_EXT[@]}" | sed 's/ -o $//') \) -print0)
}

copy_set "$FROM" "$LEFT"
copy_set "$TO"   "$RIGHT"

PAIR="$(basename "$FROM")-to-$(basename "$TO")"
PATCH="$OUTDIR/$PAIR.settings.patch"
STAT="$OUTDIR/$PAIR.settings.stat.txt"

git diff --no-index --patch --text "$LEFT" "$RIGHT" > "$PATCH" || true
git diff --no-index --stat  --text "$LEFT" "$RIGHT" > "$STAT"  || true

echo "Diffs:"
echo " - $PATCH"
echo " - $STAT"
