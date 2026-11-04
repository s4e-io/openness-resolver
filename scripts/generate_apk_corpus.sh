#!/usr/bin/env bash
# Label APK version pairs with native `apk version -t` inside an Alpine
# container and write testdata/apk/corpus.txt.
# Development/CI tool only; the production resolver never shells out to apk.
set -euo pipefail

cd "$(dirname "$0")/.."
EVIDENCE="${1:-../linux-20260801T220928Z.openness.txt}"

mkdir -p testdata/apk
python3 scripts/generate_apk_corpus.py "$EVIDENCE" > testdata/apk/pairs.txt
echo "generated $(wc -l < testdata/apk/pairs.txt) pairs"

docker run --rm -i -v "$PWD/testdata/apk:/w" alpine:3.19 sh -s <<'EOF'
set -u
out=/w/corpus.txt
: > "$out"
while read -r a b; do
  r=$(apk version -t "$a" "$b" 2>/dev/null) || continue
  case "$r" in
    "<"|"="|">") echo "$a $b $r" >> "$out" ;;
  esac
done < /w/pairs.txt
wc -l "$out"
EOF

echo "corpus written to testdata/apk/corpus.txt"
