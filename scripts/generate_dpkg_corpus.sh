#!/usr/bin/env bash
# Label dpkg version pairs with native `dpkg --compare-versions` inside an
# Ubuntu container and write testdata/dpkg/corpus.txt.
# Development/CI tool only; the production resolver never shells out to dpkg.
set -euo pipefail

cd "$(dirname "$0")/.."
EVIDENCE="${1:-../linux-20260801T220928Z.openness.txt}"

mkdir -p testdata/dpkg
python3 scripts/generate_dpkg_corpus.py "$EVIDENCE" > testdata/dpkg/pairs.txt
echo "generated $(wc -l < testdata/dpkg/pairs.txt) pairs"

docker run --rm -i -v "$PWD/testdata/dpkg:/w" ubuntu:22.04 bash -s <<'EOF'
set -u
out=/w/corpus.txt
: > "$out"
while read -r a b; do
  if dpkg --compare-versions "$a" lt "$b" 2>/dev/null; then r="<"
  elif dpkg --compare-versions "$a" eq "$b" 2>/dev/null; then r="="
  elif dpkg --compare-versions "$a" gt "$b" 2>/dev/null; then r=">"
  else continue  # dpkg rejected the version string; skip pair
  fi
  echo "$a $b $r" >> "$out"
done < /w/pairs.txt
wc -l "$out"
EOF

echo "corpus written to testdata/dpkg/corpus.txt"
