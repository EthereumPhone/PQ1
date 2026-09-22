#!/usr/bin/env bash
# Re-vendor the PQ-UI subset from a local checkout pinned in UPSTREAM.txt.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=${1:?usage: sync.sh <PQ-UI checkout>}
want=$(sed -n 's/^commit = //p' "$here/UPSTREAM.txt")
have=$(git -C "$src" rev-parse HEAD)
[ "$want" = "$have" ] || { echo "checkout at $have, UPSTREAM.txt pins $want" >&2; exit 1; }
rm -rf "$here/pq1" "$here/flows"
mkdir -p "$here/flows"
cp -r "$src/pq1" "$here/pq1"
cp "$src/flows/__init__.py" "$src/flows/__main__.py" "$src/flows/MANIFEST.md" "$here/flows/"
cp -r "$src/flows/safe" "$src/flows/fingerprint" "$here/flows/"
cp "$src/requirements.txt" "$here/"
find "$here" -name __pycache__ -type d -exec rm -rf {} +
rm -f "$here/pq1/assets/OFL.txt"   # Chakra Petch's OFL, not Aileron's — see LICENSES/Aileron.md
( cd "$here" && find pq1 flows requirements.txt -type f | sort | xargs sha256sum ) > "$here/MANIFEST.sha256"
echo "synced from $have"
