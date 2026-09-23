#!/usr/bin/env bash
# Re-vendor the PQ-UI subset from a local checkout pinned in UPSTREAM.txt, or
# verify the vendored tree against MANIFEST.sha256 (`sync.sh --check`).
#
# Vendored (the port's inputs): the design-system package `pq1/` (spec, fonts,
# marks, procedural icons), every flow family under `flows/`, the library
# animations under `screens/`, the design-rule checker `tools/check/`, the
# handoff generator `tools/handoff/` (source pages only), and the generated
# handoff catalogue `handoff/` — machine-readable `spec/*.json`, the prose
# `catalog/`, RULES/CLAUDE/README/REPORT, and the `pq1-conformance` skill's
# `port_diff.py`. NOT vendored: `handoff/previews/` (14 MB of GIF/PNG
# illustrations), `tools/handoff/report/` (2 MB of generated audit dumps),
# `renders/`, `archive/`, and the skill's duplicate copy of `spec/`.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)

# Everything MANIFEST.sha256 covers, relative to tools/pq-ui/.
manifest_roots="pq1 flows screens tools handoff requirements.txt"

if [ "${1:-}" = "--check" ]; then
    cd "$here"
    sha256sum --quiet -c MANIFEST.sha256 || { echo "pq-ui: vendored bytes differ from MANIFEST.sha256" >&2; exit 1; }
    # No unlisted files either: an extra file is drift the manifest cannot see.
    # shellcheck disable=SC2086
    listed=$(sed 's/^[0-9a-f]\{64\}  //' MANIFEST.sha256 | sort)
    present=$(find $manifest_roots -type f -not -path '*/__pycache__/*' | sort)
    if [ "$listed" != "$present" ]; then
        echo "pq-ui: vendored file set differs from MANIFEST.sha256:" >&2
        diff <(echo "$listed") <(echo "$present") >&2 || true
        exit 1
    fi
    echo "pq-ui vendored tree matches MANIFEST.sha256 ($(echo "$listed" | wc -l) files, pin $(sed -n 's/^commit = //p' UPSTREAM.txt | cut -c1-8))"
    exit 0
fi

src=${1:?usage: sync.sh <PQ-UI checkout> | sync.sh --check}
want=$(sed -n 's/^commit = //p' "$here/UPSTREAM.txt")
have=$(git -C "$src" rev-parse HEAD)
[ "$want" = "$have" ] || { echo "checkout at $have, UPSTREAM.txt pins $want" >&2; exit 1; }

rm -rf "$here/pq1" "$here/flows" "$here/screens" "$here/tools" "$here/handoff"
cp -r "$src/pq1" "$here/pq1"
cp -r "$src/flows" "$here/flows"
cp -r "$src/screens" "$here/screens"
mkdir -p "$here/tools/handoff" "$here/handoff/skill/pq1-conformance"
cp -r "$src/tools/check" "$here/tools/check"
cp "$src"/tools/handoff/*.py "$here/tools/handoff/"
cp -r "$src/tools/handoff/pages" "$here/tools/handoff/pages"
cp -r "$src/handoff/spec" "$here/handoff/spec"
cp -r "$src/handoff/catalog" "$here/handoff/catalog"
cp "$src/handoff/RULES.md" "$src/handoff/CLAUDE.md" "$src/handoff/README.md" "$src/handoff/REPORT.md" "$here/handoff/"
cp "$src/handoff/skill/pq1-conformance/SKILL.md" "$here/handoff/skill/pq1-conformance/"
cp -r "$src/handoff/skill/pq1-conformance/scripts" "$here/handoff/skill/pq1-conformance/scripts"
cp "$src/requirements.txt" "$here/"

find "$here" -name __pycache__ -type d -exec rm -rf {} +
# Illustrations are never inputs to the port; refuse any that slipped in.
find "$here/handoff" "$here/tools" \( -name '*.gif' -o -name '*.png' -o -name '*.html' \) -type f -delete
rm -f "$here/pq1/assets/OFL.txt"   # Chakra Petch's OFL, not Aileron's — see LICENSES/Aileron.md
# shellcheck disable=SC2086
( cd "$here" && find $manifest_roots -type f | sort | xargs sha256sum ) > "$here/MANIFEST.sha256"
echo "synced from $have ($(wc -l < "$here/MANIFEST.sha256") files)"
