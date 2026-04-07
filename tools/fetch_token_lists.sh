#!/usr/bin/env bash
#
# Fetch curated ERC20 token lists used as input by tools/build_erc20_db.py.
#
# Sources (verified live April 2026):
#   * tokens.uniswap.org             Uniswap Labs default list
#     (1413 entries, ~600 KB, multi-chain via `extensions.bridgeInfo`)
#   * static.optimism.io/optimism.tokenlist.json  Superchain (OP / Base /
#     Unichain / Mode / Celo / Lisk / Redstone + testnets)
#
# Output lands in build/token_lists/*.json relative to the repo root. All
# files are overwritten on each run; no state is kept between runs.
#
# Rerun whenever you want to refresh the source data, then run
# `python3 tools/build_erc20_db.py` to regenerate secure/data/erc20.json.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$repo_root/build/token_lists"
mkdir -p "$out_dir"

fetch() {
    local name="$1" url="$2"
    echo "  fetching $name" >&2
    curl -fsSL --retry 3 --retry-delay 2 -o "$out_dir/$name.json" "$url"
    local bytes
    bytes=$(wc -c <"$out_dir/$name.json")
    printf "    %8d bytes  %s\n" "$bytes" "$url" >&2
}

echo "==> Fetching curated token lists into $out_dir" >&2
fetch uniswap "https://tokens.uniswap.org"
fetch optimism "https://static.optimism.io/optimism.tokenlist.json"

echo "==> done" >&2
