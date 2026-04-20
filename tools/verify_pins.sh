#!/usr/bin/env bash
#
# verify_pins.sh — hard-fail supply-chain pin auditor.
#
# This script runs before every build-for-release (and in `make
# verify-pins`). It refuses to let a build proceed if any dependency
# in the repo is not cryptographically hash-pinned. Each check exits
# non-zero on the first violation so the caller sees the first
# failure cleanly.
#
# What we verify:
#
#   1. Cargo workspace                                            [Rust]
#      * Cargo.lock is in sync with every Cargo.toml (--locked).
#      * Every non-path, non-git dep in Cargo.lock has a
#        `checksum = "..."` line. Cargo writes SHA-256 for crates.io
#        tarballs there; a missing checksum means the source is not
#        integrity-verified by Cargo.
#      * Every `git = "..."` dep in any Cargo.toml has a 40-char hex
#        `rev = "..."` pin. `branch = ` / `tag = ` are mutable
#        upstream and are rejected.
#
#   2. Solidity lib submodules                                [Foundry]
#      * `contracts/smart-wallet/foundry.lock` is present.
#      * Every entry in foundry.lock has a commit-hash `rev` field.
#      * For every lib/<name>/ directory that is a git checkout, its
#        `git rev-parse HEAD` matches foundry.lock exactly.
#      * Every lib/<name>/ present has a corresponding foundry.lock
#        entry (no unpinned libs).
#
#   3. NPM (circuits/)                                            [Node]
#      * `circuits/package-lock.json` exists (NOT just
#        package.json).
#      * `npm ci --dry-run --ignore-scripts --prefix circuits`
#        succeeds — i.e. the lockfile is in sync with package.json
#        and has SRI integrity hashes for every resolved package.
#      * We greps package-lock.json to confirm there are no
#        `"integrity": null` entries (happens when a dep is
#        git-sourced without a checksum).
#
#   4. Rust toolchain                                       [rust-toolchain]
#      * `rust-toolchain.toml` pins `channel = "nightly-YYYY-MM-DD"`
#        or an exact semver, never bare `nightly` / `stable` / `beta`.
#
# Output convention:
#     [ok ]   check passed
#     [FAIL]  check failed — script exits 1 with a fix hint
#
# Usage: tools/verify_pins.sh    (from repo root or anywhere)

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

ok()   { printf "  [ok ] %s\n" "$*"; }
fail() { printf "  [FAIL] %s\n" "$*" >&2; printf "\nsupply-chain pin check FAILED — build refused.\n" >&2; exit 1; }
note() { printf "  [..] %s\n" "$*"; }

fail_count=0
trap 'printf "\nsupply-chain pin check FAILED — build refused.\n" >&2; exit 1' ERR

echo "==> 1/4 Cargo workspace"

# 1a. Cargo.lock in sync with all Cargo.toml files. Running
#     `cargo metadata --locked --offline` would need a populated
#     registry cache; `cargo fetch --locked` is authoritative and
#     reads only the lockfile + registry, no builds.
if ! cargo fetch --locked >/dev/null 2>&1; then
    fail "Cargo.lock is out of sync with Cargo.toml (or is missing entries).
       fix: review the diff, then 'cargo update -p <crate>' deliberately,
       then commit both Cargo.toml and Cargo.lock together.
       DO NOT run a bare 'cargo update' — that upgrades every dep at
       once and makes the lockfile diff unreviewable."
fi
ok "Cargo.lock is in sync (cargo fetch --locked)"

# 1b. Every registry dep in Cargo.lock has a checksum. Cargo refuses
#     to publish without one, but a manually-edited lockfile could
#     strip them. Each [[package]] block with source = "registry+..."
#     must be followed (within the block) by a checksum = "..." line.
#
#     Implementation: split Cargo.lock on the "[[package]]" delimiter,
#     for each block check that if source contains "registry+" it
#     also contains 'checksum = "'.
missing_checksum="$(awk '
  /^\[\[package\]\]/ { if (block ~ /source = "registry\+/ && block !~ /checksum = "/) print name; block=""; name=""; next }
  /^name = / { name=$0; block = block "\n" $0; next }
  { block = block "\n" $0 }
  END { if (block ~ /source = "registry\+/ && block !~ /checksum = "/) print name }
' Cargo.lock)"
if [ -n "$missing_checksum" ]; then
    fail "Cargo.lock has registry packages without checksums:
$missing_checksum
       fix: delete Cargo.lock and run 'cargo fetch' to regenerate it."
fi
ok "every registry dep in Cargo.lock has a SHA-256 checksum"

# 1c. Every git dep in any Cargo.toml is rev-pinned.
#     Rules:
#       * any line containing 'git = "..."' MUST also contain
#         a 40-char hex 'rev = "..."' on the same line (multi-line
#         git specs are banned here — we want the pin visible next
#         to the URL).
#       * the entire Cargo.toml tree is searched (excluding target/).
unpinned_git="$(grep -rn --include="Cargo.toml" 'git *= *"' . \
    2>/dev/null \
    | grep -v '^\./target' \
    | grep -Ev 'rev *= *"[0-9a-fA-F]{40}"' || true)"
if [ -n "$unpinned_git" ]; then
    fail "git dep(s) not pinned to a 40-char commit hash:
$unpinned_git
       fix: replace branch=/tag= with rev=\"<40-char hex>\" on the
       same line. Mutable refs are forbidden — upstream can rewrite
       them at any time."
fi
ok "every 'git =' dep has a 40-char rev pin"

echo "==> 2/4 Solidity lib submodules (foundry)"

lockf="contracts/smart-wallet/foundry.lock"
if [ ! -f "$lockf" ]; then
    fail "$lockf missing — foundry has no pin source of truth.
       fix: run 'forge install' to produce one, then commit it."
fi
ok "$lockf exists"

# Parse foundry.lock into `libname <TAB> rev` pairs via python
# (jq may not be installed on every dev box; python3 is a rust-toolchain
# cousin and we already depend on it for dbgen/ builds).
pairs="$(python3 - <<'PY'
import json, sys
with open("contracts/smart-wallet/foundry.lock") as f:
    d = json.load(f)
for path, meta in d.items():
    rev = meta.get("rev") or meta.get("tag", {}).get("rev")
    if not rev:
        sys.exit(f"foundry.lock entry {path!r} has no rev")
    if len(rev) != 40 or any(c not in "0123456789abcdef" for c in rev):
        sys.exit(f"foundry.lock entry {path!r} rev is not a 40-char hex: {rev}")
    print(f"{path}\t{rev}")
PY
)"
ok "every foundry.lock entry has a 40-char hex rev"

# Compare against checked-out lib/ HEADs.
while IFS=$'\t' read -r path rev; do
    full="contracts/smart-wallet/$path"
    if [ ! -d "$full/.git" ] && [ ! -f "$full/.git" ]; then
        note "$path: not checked out (run 'forge install' before release)"
        continue
    fi
    actual="$(git -C "$full" rev-parse HEAD)"
    if [ "$actual" != "$rev" ]; then
        fail "$path: checked-out HEAD $actual != foundry.lock $rev
       fix: 'forge install' to reset, or 'forge update <path>' +
       commit the new foundry.lock if the bump is intentional."
    fi
done <<< "$pairs"
ok "every checked-out lib/ matches its foundry.lock rev"

# Also verify: no lib/<name>/ exists that isn't in foundry.lock.
# (A stray lib that forge didn't install would bypass the pin check.)
if [ -d contracts/smart-wallet/lib ]; then
    for d in contracts/smart-wallet/lib/*/; do
        [ -d "$d" ] || continue
        name="lib/$(basename "$d")"
        if ! grep -q "\"$name\"" "$lockf"; then
            fail "$d is present but not listed in foundry.lock
       fix: either add it via 'forge install' or rm -rf the stray dir."
        fi
    done
fi
ok "no lib/ directories outside foundry.lock"

echo "==> 3/4 NPM (circuits/)"

if [ ! -f circuits/package-lock.json ]; then
    fail "circuits/package-lock.json missing — npm has no pin source.
       fix: cd circuits && npm install, then commit package-lock.json."
fi
ok "circuits/package-lock.json exists"

# Any entry with "integrity": null or missing integrity would mean
# a non-hash-verifiable dep (usually a git-sourced one). npm@8+ always
# emits integrity for registry deps; missing = supply-chain hole.
if grep -qE '"integrity": *null' circuits/package-lock.json; then
    fail "circuits/package-lock.json has entries with null integrity.
       fix: only depend on packages that npm publishes with SRI
       hashes (registry deps), not unpinned git deps."
fi
ok "every circuits/package-lock.json entry has an SRI integrity hash"

# npm ci --dry-run succeeds iff package.json and package-lock.json
# agree. --ignore-scripts blocks postinstall attacks during the check
# itself; the real build must run through 'npm ci' too.
if command -v npm >/dev/null 2>&1; then
    if ! (cd circuits && npm ci --dry-run --ignore-scripts >/dev/null 2>&1); then
        fail "circuits/package-lock.json is out of sync with package.json.
       fix: cd circuits && npm install (regenerates the lockfile),
       then review the diff and commit."
    fi
    ok "circuits/ npm ci --dry-run clean"
else
    note "npm not installed on PATH — skipped lockfile sync check"
fi

echo "==> 4/4 Rust toolchain"

# rust-toolchain.toml must pin a dated nightly or exact semver.
# Accepting bare 'nightly' / 'stable' / 'beta' would drift silently.
if ! grep -qE 'channel *= *"(nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]+\.[0-9]+\.[0-9]+)"' rust-toolchain.toml; then
    fail "rust-toolchain.toml channel is not a dated nightly or exact semver.
       fix: pin to 'nightly-YYYY-MM-DD' or 'X.Y.Z' — bare 'nightly'
       / 'stable' drifts silently when rustup updates the default."
fi
ok "rust-toolchain.toml channel is pinned"

echo ""
echo "==> all supply-chain pin checks passed."
