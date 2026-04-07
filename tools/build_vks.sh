#!/usr/bin/env bash
#
# build_vks.sh — compile Circom circuits under `circuits/` into the
# 960-byte `.vk.bin` files consumed by `dbgen` under `secure/data/vks/`.
#
# This script is opt-in: `cargo run -p dbgen` DOES NOT invoke it. The
# script writes into `secure/data/vks/`, then the user runs `dbgen`
# separately. See circuits/README.md and circuits/UPSTREAM.md.
#
# Prereqs: circom (2.x), node (20+), snarkjs (installed via
# `npm ci --prefix circuits`), a BLS12-381 powers-of-tau file matching
# `circuits/ptau.lock`.
#
# Usage:
#   tools/build_vks.sh                    # build every circuit
#   tools/build_vks.sh aave_v3_pool       # build one circuit by id
#   tools/build_vks.sh --from-zkey <id>=<path>    # skip compile+setup
#                                                   and just extract
#                                                   the VK from an
#                                                   existing .zkey
#   tools/build_vks.sh --list             # list circuit ids from
#                                           circuits.json
#   tools/build_vks.sh -h | --help
#
# Reproducibility model: snarkjs `zkey contribute` (v0.7.4) is NOT
# deterministic even with the `-e=<hex>` entropy flag pinned — empirical
# tests show three runs with identical inputs produce three different
# zkeys. To work around this, the committed source of truth for each
# circuit is a CHECKED-IN `circuit_final.zkey` file at
# `circuits/<proto>/<action>/circuit_final.zkey` (~1-4 MB per circuit).
# This script prefers that committed zkey over running the full
# compile + setup + contribute pipeline, so successive `build_vks.sh`
# runs always produce byte-identical `.vk.bin` files. The circuit
# sources + .zkey together form the canonical pin; the zkey is the
# "build artifact elevated to source of truth".
#
# Mode selection (per circuit):
#
#   1. `--from-zkey <id>=<path>` on the command line
#                                   → extract from an arbitrary path,
#                                     ignore any committed zkey
#   2. `circuits/<src_dir>/circuit_final.zkey` exists in-tree
#                                   → extract from it (the normal
#                                     reproducibility path)
#   3. Neither of the above         → run the full compile + setup +
#                                     contribute pipeline (used when
#                                     AUTHORING a new circuit; run
#                                     once, then copy the resulting
#                                     `build/circuits/<id>/circuit_final.zkey`
#                                     into the circuit source dir,
#                                     `git add` it, and never rerun
#                                     setup for that circuit again)

set -euo pipefail

# ── Paths ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CIRCUITS_DIR="$REPO_ROOT/circuits"
CIRCUITS_JSON="$CIRCUITS_DIR/circuits.json"
PTAU_LOCK="$CIRCUITS_DIR/ptau.lock"
VK_JSON_TO_BIN="$CIRCUITS_DIR/scripts/vk_json_to_bin.js"
NODE_MODULES="$CIRCUITS_DIR/node_modules"

BUILD_ROOT="$REPO_ROOT/build"
BUILD_CIRCUITS="$BUILD_ROOT/circuits"
BUILD_PTAU="$BUILD_ROOT/ptau"

VKS_OUT_DIR="$REPO_ROOT/secure/data/vks"

# ── Colors ─────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    C_GREEN="$(printf '\033[0;32m')"
    C_BLUE="$(printf '\033[0;34m')"
    C_YELLOW="$(printf '\033[0;33m')"
    C_RED="$(printf '\033[0;31m')"
    C_BOLD="$(printf '\033[1m')"
    C_OFF="$(printf '\033[0m')"
else
    C_GREEN="" C_BLUE="" C_YELLOW="" C_RED="" C_BOLD="" C_OFF=""
fi

log()  { printf "%s[..]%s %s\n" "$C_BLUE"   "$C_OFF" "$*"; }
ok()   { printf "%s[ok]%s %s\n" "$C_GREEN"  "$C_OFF" "$*"; }
warn() { printf "%s[!!]%s %s\n" "$C_YELLOW" "$C_OFF" "$*" >&2; }
err()  { printf "%s[KO]%s %s\n" "$C_RED"    "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── Arg parsing ────────────────────────────────────────────────────────
IDS=()
FROM_ZKEY_MAP=""  # newline-separated "id=path" pairs
LIST_ONLY=0

usage() {
    sed -n '2,25p' "$0" | sed 's|^# \?||'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --list)    LIST_ONLY=1; shift ;;
        --from-zkey)
            [ $# -ge 2 ] || die "--from-zkey requires <id>=<path>"
            case "$2" in
                *=*) FROM_ZKEY_MAP="${FROM_ZKEY_MAP}${2}
" ;;
                *)   die "--from-zkey argument must be <id>=<path>, got: $2" ;;
            esac
            shift 2
            ;;
        --*)       die "Unknown option: $1" ;;
        *)         IDS+=("$1"); shift ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────

# Run node with circuits.json preloaded. Usage: node_on_manifest '<js expr>'
node_on_manifest() {
    node -e "
      const manifest = JSON.parse(require('fs').readFileSync('$CIRCUITS_JSON', 'utf8'));
      $1
    "
}

list_circuits() {
    node_on_manifest '
      for (const c of manifest) console.log(c.id);
    '
}

# Look up a field on a given circuit by id. Prints the raw field value.
get_circuit_field() {
    local id="$1" field="$2"
    node_on_manifest "
      const c = manifest.find(c => c.id === ${id@Q});
      if (!c) { process.exit(3); }
      const v = c[${field@Q}];
      if (v === undefined) { process.exit(4); }
      process.stdout.write(String(v));
    "
}

# Look up a value from FROM_ZKEY_MAP for a given id. Empty if not present.
get_from_zkey() {
    local id="$1" line
    printf "%s" "$FROM_ZKEY_MAP" | while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
            "$id="*) printf "%s" "${line#*=}"; return 0 ;;
        esac
    done
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ── Prereq checks ──────────────────────────────────────────────────────

check_prereqs_basics() {
    command -v node >/dev/null 2>&1 || die "node not in PATH (need node 20+)"
    [ -f "$VK_JSON_TO_BIN" ] || die "missing $VK_JSON_TO_BIN"
    [ -f "$CIRCUITS_JSON" ]  || die "missing $CIRCUITS_JSON"
}

# Node + snarkjs only. Used for the --from-zkey path where we skip
# compile + trusted setup and just extract the VK from an existing zkey.
check_prereqs_extract_only() {
    check_prereqs_basics
    if [ ! -d "$NODE_MODULES" ] || [ ! -d "$NODE_MODULES/snarkjs" ]; then
        log "installing npm deps into $NODE_MODULES ..."
        (cd "$CIRCUITS_DIR" && npm ci)
    fi
    SNARKJS_BIN="$NODE_MODULES/.bin/snarkjs"
    [ -x "$SNARKJS_BIN" ] || die "snarkjs binary missing at $SNARKJS_BIN"
}

# Full toolchain: circom + node + snarkjs. Used when any circuit needs
# to go through the compile + setup + contribute pipeline.
check_prereqs_full() {
    check_prereqs_extract_only
    if ! command -v circom >/dev/null 2>&1; then
        die "circom not in PATH — install circom 2.x (see circuits/README.md)"
    fi
}

# ── Powers-of-Tau resolution ───────────────────────────────────────────

# Populate $PTAU_FILE with a verified path to the pot file for a given
# circuit. Looks at local fallback sources, copies the file into
# build/ptau/, verifies the SHA-256 against ptau.lock, and aborts on
# mismatch. Does NOT fetch over the network — if no local copy is
# found, the user is told where to put it.
resolve_ptau() {
    local want_name want_sha
    want_name="$(node_on_manifest 'process.stdout.write(JSON.parse(require("fs").readFileSync("'"$PTAU_LOCK"'","utf8")).name);')"
    want_sha="$(node_on_manifest 'process.stdout.write(JSON.parse(require("fs").readFileSync("'"$PTAU_LOCK"'","utf8")).sha256);')"

    local dest="$BUILD_PTAU/$want_name"
    mkdir -p "$BUILD_PTAU"

    if [ -f "$dest" ]; then
        local have_sha
        have_sha="$(sha256_of "$dest")"
        if [ "$have_sha" = "$want_sha" ]; then
            PTAU_FILE="$dest"
            return 0
        fi
        warn "existing $dest has wrong sha256; re-resolving"
        rm -f "$dest"
    fi

    # Try local fallback sources declared in ptau.lock.
    local found=""
    # Read each source.path from ptau.lock.
    local paths
    paths="$(node_on_manifest '
      const lock = JSON.parse(require("fs").readFileSync("'"$PTAU_LOCK"'","utf8"));
      const sources = Array.isArray(lock.sources) ? lock.sources : [];
      for (const s of sources) {
        if (s.kind === "local-fallback" && s.path) console.log(s.path);
      }
    ')"

    while IFS= read -r p; do
        [ -z "$p" ] && continue
        # paths in ptau.lock are relative to circuits/, resolve them
        case "$p" in
            /*) candidate="$p" ;;
            *)  candidate="$CIRCUITS_DIR/$p" ;;
        esac
        if [ -f "$candidate" ]; then
            log "using local-fallback pot file: $candidate"
            cp "$candidate" "$dest"
            local have_sha
            have_sha="$(sha256_of "$dest")"
            if [ "$have_sha" = "$want_sha" ]; then
                found="$dest"
                break
            fi
            warn "local-fallback $candidate has wrong sha256 ($have_sha != $want_sha); skipping"
            rm -f "$dest"
        fi
    done <<< "$paths"

    if [ -z "$found" ]; then
        err "powers-of-tau file '$want_name' not available"
        err "expected sha256: $want_sha"
        err "drop the file at:  $dest"
        err "or update circuits/ptau.lock with a working local-fallback path"
        exit 2
    fi

    ok "pot file ready: $dest ($(sha256_of "$dest"))"
    PTAU_FILE="$dest"
}

# ── Build one circuit from source (compile + setup + contribute + export) ──
build_from_source() {
    local id="$1"
    local src out domain n_public constraint_budget proto_dir seed_file
    src="$(get_circuit_field "$id" src)"        || die "$id: missing src in circuits.json"
    out="$(get_circuit_field "$id" out)"        || die "$id: missing out in circuits.json"
    n_public="$(get_circuit_field "$id" n_public)" || die "$id: missing n_public in circuits.json"

    local circuit_src="$CIRCUITS_DIR/$src"
    [ -f "$circuit_src" ] || die "$id: source not found: $circuit_src"

    proto_dir="$(dirname "$circuit_src")"
    seed_file="$proto_dir/contribution.seed"

    local work="$BUILD_CIRCUITS/$id"
    mkdir -p "$work"

    log "[$id] circom compile $src"
    (cd "$REPO_ROOT" && circom "$circuit_src" \
        --r1cs --wasm --sym \
        --prime bls12381 \
        --output "$work" \
        -l "$NODE_MODULES" >/dev/null)

    # snarkjs r1cs info emits a short stats block; capture constraints
    local r1cs_base
    r1cs_base="$(basename "$src" .circom)"
    local r1cs_file="$work/${r1cs_base}.r1cs"
    [ -f "$r1cs_file" ] || die "$id: r1cs not produced at $r1cs_file"

    log "[$id] r1cs info"
    "$SNARKJS_BIN" r1cs info "$r1cs_file" | sed 's/^/  /'

    log "[$id] groth16 setup (using $(basename "$PTAU_FILE"))"
    "$SNARKJS_BIN" groth16 setup "$r1cs_file" "$PTAU_FILE" "$work/circuit_0000.zkey" >/dev/null

    local entropy
    if [ -f "$seed_file" ]; then
        # Deterministic phase-2 contribution using the committed seed.
        entropy="$(xxd -p -c 999 "$seed_file")"
        ok "[$id] using pinned contribution.seed"
    else
        warn "[$id] NO contribution.seed — using random entropy (not reproducible)"
        entropy="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
    fi

    log "[$id] zkey contribute"
    "$SNARKJS_BIN" zkey contribute \
        "$work/circuit_0000.zkey" \
        "$work/circuit_final.zkey" \
        --name="sphincs_rust $id" \
        -e="$entropy" >/dev/null

    log "[$id] zkey verify"
    "$SNARKJS_BIN" zkey verify \
        "$r1cs_file" \
        "$PTAU_FILE" \
        "$work/circuit_final.zkey" >/dev/null

    log "[$id] export verification_key.json"
    "$SNARKJS_BIN" zkey export verificationkey \
        "$work/circuit_final.zkey" \
        "$work/verification_key.json" >/dev/null

    extract_vk_bin "$id" "$work/verification_key.json"
}

# ── Extract VK from an existing zkey (skip compile + setup) ────────────
extract_from_zkey() {
    local id="$1" zkey_src="$2"
    [ -f "$zkey_src" ] || die "$id: --from-zkey path does not exist: $zkey_src"

    local work="$BUILD_CIRCUITS/$id"
    mkdir -p "$work"

    log "[$id] copying upstream zkey: $zkey_src"
    cp "$zkey_src" "$work/circuit_final.zkey"

    log "[$id] export verification_key.json"
    "$SNARKJS_BIN" zkey export verificationkey \
        "$work/circuit_final.zkey" \
        "$work/verification_key.json" >/dev/null

    extract_vk_bin "$id" "$work/verification_key.json"
}

# ── Convert a verification_key.json into the 960-byte .vk.bin ─────────
extract_vk_bin() {
    local id="$1" vk_json="$2"
    local out n_public
    out="$(get_circuit_field "$id" out)"
    n_public="$(get_circuit_field "$id" n_public)"

    mkdir -p "$VKS_OUT_DIR"
    local vk_bin="$VKS_OUT_DIR/$out"

    log "[$id] vk_json_to_bin → $vk_bin"
    node "$VK_JSON_TO_BIN" \
        --in "$vk_json" \
        --out "$vk_bin" \
        --n-public "$n_public"

    local sha
    sha="$(sha256_of "$vk_bin")"
    ok "[$id] wrote $vk_bin (sha256=$sha)"
    SUMMARY="${SUMMARY}${id}|${out}|${sha}
"
}

# ── Main ───────────────────────────────────────────────────────────────
if [ "$LIST_ONLY" -eq 1 ]; then
    check_prereqs_basics
    list_circuits
    exit 0
fi

check_prereqs_basics

# If no ids specified, build every circuit in circuits.json.
if [ ${#IDS[@]} -eq 0 ]; then
    while IFS= read -r line; do
        [ -z "$line" ] || IDS+=("$line")
    done < <(list_circuits)
fi
[ ${#IDS[@]} -gt 0 ] || die "no circuits to build (circuits.json empty?)"

# Decide whether we need the full toolchain (compile + setup) or only
# the snarkjs/vk_json_to_bin extraction path. The extraction path is
# sufficient when every requested circuit is either (a) overridden
# via --from-zkey or (b) has a committed circuit_final.zkey next to
# its source. Otherwise at least one circuit goes through the full
# circom + snarkjs setup pipeline.
NEED_FULL=0
for id in "${IDS[@]}"; do
    if [ -n "$(get_from_zkey "$id")" ]; then
        continue
    fi
    src_rel="$(get_circuit_field "$id" src)" || die "$id: missing src in circuits.json"
    if [ -f "$CIRCUITS_DIR/$(dirname "$src_rel")/circuit_final.zkey" ]; then
        continue
    fi
    NEED_FULL=1
    break
done

if [ "$NEED_FULL" -eq 1 ]; then
    check_prereqs_full
    resolve_ptau
else
    check_prereqs_extract_only
fi

SUMMARY=""
for id in "${IDS[@]}"; do
    # Mode selection order:
    #  1. explicit --from-zkey override
    #  2. committed circuit_final.zkey next to the circuit source
    #  3. full compile + setup + contribute from source
    override_zkey="$(get_from_zkey "$id")"
    if [ -n "$override_zkey" ]; then
        extract_from_zkey "$id" "$override_zkey"
        continue
    fi

    src_rel="$(get_circuit_field "$id" src)" || die "$id: missing src in circuits.json"
    in_tree_zkey="$CIRCUITS_DIR/$(dirname "$src_rel")/circuit_final.zkey"
    if [ -f "$in_tree_zkey" ]; then
        log "[$id] found in-tree circuit_final.zkey → reproducing from committed zkey"
        extract_from_zkey "$id" "$in_tree_zkey"
    else
        warn "[$id] no committed circuit_final.zkey next to the source"
        warn "[$id] running full setup + contribute pipeline (NOT reproducible)"
        warn "[$id] after the build, commit build/circuits/$id/circuit_final.zkey"
        warn "[$id] to $CIRCUITS_DIR/$(dirname "$src_rel")/ to pin the VK"
        build_from_source "$id"
    fi
done

printf "\n%s─── summary ──────────────────────────────────────────────%s\n" \
    "$C_BOLD" "$C_OFF"
printf "%-24s %-30s %s\n" "id" "out" "sha256"
printf "%s" "$SUMMARY" | while IFS='|' read -r id out sha; do
    [ -z "$id" ] && continue
    printf "%-24s %-30s %s\n" "$id" "$out" "$sha"
done
printf "\n"
ok "done — run \`cargo run -p dbgen\` to fold new VKs into the firmware DB"
