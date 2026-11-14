#!/usr/bin/env bash
# RESEARCH (round 20 addendum, 2026-11-14): the Rust half of the FORS / WOTS secret position-binding
# regression (twin: c10v2/position_binding.py). Runs on a SEPARATE copy of the round-20 sphincs-c10
# copy (target/proto-full-pb), so the measured copy target/proto-full is not touched and no product
# crate is edited. Per variant: tests/v2_position_binding.rs (F: two honest signatures, same FORS
# leaf, different positions; W: wots_secret grid + honest positions) and the product's own
# tests/fors_position_binding.rs must pass. Per planted mutant (feature pb-mut-*, copy only): the
# intended test must fail with its "F FAILED" / "W FAILED" message, the other must pass, no SETUP
# assertion may fire (the mutant's signatures still verify), and v2_kat (Rust == Python) must fail.
set -euo pipefail
cd "$(dirname "$0")/.."
P=target/proto-full
Q=target/proto-full-pb
test -d "$P/sphincs-c10" || { echo "run proto_full/mk.sh first"; exit 2; }
rm -rf "$Q"
mkdir -p "$Q"
cp -r "$P/sphincs-c10" "$Q/"
cp proto_full/v2_position_binding.rs "$Q/sphincs-c10/tests/"
python3 - "$Q/sphincs-c10" <<'EOF'
import sys
d = sys.argv[1]
p = f"{d}/Cargo.toml"; s = open(p).read()
feat = ("pb-mut-fors-ht = []\npb-mut-wots-layer = []\npb-mut-wots-tree = []\npb-mut-wots-kp = []\n"
        "pb-mut-2b-drop-a7-position = []\n")
assert s.count("[features]\n") == 1
open(p, "w").write(s.replace("[features]\n", "[features]\n" + feat))
p = f"{d}/src/v2hash.rs"; s = open(p).read()
f = "pub fn fors_secret(sk_seed: &[u8; 32], ht_idx: u32, tree_idx: u32, leaf_idx: u32) -> [u8; N] {\n"
w = "pub fn wots_secret(sk_seed: &[u8; 32], layer: u32, tree: u64, kp: u32, chain_idx: u32) -> [u8; N] {\n"
assert s.count(f) == 1 and s.count(w) == 1
s = s.replace(f, f + '    #[cfg(feature = "pb-mut-fors-ht")]\n    let ht_idx = { let _ = ht_idx; 0u32 };\n')
s = s.replace(w, w
    + '    #[cfg(feature = "pb-mut-wots-layer")]\n    let layer = { let _ = layer; 0u32 };\n'
    + '    #[cfg(feature = "pb-mut-wots-tree")]\n    let tree = { let _ = tree; 0u64 };\n'
    + '    #[cfg(feature = "pb-mut-wots-kp")]\n    let kp = { let _ = kp; 0u32 };\n'
    # the two-block PRFs with tree and kp squeezed out of the A7 tail (block 1 keeps the layer)
    + '    #[cfg(all(feature = "pb-mut-2b-drop-a7-position", feature = "v2-wprf2b"))]\n'
    + '    let (tree, kp) = { let _ = (tree, kp); (0u64, 0u32) };\n')
open(p, "w").write(s)
EOF
VARIANTS=(draft03 prf2 wprf2b prf2+wprf2b all3 full)
feat() {
  case "$1" in
    draft03) echo v2 ;; prf2) echo v2,v2-prf2 ;; wprf2b) echo v2,v2-wprf2b ;;
    prf2+wprf2b) echo v2,v2-prf2,v2-wprf2b ;; all3) echo v2,v2-ts200,v2-prf2,v2-split810 ;;
    full) echo v2,v2-ts200,v2-prf2,v2-split810,v2-wprf2b ;; *) echo "unknown variant $1" >&2; exit 2 ;;
  esac
}
LOG=$Q/logs
mkdir -p "$LOG"
run() { # features test log
  (cd "$Q/sphincs-c10" && CARGO_TARGET_DIR=../tgt cargo test --offline --release --features "sim-internals,$1" --test "$2" -- --nocapture) > "$3" 2>&1
}
bad=0
for v in "${VARIANTS[@]}"; do
  f=$(feat "$v")
  l="$LOG/$v-honest.log"
  if run "$f" v2_position_binding "$l" && run "$f" fors_position_binding "$LOG/$v-product.log"; then
    echo "PASS $v: $(grep -m1 '^pair msgs' "$l"); $(grep -c '^test .* ok$' "$l") + $(grep -c '^test .* ok$' "$LOG/$v-product.log") tests ok"
  else
    echo "FAIL $v (see $l)"; bad=$((bad + 1))
  fi
  muts=(pb-mut-fors-ht pb-mut-wots-layer pb-mut-wots-tree pb-mut-wots-kp)
  case "$v" in *wprf2b*|full) muts+=(pb-mut-2b-drop-a7-position) ;; esac
  for m in "${muts[@]}"; do
    ml="$LOG/$v-$m.log"
    if [[ $m == pb-mut-fors-ht ]]; then want="F FAILED"; ok_test=wots_binding_grid_and_honest_positions
    else want="W FAILED"; ok_test=fors_binding_two_honest_signatures; fi
    rc=0; run "$f,$m" v2_position_binding "$ml" || rc=$?
    if (( rc != 0 )) && grep -q "$want" "$ml" && grep -q "^test $ok_test ... ok$" "$ml" && ! grep -q "SETUP" "$ml"; then
      verdict="CAUGHT ($want; $ok_test ok; mutant signatures verify)"
    else
      verdict="NOT CAUGHT (rc $rc, see $ml)"; bad=$((bad + 1))
    fi
    kat="n/a (no KAT set)"
    if [[ $v != prf2+wprf2b ]]; then
      krc=0; run "$f,$m" v2_kat "$LOG/$v-$m-kat.log" || krc=$?
      if (( krc != 0 )); then kat="v2_kat FAILS (Rust != Python reference)"; else kat="v2_kat passes"; bad=$((bad + 1)); fi
    fi
    echo "  mutant $m: $verdict; $kat"
  done
done
echo "position_binding.sh: $([[ $bad == 0 ]] && echo OK || echo "$bad FAILURE(S)")"
exit $(( bad != 0 ))
