#!/usr/bin/env bash
# =============================================================================
# verify-easycrypt -- compile the SPHINCS+C EasyCrypt port and assert its ledger.
#
# WHY THIS EXISTS
#   Two axioms in `theft_free`'s closure -- A5-EUFCMA and A5-ITSR -- cite this
#   EasyCrypt development as evidence. Until 2026-07-10 that evidence lived in a
#   REMOTE-LESS local repo (`~/repos/c10-eufcma-port`), so nobody but its author
#   could check it. STATUS.md's rule #1 is "every DONE row carries a
#   spot-checkable evidence pointer." This makes it true.
#
# MODES (F5, 2026-07-16 -- partial/full are now DISTINCT, and "full" is honest)
#   --dry-run     ledger pins only, NO toolchain. Admit/axiom COUNTS + the
#                 SEMANTIC axiom pin (exact name->statement set). This is what
#                 `make verify-easycrypt-pins` runs.
#   (default)     PARTIAL compile: the stdlib-only +C/FORS chain compiles; the
#                 MM45-chain drafts are SKIPPED LOUDLY when SPHINCS_PLUS.eco is
#                 absent (they need z3 4.13.x -- see the toolchain caveat). This
#                 exits OK but PRINTS "PARTIAL, NOT a full verification"; a skip
#                 is NOT a pass.
#   --full        FULL verification: requires 21/21 .ec files compiled, ZERO
#                 skips (implies FORCE_MM45=1). If SPHINCS_PLUS.eco cannot build,
#                 the MM45 drafts fail to compile and this FAILS -- exactly the
#                 honesty F5 asks for ("full means 21/21, zero skips").
#   --self-test   wired-in NEGATIVE CONTROL for the semantic axiom pin, NO
#                 toolchain: mutate a copy so `dmkey_ll : is_lossless dmkey`
#                 becomes `dmkey_ll : false` (COUNT preserved) and assert the pin
#                 FIRES; assert the clean set PASSES. Proves the pin is not vacuous.
#
# WHAT IT CHECKS (all falsifiable)
#   1. EVERY .ec file compiles AS A TARGET (full mode). EasyCrypt's `require`
#      does NOT re-verify a dependency's proofs -- it imports its lemma
#      STATEMENTS and trusts them. A file can `require` a theory whose proofs are
#      broken and still compile EXIT 0. Also: `admit` compiles EXIT 0 with ZERO
#      output. Exit code proves nothing on its own.
#   2. The comment-stripped admit count matches the pinned ledger, per file.
#   3. The comment-stripped axiom COUNT matches the pinned ledger.
#   4. (F5) The SEMANTIC axiom pin: the exact (name -> full statement) set equals
#      easycrypt/axiom_pins.txt. A count pin alone cannot catch delete-one-add-one
#      (count preserved) or a weakened body (`is_lossless dmkey` -> `false`); this
#      does. Both axiom-bearing files (FORS_C10.ec, STCR_C.ec) are stdlib-only, so
#      this runs toolchain-free in --dry-run.
#
# Compilation remains local: it needs the pinned EasyCrypt/prover setup
# (see ../easycrypt/PROVENANCE.md). The toolchain-free --self-test and --dry-run
# pin checks ARE run per PR by verify-easycrypt-pins in lean-fv.yml (#664).
#
# TOOLCHAIN CAVEAT (verified 2026-07-10). The STDLIB-ONLY +C chain compiles as a
# target with Alt-Ergo 2.6.0 ALONE. The MM45-CHAIN drafts `require import
# SPHINCS_PLUS`, and SPHINCS_PLUS.eco CANNOT be built fresh on this box: it fails
# `cannot prove goal (strict)` under Alt-Ergo 2.6.0 / z3 4.16.0 / z3 4.13.4. MM45
# CI passes it, so it is a platform/prover-BUILD difference, not a proof defect;
# a full MM45-chain build needs MM45's docker image / CI toolchain. So in the
# DEFAULT (partial) mode, when SPHINCS_PLUS.eco is ABSENT the MM45-chain drafts
# are SKIPPED LOUDLY and only the stdlib-only chain is gated. --full (FORCE_MM45=1)
# compiles them anyway (fail-closed).
#
# The MM45 reference proofs are NOT vendored (they are large and third-party):
#     git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC
#     git clone --depth 1 https://github.com/MM45/FV-XMSS-EC
# and point EC_FV_ROOT at their parent directory (default: ~/repos/c10-eufcma-port).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EC_DIR="$HERE/../easycrypt"
DRAFTS="$EC_DIR/drafts"
AXIOM_PINS="$EC_DIR/axiom_pins.txt"
EC_FV_ROOT="${EC_FV_ROOT:-$HOME/repos/c10-eufcma-port}"

# ---- MODE (F5) --------------------------------------------------------------
MODE=default
case "${1:-}" in
  --dry-run)   MODE=dry ;;
  --full)      MODE=full ;;
  --self-test) MODE=selftest ;;
  "")          MODE=default ;;
  *) echo "usage: $0 [--dry-run|--full|--self-test]"; exit 2 ;;
esac

# ---- PINNED LEDGER. Any drift here is a FAILURE, not a warning. -------------
# Files permitted to contain an `admit`, with the exact count. Both are ORPHANED
# (required by nothing); the capstone's chain is admit-free.
declare -A EXPECTED_ADMITS=(
  [FORS_C_TreePort.ec]=1      # F-EXTRACT-OP; orphaned
  [WOTS_C_Interactive.ec]=1   # interactive S-TCR(+C) sim; orphaned
)
EXPECTED_TOTAL_AXIOMS=8       # dpp_ll, dmkey_ll, good_pos, size_g, eqiks_g, neqisvs_g, rng_g, uniq_g
EXPECTED_TOTAL_EC=22          # F5: --full requires all .ec compiled, zero skips. 22nd =
                              # SPHINCS_C_c10.ec (C10-concrete capstone, 2026-07-17): MM45-chain,
                              # SKIPPED here, VERIFIED as a target only in the docker gate
                              # (docker/gate-c10-capstone.sh + GATE-RECEIPT-2026-07-17.log).

# NESTING-AWARE sweep (scripts/ec_sweep.py) — a naive comment strip over/under-counts.
sweep()          { python3 "$HERE/ec_sweep.py" "$1"; }
count_admits()   { sweep "$1" | cut -f2; }
count_axioms()   { sweep "$1" | cut -f3; }

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf '  FAIL: %s\n' "$*"; fail=1; }

# ---- (4) SEMANTIC axiom pin (F5): exact (name -> statement) set -------------
# Compares the live extraction (scripts/ec_axioms.py) against the pinned
# easycrypt/axiom_pins.txt. Toolchain-free (both axiom-bearing files are
# stdlib-only). `_files` arg lets --self-test point at a mutated copy.
semantic_axiom_pin() {
  local dir="${1:-$DRAFTS}"
  if [ ! -f "$AXIOM_PINS" ]; then bad "semantic axiom pin file missing: $AXIOM_PINS"; return; fi
  local got exp
  got="$(python3 "$HERE/ec_axioms.py" "$dir"/*.ec)"
  exp="$(grep -vE '^\s*#|^\s*$' "$AXIOM_PINS")"
  if [ "$got" != "$exp" ]; then
    bad "SEMANTIC axiom pin drift — the live (name -> statement) set != easycrypt/axiom_pins.txt."
    printf '%s\n' "  --- pinned (axiom_pins.txt) ---"; printf '%s\n' "$exp" | sed 's/^/    /'
    printf '%s\n' "  --- live (ec_axioms.py) ---";     printf '%s\n' "$got" | sed 's/^/    /'
    printf '%s\n' "  A deleted/added/renamed axiom, or a weakened statement (e.g. is_lossless -> false), changed the set."
  else
    note "semantic axiom pin: exact (name -> statement) set matches axiom_pins.txt"
  fi
}

# ---- --self-test: wired-in NEGATIVE CONTROL for the semantic pin ------------
if [ "$MODE" = selftest ]; then
  echo "=== check_easycrypt --self-test (negative control for the semantic axiom pin) ==="
  ok=1
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  cp "$DRAFTS"/*.ec "$tmp/"
  # (control) an UNMUTATED copy must MATCH the pin.
  fail=0; semantic_axiom_pin "$tmp" >/dev/null 2>&1
  if [ "$fail" = 0 ]; then echo "  ok: clean copy MATCHES the pin (not always-firing)"; else echo "  FAIL: clean copy did not match the pin (pin/extractor drift)"; ok=0; fi
  # (PoC) weaken dmkey_ll from `is_lossless dmkey` to `false` — COUNT is preserved.
  sed -i 's/^axiom dmkey_ll : is_lossless dmkey\./axiom dmkey_ll : false./' "$tmp/FORS_C10.ec"
  before="$(python3 "$HERE/ec_sweep.py" "$tmp/FORS_C10.ec" | cut -f3)"
  fail=0; semantic_axiom_pin "$tmp" >/dev/null 2>&1
  if [ "$fail" != 0 ]; then echo "  ok: dmkey_ll:false weakening CAUGHT by the semantic pin (count still $before)"; else echo "  FAIL: dmkey_ll:false weakening NOT caught — the pin is vacuous!"; ok=0; fi
  # (PoC) delete good_pos and add a benign axiom — COUNT preserved (8).
  cp "$DRAFTS"/*.ec "$tmp/"
  sed -i 's/^axiom good_pos (m : msg) : 0%r < mu dmkey (good m)\./axiom benign_filler : true./' "$tmp/FORS_C10.ec"
  fail=0; semantic_axiom_pin "$tmp" >/dev/null 2>&1
  if [ "$fail" != 0 ]; then echo "  ok: delete-good_pos+add-benign (count preserved) CAUGHT by the semantic pin"; else echo "  FAIL: delete-one-add-one NOT caught — the pin is vacuous!"; ok=0; fi
  echo; [ "$ok" = 1 ] && { echo "=== self-test PASS ==="; exit 0; } || { echo "=== self-test FAILED ==="; exit 1; }
fi

echo "=== verify-easycrypt (mode: $MODE) ==="
[ -d "$DRAFTS" ] || { echo "FAIL: no drafts at $DRAFTS"; exit 1; }

# ---- (2)+(3) ledger pins: no toolchain needed --------------------------------
echo
echo "[pins] comment-stripped admit/axiom sweep + semantic axiom pin"
total_axioms=0
ec_count=0
for f in "$DRAFTS"/*.ec; do
  b="$(basename "$f")"
  ec_count=$(( ec_count + 1 ))
  a="$(count_admits "$f")"
  x="$(count_axioms "$f")"
  total_axioms=$(( total_axioms + x ))
  exp="${EXPECTED_ADMITS[$b]:-0}"
  if [ "$a" != "$exp" ]; then
    bad "$b has $a admit(s), ledger pins $exp"
  fi
done
for b in "${!EXPECTED_ADMITS[@]}"; do
  [ -f "$DRAFTS/$b" ] || bad "ledger pins admits in $b, but the file is gone"
done
if [ "$total_axioms" != "$EXPECTED_TOTAL_AXIOMS" ]; then
  bad "total axioms = $total_axioms, ledger pins $EXPECTED_TOTAL_AXIOMS"
else
  note "axioms: $total_axioms (matches count ledger)"
fi
if [ "$ec_count" != "$EXPECTED_TOTAL_EC" ]; then
  bad ".ec file count = $ec_count, expected $EXPECTED_TOTAL_EC (a draft was added/removed)"
fi
note "admits: pinned to ${#EXPECTED_ADMITS[@]} orphaned file(s)"
semantic_axiom_pin "$DRAFTS"

if [ "$MODE" = dry ]; then
  echo
  [ "$fail" = 0 ] && echo "=== PINS OK (dry-run; proofs NOT compiled) ===" || echo "=== PINS FAIL ==="
  exit "$fail"
fi

# ---- (1) compile EVERY file as a target --------------------------------------
FV_S="$EC_FV_ROOT/FV-SPHINCSPLUS-EC/proofs"
FV_X="$EC_FV_ROOT/FV-XMSS-EC/proofs"
if [ ! -d "$FV_S" ] || [ ! -d "$FV_X" ]; then
  echo
  echo "SKIP: MM45 reference proofs not found under EC_FV_ROOT=$EC_FV_ROOT"
  echo "  git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC"
  echo "  git clone --depth 1 https://github.com/MM45/FV-XMSS-EC"
  echo "  then re-run, or: EC_FV_ROOT=<parent> make verify-easycrypt"
  if [ "$MODE" = full ]; then
    echo "FAIL: --full requires the MM45 reference proofs (21/21, zero skips) but they are absent."
    exit 1
  fi
  exit "$fail"
fi
# ALWAYS prefer the PINNED r2026.02 helper. A bare `easycrypt` on PATH may be the
# `checkct` dev switch, which CANNOT compile the FV `WOTS_TW_ES.ec`.
EC_SH="${EC_SH:-$EC_DIR/ec-r2026.sh}"
if [ ! -x "$EC_SH" ]; then
  echo "SKIP: no $EC_SH (see ../easycrypt/PROVENANCE.md)"
  if [ "$MODE" = full ]; then echo "FAIL: --full requires the pinned EasyCrypt toolchain."; exit 1; fi
  exit "$fail"
fi

# include order matters: XMSS BEFORE SPHINCSPLUS, else `unknown type diff_t`
INC=(-I "$FV_X" -I "$FV_S" -I "$DRAFTS")

# --full implies FORCE_MM45=1 (compile the MM45-chain drafts too; fail-closed).
[ "$MODE" = full ] && FORCE_MM45=1
SP_DEP="$(python3 - "$DRAFTS" <<'PY'
import os,re,sys,glob
d=sys.argv[1]; drafts={os.path.basename(p)[:-3]:p for p in glob.glob(os.path.join(d,"*.ec"))}
def reqs(f):
    s=set()
    for line in open(f):
        if re.match(r'\s*(?:require|clone)\b',line):
            for t in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',line):
                if t in drafts or t=="SPHINCS_PLUS": s.add(t)
    return s
dep=set(); changed=True
while changed:
    changed=False
    for n,p in drafts.items():
        if n in dep: continue
        r=reqs(p)
        if "SPHINCS_PLUS" in r or (r & dep): dep.add(n); changed=True
print(" ".join(sorted(dep)))
PY
)"
skip_sp=0
if [ ! -f "$FV_S/SPHINCS_PLUS.eco" ] && [ "${FORCE_MM45:-0}" != 1 ]; then
  skip_sp=1
  echo
  echo "WARN: $FV_S/SPHINCS_PLUS.eco absent (needs z3 4.13.x -- see header)."
  echo "      SKIPPING the MM45-chain drafts (not a proof defect); gating the"
  echo "      stdlib-only +C/FORS chain. Use --full (FORCE_MM45=1) to compile them."
fi

echo
echo "[compile] every .ec as a TARGET (require does NOT re-verify)"
find "$DRAFTS" -name '*.eco' -delete 2>/dev/null
skipped=0
compiled=0
for f in "$DRAFTS"/*.ec; do
  b="$(basename "$f")"
  bn="${b%.ec}"
  if [ "$skip_sp" = 1 ] && printf ' %s ' "$SP_DEP" | grep -q " $bn "; then
    printf '  SKIP (MM45-chain, no SPHINCS_PLUS.eco): %s\n' "$b"
    skipped=$(( skipped + 1 ))
    continue
  fi
  if [ -n "${EC_SH:-}" ]; then
    timeout 1800 bash "$EC_SH" compile "${INC[@]}" "$f" >/dev/null 2>&1
  else
    timeout 1800 easycrypt compile "${INC[@]}" "$f" >/dev/null 2>&1
  fi
  rc=$?
  if [ "$rc" != 0 ]; then bad "$b does not compile (exit $rc)"; else note "ok  $b"; compiled=$(( compiled + 1 )); fi
done
find "$DRAFTS" -name '*.eco' -delete 2>/dev/null
[ "$skipped" != 0 ] && note "SKIPPED $skipped MM45-chain file(s) -- need z3 4.13.x / prebuilt SPHINCS_PLUS.eco (see header); NOT verified here"

# F5: --full is only a full verification if NOTHING was skipped and all 21 built.
if [ "$MODE" = full ]; then
  if [ "$skipped" != 0 ]; then bad "--full: $skipped file(s) SKIPPED (a full verification requires 0 skips)"; fi
  if [ "$compiled" != "$EXPECTED_TOTAL_EC" ]; then bad "--full: compiled $compiled/$EXPECTED_TOTAL_EC .ec files (need all 21)"; fi
fi

echo
if [ "$fail" = 0 ]; then
  if [ "$MODE" = full ]; then echo "=== verify-easycrypt FULL OK ($compiled/$EXPECTED_TOTAL_EC compiled, 0 skipped) ==="
  elif [ "$skipped" != 0 ]; then echo "=== verify-easycrypt PARTIAL OK (stdlib chain; $skipped MM45-chain SKIPPED — NOT a full verification; use --full) ==="
  else echo "=== verify-easycrypt OK ($compiled compiled) ==="; fi
else echo "=== verify-easycrypt FAIL ==="; fi
exit "$fail"
