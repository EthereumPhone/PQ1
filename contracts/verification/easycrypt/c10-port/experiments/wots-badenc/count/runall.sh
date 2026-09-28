#!/usr/bin/env bash
# SUPERSEDED 2026-09-21: VecDP/CountDS/C10SurfaceKernel/C10Surface were PROMOTED to
# cdrafts-split/ and are no longer in this directory, so the positive-chain loop below
# will not resolve as written.  Kept as the development receipt.  The promoted files are
# compiled as gate targets on every run; the controls here are driven by PHASE 3 with
# -I base-c10-split -I cdrafts-split.
# Full clean receipt run: wipe every .eco, rebuild the chain with -check-all,
# then run every control and record its RC.
set -u
cd /work
D=experiments/wots-badenc/count
rm -f "$D"/*.eco "$D"/controls/*.eco "$D"/receipt.txt
{
  echo "== POSITIVE CHAIN (every project .eco wiped first; dependency order) =="
  for f in VecDP CountDS C10SurfaceKernel C10Surface ScriptProbe; do
    t0=$(date +%s%N)
    easycrypt compile -I "$D" -I "$D/controls" "$D/$f.ec" > "$D/$f.out" 2>&1
    rc=$?
    t1=$(date +%s%N)
    eco=NO; [ -f "$D/$f.eco" ] && eco="yes"
    echo "$f RC=$rc WALL_MS=$(( (t1-t0)/1000000 )) ECO=$eco"
  done
  echo
  echo "== CONTROLS (KctlC/KctlE must PASS, all others must FAIL) =="
  for f in KctlA KctlB KctlC KctlD KctlE CtlSum204 CtlLen42 CtlVal; do
    rm -f "$D/controls/$f.eco"
    t0=$(date +%s%N)
    easycrypt compile -I "$D" -I "$D/controls" "$D/controls/$f.ec" > "$D/controls/$f.out" 2>&1
    rc=$?
    t1=$(date +%s%N)
    eco=NO; [ -f "$D/controls/$f.eco" ] && eco="yes"
    msg=$(tr '\r' '\n' < "$D/controls/$f.out" | grep -m1 -E '^\[critical\]' | cut -c1-160)
    echo "$f RC=$rc WALL_MS=$(( (t1-t0)/1000000 )) ECO=$eco :: ${msg:-<no diagnostic>}"
  done
  echo
  echo "== LEDGER: admit / axiom / declare axiom in this directory =="
  grep -nE '(^|[^[:alnum:]_])(admit|admitted)([^[:alnum:]_]|$)' "$D"/*.ec "$D"/controls/*.ec || echo "admit-hits: none"
  grep -nE '(^|[^[:alnum:]_])(axiom|declare axiom)([^[:alnum:]_]|$)' "$D"/*.ec "$D"/controls/*.ec || echo "axiom-hits: none"
} > "$D/receipt.txt" 2>&1
