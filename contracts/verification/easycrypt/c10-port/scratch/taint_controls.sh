#!/usr/bin/env bash
# DISCRIMINATING CONTROLS for tools/taint_closure.py (PHASE 5).
# A containment check that cannot go RED is decoration.  Each control DELETES a specific
# piece of information and must fail FOR THE DECLARED REASON -- polarity alone is not
# enough (a control that fails on a typo scores "RED" while testing nothing).
# Runs in a symlink farm; the real tree is never modified.
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0

farm() {  # build a fresh symlink farm; $1 (optional) = file to make a REAL copy of
  rm -rf "$T/w"; mkdir -p "$T/w/tools"
  cp "$ROOT/cert-cone-files-split.tsv" "$T/w/"
  cp "$ROOT/cert-taint-closure.tsv"    "$T/w/"
  cp "$ROOT/tools/taint_closure.py"    "$T/w/tools/"
  while read -r f; do
    case "$f" in ''|\#*) continue;; esac
    mkdir -p "$T/w/$(dirname "$f")"
    if [ "${1:-}" = "$f" ]; then cp "$ROOT/$f" "$T/w/$f"; else ln -s "$ROOT/$f" "$T/w/$f"; fi
  done < "$ROOT/cert-cone-files-split.tsv"
}

grade() {  # $1 name  $2 expected-substring
  out=$(cd "$T/w" && python3 tools/taint_closure.py --check 2>&1); rc=$?
  if [ $rc -eq 0 ]; then
    echo "  FAIL $1: check PASSED but the information was deleted"; fail=$((fail+1)); return
  fi
  if printf '%s' "$out" | grep -qF "$2"; then
    echo "  OK   $1 (RED for the declared reason)"; pass=$((pass+1))
  else
    echo "  FAIL $1: RED for the WRONG reason"; echo "       want: $2"; echo "       got : $(printf '%s' "$out" | head -2)"; fail=$((fail+1))
  fi
}

echo "=== T0 baseline: unmutated farm MUST PASS (else every control below is vacuous) ==="
farm
out=$(cd "$T/w" && python3 tools/taint_closure.py --check 2>&1); rc=$?
if [ $rc -eq 0 ]; then echo "  OK   baseline green"; pass=$((pass+1)); else echo "  FAIL baseline RED -- controls would be meaningless: $out"; fail=$((fail+1)); fi

echo "=== T1 THE NAMED REGRESSION: wire _Unfolded into the headline ==="
farm cdrafts-split/GprocChargedQWired.ec
python3 - "$T/w/cdrafts-split/GprocChargedQWired.ec" <<'PY'
import sys,re
p=sys.argv[1]; s=open(p).read()
old="move=> hc hmkg hdf8n hdflen hdf2 hdfnk.\n"
assert s.count(old)==1, s.count(old)
s=s.replace(old, old+"have _taint := EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded.\n")
open(p,'w').write(s)
PY
grade "T1 headline wired to _Unfolded" "HEADLINE IS TAINTED"

echo "=== T2 the admit disappears (parser/tree drift) ==="
farm base-c10-split/WOTS_TW_ES.ec
python3 - "$T/w/base-c10-split/WOTS_TW_ES.ec" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read().split('\n')
import re
# NB: the raw line is `admit.    (* <-- THE PRE-EXISTING GAP ... *)`.  An exact
# `strip()=='admit.'` match does NOT fire -- that bug made this control silently
# non-discriminating on its first run.  Match the TACTIC, not the whole line.
hit=False
for i,l in enumerate(s):
    if 1500 < i+1 < 1525 and re.match(r'\s*admit\.', l): s[i]='trivial.'; hit=True; break
assert hit, 'T2 mutation did not apply -- the control would be vacuous'
open(p,'w').write('\n'.join(s))
PY
grade "T2 admit removed" "anti-vacuity"

echo "=== T3 manifest gutted ==="
farm; : > "$T/w/cert-taint-closure.tsv"
grade "T3 manifest gutted" "no rows"

echo "=== T4 manifest site does not resolve (stale line number) ==="
farm
sed -i 's|^base-c10-split/WOTS_TW_ES.ec\t6578\t|base-c10-split/WOTS_TW_ES.ec\t6579\t|' "$T/w/cert-taint-closure.tsv"
grade "T4 stale manifest line" "does not resolve"

echo "=== T5 ONE-LINE PROOF (hole found by GPT-5.6, 2026-08-27): a same-line lemma that"
echo "        applies an admit must NOT be invisible to the closure ==="
farm base-c10-split/WOTS_TW_ES.ec
python3 - "$T/w/base-c10-split/WOTS_TW_ES.ec" <<'T5PY'
import sys
p=sys.argv[1]; L=open(p).read().split('\n')
hit=False
for i,l in enumerate(L):
    if i>1513 and l.strip()=='qed.':
        L.insert(i+1, "lemma T5_oneline_taint : true. proof. have _ := nhchwcoll_hchwpre_msg. trivial. qed.")
        hit=True; break
assert hit, 'T5 mutation did not apply -- the control would be vacuous'
open(p,'w').write('\n'.join(L))
T5PY
grade "T5 one-line lemma applying an admit" "TAINT CLOSURE GREW"

echo "=== T6 SHADOWED BASENAME (hole found by GPT-5.6, 2026-08-27): 54 basenames are"
echo "        declared in >1 cone file; a duplicated HEADLINE name must be REFUSED ==="
farm cdrafts-split/GprocQWired.ec
python3 - "$T/w/cdrafts-split/GprocQWired.ec" <<'T6PY'
import sys
p=sys.argv[1]; s=open(p).read()
s += "\n\nlemma EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT : true. proof. trivial. qed.\n"
open(p,'w').write(s)
T6PY
grade "T6 headline basename shadowed in a 2nd file" "ambiguous, refusing to guess"

echo "=== T7 TRAILING qed (hole found by Kimi K3, 2026-08-27): a proof closed as"
echo "        \`proof. by ... qed.\` must TERMINATE, not swallow the rest of the file ==="
farm base-c10-split/WOTS_TW_ES.ec
python3 - "$T/w/base-c10-split/WOTS_TW_ES.ec" <<'T7PY'
import sys
p=sys.argv[1]; L=open(p).read().split('\n')
hit=False
for i,l in enumerate(L):
    if i>1513 and l.strip()=='qed.':
        # trailing-qed shape: if the terminator is line-initial-only, this never closes
        L.insert(i+1, "lemma T7_trailing : true.")
        L.insert(i+2, "proof. have _ := nhchwcoll_hchwpre_msg. trivial. qed.")
        hit=True; break
assert hit, 'T7 mutation did not apply -- the control would be vacuous'
open(p,'w').write('\n'.join(L))
T7PY
grade "T7 trailing-qed lemma applying an admit" "TAINT CLOSURE GREW"

echo "=== T8 PARSER COVERAGE (the guard Kimi recommended): if the parser stops"
echo "        registering declarations, that must FAIL, not silently shrink the closure ==="
farm
python3 - "$T/w/tools/taint_closure.py" <<'T8PY'
import sys
p=sys.argv[1]; s=open(p).read()
# re-break the terminator exactly as it was before the 2026-08-27 fix
old = "if re.search(r'(?:^|[^A-Za-z0-9_\\'])(?:qed|abort)\\.', l):"
assert s.count(old)==1, 'T8 mutation target not found -- control would be vacuous'
open(p,'w').write(s.replace(old, "if re.match(r'\\s*qed\\.', l) or re.match(r'\\s*abort\\.', l):"))
T8PY
grade "T8 terminator re-broken to line-initial only" "parser coverage"

echo
echo "taint controls: pass=$pass fail=$fail"
[ "$fail" -eq 0 ] || exit 1
