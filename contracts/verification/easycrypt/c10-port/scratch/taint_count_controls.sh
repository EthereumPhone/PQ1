#!/usr/bin/env bash
# CONTROLS FOR THE TAINT-CONTROL INVENTORY GUARD (added 2026-09-14).
# PHASE 5 used to trust scratch/taint_controls.sh's exit status, which is nonzero only when
# a control FAILS -- so a control that never RAN scored nothing and the gate still printed
# OK.  Demonstrated on the pre-fix lines, not argued: with T9's grade call blinded they
# printed `OK   taint controls: taint controls: pass=10 fail=0` and left fail=0
# (scratch/PREDICTION-taint-count-guard-2026-09-14.md).
#
# The fix is a count parsed out of that script's summary, which is new code in the
# cheapest place there is to weaken a gate.  So this runs THE GATE'S OWN LINES, extracted
# between its BEGIN/END taint-controls-count markers (NOT a re-implementation), against
# REAL copies of taint_controls.sh that have been weakened, and grades each variant on the
# MESSAGE, not the polarity.  Runs in a symlink farm; the real tree is never modified.
set -u
set -o pipefail   # the gate's shell options, so its lines run here as they run there
cd "$(dirname "$0")/.."
export LC_ALL=C
ROOT=$PWD
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; kfail=0

eval "$(grep -E '^EXPECT_TAINT_CTLS=[0-9]+$' cert_gate_split.sh)"
[ -n "${EXPECT_TAINT_CTLS:-}" ] || { echo "FAIL EXPECT_TAINT_CTLS not found in cert_gate_split.sh"; exit 1; }
block=$(awk '/# END taint-controls-count/{on=0} on{print} /# BEGIN taint-controls-count/{on=1}' cert_gate_split.sh)
case "$block" in
  *'bash scratch/taint_controls.sh'*EXPECT_TAINT_CTLS*) ;;
  *) echo "FAIL BEGIN/END taint-controls-count markers do not bracket the guard -- every variant would be vacuous"; exit 1;;
esac

# $1 name  $2 expected substring  $3 1 = must go RED, 0 = must stay GREEN
# stdin: a python mutation applied to the copy (argv[1] = its path); empty = unmutated
variant() {
  rm -rf "$T/r"; mkdir -p "$T/r/scratch"
  for x in "$ROOT"/*; do
    b=$(basename "$x"); [ "$b" = scratch ] || ln -s "$x" "$T/r/$b"
  done
  # The controls read more of scratch/ since 2026-09-15 (the scope probes, for the linkage check).
  # Link ALL of it except the copy under test -- a farm carrying only taint_controls.sh turned T0
  # RED for the WRONG reason and failed V0/V1/V3 on the first sandbox run of that change.
  for x in "$ROOT"/scratch/*; do
    b=$(basename "$x"); [ "$b" = taint_controls.sh ] || ln -s "$x" "$T/r/scratch/$b"
  done
  cp "$ROOT/scratch/taint_controls.sh" "$T/r/scratch/taint_controls.sh"
  mut=$(cat)
  if [ -n "$mut" ] && ! python3 -c "$mut" "$T/r/scratch/taint_controls.sh"; then
    echo "  FAIL $1: mutation did not apply -- the variant would be vacuous"; kfail=$((kfail+1)); return
  fi
  out=$(cd "$T/r" || exit 99; fail=0; eval "$block"; echo "__GATE_FAIL=$fail")
  gf=$(printf '%s\n' "$out" | sed -n 's/^__GATE_FAIL=\([0-9][0-9]*\)$/\1/p')
  if [ -z "$gf" ]; then
    echo "  FAIL $1: the gate lines did not run to completion"; kfail=$((kfail+1)); return
  fi
  if [ "$3" = 1 ] && [ "$gf" -eq 0 ]; then
    echo "  FAIL $1: the gate stayed GREEN but a control was removed"; kfail=$((kfail+1)); return
  fi
  if [ "$3" = 0 ] && [ "$gf" -ne 0 ]; then
    echo "  FAIL $1: the unmutated controls turned the gate RED -- every variant below is vacuous"
    printf '%s\n' "$out" | sed 's/^/       /'; kfail=$((kfail+1)); return
  fi
  if printf '%s\n' "$out" | grep -qF "$2"; then
    echo "  OK   $1 (for the declared reason)"; pass=$((pass+1))
  else
    echo "  FAIL $1: WRONG reason"; echo "       want: $2"
    echo "       got : $(printf '%s\n' "$out" | grep -v '^__GATE_FAIL=' | head -2)"; kfail=$((kfail+1))
  fi
}

N=$EXPECT_TAINT_CTLS

echo "=== V0 unmutated: MUST stay GREEN with the full count (else V1..V3 are vacuous) ==="
variant "V0 unmutated" "OK   taint controls: pass=$N unique=$N fail=0 expected=$N" 0 </dev/null

echo "=== V1 one grade call blinded: the control's mutation runs, nothing is graded ==="
variant "V1 T9 grade blinded" "FAIL taint control inventory: pass=$((N-1)) unique=$((N-1))" 1 <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = 'grade "T9 clone of an admit-containing theory"'
assert s.count(old) == 1, 'V1 target not found'
open(p, 'w').write(s.replace(old, ': ' + old))
PY

echo "=== V2 early exit 0 after the baseline: the summary line is never printed ==="
variant "V2 early exit 0" "FAIL taint controls: summary line NOT PARSED" 1 <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split('\n')
hits = [i for i, l in enumerate(L) if l.startswith('if [ $rc -eq 0 ]; then echo "  OK   baseline green"')]
assert len(hits) == 1, 'V2 target not found'
L.insert(hits[0] + 1, 'exit 0')
open(p, 'w').write('\n'.join(L))
PY

echo "=== V3 a control deleted and ANOTHER duplicated in its place: pass count unchanged ==="
variant "V3 T10 replaced by a copy of T9" "FAIL taint control inventory: pass=$N unique=$((N-1))" 1 <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split('\n')
def span(tag):
    a = [i for i, l in enumerate(L) if l.startswith('echo "=== ' + tag + ' ')]
    b = [i for i, l in enumerate(L) if l.startswith('grade "' + tag + ' ')]
    assert len(a) == 1 and len(b) == 1 and a[0] < b[0], ('V3 target not found', tag, a, b)
    return a[0], b[0]
a9, b9 = span('T9'); a10, b10 = span('T10')
L[a10:b10 + 1] = L[a9:b9 + 1]
open(p, 'w').write('\n'.join(L))
PY

echo
# FORMAT CONTRACT: cert_gate_split.sh compares the next line EXACTLY against
# pass=EXPECT_TAINT_COUNT_CTLS fail=0.  Adding a variant means bumping that constant.
echo "taint count controls: pass=$pass fail=$kfail"
[ "$kfail" -eq 0 ] || exit 1
