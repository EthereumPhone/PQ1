#!/usr/bin/env bash
# Historical external capstone; current split uses cert_gate_split.sh.
# gate-c10-capstone.sh — capstone gate. Run INSIDE fv-sphincsplus-ec:r2026.02
# (image ENTRYPOINT = `opam exec --`).  /work = c10-eufcma-port (mounted).
#
# SOUNDNESS: EasyCrypt `require` does NOT re-verify a dependency — it trusts the .eco
# (and even trusts an on-demand source compile without running its proofs; empirically
# verified).  So a single `compile capstone` is UNSOUND.  This gate compiles EVERY file
# in the capstone's transitive closure (MM45 base proofs + the +C drafts + the wired
# capstone) AS A TARGET, in dependency order, after nuking all .eco — so every file's
# proofs are verified THIS run and no stale/untrusted .eco is ever relied upon.
#
# Then three honesty controls, each of which MUST fail-to-compile-as-a-target:
#   C1  drop the htree FORS-tree premise          C2  zero the ITSRC10 forgery term
#   C3  remove the good_pos (=p_nu) axiom          (the advisor's load-bearingness test)
# Exit 0 iff  G green AND C1,C2,C3 all red.
set -uo pipefail

SRC=/work
W=/tmp/w; rm -rf "$W"; mkdir -p "$W"
cp -r "$SRC/FV-SPHINCSPLUS-EC/proofs" "$W/proofs"
cp -r "$SRC/drafts"                   "$W/drafts"
cp "$SRC/FV-SPHINCSPLUS-EC/easycrypt.project" "$W/easycrypt.project"   # both provers (Alt-Ergo+Z3)
find "$W" -name '*.eco' -delete

PRISTINE_CAP="$SRC/pending-2b-wire/SPHINCS_C.c10-fors.ec.UNGATED"
CAP="$W/drafts/SPHINCS_C_c10.ec"
cp "$PRISTINE_CAP" "$CAP"
cp "$W/drafts/FORS_C10.ec" /tmp/FORS_C10.pristine

# EC compile-as-target: run from $W so easycrypt.project (both provers) is picked up.
EC() { ( cd "$W" && easycrypt compile -p Alt-Ergo@2.6.0 -p Z3@4.13.4 -I "$W/proofs" -I "$W/drafts" "$1" ); }

# --- topo-sort the capstone's transitive closure by require/clone graph ---
mapfile -t ORDER < <(python3 - "$W" <<'PY'
import os,re,sys,glob
root=sys.argv[1]; files={}
for d in ("proofs","drafts"):
    for p in glob.glob(os.path.join(root,d,"*.ec"))+glob.glob(os.path.join(root,d,"*.eca")):
        files[os.path.basename(p).rsplit('.',1)[0]]=p
def reqs(p):
    s=set()
    for ln in open(p,encoding='utf-8',errors='ignore'):
        if re.match(r'\s*(?:require|clone)\b',ln):
            for t in re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',ln):
                if t in files: s.add(t)
    return s
want={"SPHINCS_C_c10"}; ch=True
while ch:
    ch=False
    for n in list(want):
        for r in reqs(files[n]):
            if r not in want: want.add(r); ch=True
order=[]; done=set()
while len(done)<len(want):
    prog=False
    for n in sorted(want):
        if n in done: continue
        if (reqs(files[n]) & want) <= done: order.append(files[n]); done.add(n); prog=True
    if not prog: sys.stderr.write("CYCLE: %s\n"%(want-done)); sys.exit(2)
print("\n".join(order))
PY
)
echo "=== closure compile order (${#ORDER[@]} files, as targets) ==="
printf '  %s\n' "${ORDER[@]##*/}"

echo "############ STAGE G — every closure file compiles AS A TARGET (must all pass) ############"
rcG=0
for f in "${ORDER[@]}"; do
  b=$(basename "$f")
  if EC "$f" >"/tmp/g.$b.log" 2>&1; then echo "  ok    $b"; else echo "  FAIL  $b"; tail -4 "/tmp/g.$b.log"|sed 's/^/        /'; rcG=1; fi
done
# Direct compilation is necessary but does not reject an unfinished EOF proof.
[ "${#ORDER[@]}" -gt 0 ] || rcG=1
for f in "${ORDER[@]}"; do
  b=$(basename "$f"); printf 'require %s.\n' "${b%.*}" > "$W/RequireProbe.ec"
  if ! EC "$W/RequireProbe.ec" > /tmp/require-probe.log 2>&1; then
    echo "FAIL cannot require $b"; tail -4 /tmp/require-probe.log; rcG=1
  fi
  rm -f "$W/RequireProbe.eco"
done
echo "== rcG=$rcG (expect 0) =="

fire() { # $1=label $2=file-that-must-fail  — expects the just-run EC to have FAILED
  local rc=$1; shift
  if [ "$rc" -ne 0 ]; then echo "  ✓ FIRED (rc=$rc)"; else echo "  ✗ DID NOT FIRE (rc=0) — control is vacuous!"; fi
}

echo "############ CONTROL C1 — drop htree tree premise (recompile capstone as target; must FAIL) ############"
cp "$PRISTINE_CAP" "$CAP"; rm -f "$W/drafts/SPHINCS_C_c10.eco"
sed -i 's/move=> hc encb htree hfx hbridge\./move=> hc encb hfx hbridge./' "$CAP"
EC "$CAP" >/tmp/c1.log 2>&1; rcC1=$?; tail -3 /tmp/c1.log|sed 's/^/    /'; fire "$rcC1"

echo "############ CONTROL C2 — zero the ITSRC10 forgery term (must FAIL) ############"
cp "$PRISTINE_CAP" "$CAP"; rm -f "$W/drafts/SPHINCS_C_c10.eco"
perl -0pi -e 's/Pr\[M\.F\.ITSRC10.*?\]/0%r/s' "$CAP"
grep -q '0%r + mtree_openpre' "$CAP" && echo "    (mutation applied)" || echo "    (WARN: mutation did not match)"
EC "$CAP" >/tmp/c2.log 2>&1; rcC2=$?; tail -3 /tmp/c2.log|sed 's/^/    /'; fire "$rcC2"

echo "############ CONTROL C3 — remove good_pos (=p_nu) axiom from FORS_C10 (recompile FORS_C10 as target; must FAIL) ############"
cp /tmp/FORS_C10.pristine "$W/drafts/FORS_C10.ec"
sed -i 's|^axiom good_pos.*|(* good_pos REMOVED for honesty control C3 *)|' "$W/drafts/FORS_C10.ec"
rm -f "$W/drafts/FORS_C10.eco" "$W/drafts/FORS_C10_Multi.eco" "$W/drafts/SPHINCS_C_c10.eco"
EC "$W/drafts/FORS_C10.ec" >/tmp/c3.log 2>&1; rcC3=$?; tail -5 /tmp/c3.log|sed 's/^/    /'; fire "$rcC3"
cp /tmp/FORS_C10.pristine "$W/drafts/FORS_C10.ec"

echo; echo "################## VERDICT ##################"
echo "rcG=$rcG  rcC1=$rcC1  rcC2=$rcC2  rcC3=$rcC3"
if [ "$rcG" -eq 0 ] && [ "$rcC1" -ne 0 ] && [ "$rcC2" -ne 0 ] && [ "$rcC3" -ne 0 ]; then
  echo "OVERALL: PASS — capstone-C10 verified as a target over the full closure + all 3 controls fired."
  echo "         good_pos (=p_nu) IS load-bearing → the C10-concrete wire is real, not cosmetic."
  exit 0
else
  echo "OVERALL: REVIEW"
  [ "$rcC3" -eq 0 ] && echo "  - C3 did NOT fire: good_pos NOT load-bearing → C10 wire partly COSMETIC (report honestly)."
  exit 1
fi
