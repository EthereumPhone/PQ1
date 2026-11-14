#!/usr/bin/env bash
# run_plants.sh — round 21: run the #1148 plant ELFs (proto_full/mk_plants.sh) on the kit, flash-only, and name the check
# that refused each one. A plant passes only if its refusal comes from the expected NAMED check: one of the top-cache
# asserts (panic location in topcache.rs at a known assert line) or the chain's verify-before-release gate; any other
# halt is reported as a crash and fails. Prints one JSON line per run.
set -u
D="$(cd "$(dirname "$0")/.." && pwd)"; cd "$D"; R=target/proto-full/run_flash_sig.sh; A=target/proto-cf/assert-lines.txt
bad=0
for cand in full np2; do
  for p in none digest own b0 b2 b5 noroot; do
    e=out/r21-plant-$cand-$p.elf; n=r21-plant-$cand-$p
    : > "$e.openocd.log"
    SIGW=1002 timeout 600 bash $R "$e" 0x30000000 96 120 > "out/$n-run.log" 2>&1; rc=$?
    cp "$e.openocd.log" "out/$n.openocd.log"
    python3 - "out/$n.openocd.log" "$n" "$p" "$rc" "$A" <<'PY' || bad=$((bad + 1))
import json, re, sys
log, name, plant, rc, alines = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
L = open(log).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
sig = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('SIG0_WORDS')), None)
names = {}
for l in open(alines):
    ln, txt = l.split(":", 1)
    names[int(ln)] = re.search(r'"([^"]+)"', txt).group(1)
r = dict(run=name, plant=plant, runner_rc=rc)
if not w:
    r.update(ok=False, why="no result words"); print(json.dumps(r)); sys.exit(1)
o = w[64:96]
st = w[0]
ph = dict(zip(['rate_cfi', 'optrand', 'shuffle', 'sign_a', 'delay1', 'sign_b', 'ct_eq', 'delay2', 'verify', 'verify_gate',
               'cfi_check', 'tail', 'release_copy'], o[4:17]))
released_sig = bool(sig) and any(sig)
r.update(status=hex(st), progress=o[1], chains_ok=o[3], i0=o[25] >> 8, planted_node=o[25] & 0xFF,
         signature_bytes_released=released_sig)
if st == 0x444F4E45:
    if o[3] == 1:
        r['outcome'] = 'released (chain completed)'
    elif ph['ct_eq'] and ph['verify'] and not ph['verify_gate']:
        r['outcome'] = 'refused by verify-before-release (the A/B compare passed)'
    elif not ph['ct_eq']:
        r['outcome'] = 'refused at the A/B compare'
    else:
        r['outcome'] = 'refused (other gate)'
elif st == 0x48410000 | 0xF1:
    line, intc = o[23], o[24]
    r.update(panic_line=line, panic_in_topcache=bool(intc))
    r['outcome'] = f'refused by assert "{names[line]}"' if intc and line in names else 'CRASH (panic outside the named checks)'
else:
    r['outcome'] = f'CRASH (status {hex(st)})'
want = {'none': 'released (chain completed)', 'digest': 'refused by assert "top cache digest mismatch"',
        'own': 'refused by assert "top cache: rebuilt subtree differs"',
        'b0': 'refused by assert "top cache: root is not pk_root"', 'b2': 'refused by assert "top cache: root is not pk_root"',
        'b5': 'refused by assert "top cache: root is not pk_root"',
        'noroot': 'refused by verify-before-release (the A/B compare passed)'}[plant]
r['expected'] = want
r['ok'] = r['outcome'] == want and (plant == 'none') == released_sig and (plant == 'none' or o[3] == 0)
print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
PY
  done
done
echo "run_plants: $([ $bad -eq 0 ] && echo OK || echo "$bad FAILURE(S)")"
exit $(( bad != 0 ))
