#!/usr/bin/env bash
# gate_residue.sh — round 9 standing gate: the dead-stack residue suites (residue.rs).
# v1: bench_v1micro (7 cases: key loop, sign-shape keys, FORS subtree, grind x2, prf_chain16, chain16; part of
# experiment_v1micro.sh's ok). v2: bench_v2drv --features residue (9 cases: wots_chains16, wots_pk16,
# prf_chain16, fors_leaf16, fors_subtree16 h=4/7, chain16, grind_r 119/103). Product (round 13): bench_chain
# --features residue, product-shaped (3 cases: oneshot16 on the wots_secret preimage, oneshot on a secret-PRF
# preimage, streaming with the key in its own update).
# Round 14: each suite also runs its `residue-control` build, whose two positive controls (a function that copies
# the key into its own frame; a key word written just below sp, the scan's endpoint) must both be flagged, and
# nothing else: a scan that cannot see the top band fails the gate. Prints one JSON line; exit 0 = no residue.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
V1=$(./experiment_v1micro.sh)
V1C=$(BENCH_FEATURES=residue-control ./experiment_v1micro.sh)
words() {  # words <elf-log>: "status stage cases mask"
  python3 - "$1" <<'PY'
import sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
o = w[64:96] if w else [0] * 32
print(w[0] if w else 0, o[1], o[2], o[3])
PY
}
run() {  # run <crate> <lib> <features> <out> <extra rustflags mode>
  if [ "$5" = product ]; then
    BENCH_RUSTFLAGS= BENCH_FEATURES=$3 CRATE=$1 LIBNAME=$2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN" ./build_any.sh out/$4.elf > out/$4-build.log 2>&1 || { echo "0 0 0 0"; return; }
  else
    BENCH_FEATURES=$3 CRATE=$1 LIBNAME=$2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" ./build_any.sh out/$4.elf > out/$4-build.log 2>&1 || { echo "0 0 0 0"; return; }
  fi
  timeout 600 bash harness/run_flash.sh out/$4.elf 0x30000000 96 300 > out/$4-run.log 2>&1
  words out/$4.elf.openocd.log
}
V2=$(run bench_v2drv c10_bench_v2drv residue drvres bench)
V2C=$(run bench_v2drv c10_bench_v2drv residue-control drvresc bench)
PR=$(run bench_chain c10_bench_chain residue chainres product)
PRC=$(run bench_chain c10_bench_chain residue-control chainresc product)
python3 - "$V1" "$V1C" "$V2" "$V2C" "$PR" "$PRC" <<'PY'
import json, sys
v1, v1c = json.loads(sys.argv[1]), json.loads(sys.argv[2])
def w(s):
    st, stage, cases, mask = (int(x) for x in s.split())
    return dict(ok_run=st == 0x444F4E45 and stage == 401, cases=cases, mask=mask)
v2, v2c, pr, prc = (w(x) for x in sys.argv[3:7])
r = dict(v1_cases=v1.get('residue_cases'), v1_mask=v1.get('residue_mask'),
         v1_control=(v1c.get('residue_cases'), v1c.get('residue_mask')),
         v2_cases=v2['cases'], v2_mask=hex(v2['mask']), v2_control=(v2c['cases'], hex(v2c['mask'])),
         product_cases=pr['cases'], product_mask=hex(pr['mask']), product_control=(prc['cases'], hex(prc['mask'])))
r['ok'] = (bool(v1.get('ok')) and v1.get('residue_cases') == 7 and v1.get('residue_mask') == '0x0'
           and bool(v1c.get('ok')) and v1c.get('residue_control') is True
           and v1c.get('residue_cases') == 9 and v1c.get('residue_mask') == '0x180'
           and v2['ok_run'] and v2['cases'] == 9 and v2['mask'] == 0
           and v2c['ok_run'] and v2c['cases'] == 11 and v2c['mask'] == 0x600
           and pr['ok_run'] and pr['cases'] == 3 and pr['mask'] == 0
           and prc['ok_run'] and prc['cases'] == 5 and prc['mask'] == 0x18)
print(json.dumps(r))
sys.exit(0 if r['ok'] else 1)
PY
