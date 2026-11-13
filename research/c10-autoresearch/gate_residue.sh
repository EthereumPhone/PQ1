#!/usr/bin/env bash
# gate_residue.sh — round 9 standing gate: the dead-stack residue suites (residue.rs).
# v1: bench_v1micro (7 cases: key loop, sign-shape keys, FORS subtree, grind x2, prf_chain16, chain16; part of
# experiment_v1micro.sh's ok). v2: bench_v2drv --features residue (9 cases: wots_chains16, wots_pk16,
# prf_chain16, fors_leaf16, fors_subtree16 h=4/7, chain16, grind_r 119/103). Prints one JSON line; exit 0 = no residue.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
V1=$(./experiment_v1micro.sh)
BENCH_FEATURES=residue CRATE=bench_v2drv LIBNAME=c10_bench_v2drv LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" ./build_any.sh out/drvres.elf > out/drvres-build.log 2>&1 || { echo '{"ok": false, "why": "v2 residue build failed"}'; exit 2; }
timeout 600 bash harness/run_flash.sh out/drvres.elf 0x30000000 96 300 > out/drvres-run.log 2>&1
python3 - out/drvres.elf.openocd.log "$V1" <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
v1 = json.loads(sys.argv[2])
o = w[64:96] if w else [0] * 32
r = dict(v1_ok=v1.get('ok'), v1_cases=v1.get('residue_cases'), v1_mask=v1.get('residue_mask'),
         v2_status=hex(w[0]) if w else None, v2_stage=o[1], v2_cases=o[2], v2_mask=hex(o[3]))
r['ok'] = bool(v1.get('ok')) and v1.get('residue_cases') == 7 and v1.get('residue_mask') == '0x0' and \
          w is not None and w[0] == 0x444F4E45 and o[1] == 401 and o[2] == 9 and o[3] == 0
print(json.dumps(r))
sys.exit(0 if r['ok'] else 1)
PY
