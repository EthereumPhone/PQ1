#!/usr/bin/env bash
# experiment_drv.sh [guard] — #1155 spec §7 gate 5: every fused v2 driver entry against software SHA-256 on the
# kit, with a v1 digest interleaved between v2 calls (bench_v2drv). `guard` adds the out-of-range subtree control,
# which must halt through the driver's fault hook. Harness v3b (flash, ICACHE 2-way).
set -u
G=${1:-}; D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
BENCH_FEATURES=$G CRATE=bench_v2drv LIBNAME=c10_bench_v2drv LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" ./build_any.sh out/drv$G.elf > out/drv$G-build.log 2>&1 || { echo "{\"ok\": false, \"why\": \"build failed\"}"; exit 2; }
timeout 600 bash harness/run_flash.sh out/drv$G.elf 0x30000000 96 300 > out/drv$G-run.log 2>&1
python3 - out/drv$G.elf.openocd.log "$G" <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
if not w: print(json.dumps({'ok': False, 'why': 'no result words'})); sys.exit(1)
o = w[64:96]
r = dict(status=hex(w[0]), magic=hex(o[0]), stage=o[1], checks=o[2], failed=o[3], per_group=o[4:15],
         first_fail=(o[15], o[16]) if o[3] else None, v1_probes=o[17])
groups = ['v1-oneshot', 'chain16', 'prf_chain16', 'node16', 'fors_leaf16', 'fors_subtree16', 'search43_target', 'v1-stream', 'wots_chains16', 'wots_pk16', 'grind_r']
r['per_group'] = dict(zip(groups, o[4:15]))
if sys.argv[2] == 'guard':
    r['ok'] = w[0] == 0x484100F0 and o[1] == 200 and o[3] == 0
else:
    r['ok'] = w[0] == 0x444F4E45 and o[0] == 0x44525632 and o[1] == 100 and o[3] == 0 and o[2] > 0
print(json.dumps(r))
PY
