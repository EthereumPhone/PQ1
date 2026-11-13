#!/usr/bin/env bash
# experiment_micro.sh — round 6 "test zero": DWT cycles per digest of each fused v2 entry (bench_v2micro). Not a gate.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
CRATE=bench_v2micro LIBNAME=c10_bench_v2micro LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" ./build_any.sh out/micro.elf > out/micro-build.log 2>&1 || { echo '{"ok": false, "why": "build failed"}'; exit 2; }
timeout 600 bash harness/run_flash.sh out/micro.elf 0x30000000 96 300 > out/micro-run.log 2>&1
python3 - out/micro.elf.openocd.log <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
o = w[64:96]
names = ['chain16 x15', 'chain16 x1 (entry+1)', 'node16', 'wots_chains16', 'wots_pk16 (/digest)', 'fors_subtree16 h11', 'search43 per try']
r = {'ok': w[0] == 0x444F4E45 and o[1] == 100}
for i, n in enumerate(names):
    c, d = o[2 + 2 * i], o[3 + 2 * i]
    r[n] = round(c / d, 1) if d else None
if o[17]:  # round 7 probes
    r['floor_poll_min'] = o[16]; r['floor_poll_mean'] = round(o[17] / 1000, 1)
    r['floor_spin_d'] = o[18]; r['spin_cyc_per_iter'] = round(o[19] / 1000, 2)
    r['v1step_t1_16st'] = o[20] / 256; r['v1step_t2_17th'] = o[21] / 256; r['v1step_t3_dcal'] = o[22] / 256; r['v1step_t4_dcis'] = o[23] / 256
    r['search205_per_try'] = round(o[26] / o[27], 1) if o[27] else None; r['search205_tries'] = o[27]
    r['v1_chain16_x15'] = round(o[28] / o[29], 1) if o[29] else None; r['v1_wots_chains16'] = round(o[30] / o[31], 1) if o[31] else None
print(json.dumps(r))
PY
