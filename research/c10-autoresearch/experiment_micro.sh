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
    for n, i in (('din_store', 20), ('sr_load', 22), ('hr_load', 24)):
        a, b = o[i] / 256, o[i + 1] / 256
        r[n + '_per_access'] = round((b - a) / 12, 2); r[n + '_k2'] = round(a, 1)
    r['dcal_to_dcis'] = o[26] / 1000; r['dcal_to_busy_clear'] = o[27] / 1000
    r['step_t1_issue'] = o[28] / 1000; r['step_t2_dcis'] = o[29] / 1000; r['step_t3_busyclr'] = o[30] / 1000; r['step_t2_with_gap39'] = o[31] / 1000
print(json.dumps(r))
PY
