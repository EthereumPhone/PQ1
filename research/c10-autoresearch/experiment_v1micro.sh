#!/usr/bin/env bash
# experiment_v1micro.sh — round 8 "test zero" for v1: DWT cycles of each v1 driver entry (bench_v1micro). Not a gate.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
CRATE=bench_v1micro LIBNAME=c10_bench_v1micro LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/v1micro.elf > out/v1micro-build.log 2>&1 || { echo '{"ok": false, "why": "build failed"}'; exit 2; }
timeout 600 bash harness/run_flash.sh out/v1micro.elf 0x30000000 96 300 > out/v1micro-run.log 2>&1
python3 - out/v1micro.elf.openocd.log <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
o = w[64:96]
r = {'ok': w[0] == 0x444F4E45 and o[1] == 100}
def q(i): return (o[i], o[i + 1])
c, d = q(2); r['chains16_keygen_per_digest'] = round(c / d, 1)
c, d = q(4); r['grindcheck'] = c; r['grindcheck_fail'] = d
if c != 4 or d != 0: r['ok'] = False
c, d = q(6); r['chain16_x15_per_step'] = round(c / d, 1)
c, d = q(8); r['fors_subtree16_per_call'] = round(c / d, 1); r['fors_subtree16_per_digest'] = round(c / d / 47, 1)
c, d = q(10); r['searchcheck'] = c; r['searchcheck_fail'] = d
if c != 12 or d != 0: r['ok'] = False
c, d = q(12); r['search128_prednever_per_try'] = round(c / d, 1)
c, d = q(14); r['search128_205_per_try'] = round(c / d, 1) if d else None; r['search128_205_tries'] = d
c, d = q(16); r['th_multi16_43_per_call'] = round(c / d, 1)
c, d = q(18); r['grind_per_nonce'] = round(c / d, 1) if d else None; r['grind_nonces'] = d
c, d = q(20); r['residue_cases'] = c; r['residue_mask'] = hex(d)
if c != 7 or d != 0: r['ok'] = False
c, d = q(22); r['node16'] = round(c / d, 1)
c, d = q(24); r['fors_leaf16'] = round(c / d, 1)
c, d = q(26); r['keycheck_keys'] = c; r['keycheck_bad'] = d
if c != 8 or d != 0: r['ok'] = False
c, d = q(28); r['subcheck_trees'] = c; r['subcheck_bad'] = d
if c != 4 or d != 0: r['ok'] = False
for i, nw in zip((30,), (32,)):
    c, d = q(i); r['raw%d_loop' % nw] = round(c / 2000, 1); r['raw%d_init_dcis' % nw] = round(d / 2000, 1)
print(json.dumps(r))
PY
