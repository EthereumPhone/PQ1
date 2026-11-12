#!/usr/bin/env bash
# experiment_avg.sh <v1|v2f> — #1155: mean single-pass sign over 16 messages (grind luck averaged), harness v3b.
set -u
V=${1:?v1|v2f|v2fl}; D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
CRATE=bench_avg_$V LIBNAME=c10_bench_avg_$V LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/avg-$V.elf > out/avg-$V-build.log 2>&1 || { echo "{\"ok\": false, \"why\": \"build failed ($V)\"}"; exit 2; }
timeout 600 bash harness/run_flash.sh out/avg-$V.elf 0x30000000 96 240 > out/avg-$V-run.log 2>&1
python3 - out/avg-$V.elf.openocd.log $V <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
r = {'ok': False, 'variant': sys.argv[2]}
if not w or w[0] != 0x444F4E45: r['why'] = 'status %s' % (hex(w[0]) if w else None); print(json.dumps(r)); sys.exit(1)
o = w[64:96]
if o[0] != 0x43313041 or o[1] != 100: r['why'] = 'magic/stage %x %d' % (o[0], o[1]); print(json.dumps(r)); sys.exit(1)
if o[7] != 16: r['why'] = 'only %d/16 verified' % o[7]; print(json.dumps(r)); sys.exit(1)
per = o[16:32]; tot = o[4] | o[5] << 32
r.update(ok=True, keygen=o[3], mean_sign=tot // 16, min_sign=min(per), max_sign=max(per), mean_verify=o[6] // 16,
         cached_est=2 * (tot // 16) + o[6] // 16, cached_est_s=round((2 * (tot // 16) + o[6] // 16) / 160e6, 4), per_sign=per)
print(json.dumps(r))
PY
