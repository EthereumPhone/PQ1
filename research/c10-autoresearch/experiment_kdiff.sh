#!/usr/bin/env bash
# experiment_kdiff.sh — v1 kit differential (bench_diff): 32 cases signed on the kit through the fast paths,
# per-signature software SHA-256, compared with out/diff-ref.txt (pristine master); plus the search128 edge mask.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
CRATE=bench_diff LIBNAME=c10_bench_diff LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/diff.elf > out/diff-build.log 2>&1 || { echo '{"ok": false, "why": "build failed"}'; exit 2; }
timeout 900 bash harness/run_flash.sh out/diff.elf 0x30000000 96 600 > out/diff-run.log 2>&1
python3 - out/diff.elf.openocd.log out/diff-ref.txt <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
s = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('SIG0_WORDS')), None)
o = w[64:96]
b = b''.join(x.to_bytes(4, 'little') for x in s)
got = ['%d %s %s' % (i, b[48*i:48*i+16].hex(), b[48*i+16:48*i+48].hex()) for i in range(32)]
ref = [l.strip() for l in open(sys.argv[2]) if l.strip()]
eq = sum(g == r for g, r in zip(got, ref))
open('out/diff-fast.txt', 'w').write('\n'.join(got) + '\n')
r = dict(status=hex(w[0]), stage=o[1], cases=o[2], verified=o[3], search_edges=hex(o[4]), equal=eq)
r['ok'] = w[0] == 0x444F4E45 and o[1] == 8 and o[2] == 32 and o[3] == 32 and o[4] == 0x3F and eq == 32
print(json.dumps(r))
PY
