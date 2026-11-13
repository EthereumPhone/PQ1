#!/usr/bin/env bash
# experiment_v2b.sh — TRACK B on v2 (#1148 x #1155): host gate (host_v2f --features topcache: golden-v2 bytes, 3 hits),
# then bench_v2fb on the kit (harness v3b): golden-v2 bytes + OUT[14] == 3 cache hits. keygen = fill + confirm.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
# Format-options check: VARF selects a variant (e.g. split810, ts200,prf2,split810) and GOLDEN its golden.
G=${GOLDEN:-golden-v2.bin}; VARF=${VARF:-}
( cd host_v2f && CARGO_TARGET_DIR="$D/target-v2fc" cargo build --release --offline -q --features topcache${VARF:+,$VARF} ) > out/hostv2b-build.log 2>&1 || { echo '{"ok": false, "why": "host build failed"}'; exit 2; }
"$D/target-v2fc/release/c10-ar-host" check "$G" > out/hostv2b.log 2>&1 || { echo "{\"ok\": false, \"why\": \"host gate: $(tail -1 out/hostv2b.log)\"}"; exit 1; }
grep -q '^TOPCACHE_HITS 3$' out/hostv2b.log || { echo '{"ok": false, "why": "host: cache not used 3 times"}'; exit 1; }
BENCH_FEATURES=$VARF CRATE=bench_v2fb LIBNAME=c10_bench_v2fb LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/expv2b.elf > out/kitv2b-build.log 2>&1 || { echo '{"ok": false, "why": "kit build failed"}'; exit 2; }
timeout 400 bash harness/run_flash.sh out/expv2b.elf 0x30000000 96 60 > out/kitv2b-run.log 2>&1
python3 - out/expv2b.elf.openocd.log "$G" <<'PY'
import json, subprocess, sys
r = json.loads(subprocess.run(['./evaluate.py', sys.argv[1], sys.argv[2]], capture_output=True, text=True).stdout)
w = [int(x, 16) for x in next(l for l in open(sys.argv[1]) if l.startswith('RESULT_WORDS')).split()[1:]]
r['cache_hits'] = w[64 + 14]
if r.get('ok') and r['cache_hits'] != 3:
    r['ok'] = False; r['why'] = 'kit: cache hits %d != 3' % r['cache_hits']
r['keygen_note'] = 'keygen = fill + confirm (two top-tree builds)'
print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
PY
