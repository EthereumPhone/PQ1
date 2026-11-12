#!/usr/bin/env bash
# experiment_b.sh — TRACK-B evaluation (top-layer cache): host gate with --features topcache (golden bytes, 3 hits,
# exact digest drop), then bench_b on the kit (harness v3b), golden bytes + OUT[14] == 3 hits.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
( cd host && CARGO_TARGET_DIR="$D/target-b" cargo build --release --offline -q --features topcache ) > out/hostb-build.log 2>&1 || { echo '{"ok": false, "why": "host-b build failed"}'; exit 2; }
"$D/target-b/release/c10-ar-host" check golden.bin > out/hostb.log 2>&1 || { echo "{\"ok\": false, \"why\": \"host-b gate: $(tail -1 out/hostb.log)\"}"; exit 1; }
grep -q '^TOPCACHE_HITS 3$' out/hostb.log || { echo '{"ok": false, "why": "host-b: cache not used 3 times"}'; exit 1; }
CRATE=bench_b LIBNAME=c10_bench_b EXTRA_LDFLAGS="${EXTRA_LDFLAGS:-}" LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/expb.elf > out/kitb-build.log 2>&1 || { echo '{"ok": false, "why": "kit-b build failed"}'; exit 2; }
timeout 400 bash harness/run_flash.sh out/expb.elf 0x30000000 96 60 > out/kitb-run.log 2>&1
python3 - out/expb.elf.openocd.log <<'PY'
import json, subprocess, sys
r = json.loads(subprocess.run(['./evaluate.py', sys.argv[1], 'golden.bin'], capture_output=True, text=True).stdout)
w = [int(x, 16) for x in next(l for l in open(sys.argv[1]) if l.startswith('RESULT_WORDS')).split()[1:]]
r['cache_hits'] = w[64 + 14]
if r.get('ok') and r['cache_hits'] != 3:
    r['ok'] = False; r['why'] = 'kit: cache hits %d != 3' % r['cache_hits']
r['keygen_note'] = 'keygen = fill + confirm (two top-tree builds)'
print(json.dumps(r)); sys.exit(0 if r['ok'] else 1)
PY
