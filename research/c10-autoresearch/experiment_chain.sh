#!/usr/bin/env bash
# experiment_chain.sh <tag> — round 13: the product sign chain (bench_chain) with DWT phase stamps.
# BENCH_FEATURES selects the configuration (tick | tick-batch | research,tick | ...). Product-shaped by
# default: generic thumbv8m.main (no target-cpu, as the firmware), pqsigner-hw at the root profile's "z",
# the shipped 1-way ICACHE. BENCH_RUSTFLAGS / BENCH_CARGO_ARGS / EXP_CFLAGS override. Prints one JSON line.
set -u
T=${1:?tag}; D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
BENCH_RUSTFLAGS=${BENCH_RUSTFLAGS-} CRATE=bench_chain LIBNAME=c10_bench_chain LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS-}" \
  ./build_any.sh out/chain-$T.elf > out/chain-$T-build.log 2>&1 || { echo "{\"ok\": false, \"why\": \"build failed ($T)\"}"; exit 2; }
timeout 900 bash harness/run_flash.sh out/chain-$T.elf 0x30000000 96 600 > out/chain-$T-run.log 2>&1
python3 - out/chain-$T.elf.openocd.log "$T" <<'PY'
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
r = {'ok': False, 'tag': sys.argv[2]}
if not w or w[0] != 0x444F4E45: r['why'] = 'status %s' % (hex(w[0]) if w else None); print(json.dumps(r)); sys.exit(1)
o = w[64:96]
names = ['rate_cfi', 'optrand', 'shuffle', 'sign_a', 'delay1', 'sign_b', 'ct_eq', 'delay2', 'verify', 'verify_gate', 'cfi_check', 'tail', 'release_copy']
r.update(ok=o[0] == 0x43484E31 and o[1] == 100 and o[3] == 16, keygen=o[2], chains_ok=o[3],
         phases=dict(zip(names, o[4:17])), chain_mean=o[17], progress_calls=o[18], ticks=o[19], delay_iters=o[20])
print(json.dumps(r))
PY
