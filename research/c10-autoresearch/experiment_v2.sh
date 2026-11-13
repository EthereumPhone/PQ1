#!/usr/bin/env bash
# experiment_v2.sh <os|v2> — #1155 measurement: the oneshot driver path, v1 (bench_os, gate golden.bin)
# or v2 (bench_v2, gate golden-v2.bin = host_v2 = Python reference). Harness v3b (flash, ICACHE 2-way).
set -u
V=${1:?os|v2}; D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"; mkdir -p out
G=golden.bin; case $V in v2*) G=golden-v2.bin;; esac
G=${GOLDEN:-$G}  # format-options check: a variant golden (BENCH_FEATURES selects the variant)
CRATE=bench_$V LIBNAME=c10_bench_$V LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN ${EXP_CFLAGS--DICACHE_2WAY}" ./build_any.sh out/exp-$V.elf > out/kit-$V-build.log 2>&1 || { echo "{\"ok\": false, \"why\": \"kit build failed ($V)\"}"; exit 2; }
timeout 400 bash harness/run_flash.sh out/exp-$V.elf 0x30000000 96 60 > out/kit-$V-run.log 2>&1
./evaluate.py out/exp-$V.elf.openocd.log $G
