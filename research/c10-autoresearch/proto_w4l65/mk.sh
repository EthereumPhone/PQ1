#!/usr/bin/env bash
# mk.sh — rebuild the w4l65 prototype copy in target/proto-w4l65 (gitignored) and run its host checks.
# See apply.py for why it is a copy. Kit runs: run_kit.sh (flash-only; never option bytes).
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; R="$(cd "$D/../.." && pwd)"; P="$D/target/proto-w4l65"
rm -rf "$P"; mkdir -p "$P"
rsync -a --exclude target "$R/sphincs-c10/" "$P/sphincs-c10/"
rsync -a --exclude target "$D/host_v2/" "$P/host_v2/"
rsync -a --exclude target "$D/bench_v2/" "$P/bench_v2/"
cp "$D/harness/run_flash.sh" "$P/run_flash_sig.sh"; cp "$D/evaluate.py" "$P/evaluate_sig.py"
cp "$R/Cargo.lock" "$P/sphincs-c10/Cargo.lock"
python3 "$D/proto_w4l65/apply.py" "$P"
# Rust == Python (c10v2_ref.py --variant w4l65) KATs and +C near-misses; draft 0.3 KATs with the flag off
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-w4l65 --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat0 cargo test --offline --release --features v2 --test v2_kat -q )
# exact SHA-256 digest counts (software hooks) and the kit golden
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt cargo build --offline --release -q && CARGO_TARGET_DIR=../tgt-w4 cargo build --offline --release -q --features w4l65 )
"$P/tgt/release/c10-ar-host" write "$P/golden-d03.bin"; cmp "$P/golden-d03.bin" "$D/golden-v2.bin"
"$P/tgt-w4/release/c10-ar-host" write "$P/golden-w4l65.bin"; cmp "$P/golden-w4l65.bin" "$D/golden-v2-w4l65.bin"
# kit ELFs
cd "$D"
for v in d03 w4l65; do F=""; [ $v = w4l65 ] && F=w4l65
  CRATE=target/proto-w4l65/bench_v2 LIBNAME=c10_bench_v2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-$v.elf
done
