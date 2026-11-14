#!/usr/bin/env bash
# mk.sh — rebuild the d3l46 prototype in target/proto-d3 (gitignored): Rust == Python KATs, host counts and golden,
# the generic-path kit ELFs (draft 0.3 baseline and d3l46). Kit: proto_d3/run_kit.sh (flash-only).
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; R="$(cd "$D/../.." && pwd)"; P="$D/target/proto-d3"
rm -rf "$P"; mkdir -p "$P"
rsync -a --exclude target "$R/sphincs-c10/" "$P/sphincs-c10/"
rsync -a --exclude target "$D/host_v2/" "$P/host_v2/"
rsync -a --exclude target "$D/bench_v2/" "$P/bench_v2/"
cp "$D/harness/run_flash.sh" "$P/run_flash_sig.sh"; cp "$D/evaluate.py" "$P/evaluate_sig.py"; cp "$R/Cargo.lock" "$P/sphincs-c10/Cargo.lock"
python3 "$D/proto_d3/apply.py" "$P"
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-d3l46 --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat0 cargo test --offline --release --features v2 --test v2_kat -q )
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt cargo build --offline --release -q && CARGO_TARGET_DIR=../tgt-d3 cargo build --offline --release -q --features d3l46 )
"$P/tgt/release/c10-ar-host" write "$P/golden-d03.bin"; cmp "$P/golden-d03.bin" "$D/golden-v2.bin"
"$P/tgt-d3/release/c10-ar-host" write "$P/golden-d3l46.bin"; cmp "$P/golden-d3l46.bin" "$D/golden-v2-d3l46.bin"
cd "$D"
for v in d03 d3l46; do F=""; [ $v = d3l46 ] && F=d3l46
  CRATE=target/proto-d3/bench_v2 LIBNAME=c10_bench_v2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-d3-$v.elf
done
