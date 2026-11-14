#!/usr/bin/env bash
# mk.sh — rebuild the round-20 full-stack tree in target/proto-full (gitignored): fresh copies, proto_w4l65/apply.py
# (sections 1-10), then proto_full/apply.py; Rust == Python KATs, host golden, format tests, and every kit ELF.
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; R="$(cd "$D/../.." && pwd)"; P="$D/target/proto-full"
rm -rf "$P"; mkdir -p "$P"
for c in sphincs-c10 hw domain; do rsync -a --exclude target "$R/$c/" "$P/$c/"; done
for c in host_v2 bench_v2 bench_v2f bench_avg_v2f bench_v2drv bench_chain bench_v2fb; do rsync -a --exclude target "$D/$c/" "$P/$c/"; done
cp "$D/harness/run_flash.sh" "$P/run_flash_sig.sh"; cp "$D/evaluate.py" "$P/evaluate_sig.py"; cp "$D/harness/run_profile.sh" "$P/run_profile_sig.sh"
cp "$R/Cargo.lock" "$P/sphincs-c10/Cargo.lock"; cp "$R/Cargo.lock" "$P/domain/Cargo.lock"
python3 "$D/proto_w4l65/apply.py" "$P"
python3 "$D/proto_full/apply.py" "$P"
# Rust == Python: the full stack, all3 (unchanged), the merged PRF alone is covered by the full stack
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-ts200,v2-prf2,v2-split810,v2-wprf2b --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-ts200,v2-prf2,v2-split810 --test v2_kat -q )
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt-full cargo build --offline --release -q --features ts200,prf2,split810,wprf2b )
"$P/tgt-full/release/c10-ar-host" write "$P/golden-full.bin"; cmp "$P/golden-full.bin" "$D/golden-v2-all3-wprf2b.bin"
# format tests: the full stack's descriptor, and the known formats still pairwise distinct
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q --features format-kdf,ts200,prf2,split810,wprf2b --test format_kdf )
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q --features format-kdf,ts200,prf2,split810 --test format_kdf )
cd "$D"
B() { CRATE=target/proto-full/$1 LIBNAME=$2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="$3" BENCH_RUSTFLAGS="${5-}" BENCH_FEATURES=$4 ./build_any.sh out/$6.elf; }
FULL=ts200,prf2,split810,wprf2b,topcache
# the FI chain mirror (product-shaped: generic target, 1-way ICACHE): full stack, controls, bridge, ablations
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$FULL "" r20-chain-full
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$FULL,fi-control-cmp "" r20-chain-full-cmp
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$FULL,fi-control-verify "" r20-chain-full-ver
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,prf2,split810,topcache "" r20-chain-bridge
B bench_chain c10_bench_chain "-DFLASHRUN" v2,prf2,split810,wprf2b,topcache "" r20-chain-no-ts200
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,prf2,wprf2b,topcache "" r20-chain-no-split810
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,prf2,split810,wprf2b "" r20-chain-no-cache
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,split810,wprf2b,topcache "" r20-chain-no-prf2
B bench_chain c10_bench_chain "-DFLASHRUN" v2,wprf2b "" r20-chain-d03w
# 16-message means (research bench: 2-way ICACHE); bench_avg_v2f's wprf2b-asm = the wprf2b atom without rust-key
B bench_avg_v2f c10_bench_avg_v2f "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810,wprf2b-asm,topcache "-C target-cpu=cortex-m33 -C target-feature=-fpregs" r20-avg-full
B bench_avg_v2f c10_bench_avg_v2f "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810,topcache "-C target-cpu=cortex-m33 -C target-feature=-fpregs" r20-avg-bridge
# fixed messages with the cache: golden byte-compare and cache hits
B bench_v2fb c10_bench_v2fb "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810,wprf2b "-C target-cpu=cortex-m33 -C target-feature=-fpregs" r20-fb-full
B bench_v2fb c10_bench_v2fb "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810 "-C target-cpu=cortex-m33 -C target-feature=-fpregs" r20-fb-bridge
# residue suite with the merged PRF's patterns
for f in residue residue-control; do
  B bench_v2drv c10_bench_v2drv "-DFLASHRUN -DICACHE_2WAY" $f,cand-full "-C target-cpu=cortex-m33 -C target-feature=-fpregs" r20-res-$f
done
