#!/usr/bin/env bash
# mk21.sh — round 21 on top of the round-20 tree target/proto-full (run proto_full/mk.sh first): apply21.py, then the
# no-prf2 candidate (v2 0.3 + ts200 + split810 + top cache + wprf2b + fmtKDF): Rust == Python KATs, host golden ==
# the committed golden (and == the Python reference), its format tests, its kit ELFs; then a sample of round-20 ELFs
# rebuilt as chk-* and compared with the round-20 out/ files (apply21 must move none of them).
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; P="$D/target/proto-full"; TAG=ts200-split810-wprf2b
python3 "$D/proto_full/apply21.py" "$P"
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-ts200,v2-split810,v2-wprf2b --test v2_kat -q )
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt-np2 cargo build --offline --release -q --features ts200,split810,wprf2b )
"$P/tgt-np2/release/c10-ar-host" write "$P/golden-np2.bin"
G="$D/golden-v2-$TAG.bin"
if [ -f "$G" ]; then cmp "$P/golden-np2.bin" "$G"; else cp "$P/golden-np2.bin" "$G"; fi
python3 "$D/c10v2/golden_python_check.py" ts200,split810,wprf2b "$G"
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q --features format-kdf,ts200,split810,wprf2b --test format_kdf )
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q --features format-kdf,ts200,prf2,split810,wprf2b --test format_kdf )
cd "$D"
B() { CRATE=target/proto-full/$1 LIBNAME=$2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="$3" BENCH_RUSTFLAGS="${5-}" BENCH_FEATURES=$4 ./build_any.sh out/$6.elf; }
NP2=ts200,split810,wprf2b,topcache
M33="-C target-cpu=cortex-m33 -C target-feature=-fpregs"
# the FI chain mirror (product-shaped) and its two positive controls
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$NP2 "" r21-chain-np2
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$NP2,fi-control-cmp "" r21-chain-np2-cmp
B bench_chain c10_bench_chain "-DFLASHRUN" v2,$NP2,fi-control-verify "" r21-chain-np2-ver
# 16-message means (research bench) and the golden byte-compare
B bench_avg_v2f c10_bench_avg_v2f "-DFLASHRUN -DICACHE_2WAY" ts200,split810,wprf2b-asm,topcache "$M33" r21-avg-np2
B bench_v2fb c10_bench_v2fb "-DFLASHRUN -DICACHE_2WAY" ts200,split810,wprf2b "$M33" r21-fb-np2
for f in residue residue-control; do
  B bench_v2drv c10_bench_v2drv "-DFLASHRUN -DICACHE_2WAY" $f,cand-np2 "$M33" r21-res-np2-$f
done
# round-20 ELFs unchanged by apply21 (a sample across the four bench crates)
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,prf2,split810,wprf2b,topcache "" chk-r20-chain-full
B bench_chain c10_bench_chain "-DFLASHRUN" v2,ts200,split810,wprf2b,topcache "" chk-r20-chain-no-prf2
B bench_v2fb c10_bench_v2fb "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810,wprf2b "$M33" chk-r20-fb-full
B bench_avg_v2f c10_bench_avg_v2f "-DFLASHRUN -DICACHE_2WAY" ts200,prf2,split810,wprf2b-asm,topcache "$M33" chk-r20-avg-full
B bench_v2drv c10_bench_v2drv "-DFLASHRUN -DICACHE_2WAY" residue,cand-full "$M33" chk-r20-res-residue
for c in chain-full chain-no-prf2 fb-full avg-full res-residue; do
  if [ -f "out/r20-$c.elf" ]; then cmp "out/chk-r20-$c.elf" "out/r20-$c.elf" && echo "r20-$c: byte-identical after apply21"; fi
done
cmp out/r21-chain-np2.elf out/r20-chain-no-prf2.elf && echo "r21-chain-np2 == r20-chain-no-prf2 (same build)"
echo "mk21 OK"
