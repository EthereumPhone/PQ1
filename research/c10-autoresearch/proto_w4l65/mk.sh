#!/usr/bin/env bash
# mk.sh — rebuild the w4l65 prototype copy in target/proto-w4l65 (gitignored) and run its host checks.
# See apply.py for why it is a copy. Kit runs: run_kit.sh (flash-only; never option bytes).
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"; R="$(cd "$D/../.." && pwd)"; P="$D/target/proto-w4l65"
rm -rf "$P"; mkdir -p "$P"
rsync -a --exclude target "$R/sphincs-c10/" "$P/sphincs-c10/"
rsync -a --exclude target "$D/host_v2/" "$P/host_v2/"
rsync -a --exclude target "$D/bench_v2/" "$P/bench_v2/"
rsync -a --exclude target "$R/hw/" "$P/hw/"
rsync -a --exclude target "$D/bench_v2f/" "$P/bench_v2f/"
rsync -a --exclude target "$D/bench_avg_v2f/" "$P/bench_avg_v2f/"
rsync -a --exclude target "$R/domain/" "$P/domain/"
rsync -a --exclude target "$D/bench_v2drv/" "$P/bench_v2drv/"
rsync -a --exclude target "$D/bench_chain/" "$P/bench_chain/"
cp "$D/harness/run_flash.sh" "$P/run_flash_sig.sh"; cp "$D/evaluate.py" "$P/evaluate_sig.py"; cp "$D/harness/run_profile.sh" "$P/run_profile_sig.sh"
cp "$R/Cargo.lock" "$P/sphincs-c10/Cargo.lock"; cp "$R/Cargo.lock" "$P/domain/Cargo.lock"
python3 "$D/proto_w4l65/apply.py" "$P"
# Rust == Python (c10v2_ref.py --variant w4l65) KATs and +C near-misses; draft 0.3 KATs with the flag off
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat cargo test --offline --release --features v2,v2-w4l65 --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-kat0 cargo test --offline --release --features v2 --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-katc cargo test --offline --release --features v2,v2-wprf2b --test v2_kat -q )
( cd "$P/sphincs-c10" && CARGO_TARGET_DIR=../tgt-katc cargo test --offline --release --features v2,v2-w4l65,v2-wprf2b --test v2_kat -q )
# round 17, gate (d): the stock domain suite (every pinned recovery / tag vector) with format-kdf off, unchanged;
# then the format tests once per format; then the two refusals (v2 without format-kdf, format-kdf on v1)
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q )
for f in v2 w4l65 wprf2b w4l65,wprf2b ts200 prf2 split810 ts200,prf2,split810 forslastprf; do
  ( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo test --offline --release -q --features format-kdf,$f --test format_kdf )
done
for ctl in "v2:must bind its format" "format-kdf:binds v2 formats only"; do
  if out=$(cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo check --offline -q --features "${ctl%%:*}" 2>&1); then
    echo "CONTROL FAILED: --features ${ctl%%:*} compiled"; exit 1; fi
  echo "$out" | grep -q "${ctl#*:}" || { echo "CONTROL FAILED for the wrong reason: ${ctl%%:*}"; echo "$out" | tail -5; exit 1; }
  echo "control ok: --features ${ctl%%:*} refused (${ctl#*:})"
done
# the legacy c7 routes are gone under format-kdf: a probe calling all seven must fail to compile on each name
cat > "$P/domain/tests/legacy_probe.rs" <<'RS'
#![allow(unused)]
use pqsigner_domain as d;
fn probe(e: &[u8; 32], s: &[u8; 64]) {
    let _ = d::slhdsa_seed_from_bip39(s);
    let _ = d::derive_signing_key_from_entropy(e);
    let _ = d::derive_keypair_from_entropy(e);
    let _ = d::bootstrap_seed_from_bip39(s);
    let _ = d::derive_bootstrap_key_from_entropy(e);
    let _ = d::derive_bootstrap_keypair_from_entropy(e);
    let _ = d::derive_bootstrap_vk_from_entropy(e);
}
RS
( cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo check --offline -q --tests --test legacy_probe ) || { echo "legacy probe: stock build does not compile"; exit 1; }
if out=$(cd "$P/domain" && CARGO_TARGET_DIR=../tgt-dom cargo check --offline -q --features format-kdf,v2 --tests --test legacy_probe 2>&1); then
  echo "CONTROL FAILED: the legacy c7 routes exist under format-kdf"; exit 1; fi
n=$(echo "$out" | grep -c "cannot find function")
[ "$n" -eq 7 ] || { echo "CONTROL FAILED: $n of 7 legacy routes refused"; echo "$out" | tail -8; exit 1; }
echo "control ok: all 7 legacy c7 routes absent under format-kdf (stock build compiles them)"
rm -f "$P/domain/tests/legacy_probe.rs"
python3 "$D/proto_w4l65/plants_d.py" "$P"
# exact SHA-256 digest counts (software hooks) and the kit golden
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt cargo build --offline --release -q && CARGO_TARGET_DIR=../tgt-w4 cargo build --offline --release -q --features w4l65 )
"$P/tgt/release/c10-ar-host" write "$P/golden-d03.bin"; cmp "$P/golden-d03.bin" "$D/golden-v2.bin"
"$P/tgt-w4/release/c10-ar-host" write "$P/golden-w4l65.bin"; cmp "$P/golden-w4l65.bin" "$D/golden-v2-w4l65.bin"
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt-c cargo build --offline --release -q --features wprf2b )
"$P/tgt-c/release/c10-ar-host" write "$P/golden-wprf2b.bin"; cmp "$P/golden-wprf2b.bin" "$D/golden-v2-wprf2b.bin"
( cd "$P/host_v2" && CARGO_TARGET_DIR=../tgt-cw cargo build --offline --release -q --features w4l65-wprf2b )
"$P/tgt-cw/release/c10-ar-host" write "$P/golden-w4l65-wprf2b.bin"; cmp "$P/golden-w4l65-wprf2b.bin" "$D/golden-v2-w4l65-wprf2b.bin"
# kit ELFs
cd "$D"
for v in d03 w4l65; do F=""; [ $v = w4l65 ] && F=w4l65
  CRATE=target/proto-w4l65/bench_v2 LIBNAME=c10_bench_v2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-$v.elf
done
# round 17: the fused one-block driver (copy of hw/), draft 0.3 and w4l65
for v in d03 w4l65; do F=""; [ $v = w4l65 ] && F=w4l65
  CRATE=target/proto-w4l65/bench_v2f LIBNAME=c10_bench_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-f-$v.elf
done
# 16-message means (grind luck averaged), fused
for v in d03 w4l65; do F=""; [ $v = w4l65 ] && F=w4l65
  CRATE=target/proto-w4l65/bench_avg_v2f LIBNAME=c10_bench_avg_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-avg-f-$v.elf
done
# round 17, gate (c): wprf2b against draft 0.3 — generic path; fused with the Rust key loop (fixed messages + 16-message means)
CRATE=target/proto-w4l65/bench_v2 LIBNAME=c10_bench_v2 LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=wprf2b ./build_any.sh out/proto-wprf2b.elf
for v in rk-d03 wprf2b; do F=rustkey; [ $v = wprf2b ] && F=wprf2b
  CRATE=target/proto-w4l65/bench_v2f LIBNAME=c10_bench_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-f-$v.elf
  CRATE=target/proto-w4l65/bench_avg_v2f LIBNAME=c10_bench_avg_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$F ./build_any.sh out/proto-avg-f-$v.elf
done
# round 18: wprf2b in the dt32 asm key loop (fixed messages + 16-message means)
CRATE=target/proto-w4l65/bench_v2f LIBNAME=c10_bench_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=wprf2b-asm ./build_any.sh out/proto-f-wprf2b-asm.elf
CRATE=target/proto-w4l65/bench_avg_v2f LIBNAME=c10_bench_avg_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=wprf2b-asm ./build_any.sh out/proto-avg-f-wprf2b-asm.elf
# round 18: w4l65 at full speed (T_65 feed, w = 4 asm search), alone and with wprf2b
for v in w4l65-asm w4l65-wprf2b; do
  CRATE=target/proto-w4l65/bench_v2f LIBNAME=c10_bench_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$v ./build_any.sh out/proto-f-$v.elf
  CRATE=target/proto-w4l65/bench_avg_v2f LIBNAME=c10_bench_avg_v2f LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$v ./build_any.sh out/proto-avg-f-$v.elf
done
# round 18 assurance builds: residue suites and the FI chain mirror on both candidates
for c in d03w w4w; do
  for f in residue residue-control; do
    CRATE=target/proto-w4l65/bench_v2drv LIBNAME=c10_bench_v2drv LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN -DICACHE_2WAY" BENCH_FEATURES=$f,cand-$c ./build_any.sh out/proto-res-$c-$f.elf
  done
  for f in "" ,fi-control-cmp ,fi-control-verify; do
    BENCH_RUSTFLAGS= CRATE=target/proto-w4l65/bench_chain LIBNAME=c10_bench_chain LDSCRIPT=link_flash.ld EXTRA_CFLAGS="-DFLASHRUN" BENCH_FEATURES=cand-$c$f ./build_any.sh out/proto-chain-$c${f#,}.elf
  done
done
