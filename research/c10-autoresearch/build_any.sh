#!/usr/bin/env bash
# build.sh <out.elf> — builds the kit bench (Rust staticlib + frozen C harness) into an SRAM-only ELF.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; OUT="${1:-$D/out/bench.elf}"; mkdir -p "$(dirname "$OUT")"; OUT="$(readlink -f "$OUT")"
( cd "$D/${CRATE:-bench}" && CARGO_TARGET_DIR="$D/target" cargo build --release --offline --target thumbv8m.main-none-eabi -q )
arm-none-eabi-gcc -mcpu=cortex-m33 -mthumb -O2 -ffunction-sections -fdata-sections -ffreestanding -nostdlib \
  -DCLK160 ${EXTRA_CFLAGS:-} -I"$D/harness" -T "$D/harness/${LDSCRIPT:-link_cbus.ld}" -Wl,--gc-sections \
  "$D/harness/startup.c" "$D/harness/clk.c" "$D/target/thumbv8m.main-none-eabi/release/lib${LIBNAME:-c10_bench}.a" -lgcc -o "$OUT"
arm-none-eabi-size "$OUT" | tail -1
