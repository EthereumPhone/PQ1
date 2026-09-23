#!/usr/bin/env bash
# build-evt-image.sh — build a pq1 EVT dual-world image pair ready for
# tools/flash-evt-dfu.sh.
#
# WHY THIS IS A REPO TOOL (2026-09-23)
#
# This recipe was carried in throwaway scratchpad scripts and cost two separate
# failures in one day:
#
#   1. The ELF->bin conversion was wrong. The non-secure section list was
#      applied to the secure image, silently dropping .data and the CMSE
#      veneers — 426,688 B flashed as 415,612 B, with the flasher reporting
#      "Download verified successfully" throughout. Now delegated to
#      tools/elf-to-bin.sh, which selects by address and proves the span.
#   2. The script was deleted when the scratchpad was cleaned, the build
#      therefore never ran, and a STALE ELF was nearly flashed and read as
#      evidence about code that was not in it.
#
# Hence the two guards at the end: every output must be newer than this script
# invocation, and the gateway ABI join must pass. Both failures above would
# have been caught by them.
#
# Usage:
#   tools/build-evt-image.sh <out-dir> [extra-secure-features]
#
#   tools/build-evt-image.sh evt-images/ui733
#   tools/build-evt-image.sh evt-images/ui733 aw99703-ovp-low,aw99703-full-brightness
set -euo pipefail

OUT=${1:?usage: $0 <out-dir> [extra-secure-features]}
EXTRA=${2:-}

cd "$(dirname "$0")/.."
START=$(date +%s)

TARGET=thumbv8m.main-none-eabi
VENEERS=$PWD/target/veneers.o
SECURE_ELF=target/secure/$TARGET/release/sphincs-tz-secure
NONSECURE_ELF=target/nonsecure/$TARGET/release/sphincs-tz-nonsecure

# Base feature set for the sealed EVT screen unit: interactive (no e2e-test),
# dev-testkey for stable bench credentials, real dual-SE, USB, LCD.
SEC_FEATURES=dual-se,dev-testkey,ui-lcd,stm32u585,usb,board-pq1
[ -n "$EXTRA" ] && SEC_FEATURES="$SEC_FEATURES,$EXTRA"
NS_FEATURES=stm32u585,usb,board-pq1

REPRO="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=/nix/store=/nix-store --remap-path-prefix=$PWD=/pqsigner -C link-arg=--build-id=none"
R=CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS

# RUSTFLAGS from the caller's environment would reach host build scripts and
# break them; the firmware flags go through the target-specific variable only.
unset RUSTFLAGS

echo "==> secure   [$SEC_FEATURES]"
env "$R=-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $REPRO -C link-arg=--cmse-implib -C link-arg=--out-implib=$VENEERS" \
  cargo build --locked --release --target $TARGET --target-dir target/secure \
    -p sphincs-tz-secure --no-default-features --features "$SEC_FEATURES"

# cargo does not track files named in RUSTFLAGS link-args, so without forcing
# this the NS keeps calling STALE veneer addresses and the first gateway call
# faults into secure -> reset. (Makefile 3d8b014a; see project_usb_signing_proven.)
echo "==> forcing NS relink"
rm -f "$NONSECURE_ELF" target/nonsecure/$TARGET/release/deps/sphincs_tz_nonsecure-*

echo "==> nonsecure [$NS_FEATURES]"
env "$R=-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x $REPRO -C link-arg=$VENEERS" \
  cargo build --locked --release --target $TARGET --target-dir target/nonsecure \
    -p sphincs-tz-nonsecure --features "$NS_FEATURES"

echo "==> gateway ABI join"
tools/check-gateway-abi.sh "$SECURE_ELF" "$NONSECURE_ELF"

echo "==> converting"
mkdir -p "$OUT"
tools/elf-to-bin.sh "$SECURE_ELF" "$OUT/secure.bin"
tools/elf-to-bin.sh "$NONSECURE_ELF" "$OUT/nonsecure.bin"

# FRESHNESS GUARD. A deleted or silently-failing build step leaves last run's
# artefacts in place, and flashing those reads as evidence about code that is
# not in them. Nothing here is older than this invocation.
for f in "$SECURE_ELF" "$NONSECURE_ELF" "$OUT/secure.bin" "$OUT/nonsecure.bin"; do
  if [ "$(stat -c %Y "$f")" -lt "$START" ]; then
    echo "build-evt-image: STALE — $f predates this run ($(stat -c %y "$f"))" >&2
    exit 1
  fi
done

echo "==> OK, all artefacts fresh:"
ls -l "$OUT"
