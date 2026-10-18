#!/bin/bash
# DVT checklist 13.10: can a parked non-secure SysTick hold the 120 s idle wipe off?
#
# Usage: tools/dvt/idle_hold.sh <ABSOLUTE output dir> [nobump]   (SECS=420 sets the watch length)
#   IHT_HOLD_MS=<ms> sets the park length (default 200000). SFEAT_NO_IWDG=1 drops `iwdg` from the
#   secure image, so only the SysTick idle-wipe deferral bound (#981 layer B) can end the hold.
#   BOUND_MS=<ms> [EXPECT_RESET=1] makes idle_hold.py print a PASS/FAIL verdict. DEBUG=1 adds debug-log
#   and keeps `probe-rs run` attached for SECS seconds (secure log in <dir>/run-<mode>.log) instead
#   of the detached SWD watch.
# Builds secure (mock-se, ui-noop, e2e-test, iwdg, NO debug-log: the probe detaches, and a
# semihosting BKPT with no debugger resets the board) + NS `idle-hold-test` (or the
# `idle-hold-nobump` control), flashes both, resets, and watches it over SWD with
# tools/dvt/idle_hold.py. Option bytes are not touched (the unit must already be TZEN=1 with
# bank 2 non-secure). Neither secure element is used (mock-se); the OTP is not written
# (otp-hardcoded-master-key).
set -u
cd "$(dirname "$0")/../.."
SP=$1; MODE=${2:-bump}; SECS=${SECS:-420}
SFEAT=mock-se,ui-noop,e2e-test,stm32u585,hw-sha256,iwdg,otp-hardcoded-master-key,board-pq1
[ "${SFEAT_NO_IWDG:-0}" = 1 ] && SFEAT=${SFEAT/,iwdg,/,} && MODE=$MODE-noiwdg
[ "${DEBUG:-0}" = 1 ] && SFEAT=$SFEAT,debug-log
NFEAT=idle-hold-test,stm32u585,board-pq1; [ "${MODE%-noiwdg}" = nobump ] && NFEAT=idle-hold-nobump,stm32u585,board-pq1
[ "${SFEAT_NO_IWDG:-0}" = 1 ] || NFEAT=$NFEAT,iwdg
RF="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=/nix/store=/nix-store --remap-path-prefix=$PWD=/pqsigner -C link-arg=--build-id=none"
SE=target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
NE=target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
rm -f $SE target/secure/thumbv8m.main-none-eabi/release/deps/sphincs_tz_secure-*
FSBL_VENDOR_PUBKEY=$PWD/target/dev_vendor_pubkey.bin CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=--cmse-implib -C link-arg=--out-implib=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/secure -p sphincs-tz-secure --no-default-features --features $SFEAT || exit 1
rm -f $NE target/nonsecure/thumbv8m.main-none-eabi/release/deps/sphincs_tz_nonsecure-*
IHT_HOLD_MS=${IHT_HOLD_MS:-200000} CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/nonsecure -p sphincs-tz-nonsecure --no-default-features --features $NFEAT || exit 1
tools/check-gateway-abi.sh $SE $NE || exit 1
cp $SE $SP/secure-$MODE.elf; cp $NE $SP/ns-$MODE.elf
probe-rs download --chip STM32U585CIUx $NE && probe-rs download --chip STM32U585CIUx $SE || exit 1
if [ "${DEBUG:-0}" = 1 ]; then
  timeout $SECS probe-rs run --chip STM32U585CIUx $SE > $SP/run-$MODE.log 2>&1
  grep -vE 'WARN|retrying' $SP/run-$MODE.log | tail -40; exit 0
fi
probe-rs reset --chip STM32U585CIUx || exit 1
VERDICT_ARGS=; [ -n "${BOUND_MS:-}" ] && VERDICT_ARGS="--bound-ms $BOUND_MS"; [ "${EXPECT_RESET:-0}" = 1 ] && VERDICT_ARGS="$VERDICT_ARGS --expect-reset"
python3 -I tools/dvt/idle_hold.py --ns-elf $SP/ns-$MODE.elf --s-elf $SP/secure-$MODE.elf --secs $SECS --out $SP/idle-hold-$MODE.jsonl $VERDICT_ARGS
