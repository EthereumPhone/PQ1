#!/bin/bash
# DVT checklist 3.9 / #982: can a non-secure DMA master read the OTP, the UID or secure memory?
#
# Usage: tools/dvt/dma_probe.sh <ABSOLUTE output dir> [locked|control]
#   locked  (default) judge with `dma_probe.py --expect-locked`: the secure image claims and locks
#           every GPDMA1/LPDMA1 channel (#982), so no case may move a byte.
#   control the pre-#982 judgement (NS->NS controls must copy); use it with SRC_TREE=<a worktree of
#           a pre-fix commit> for the same-session positive control. The NS probe source is always
#           taken from THIS tree, so both runs execute the same probe.
# Builds secure (mock-se, ui-noop, e2e-test for the tzic_status veneer, NO debug-log: the probe
# detaches) + NS `dma-probe`, flashes both, resets, and reads the result statics over SWD. Option
# bytes are not touched (the unit must already be TZEN=1 with bank 2 non-secure). Neither secure
# element is used (mock-se); the OTP is not written (otp-hardcoded-master-key). Nothing signs, so
# flash page 123 is not written.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
SP=$1; MODE=${2:-locked}
SRC=${SRC_TREE:-$HERE}
cd "$SRC" || exit 1
if [ "$SRC" != "$HERE" ]; then
  cp "$HERE/nonsecure/src/dma_probe.rs" nonsecure/src/dma_probe.rs || exit 1
fi
SFEAT=mock-se,ui-noop,e2e-test,stm32u585,hw-sha256,otp-hardcoded-master-key,board-pq1
NFEAT=dma-probe,stm32u585,board-pq1
RF="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=/nix/store=/nix-store --remap-path-prefix=$PWD=/pqsigner -C link-arg=--build-id=none"
SE=target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
NE=target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
rm -f $SE target/secure/thumbv8m.main-none-eabi/release/deps/sphincs_tz_secure-*
FSBL_VENDOR_PUBKEY=$HERE/target/dev_vendor_pubkey.bin CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=--cmse-implib -C link-arg=--out-implib=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/secure -p sphincs-tz-secure --no-default-features --features $SFEAT || exit 1
rm -f $NE target/nonsecure/thumbv8m.main-none-eabi/release/deps/sphincs_tz_nonsecure-*
CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/nonsecure -p sphincs-tz-nonsecure --no-default-features --features $NFEAT || exit 1
tools/check-gateway-abi.sh $SE $NE || exit 1
cp $SE "$SP/secure-$MODE.elf"; cp $NE "$SP/ns-$MODE.elf"
git -C "$SRC" rev-parse --short HEAD > "$SP/commit-$MODE.txt"
probe-rs download --chip STM32U585CIUx $NE && probe-rs download --chip STM32U585CIUx $SE || exit 1
# NS SRAM2 survives a reset (SRAM2_RST=1), so the previous run's complete result block would satisfy
# the reader before this boot reaches the probe. Clear it first.
HDR=$(arm-none-eabi-nm $NE | awk '$3=="DMA_PROBE_HDR"{print "0x"$1}')
[ -n "$HDR" ] || exit 1
probe-rs write --chip STM32U585CIUx b32 $HDR $(printf '0 %.0s' $(seq 14)) || exit 1
probe-rs reset --chip STM32U585CIUx || exit 1
EXPECT=; [ "$MODE" = locked ] && EXPECT=--expect-locked
python3 -I "$HERE/tools/dvt/dma_probe.py" --ns-elf "$SP/ns-$MODE.elf" $EXPECT --out "$SP/dma-probe-$MODE.json" | tee "$SP/dma-probe-$MODE.log"
exit "${PIPESTATUS[0]}"
