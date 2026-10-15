#!/bin/bash
# DVT checklist 5.4/5.5: SRAM secret residue before/after CMD_LOCK on the mock-SE e2e image.
#
# Usage: tools/dvt/residue.sh <ABSOLUTE output dir>    (SFEAT=... overrides the secure features)
# Builds secure (mock-se, ui-noop, NO debug-log: semihosting after the probe detaches would
# reset-loop the board) + NS bench-key-speed with BENCH_RESIDUE=1, signs once, parks, dumps
# 0x3000_0000+768 KB ("unlocked"), releases RESIDUE_GO over SWD (NS calls CMD_LOCK), dumps again
# ("locked"). Search the dumps with:
#   (cd tools/dvt/derive && cargo run -q) > <dir>/derived.txt
#   python3 -I tools/dvt/sram_search.py <dir>/derived.txt <dir>/sram-*.bin
set -u
cd "$(dirname "$0")/../.."
SP=$1; SFEAT=${SFEAT:-mock-se,ui-noop,e2e-test,stm32u585,hw-sha256,board-pq1}
RF="-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=/nix/store=/nix-store --remap-path-prefix=$PWD=/pqsigner -C link-arg=--build-id=none"
SE=target/secure/thumbv8m.main-none-eabi/release/sphincs-tz-secure
NE=target/nonsecure/thumbv8m.main-none-eabi/release/sphincs-tz-nonsecure
FSBL_VENDOR_PUBKEY=$PWD/target/dev_vendor_pubkey.bin CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=--cmse-implib -C link-arg=--out-implib=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/secure -p sphincs-tz-secure --no-default-features --features $SFEAT || exit 1
rm -f $NE target/nonsecure/thumbv8m.main-none-eabi/release/deps/sphincs_tz_nonsecure-*
BENCH_RESIDUE=1 CARGO_TARGET_THUMBV8M_MAIN_NONE_EABI_RUSTFLAGS="$RF -C link-arg=$PWD/target/veneers.o" \
  cargo build --locked --release --target thumbv8m.main-none-eabi --target-dir target/nonsecure -p sphincs-tz-nonsecure --features bench-key-speed,stm32u585,board-pq1 || exit 1
probe-rs download --chip STM32U585CIUx $NE && probe-rs download --chip STM32U585CIUx $SE || exit 1
GO=0x$(arm-none-eabi-nm $NE | awk '/ RESIDUE_GO$/{print $1}'); ST=0x$(arm-none-eabi-nm $NE | awk '/ RESIDUE_LOCK_ST$/{print $1}')
echo "RESIDUE_GO=$GO RESIDUE_LOCK_ST=$ST"
probe-rs run --chip STM32U585CIUx $SE > $SP/residue-run.log 2>&1 &
P=$!
for i in $(seq 1 300); do grep -q "PARK stage=1" $SP/residue-run.log && break; sleep 1; done
T0=$(date +%s); kill -INT $P; wait $P 2>/dev/null
grep -E "\[NS\]" $SP/residue-run.log | tail -5
dump(){ timeout 120 STM32_Programmer_CLI -c port=SWD mode=HOTPLUG -u 0x30000000 0xC0000 $SP/sram-$1.bin -u 0x38020000 0x4000 $SP/sram4-$1.bin 2>&1 | grep -c "successfully"; }
echo "dump unlocked (t+$(( $(date +%s)-T0 ))s): $(dump unlocked)"
probe-rs write --chip STM32U585CIUx b32 $GO 1 2>&1 | tail -1; sleep 5
echo "LOCK_ST=$(probe-rs read --chip STM32U585CIUx b32 $ST 1 2>&1 | tail -1) (t+$(( $(date +%s)-T0 ))s)"
echo "dump locked: $(dump locked)"
echo "DHCSR=$(probe-rs read --chip STM32U585CIUx b32 0xE000EDF0 1 2>&1 | tail -1)"
