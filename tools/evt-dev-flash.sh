#!/usr/bin/env bash
# evt-dev-flash.sh — UI-iteration loop for a sealed pq1 EVT over USB-C ROM DFU.
#
#   tools/evt-dev-flash.sh            # build dev image (real SEs + LCD + dev-dfu), then flash
#   tools/evt-dev-flash.sh --no-build # flash the last built dev image
#
# Getting the board into DFU without a cable: with a `dev-dfu` image on it,
# HOLD BOTH BUTTONS while plugging the USB-C in; the firmware clears
# nSWBOOT0/nBOOT0 and reloads option bytes, and the chip re-enumerates as
# 0483:df11. (The SBU-bridged cable still works too, if you have one.)
#
# Why no TrustZone regression here: the ROM bootloader runs non-secure when
# TZEN=1 and cannot touch the secure bank. Instead of regressing TZEN (RDP
# 0->1->0, mass erase) this script temporarily marks bank 1 NON-secure
# (SECWM1_PSTRT=0x7F > SECWM1_PEND=0x0), writes + verifies both images,
# then restores SECWM1 = whole bank 1 secure. TZEN, RDP, SECBOOTADD0 and
# SECWM2 are never touched. Last step restores nSWBOOT0=1 nBOOT0=1, which
# boots flash (and keeps the BOOT0-pin path usable as a rescue).
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=1
for a in "$@"; do case $a in --no-build) BUILD=0;; *) echo "unknown arg $a" >&2; exit 2;; esac; done

T=thumbv8m.main-none-eabi
IMG=evt-images/dev
FEAT_S="dual-se,dev-testkey,ui-lcd,dev-dfu,stm32u585,usb,board-pq1"
P="STM32_Programmer_CLI -c port=USB1"
strip() { sed -r 's/\x1b\[[0-9;]*[mK]//g'; }
cur() { { lsusb -d 0483:df11 2>/dev/null || true; } | { grep -o 'Bus [0-9]* Device [0-9]*' || true; } | head -1; }
wait_dfu() {
  # $1 = label; waits for a DFU enumeration DIFFERENT from $OLD (or any, if OLD empty)
  for i in $(seq 1 900); do
    d=$(cur)
    if [ -n "$d" ] && [ "$d" != "${OLD:-}" ]; then echo "[$1] DFU: $d"; OLD=$d; sleep 2; return 0; fi
    sleep 1
  done
  echo "[$1] TIMEOUT waiting for DFU" >&2; exit 1
}
ob() { $P -ob displ 2>&1 | strip | grep -E '^\s*(RDP|TZEN|nSWBOOT0|nBOOT0|SECWM1_PSTRT|SECWM1_PEND|SECWM2_PSTRT|SECWM2_PEND|SECBOOTADD0)\s'; }

if [ $BUILD = 1 ]; then
  echo "==> building dev image: $FEAT_S"
  make -n build-hw-dual-se-lcd-standalone BOARD=pq1 \
    | grep -B1 -A3 'cargo build' | grep -v -E '^--$|probe-rs|^echo' \
    | sed -e "s/dual-se,optiga-hw-counter,dev-testkey,ui-lcd,stm32u585,usb,board-pq1/$FEAT_S/" \
    > $IMG.cmds.sh
  grep -q -- "--features $FEAT_S" $IMG.cmds.sh || { echo "!! feature substitution failed; see $IMG.cmds.sh" >&2; exit 1; }
  bash -e $IMG.cmds.sh > $IMG.build.log 2>&1 || { grep -n -A12 '^error' $IMG.build.log | head -60; exit 1; }
  mkdir -p $IMG
  cp target/secure/$T/release/sphincs-tz-secure $IMG/secure.elf
  cp target/nonsecure/$T/release/sphincs-tz-nonsecure $IMG/nonsecure.elf
  arm-none-eabi-objcopy -O binary $IMG/secure.elf $IMG/secure.bin
  arm-none-eabi-objcopy -O binary $IMG/nonsecure.elf $IMG/nonsecure.bin
  echo "$(git rev-parse --short HEAD) $FEAT_S" > $IMG/FEATURES.txt
  echo "==> built: $(stat -c%s $IMG/secure.bin) B secure, $(stat -c%s $IMG/nonsecure.bin) B nonsecure; dev-dfu linked: $(arm-none-eabi-nm -C $IMG/secure.elf | grep -c dev_dfu)"
fi
[ -f $IMG/secure.bin ] && [ -f $IMG/nonsecure.bin ] || { echo "no image in $IMG" >&2; exit 1; }

cat <<'MSG'
==> Put the EVT into DFU now:
      no cable:   HOLD BOTH BUTTONS, then plug USB-C in (dev-dfu image required)
      with cable: plug in through the SBU-bridged adapter
    waiting for 0483:df11 ...
MSG
OLD=""; wait_dfu start
echo "==> option bytes:"; ob | tee $IMG/ob-before.txt
grep -qE '^\s*RDP\s*:\s*0xAA' $IMG/ob-before.txt || { echo "!! RDP not level 0 — stop" >&2; exit 1; }
grep -qE '^\s*TZEN\s*:\s*0x1' $IMG/ob-before.txt || { echo "!! TZEN=0 — this script assumes the TZEN=1 layout; use tools/flash-evt-dfu.sh" >&2; exit 1; }

echo "==> bank 1 temporarily NON-secure (so the NS bootloader can write/verify it)"
$P -ob SECWM1_PSTRT=0x7F SECWM1_PEND=0x0 2>&1 | strip | grep -E -i 'rror|success' | tail -2
sleep 5; wait_dfu after-secwm1-off
ob | grep -E 'SECWM1'

# With TZEN=1 the programmer classifies the aliases as "Not flash Memory" and
# skips its per-write erase, so a download over old contents can only clear
# bits — verify then fails (seen 2026-09-21 at 0x0810432C). Erase explicitly
# now that both banks are non-secure to the bootloader.
echo "==> mass erase"
$P -e all 2>&1 | strip | grep -E -i 'rror|erase' | tail -1
sleep 3; lsusb -d 0483:df11 >/dev/null || wait_dfu after-erase

# The bootloader occasionally fails a download with "failed to download
# Sector[0]" right after an erase/OB reload (seen 2026-09-21); a retry on the
# same enumeration succeeds, so try each write up to 3 times.
write_verified() {  # $1 = file, $2 = address
  for attempt in 1 2 3; do
    if $P -w "$1" "$2" -v 2>&1 | strip | grep -q 'Download verified successfully'; then echo "  verified ($1 @ $2, attempt $attempt)"; return 0; fi
    echo "  attempt $attempt failed for $1 — retrying"; sleep 3
    lsusb -d 0483:df11 >/dev/null || wait_dfu retry
  done
  echo "!! $1 could not be written after 3 attempts — chip left in DFU with bank 1 non-secure; re-run" >&2; exit 1
}
echo "==> write NS @0x08100000 + verify"; write_verified $IMG/nonsecure.bin 0x08100000
echo "==> write S @0x08000000 + verify";  write_verified $IMG/secure.bin 0x08000000
$P -u 0x08000000 0x10 $IMG/rb-s.bin >/dev/null 2>&1; $P -u 0x08100000 0x10 $IMG/rb-ns.bin >/dev/null 2>&1
cmp -n 16 $IMG/rb-s.bin $IMG/secure.bin && echo "S head OK" || { echo "!! S head mismatch — chip left in DFU with bank 1 non-secure; re-run" >&2; exit 1; }
cmp -n 16 $IMG/rb-ns.bin $IMG/nonsecure.bin && echo "NS head OK" || { echo "!! NS head mismatch — re-run" >&2; exit 1; }

echo "==> bank 1 back to secure"
$P -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F 2>&1 | strip | grep -E -i 'rror|success' | tail -2
sleep 5; wait_dfu after-secwm1-on
ob | tee $IMG/ob-after.txt
grep -qE '^\s*SECWM1_PSTRT\s*:\s*0x0\b' $IMG/ob-after.txt && grep -qE '^\s*SECWM1_PEND\s*:\s*0x7F' $IMG/ob-after.txt || { echo "!! SECWM1 not restored — do NOT boot; re-run" >&2; exit 1; }

echo "==> boot from flash: nSWBOOT0=1 nBOOT0=1 (pin path kept; with the SBU cable attached the chip stays in DFU until you unplug it)"
# When DFU was entered by software (nSWBOOT0=0), this OB reload boots FLASH
# immediately, so the chip leaves the bus mid-command and the programmer
# reports "Downloading Option Bytes Data failed / Uploading Option Bytes bank:
# 0 failed" even though the write took (2026-09-21). "Success" or "unchanged"
# appear only when the SBU cable keeps the chip in DFU. Either way: check the
# LCD — the wallet does not enumerate on USB until it is unlocked.
$P -ob nSWBOOT0=1 nBOOT0=1 2>&1 | strip | grep -E -i 'rror|success|unchanged' | tail -2 || true
sleep 3
if lsusb -d 0483:df11 >/dev/null 2>&1; then
  echo "==> still in DFU (SBU cable attached, or the OB write did not take): checking boot bits"
  $P -ob displ 2>&1 | strip | grep -E '^\s*(nSWBOOT0|nBOOT0)\s' || true
  echo "    if they read 0x0/0x0, re-run just this step: $P -ob nSWBOOT0=1 nBOOT0=1"
else
  echo "==> chip left DFU: it is booting the new image (look at the LCD)."
fi
echo "==> DONE"
