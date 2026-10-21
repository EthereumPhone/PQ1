#!/usr/bin/env bash
# flash.sh — first-flash a pq1 DEV UNIT with a dev-unit release (devunit-ab).
#
#   tools/devunit/flash.sh <release-dir> --dfu [--erase-all]   # USB-C, ROM DFU
#   tools/devunit/flash.sh <release-dir> --swd [--erase-all]   # ST-LINK on J210
#
# <release-dir> is target/devunit/releases/<profile>-<version> from
# tools/devunit/release.sh. Writes the FSBL, manifest A and the slot-A images,
# erases manifest B and the boot log, and programs the dev-unit option bytes:
#
#   TZEN=1, SECWM1 = bank 1 all secure (0x00..0x7F),
#   SECWM2 = 0x30..0x7F (bank-2 pages 48..127 = secure slot B),
#   SECBOOTADD0 = 0x180000 (the FSBL at 0x0C000000), nSWBOOT0=1, nBOOT0=1.
#
# Nothing irreversible: RDP stays 0xAA, no WRP, no OTP. After this, updates
# go over USB with tools/devunit/fwupdate.py — this script is only for the
# first flash (or a recovery).
#
# Erase: by default only what the layout owns is erased — bank 1 pages 0..86
# and all of bank 2 — so bank-1 pages 123..127 (the wallet's PIN counter, PIN
# salt, off-chain counters) survive and an existing wallet keeps working.
# --erase-all mass-erases instead: use it for a blank unit or one carrying
# foreign firmware (ODM test image), never on a unit whose wallet matters.
#
# DFU entry on a sealed unit: a `dev-dfu` image enters the ROM bootloader when
# BOTH buttons are held while plugging in USB-C; otherwise use the SBU-bridged
# USB-C adapter (docs/hardware/evt-dev-loop.md). With TZEN=1 the ROM
# bootloader runs non-secure, so the watermarks are opened for the writes and
# closed again at the end (the evt-dev-flash.sh method; no RDP excursion).
set -euo pipefail
cd "$(dirname "$0")/../.."

REL=${1:?usage: $0 <release-dir> --dfu|--swd [--erase-all]}; shift
MODE=""; ERASE_ALL=0
for a in "$@"; do case $a in --dfu) MODE=dfu;; --swd) MODE=swd;; --erase-all) ERASE_ALL=1;; *) echo "unknown arg $a" >&2; exit 2;; esac; done
[ -n "$MODE" ] || { echo "choose --dfu or --swd" >&2; exit 2; }
F=$REL/factory
for f in fsbl.bin manifest-a.bin secure-a.bin nonsecure-a.bin; do
  [ -f "$F/$f" ] || { echo "missing $F/$f" >&2; exit 2; }
done

PROG=${STM32_PROG:-STM32_Programmer_CLI}
LOG=$REL/flash-$MODE-$(date +%Y%m%d-%H%M%S).log
strip() { sed -r 's/\x1b\[[0-9;]*[mK]//g'; }
say() { echo "==> $*" | tee -a "$LOG"; }

if [ $MODE = dfu ]; then
  P="$PROG -c port=USB1"
  # Everything is written through the NON-SECURE aliases while the
  # watermarks are open: bank 1 at 0x08000000, bank 2 at 0x08100000.
  A_FSBL=0x08000000; A_MAN_A=0x08008000; A_SEC_A=0x0800E000; A_NS_A=0x08100000
  cur() { { lsusb -d 0483:df11 2>/dev/null || true; } | { grep -o 'Bus [0-9]* Device [0-9]*' || true; } | head -1; }
  wait_link() {
    for i in $(seq 1 120); do
      d=$(cur)
      if [ -n "$d" ] && [ "$d" != "${OLD:-}" ]; then OLD=$d; sleep 2; return 0; fi
      sleep 1
    done
    echo "!! no DFU device (0483:df11) — hold BOTH buttons while plugging USB-C in (dev-unit images: keep holding ~8 s), or use the SBU adapter" >&2; exit 1
  }
  OLD=""; say "waiting for the ROM DFU bootloader (0483:df11)"; wait_link
else
  P="$PROG -c port=SWD mode=UR"
  # The debugger is a secure master: bank-1 images go to their secure alias,
  # the non-secure image to its own alias.
  A_FSBL=0x0C000000; A_MAN_A=0x0C008000; A_SEC_A=0x0C00E000; A_NS_A=0x08100000
  wait_link() { sleep 2; }
fi

ob() { $P -ob displ 2>&1 | strip | grep -E '^\s*(RDP|TZEN|nSWBOOT0|nBOOT0|SWAP_BANK|SECWM1_PSTRT|SECWM1_PEND|SECWM2_PSTRT|SECWM2_PEND|SECBOOTADD0|BOOT_LOCK|SRAM_RST)\s'; }
field() { grep -E "^\s*$1\s*:" "$2" | head -1 | sed -E 's/^[^:]*:\s*(0x[0-9A-Fa-f]+).*/\1/'; }
obwrite() {  # program option bytes; the chip resets and (DFU) re-enumerates
  say "option bytes: $*"
  $P -ob "$@" 2>&1 | strip | tee -a "$LOG" | grep -E -i 'rror|success|unchanged' | tail -2 || true
  sleep 5; wait_link
}

say "option bytes before:"; ob | tee "$REL/ob-before-$MODE.txt" | tee -a "$LOG"
[ "$(field RDP "$REL/ob-before-$MODE.txt")" = "0xAA" ] || { echo "!! RDP is not level 0 — stop (see tools/flash-evt-dfu.sh for regression)" >&2; exit 1; }
[ "$(field SWAP_BANK "$REL/ob-before-$MODE.txt")" = "0x0" ] || { echo "!! SWAP_BANK set — stop" >&2; exit 1; }
TZEN=$(field TZEN "$REL/ob-before-$MODE.txt")

if [ $MODE = dfu ] && [ "$TZEN" = "0x1" ]; then
  # The non-secure ROM bootloader can only reach non-secure pages.
  obwrite SECWM1_PSTRT=0x7F SECWM1_PEND=0x0 SECWM2_PSTRT=0x7F SECWM2_PEND=0x0
fi

if [ $ERASE_ALL = 1 ]; then
  say "mass erase"
  $P -e all 2>&1 | strip | tee -a "$LOG" | grep -E -i 'rror|erase' | tail -1
  sleep 3; [ $MODE = swd ] || { lsusb -d 0483:df11 >/dev/null || wait_link; }
else
  # Bank 1 pages 0..86 (FSBL, manifests, boot log, secure slot A) and bank 2
  # (both non-secure slots, secure slot B). Pages 87..127 of bank 1 are kept.
  say "erase bank 1 pages 0-86 and bank 2 (keeps bank-1 pages 87-127: wallet state)"
  $P -e [0 86] 2>&1 | strip | tee -a "$LOG" | grep -E -i 'rror|erase' | tail -1
  $P -e [128 255] 2>&1 | strip | tee -a "$LOG" | grep -E -i 'rror|erase' | tail -1
fi

write_verified() {  # $1 file, $2 address
  for attempt in 1 2 3; do
    if $P -w "$1" "$2" -v 2>&1 | strip | tee -a "$LOG" | grep -q 'Download verified successfully'; then
      say "  verified $(basename "$1") @ $2"; return 0
    fi
    say "  attempt $attempt failed for $(basename "$1") — retrying"; sleep 3
    [ $MODE = swd ] || { lsusb -d 0483:df11 >/dev/null || wait_link; }
  done
  echo "!! $1 could not be written — re-run (the unit is still in the bootloader)" >&2; exit 1
}
say "write images"
write_verified "$F/nonsecure-a.bin" $A_NS_A
write_verified "$F/secure-a.bin" $A_SEC_A
write_verified "$F/manifest-a.bin" $A_MAN_A
write_verified "$F/fsbl.bin" $A_FSBL

# Final option bytes. With TZEN=0 the watermark fields only exist after TZEN=1
# has been applied and the chip reset (and TZEN=1 defaults SECWM2 to ALL
# secure), so that is a separate step.
if [ "$TZEN" != "0x1" ]; then
  obwrite TZEN=1
fi
obwrite SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x30 SECWM2_PEND=0x7F SECBOOTADD0=0x180000

say "option bytes after:"; ob | tee "$REL/ob-after-$MODE.txt" | tee -a "$LOG"
A=$REL/ob-after-$MODE.txt
ok=1
[ "$(field TZEN "$A")" = "0x1" ] || ok=0
[ "$(field SECWM1_PSTRT "$A")" = "0x0" ] && [ "$(field SECWM1_PEND "$A")" = "0x7F" ] || ok=0
[ "$(field SECWM2_PSTRT "$A")" = "0x30" ] && [ "$(field SECWM2_PEND "$A")" = "0x7F" ] || ok=0
[ "$(field SECBOOTADD0 "$A")" = "0x180000" ] || ok=0
[ $ok = 1 ] || { echo "!! option bytes are not the dev-unit profile — re-run before booting" >&2; exit 1; }

if [ $MODE = dfu ]; then
  # Leaving software-DFU: this reload boots flash at once, so the programmer
  # usually reports a failed read-back even though the write took.
  say "boot from flash: nSWBOOT0=1 nBOOT0=1"
  $P -ob nSWBOOT0=1 nBOOT0=1 2>&1 | strip | tee -a "$LOG" | grep -E -i 'rror|success|unchanged' | tail -2 || true
  sleep 3
  if lsusb -d 0483:df11 >/dev/null 2>&1; then
    say "still in DFU (SBU adapter attached?) — unplug it and plug the unit in normally"
  fi
else
  $PROG -c port=SWD mode=HOTPLUG -rst 2>&1 | strip | tail -1 | tee -a "$LOG" || true
fi
say "DONE — the unit boots the FSBL (8 fingerprint words), then the release. Log: $LOG"
