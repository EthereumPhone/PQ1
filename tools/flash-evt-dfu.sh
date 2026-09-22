#!/usr/bin/env bash
# flash-evt-dfu.sh — flash a PQ1 EVT (AL_A66_MB_V10, STM32U585CIU6) over its
# USB-C port using the STM32 ROM bootloader (USB DFU, VID:PID 0483:df11).
# No debug probe needed.
#
# HOW THE BOARD ENTERS DFU (schematic sheet 1 "POWER" + sheet 2 "Debug"):
#   BOOT0 (MCU pin 44) has a 10K pull-down (R121) and is driven ONLY by
#   U111 (NCP114 3V3 LDO) via R131 5.1K; U111's EN comes from the USB-C
#   SBU pins via R132 10K. A laptop never drives SBU on a non-PD sink, so
#   BOOT0 has to be pulled high by hand:
#       BOOT0  = TP103 pad  (or J211 pin 3)   <-- pull to 3.3 V
#       3.3 V  = J210 pin 1 (VTref, 10R to VDD3V3)   (verify with a meter)
#   Hold that connection WHILE plugging in USB-C. BOOT0 is sampled only at
#   reset, so once 0483:df11 enumerates the wire can be removed.
#
# ORDER MATTERS (silicon-verified 2026-09-21): the ROM bootloader runs NON-secure
# once TZEN=1 and then cannot write/read the secure bank (reads come back as
# zeros, the 0x0C000000 alias is rejected). So: regress TrustZone if it is on,
# write + verify both images with TZEN=0, and set TZEN=1 LAST (activation does
# not erase flash, RM0456 §3.5.6).
#
# Usage:
#   tools/flash-evt-dfu.sh <image-dir> [--erase] [--no-ob]
#     <image-dir> contains secure.bin (linked @0x0C000000 -> flashed @0x08000000)
#                 and nonsecure.bin (linked/flashed @0x08100000)
#     --erase     mass-erase first (recommended for the first flash over ODM
#                 test firmware: pages 123..127 hold PIN/journal state)
#     --no-ob     skip the TrustZone option-byte programming step
set -euo pipefail

IMG=${1:?usage: $0 <image-dir> [--erase] [--no-ob]}; shift || true
ERASE=0; DO_OB=1
for a in "$@"; do case $a in --erase) ERASE=1;; --no-ob) DO_OB=0;; *) echo "unknown arg $a" >&2; exit 2;; esac; done
[ -f "$IMG/secure.bin" ] && [ -f "$IMG/nonsecure.bin" ] || { echo "missing $IMG/{secure,nonsecure}.bin" >&2; exit 2; }

PROG=${STM32_PROG:-STM32_Programmer_CLI}
P="$PROG -c port=USB1"
S_ADDR=0x08000000   # bank 1, physical address of the 0x0C000000 secure alias
N_ADDR=0x08100000   # bank 2, non-secure
OB="TZEN=1 SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000"

strip() { sed -r 's/\x1b\[[0-9;]*[mK]//g'; }

wait_dfu() {
  if ! lsusb -d 0483:df11 >/dev/null; then
    cat <<'MSG'
==> No STM32 in DFU mode yet.
    1. Unplug USB-C.
    2. Connect BOOT0 (TP103 / J211 pin 3) to 3.3 V (J210 pin 1).
    3. Plug USB-C in while holding that connection.
    Waiting up to 120 s for 0483:df11 ...
MSG
    for i in $(seq 1 120); do lsusb -d 0483:df11 >/dev/null && break; sleep 1; done
    lsusb -d 0483:df11 >/dev/null || { echo "!! still no DFU device. If lsusb shows nothing at all the wire/pin is wrong; if the board boots its old firmware, nSWBOOT0 may be 0 (then only SWD on J210 can help)." >&2; exit 1; }
  fi
  echo "==> DFU device: $(lsusb -d 0483:df11)"
}

wait_dfu
echo "==> Option bytes before:"
$P -ob displ 2>&1 | strip | grep -E -i '^\s*(RDP|TZEN|nSWBOOT0|nBOOT0|BOOT_LOCK|SECWM1_PSTRT|SECWM1_PEND|SECWM2_PSTRT|SECWM2_PEND|SECBOOTADD0|WRP1A|WRP1B|WRP2A|WRP2B|SWAP_BANK)\b' | tee "$IMG/ob-before.txt" || true

# Anchor on the value line: the dump also contains "RDP Level 1 Password:" lines.
if grep -qE '^\s*RDP\s*:\s*0x(BB|CC)' "$IMG/ob-before.txt"; then
  echo "!! RDP is not level 0. Level 2 = unrecoverable. Level 1 -> regress (mass erase):"
  $P -ob RDP=0xAA 2>&1 | strip | tail -3
  sleep 3; wait_dfu
fi
if grep -qE 'TZEN\s*:\s*0x1' "$IMG/ob-before.txt"; then
  # With TZEN=1 the U5 ROM bootloader runs NON-secure: it cannot write (or read —
  # reads return zeros) the secure bank, so a secure image cannot be flashed in
  # this state. Regress first: RDP 0->1, then the "TrustZone disable" special
  # command (-tzenreg), which only works at RDP=1 (at RDP 0 it is a silent no-op).
  # This mass-erases flash. Silicon-verified 2026-09-21.
  echo "!! TZEN=1: regressing TrustZone (RDP 0->1 -> tzenreg -> RDP 0, mass erase)"
  $P -ob RDP=0xBB 2>&1 | strip | grep -E -i 'error|success' | tail -2; sleep 6; wait_dfu
  # At RDP=1 the programmer cannot read the OB dump at all (it warns "under Read
  # Out Protection" / "Fail to read NVM Size"), so the only FAILURE signature is
  # a dump that still says RDP 0xAA.
  if $P -ob displ 2>&1 | strip | grep -E '^\s*RDP\s' | grep -q '0xAA'; then echo "!! RDP=1 did not take — stop" >&2; exit 1; fi
  $P -tzenreg 2>&1 | strip | grep -E -i 'error|success' | tail -2; sleep 6; wait_dfu
  $P -ob displ 2>&1 | strip | grep -E -i '^\s*(RDP|TZEN)\b' | tee "$IMG/ob-after-regression.txt"
  grep -qE 'TZEN\s*:\s*0x0' "$IMG/ob-after-regression.txt" || { echo "!! TZEN still 1 after regression — stop" >&2; exit 1; }
  ERASE=0   # already mass-erased by the regression
fi
if grep -qE 'nSWBOOT0\s*:\s*0x0' "$IMG/ob-before.txt"; then
  echo "!! nSWBOOT0=0: BOOT0 pin is ignored; you got here via nBOOT0 instead. Will set nSWBOOT0=1 at the end so the pin works next time."
  OB="$OB nSWBOOT0=1"
fi

if [ $ERASE = 1 ]; then
  echo "==> Mass erase"
  $P -e all 2>&1 | strip | tail -3
  sleep 2; wait_dfu
fi

echo "==> Writing non-secure image @ $N_ADDR ($(stat -c%s "$IMG/nonsecure.bin") B)"
$P -w "$IMG/nonsecure.bin" $N_ADDR -v 2>&1 | strip | grep -E -i 'error|verif|download' | tail -4
echo "==> Writing secure image @ $S_ADDR ($(stat -c%s "$IMG/secure.bin") B)"
$P -w "$IMG/secure.bin" $S_ADDR -v 2>&1 | strip | grep -E -i 'error|verif|download' | tail -4

if [ $DO_OB = 1 ]; then
  # Two separate OB writes: SECWM*/SECBOOTADD0 do not exist (programmer warns
  # "does not exist") until TZEN=1 has been applied and the chip has reset.
  # After TZEN=1 the defaults are SECWM1 = whole bank 1 secure and SECBOOTADD0 =
  # 0x180000 (0x0C000000), but SECWM2 defaults to ALL SECURE — bank 2 must be
  # explicitly made non-secure (PSTRT > PEND = off). Silicon-verified 2026-09-21.
  echo "==> Programming TZEN=1 (chip resets; BOOT0 still high -> re-enters DFU)"
  $P -ob TZEN=1 2>&1 | strip | grep -E -i 'error|success|warning' | tail -3
  sleep 4; wait_dfu
  echo "==> Programming SECWM2 off + SECBOOTADD0"
  $P -ob SECWM2_PSTRT=0x7F SECWM2_PEND=0x0 SECBOOTADD0=0x180000 2>&1 | strip | grep -E -i 'error|success|warning' | tail -3
  sleep 4; wait_dfu
  $P -ob displ 2>&1 | strip | grep -E -i '^\s*(RDP|TZEN|SECWM1_PSTRT|SECWM1_PEND|SECWM2_PSTRT|SECWM2_PEND|SECBOOTADD0)\b'
fi

cat <<'MSG'
==> DONE. Unplug USB-C, make sure BOOT0 is no longer tied high, plug back in.
    Verify (optional, BOOT0 high again): tools/flash-evt-dfu.sh --check not implemented; use
      STM32_Programmer_CLI -c port=USB1 -ob displ
MSG
