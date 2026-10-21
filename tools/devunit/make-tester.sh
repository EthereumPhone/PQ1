#!/usr/bin/env bash
# make-tester.sh — turn a DVT into a tester unit: wait for it in ROM DFU, then
# flash the investor release and leave it at RDP 1.
#
#   tools/devunit/make-tester.sh [<release-dir>]      # default: newest investor release
#   YES=1 tools/devunit/make-tester.sh                # skip the wipe confirmation
#
# Arms a listener for the ROM DFU bootloader (0483:df11) and, the moment the
# unit shows up, runs `flash.sh <release> --dfu --erase-all --regress`:
# RDP 1 -> 0 if the unit is already locked, mass erase, FSBL + slot A, the
# dev-unit option bytes, and RDP=0xBB in the last write. Every wallet on the
# unit is gone; the tester sets up a new one with the setup wizard.
#
# Only an `investor` release built with `devunit-die-keys` is accepted: that
# is what makes flash.sh set RDP 1, and a tester unit at RDP 0 would show
# NOT LOCKED and halt.
#
# Enter DFU: hold BOTH buttons while plugging in USB-C, keep holding ~8 s
# (through the fingerprint). Or use the SBU-bridged adapter.
set -euo pipefail
cd "$(dirname "$0")/../.."

REL=${1:-}
if [ -z "$REL" ]; then
  REL=$(ls -d target/devunit/releases/investor-* 2>/dev/null | sort -V | tail -1 || true)
  [ -n "$REL" ] || { echo "no investor release under target/devunit/releases — run: make devunit-release" >&2; exit 2; }
fi
[ -f "$REL/RELEASE.txt" ] || { echo "missing $REL/RELEASE.txt" >&2; exit 2; }
for f in fsbl.bin manifest-a.bin secure-a.bin nonsecure-a.bin; do
  [ -f "$REL/factory/$f" ] || { echo "missing $REL/factory/$f" >&2; exit 2; }
done
grep -q '^secure:.*devunit-die-keys' "$REL/RELEASE.txt" \
  || { echo "!! $REL is not a devunit-die-keys release: flash.sh would leave it at RDP 0. Use an investor release." >&2; exit 2; }

VER=$(sed -n '1s/^PQ1 dev-unit firmware \([^ ]*\).*/\1/p' "$REL/RELEASE.txt")
WORDS=$(awk '/^--- slot A build ---/{a=1;next} /^--- slot B build ---/{a=0} a && /^ +[0-9] /{printf "%s ", $2}' "$REL/RELEASE.txt")
echo "==> tester unit from $REL"
echo "    release $VER, slot A words: $WORDS"
echo "    ERASES ALL FLASH on the unit (any wallet on it is gone), ends at RDP 1"
if [ "${YES:-}" != 1 ]; then
  read -r -p "    Type YES to arm the listener: " ans
  [ "$ans" = YES ] || { echo "aborted"; exit 1; }
fi

if ! lsusb -d 0483:df11 >/dev/null 2>&1; then
  echo "==> listening for the ROM DFU bootloader (0483:df11) — hold BOTH buttons while plugging in, keep holding ~8 s"
  until lsusb -d 0483:df11 >/dev/null 2>&1; do sleep 0.5; done
fi
echo "==> DFU device detected — flashing"
tools/devunit/flash.sh "$REL" --dfu --erase-all --regress

cat <<EOF

==> Flashed $VER. Acceptance check before it ships:
    1. Unplug and replug (the first boot after the option-byte write can leave the panel black).
    2. The FSBL shows: $WORDS
    3. The setup wizard appears. NOT LOCKED / NEEDS RDP 1 means RDP 1 did not take: run this again.
    Do not set up a wallet if the tester should do it; the wizard is what they see first.
EOF
