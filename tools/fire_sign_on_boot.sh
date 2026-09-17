#!/usr/bin/env bash
# Fire the SIGN test the instant the board completes a FRESH boot.
#
# WHY THE "FRESH" MATTERS — this script's first version was wrong and
# produced a false negative. It waited for "a hidraw node matching our
# VID/PID exists", which was ALREADY TRUE: the previously wedged board
# stays enumerated (it just stops answering), so the watcher matched at
# t+0s and fired the sign into the same dead device it started against.
# Presence of a node is not an enumeration EVENT.
#
# So: record the device identity at arm time, require it to go ABSENT
# (the unplug), then require it to come back with a DIFFERENT devnum.
# Only a genuine re-enumeration satisfies that.
#
# WHY ANY OF THIS IS NEEDED: the reachable window is ~2-4 minutes wide and
# cannot be extended. `timeout::reset_activity()` responds only to physical
# button events; NS gateway traffic deliberately never refreshes it
# (secure_fi_pin_rng_pure_tests.rs:1665). Once `timeout::is_idle()` trips,
# SysTick (secure/src/main.rs:4090) pends PendSV, which loops on
# `enter_pin()` forever because that function has NO e2e-test
# short-circuit -- the CPU never returns to non-secure and USB goes silent.
# Every second of human latency after enumeration burns the window.
#
# The GET_DEVICE_INFO/GET_STATUS smoke test is deliberately SKIPPED: it
# already passed all 11 assertions. hid_sign.py's GET_WALLET_ADDRESS call
# doubles as the liveness gate.
#
# Usage: ./fire_sign_on_boot.sh [max_wait_seconds]   (default 900)

set -uo pipefail

S="$(cd "$(dirname "$0")" && pwd)"
MAX="${1:-900}"
VID=1209
PID=7051

# Print "<devnum> <sysfs-path>" for our device, or nothing if absent.
usb_identity() {
  local d
  for d in /sys/bus/usb/devices/*/; do
    [ -f "$d/idVendor" ] || continue
    if [ "$(cat "$d/idVendor" 2>/dev/null)" = "$VID" ] &&
       [ "$(cat "$d/idProduct" 2>/dev/null)" = "$PID" ]; then
      echo "$(cat "$d/devnum" 2>/dev/null) $d"
      return 0
    fi
  done
  return 1
}

find_node() {
  local d dir
  for d in /sys/class/hidraw/hidraw*/device/uevent; do
    [ -f "$d" ] || continue
    if grep -qi "HID_ID=0003:0000${VID}:0000${PID}" "$d" 2>/dev/null; then
      dir="$(dirname "$(dirname "$d")")"
      echo "/dev/$(basename "$dir")"
      return 0
    fi
  done
  return 1
}

t0=$(date +%s)
elapsed() { echo $(( $(date +%s) - t0 )); }

baseline="$(usb_identity || true)"
baseline_devnum="${baseline%% *}"
if [ -n "$baseline" ]; then
  echo "==> baseline: device present, devnum=${baseline_devnum} (this is the WEDGED one)"
  echo "    waiting for it to DISAPPEAR first -- a fresh devnum is the only accept signal"
else
  echo "==> baseline: no device present; waiting for first enumeration"
fi
echo "==> armed for up to ${MAX}s; power-cycle / replug the board now"
echo "    (boot to USB takes >300s: FSBL ~13s, then the e2e-test"
echo "     pre-clean -> wipe -> re-provision of BOTH secure elements,"
echo "     and usb_hw::init runs only after unlock)"

# Phase 1: require absence, but only if something was there to begin with.
if [ -n "$baseline" ]; then
  while usb_identity >/dev/null 2>&1; do
    if [ "$(elapsed)" -ge "$MAX" ]; then
      echo "!! device never disconnected within ${MAX}s -- was it replugged?"
      exit 3
    fi
    sleep 0.2
  done
  echo "==> DISCONNECTED at t+$(elapsed)s"
fi

# Phase 2: require a reappearance with a different devnum.
while :; do
  cur="$(usb_identity || true)"
  if [ -n "$cur" ]; then
    cur_devnum="${cur%% *}"
    if [ -z "$baseline" ] || [ "$cur_devnum" != "$baseline_devnum" ]; then
      echo "==> RE-ENUMERATED at t+$(elapsed)s, devnum=${cur_devnum} (was ${baseline_devnum:-none})"
      break
    fi
  fi
  if [ "$(elapsed)" -ge "$MAX" ]; then
    echo "!! no fresh enumeration within ${MAX}s"
    exit 2
  fi
  sleep 0.1
done

# The hidraw node is created slightly after the USB device appears, and
# udev applies 99-pqsigner.rules (MODE=0666) asynchronously after that.
node=""
for _ in $(seq 1 200); do
  if node="$(find_node)"; then
    [ -r "$node" ] && [ -w "$node" ] && break
  fi
  sleep 0.05
done
if [ -z "$node" ] || [ ! -w "$node" ]; then
  echo "!! hidraw node did not become writable (node='${node:-none}')"
  exit 2
fi

t_enum=$(date +%s)
echo "==> node ${node} writable; firing SIGN now"
echo

python3 "$S/hid_sign.py" --out "$S/sign_response.bin"
rc=$?

echo
echo "==> sign exit=${rc} at t+$(( $(date +%s) - t_enum ))s after enumeration"

if [ $rc -ne 0 ]; then
  # Distinguish "window closed mid-test" (enumerated but silent = the
  # PendSV wedge) from "device refused the command" (answers, non-OK SW).
  # These need different responses, and the SW is lost once the node dies.
  echo "==> post-mortem: does the device still answer?"
  ( cd "$S" && python3 -c "
import sys; sys.path.insert(0, '.')
from hid_smoke import find_hidraw, HidRaw, send, INS_GET_STATUS
n = find_hidraw()
print('    node:', n if n else '(de-enumerated)')
if n:
    h = HidRaw(n, 3.0)
    try:
        sw, d = send(h, INS_GET_STATUS)
        print(f'    ANSWERS: SW=0x{sw:04x} data={d.hex()} -> window still open,'
              f' so the failure was a REFUSAL, not the wedge')
    except Exception as e:
        print(f'    SILENT ({type(e).__name__}) -> wedged in secure PendSV;'
              f' the window closed mid-test')
    finally:
        h.close()
" ) 2>&1 || true
fi
exit $rc
