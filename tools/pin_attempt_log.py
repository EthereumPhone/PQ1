#!/usr/bin/env python3
"""Read the device's PIN-attempt reason log (INS 0x03) and explain it.

WHY THIS EXISTS (#715): `gated_unlock` pre-charges the page-124 attempt counter
BEFORE the secure element judges the PIN, so the counter alone cannot tell a
legitimate wrong-PIN burn from a fault that burned an attempt without ever
reaching a verdict. A unit that locked out "on its own" is otherwise
undiagnosable, because shipping images omit `debug-log` (semihosting BKPT
hard-faults on a sealed unit).

READ THIS BEFORE POWER-CYCLING A SUSPECT UNIT. The log is RAM-resident: a reset
clears it. Power-cycling first is how the original investigation lost the
evidence.

Usage:
  tools/pin_attempt_log.py            # decode the log
  tools/pin_attempt_log.py --status   # also show locked state + remaining
  tools/pin_attempt_log.py --raw      # hex dump as well

Exit status: 0 if the log was read, 1 if a FAULT reason is present, 2 if the
device could not be read.
"""

from __future__ import annotations

import argparse
import sys
import time

from hid_smoke import HidRaw, find_hidraw, send

INS_GET_STATUS = 0x02
INS_GET_PIN_ATTEMPT_LOG = 0x03
SW_OK = 0x9000
LOG_LEN = 36  # proto::PIN_ATTEMPT_LOG_LEN

# secure/src/pin_attempt_log.rs::AttemptReason — a wire format; do not renumber.
REASONS = {
    0x01: ("ok+reset", "PIN correct, counter reset: no attempt consumed"),
    0x02: ("OK BUT RESET FAILED", "PIN correct, counter stayed charged — repeats walk to a lockout with the user doing nothing wrong"),
    0x03: ("wrong PIN", "the chip judged the PIN and rejected it; the burn is legitimate"),
    0x04: ("already at max", "short-circuited at MAX_ATTEMPTS; nothing burned, nothing wiped"),
    0x05: ("precharge failed", "the counter bump failed verification; the burn may or may not have landed"),
    0x06: ("no verdict", "SE leg failed before judging the PIN; burned fail-closed"),
    0x07: ("counter unstable", "two reads of the counter disagreed (FI)"),
    0x08: ("duress wipe", "a duress PIN triggered the configured wipe"),
}
# Reasons that indicate a DEFECT rather than a user error or a normal outcome.
FAULT_REASONS = {0x02, 0x05, 0x06, 0x07}


def read_with_retry(hid: HidRaw, ins: int, want_len: int, tries: int = 3):
    """Send `ins`, retrying transient timeouts.

    PendSV blocks the non-secure world while a PIN dialog is up, so USB does
    not answer during one, and the first read afterwards can land mid-APDU. One
    timeout is not a dead device.
    """
    last = None
    for attempt in range(1, tries + 1):
        try:
            sw, data = send(hid, ins, b"")
            if sw != SW_OK:
                last = f"SW=0x{sw:04x}"
            elif len(data) < want_len:
                last = f"short response: {len(data)} B < {want_len} B"
            else:
                return data
        except Exception as e:  # noqa: BLE001 - transport is allowed to be flaky here
            last = f"{type(e).__name__}: {e}"
        if attempt < tries:
            time.sleep(2)
    print(f"!! could not read INS 0x{ins:02x} after {tries} tries ({last})", file=sys.stderr)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--status", action="store_true", help="also show lock state + remaining attempts")
    ap.add_argument("--raw", action="store_true", help="hex dump the response")
    args = ap.parse_args()

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — device not enumerated.", file=sys.stderr)
        print("   Note USB comes up only AFTER the wizard and unlock, and a PIN", file=sys.stderr)
        print("   dialog blocks the non-secure world entirely.", file=sys.stderr)
        return 2
    print(f"== device: {node}")

    hid = HidRaw(node, 12.0)
    try:
        if args.status:
            d = read_with_retry(hid, INS_GET_STATUS, 2)
            if d is not None:
                print(f"   locked={d[0]}  remaining={d[1]}")

        data = read_with_retry(hid, INS_GET_PIN_ATTEMPT_LOG, LOG_LEN)
        if data is None:
            return 2
    finally:
        hid.close()

    if args.raw:
        print(f"   raw: {data[:LOG_LEN].hex()}")

    version, count = data[0], data[1]
    dropped = (data[2] << 8) | data[3]
    if version != 1:
        print(f"!! unknown log format version {version} — this tool decodes v1", file=sys.stderr)
        return 2

    print(f"\nPIN attempt log: {count} entr{'y' if count == 1 else 'ies'}, {dropped} dropped")
    if dropped:
        print("   NOTE: the ring wrapped, so the EARLIEST cause is gone — the entry")
        print("         that would say what started a lockout is the one lost first.")
    if count == 0:
        print("   (empty — no unlock attempt since this power cycle; remember the log is RAM-resident)")
        return 0

    faults = 0
    for i in range(count):
        reason = data[4 + i * 2]
        pre = data[5 + i * 2]
        name, why = REASONS.get(reason, (f"unknown 0x{reason:02x}", "not a reason this tool knows"))
        flag = ""
        if reason in FAULT_REASONS:
            faults += 1
            flag = "   <<< FAULT"
        print(f"  {i + 1:2d}. counter_before={pre:<3} {name}{flag}")
        print(f"      {why}")

    print()
    if faults:
        print(f"VERDICT: {faults} attempt(s) consumed by a FAULT, not by user error.")
        print("         A device can reach its lockout this way with the correct PIN")
        print("         entered every time. This is issue #715 territory — capture this")
        print("         output before power-cycling.")
        return 1
    print("VERDICT: every consumed attempt has a legitimate cause (wrong PIN, or none consumed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
