#!/usr/bin/env python3
"""Smoke-test the live USB HID APDU dispatcher on a flashed pq1 board.

Sends the two cheapest v2 commands — GET_DEVICE_INFO (0x01) and
GET_STATUS (0x02) — and validates every field of the reply against
constants read out of the firmware source, rather than eyeballing bytes.

WHY VALIDATE RATHER THAN PRINT: an unvalidated probe read has produced
false findings here before. GET_DEVICE_INFO's reply is almost entirely
deterministic (protocol version, a 16-byte zero UID placeholder, the
capability word, the parameter-set tag, both signature lengths and the
EntryPoint version), so it doubles as a known-positive for the HID
framing itself. If these fields land, the framing is right. If the
device is silent, that is NOT evidence the dispatcher is dead — it is
evidence this script got no answer, and the framing must be proven
some other way before drawing any conclusion.

Transport is lifted verbatim from tools/fwup-transport-test.py (same
VID/PID, same channel, same tag, same implicit report-ID byte).

No external dependencies; /dev/hidrawN is mode 0666 via
tools/99-pqsigner.rules.
"""
from __future__ import annotations

import glob
import os
import select
import sys

# --- wire constants (tools/fwup-transport-test.py, proto/src/lib.rs) -------
VID, PID = 0x1209, 0x7051
APDU_CLA_V2 = 0xF0
HID_REPORT_SIZE = 64
HID_TAG_APDU = 0x05
HID_FIRST_DATA = HID_REPORT_SIZE - 7
HID_CONT_DATA = HID_REPORT_SIZE - 5
CHANNEL_ID = 0x0001
P1_LAST = 0x00
SW_OK = 0x9000

INS_GET_DEVICE_INFO = 0x01
INS_GET_STATUS = 0x02

# --- expected values (proto/src/lib.rs, nonsecure/src/usb/commands.rs) ----
PROTOCOL_VERSION = 0x0202          # :1833
CAP_SIGN_USEROP = 1 << 0           # :798
CAP_ERC7730_PROOF_SET = 1 << 2     # :803
DEVICE_CAPABILITIES = CAP_SIGN_USEROP | CAP_ERC7730_PROOF_SET  # :805 -> 0x5
SIG_PARAM_SET_C10 = 2              # commands.rs:416
SIG_TYPE2_LEN = 4128               # SIG_WRAPPER_LEN :905
SIG_TYPE2_HEADER_LEN = 96          # :925
EP_VERSION = 0x0006                # commands.rs:429


def find_hidraw() -> str | None:
    want = f"{VID:08X}:{PID:08X}".lower()
    for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
        try:
            with open(uevent) as fh:
                body = fh.read().lower()
        except OSError:
            continue
        if f"hid_id=0003:{want}" in body.replace(" ", ""):
            d = os.path.dirname(os.path.dirname(uevent))
            return f"/dev/{os.path.basename(d)}"
    return None


class HidRaw:
    def __init__(self, path: str, timeout_s: float = 5.0) -> None:
        self.fd = os.open(path, os.O_RDWR)
        self.timeout_s = timeout_s

    def write(self, frame: bytes) -> None:
        assert len(frame) == HID_REPORT_SIZE
        # Implicit report-ID byte: the descriptor uses none, but the
        # kernel's hidraw write path still expects it and strips it.
        os.write(self.fd, b"\x00" + frame)

    def read_frame(self) -> bytes:
        r, _, _ = select.select([self.fd], [], [], self.timeout_s)
        if not r:
            raise TimeoutError(f"no HID report within {self.timeout_s}s")
        return os.read(self.fd, HID_REPORT_SIZE)

    def close(self) -> None:
        os.close(self.fd)


def frame_apdu(apdu: bytes) -> list[bytes]:
    frames = []
    first = bytearray(HID_REPORT_SIZE)
    first[0] = (CHANNEL_ID >> 8) & 0xFF
    first[1] = CHANNEL_ID & 0xFF
    first[2] = HID_TAG_APDU
    first[3] = first[4] = 0x00
    first[5] = (len(apdu) >> 8) & 0xFF
    first[6] = len(apdu) & 0xFF
    n = min(HID_FIRST_DATA, len(apdu))
    first[7 : 7 + n] = apdu[:n]
    frames.append(bytes(first))
    off, seq = n, 1
    while off < len(apdu):
        f = bytearray(HID_REPORT_SIZE)
        f[0] = (CHANNEL_ID >> 8) & 0xFF
        f[1] = CHANNEL_ID & 0xFF
        f[2] = HID_TAG_APDU
        f[3] = (seq >> 8) & 0xFF
        f[4] = seq & 0xFF
        c = min(HID_CONT_DATA, len(apdu) - off)
        f[5 : 5 + c] = apdu[off : off + c]
        frames.append(bytes(f))
        off += c
        seq += 1
    return frames


def read_response(hid: HidRaw) -> tuple[int, bytes]:
    buf, expected, seq = bytearray(), 0, 0
    while True:
        frame = hid.read_frame()
        if len(frame) < 3 or frame[2] != HID_TAG_APDU:
            print(f"  [hid] dropping non-APDU frame tag=0x{frame[2]:02x}")
            continue
        r_seq = (frame[3] << 8) | frame[4]
        if r_seq != seq:
            raise IOError(f"seq mismatch: want {seq}, got {r_seq}")
        if seq == 0:
            expected = (frame[5] << 8) | frame[6]
            off, chunk = 7, min(HID_FIRST_DATA, expected)
        else:
            off, chunk = 5, min(HID_CONT_DATA, expected - len(buf))
        buf.extend(frame[off : off + chunk])
        seq += 1
        if len(buf) >= expected:
            break
    resp = bytes(buf[:expected])
    if len(resp) < 2:
        raise IOError(f"response too short: {len(resp)} B")
    return (resp[-2] << 8) | resp[-1], resp[:-2]


def send(hid: HidRaw, ins: int, data: bytes = b"") -> tuple[int, bytes]:
    apdu = bytes([APDU_CLA_V2, ins, P1_LAST, 0x00, len(data)]) + data
    for f in frame_apdu(apdu):
        hid.write(f)
    return read_response(hid)


FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    g = f"0x{got:x}" if isinstance(got, int) else got.hex() if isinstance(got, bytes) else got
    w = f"0x{want:x}" if isinstance(want, int) else want.hex() if isinstance(want, bytes) else want
    print(f"    {'OK  ' if ok else 'FAIL'}  {label:<22} got={g} want={w}")
    if not ok:
        FAILURES.append(f"{label}: got {g}, want {w}")


def main() -> int:
    path = find_hidraw()
    if path is None:
        print("!! no PQSigner hidraw node found (is the board attached?)")
        return 2
    print(f"==> device node: {path}")

    hid = HidRaw(path)
    try:
        print("\n==> INS 0x01 GET_DEVICE_INFO")
        sw, d = send(hid, INS_GET_DEVICE_INFO)
        print(f"    SW=0x{sw:04x}  data={len(d)} B")
        print(f"    raw: {d.hex()}")
        check("SW", sw, SW_OK)
        check("data length", len(d), 40)
        if len(d) == 40:
            check("protocol_version", int.from_bytes(d[0:2], "big"), PROTOCOL_VERSION)
            print(f"    ..    fw_version            = {d[2]}.{d[3]}.{d[4]}  (not asserted)")
            check("device_uid (16 zeros)", d[5:21], bytes(16))
            check("capabilities", int.from_bytes(d[21:25], "big"), DEVICE_CAPABILITIES)
            check("sig_param_set", d[25], SIG_PARAM_SET_C10)
            check("sig_type2_len", int.from_bytes(d[26:28], "big"), SIG_TYPE2_LEN)
            check("legacy zeros [28:36]", d[28:36], bytes(8))
            check("ep_version", int.from_bytes(d[36:38], "big"), EP_VERSION)
            check("type2_header_len", int.from_bytes(d[38:40], "big"), SIG_TYPE2_HEADER_LEN)

        print("\n==> INS 0x02 GET_STATUS")
        sw, d = send(hid, INS_GET_STATUS)
        print(f"    SW=0x{sw:04x}  data={len(d)} B  raw={d.hex()}")
        check("SW", sw, SW_OK)
        check("data length", len(d), 2)
        if len(d) == 2:
            # commands.rs:462 — byte0 is 0 when UNLOCKED, 1 when locked.
            print(f"    ..    locked_flag           = {d[0]} "
                  f"({'UNLOCKED' if d[0] == 0 else 'LOCKED'})")
            print(f"    ..    remaining_attempts    = {d[1]}")
            # e2e-test pre-unlocks the secure world; signing needs this.
            check("unlocked (e2e pre-unlock)", d[0], 0)
    except TimeoutError as e:
        print(f"\n!! TIMEOUT: {e}")
        print("!! This means THIS SCRIPT got no answer. It is NOT by itself")
        print("!! evidence the dispatcher is dead — the framing is unproven")
        print("!! until at least one command round-trips.")
        return 2
    finally:
        hid.close()

    print()
    if FAILURES:
        print(f"=== FAIL === {len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("=== PASS === framing validated; dispatcher live; secure world unlocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
