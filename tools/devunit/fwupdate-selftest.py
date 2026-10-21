#!/usr/bin/env python3
"""Refusal tests for the dev-unit USB update path (bench units only).

    tools/devunit/fwupdate-selftest.py <newer.pq1fw> <older-or-same.pq1fw>

Needs a bench image (PROFILE=bench: mock secure elements, auto-unlock and
auto-confirm), because every case below reaches the device's verifier without
a human at the screen. Each case must be REFUSED and must leave the running
release in place; the last line checks that. The newer package is never
committed — every case stops before or at COMMIT.

Cases:
  downgrade      an older (or equal) release            -> BEGIN 0x6A80
  bad-signature  one signature byte flipped, CRC fixed  -> BEGIN 0x6A80
  wrong-slot     the variant linked for the RUNNING slot -> COMMIT 0x6A80
  tampered       one secure-image byte flipped           -> COMMIT 0x6A80/0x6985
  abort          half the image, then FW_ABORT           -> nothing staged
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fwupdate as fu  # noqa: E402
from pq1fw import Package, version_label  # noqa: E402

OFF_SIGNATURE = 180
OFF_CRC32 = 8188


def recrc(m: bytearray) -> bytes:
    m[OFF_CRC32:] = (zlib.crc32(bytes(m[:OFF_CRC32])) & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(m)


def begin(dev: fu.Device, manifest: bytes) -> int:
    sw, _ = dev.chained(fu.INS_FW_BEGIN, manifest, timeout_s=120)
    return sw


def stream(dev: fu.Device, secure: bytes, nonsecure: bytes, stop_after: int | None = None) -> int:
    for kind, img in ((fu.KIND_SECURE, secure), (fu.KIND_NS, nonsecure)):
        off = 0
        while off < len(img):
            if stop_after is not None and off >= stop_after:
                return fu.SW_OK
            n = min(fu.CHUNK, len(img) - off)
            sw, _ = dev.apdu(fu.INS_FW_CHUNK, fu.P1_LAST, struct.pack(">IBBH", off, kind, 0, n) + img[off:off + n])
            if sw != fu.SW_OK:
                return sw
            off += n
    return fu.SW_OK


def main() -> None:
    newer = Package.load(sys.argv[1])
    older = Package.load(sys.argv[2])
    dev = fu.open_device()
    info = fu.device_info(dev)
    run_v, run_slot = info["fw_version"], info["slot"]
    inactive = "B" if run_slot == "A" else "A"
    print(f"device runs {version_label(run_v)} from slot {run_slot}")
    assert newer.fw_version > run_v, "first package must be newer than the running release"
    assert older.fw_version <= run_v, "second package must not be newer than the running release"
    results = []

    def case(name: str, ok: bool, detail: str) -> None:
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    sw = begin(dev, older.image(inactive, "manifest"))
    case("downgrade", sw == 0x6A80, f"BEGIN {older.label} -> 0x{sw:04X}")

    m = bytearray(newer.image(inactive, "manifest"))
    m[OFF_SIGNATURE + 100] ^= 0x01
    sw = begin(dev, recrc(m))
    case("bad-signature", sw == 0x6A80, f"BEGIN -> 0x{sw:04X}")

    # The variant linked for the RUNNING slot, streamed into the inactive one.
    wrong = run_slot
    sw = begin(dev, newer.image(wrong, "manifest"))
    if sw == fu.SW_OK:
        sw = stream(dev, newer.image(wrong, "secure"), newer.image(wrong, "nonsecure"))
        if sw == fu.SW_OK:
            sw, _ = dev.apdu(fu.INS_FW_COMMIT, fu.P1_LAST, b"", timeout_s=60)
    case("wrong-slot", sw == 0x6A80, f"slot-{wrong} build into slot {inactive}: -> 0x{sw:04X}")

    sec = bytearray(newer.image(inactive, "secure"))
    sec[len(sec) // 2] ^= 0x01
    sw = begin(dev, newer.image(inactive, "manifest"))
    if sw == fu.SW_OK:
        sw = stream(dev, bytes(sec), newer.image(inactive, "nonsecure"))
        if sw == fu.SW_OK:
            sw, _ = dev.apdu(fu.INS_FW_COMMIT, fu.P1_LAST, b"", timeout_s=60)
    case("tampered", sw in (0x6A80, 0x6985), f"COMMIT -> 0x{sw:04X}")

    sw = begin(dev, newer.image(inactive, "manifest"))
    if sw == fu.SW_OK:
        stream(dev, newer.image(inactive, "secure"), b"", stop_after=len(newer.image(inactive, "secure")) // 2)
        sw_abort, _ = dev.apdu(fu.INS_FW_ABORT, fu.P1_LAST, b"")
        sw, _ = dev.apdu(fu.INS_FW_COMMIT, fu.P1_LAST, b"", timeout_s=60)
        case("abort", sw_abort == fu.SW_OK and sw != fu.SW_OK, f"ABORT 0x{sw_abort:04X}, COMMIT after it -> 0x{sw:04X}")
    else:
        case("abort", False, f"BEGIN -> 0x{sw:04X}")

    info2 = fu.device_info(dev)
    dev.close()
    same = info2["fw_version"] == run_v and info2["slot"] == run_slot
    case("still running", same, f"{version_label(info2['fw_version'])} from slot {info2['slot']}")
    print("ALL PASS" if all(results) else "FAILURES")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
