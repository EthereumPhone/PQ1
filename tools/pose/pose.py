#!/usr/bin/env python3
"""Host side of the PQ1 proof-of-secure-erasure experiment.

Design: docs/security/user-device-verification.md § USB path.
Protocol and procedure: tools/pose/README.md.

    pose.py info
    pose.py fill    --session DIR
    (unplug the device AND the ST-LINK, wait, replug USB-C)
    pose.py verify  --session DIR --image tools/pose/prover/prover-padded.bin
    pose.py pad     IN.bin OUT.bin
    pose.py slack   --image tools/pose/prover/prover-padded.bin

No dependencies beyond the standard library: talks to /dev/hidraw directly,
like tools/hid_smoke.py.
"""

import argparse
import glob
import json
import os
import random
import secrets
import select
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

HID_ID = "0003:00001209:00007051"
PRODUCT = "PoSE prover"
MAGIC = b"PQPOSE01"
PAGE = 0x2000
FLASH_LEN = 2 * 128 * PAGE
READ_DATA = 56
WRITE_DATA = 48
MAX_REPORTS = 64
OTP_FREE = range(176, 512)  # secure/src/hw/otp.rs

SP_FLASH, SP_CANARY, SP_BKPSRAM, SP_TAMP, SP_INFO = range(5)
SPACE_LEN = {SP_CANARY: 0x10000, SP_BKPSRAM: 0x800, SP_TAMP: 128, SP_INFO: 640}

PAD_FILE = Path(__file__).with_name("prover") / "pad.bin"


# ---- pure helpers (unit-tested in test_pose.py) -----------------------------


def read_chunks(start, end, rng):
    """(offset, report_count) covering [start, end) in READ_DATA units, shuffled."""
    assert (end - start) % 4 == 0
    chunks = []
    off = start
    step = READ_DATA * MAX_REPORTS
    while off < end:
        n = min(step, end - off)
        chunks.append((off, -(-n // READ_DATA)))
        off += n
    rng.shuffle(chunks)
    return chunks


def mismatched_pages(expected, actual, base):
    """Flash page numbers (base = flash offset of expected[0]) that differ."""
    pages = set()
    for i in range(0, len(expected), 16):
        if expected[i:i + 16] != actual[i:i + 16]:
            pages.add((base + i) // PAGE)
    return sorted(pages)


def pad_image(raw, pad, size):
    if len(raw) > size:
        raise ValueError(f"prover image {len(raw)} B exceeds its {size} B pages")
    need = size - len(raw)
    if len(pad) < need:
        raise ValueError("pad.bin too short")
    return raw + pad[:need]


def decode_info(blob):
    w = struct.unpack_from("<21I", blob, 0)
    names = ["OPTR", "NSBOOTADD0R", "NSBOOTADD1R", "SECBOOTADD0R", "SECWM1R1", "SECWM1R2",
             "WRP1AR", "WRP1BR", "SECWM2R1", "SECWM2R2", "WRP2AR", "WRP2BR", "SECHDPCR"]
    info = {n: w[i] for i, n in enumerate(names)}
    info["UID"] = blob[52:64].hex()
    info["FLASHSIZE_KB"] = w[16]
    info["PWR_BDCR1"] = w[17]
    info["PROVER_PAGES"] = w[18]
    info["CHEAT_FLAGS"] = w[19]
    info["FLASH_NSSR"] = w[20]
    info["OEM_LOCKS"] = (w[20] >> 26) & 3  # lockdown.rs OEM1LOCK/OEM2LOCK, not silicon-pinned
    otp = blob[128:640]
    info["RDP"] = info["OPTR"] & 0xFF
    info["TZEN"] = (info["OPTR"] >> 31) & 1
    info["OTP_USED_HEX"] = otp[:176].hex()
    info["OTP_FREE_BLANK"] = all(b == 0xFF for b in otp[176:])
    return info


# ---- device ------------------------------------------------------------------


def find_hidraw():
    for dev in sorted(glob.glob("/sys/class/hidraw/hidraw*")):
        try:
            uevent = Path(dev, "device/uevent").read_text()
        except OSError:
            continue
        if HID_ID in uevent and PRODUCT in uevent:
            return "/dev/" + os.path.basename(dev)
    return None


class Prover:
    def __init__(self, path=None, wait=30.0):
        deadline = time.time() + wait
        while path is None:
            path = find_hidraw()
            if path is None:
                if time.time() > deadline:
                    raise SystemExit(f"no '{PRODUCT}' HID device ({HID_ID}) found")
                time.sleep(0.5)
        self.fd = os.open(path, os.O_RDWR)
        self.path = path

    def send(self, payload):
        report = bytes(payload).ljust(64, b"\0")
        os.write(self.fd, b"\0" + report)

    def recv(self, timeout=5.0):
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            raise TimeoutError("no reply from prover")
        data = os.read(self.fd, 64)
        if data[0] == 0x8F:
            raise RuntimeError("prover rejected the request")
        return data

    def hello(self):
        self.send([0x01])
        r = self.recv()
        if r[0] != 0x81 or r[2:10] != MAGIC:
            raise RuntimeError(f"not a PoSE prover: {r[:10].hex()}")
        pages, flash_len = struct.unpack_from("<II", r, 10)
        return {"version": r[1], "prover_pages": pages, "flash_len": flash_len}

    def erase(self, page):
        self.send(b"\x03" + struct.pack("<H", page))
        r = self.recv()
        if r[0] != 0x83 or r[1] != 1:
            raise RuntimeError(f"erase page {page} failed, SR=0x{struct.unpack_from('<I', r, 2)[0]:08x}")

    def write(self, sp, off, data):
        for i in range(0, len(data), WRITE_DATA):
            chunk = data[i:i + WRITE_DATA]
            assert len(chunk) % 16 == 0
            self.send(bytes([0x04, sp]) + struct.pack("<IBx", off + i, len(chunk)) + chunk)

    def status(self):
        self.send([0x07])
        r = self.recv(timeout=30)
        failed, sp = r[1], r[2]
        off, sr, writes = struct.unpack_from("<III", r, 4)
        return {"failed": bool(failed), "space": sp, "offset": off, "sr": sr, "writes": writes}

    def read(self, sp, off, nbytes):
        out = bytearray()
        while nbytes > 0:
            n = min(nbytes, READ_DATA * MAX_REPORTS)
            count = -(-n // READ_DATA)
            self.send(bytes([0x05, sp]) + struct.pack("<IH", off, count))
            got = bytearray()
            for k in range(count):
                r = self.recv()
                roff = struct.unpack_from("<I", r, 2)[0]
                if r[0] != 0x85 or r[1] != sp or roff != off + k * READ_DATA:
                    raise RuntimeError(f"bad read reply {r[:6].hex()} at {off + k * READ_DATA:#x}")
                got += r[6:6 + READ_DATA]
            out += got[:n]
            off += n
            nbytes -= n
        return bytes(out)

    def info(self):
        h = self.hello()
        return h, decode_info(self.read(SP_INFO, 0, SPACE_LEN[SP_INFO]))


# ---- commands ------------------------------------------------------------------


def cmd_info(args):
    p = Prover(args.dev)
    h, info = p.info()
    print(json.dumps({"hello": h, "info": {k: (hex(v) if isinstance(v, int) else v)
                                           for k, v in info.items()}}, indent=2))


def cmd_fill(args):
    sess = Path(args.session)
    sess.mkdir(parents=True, exist_ok=True)
    p = Prover(args.dev)
    h, info = p.info()
    prover_bytes = h["prover_pages"] * PAGE
    r = secrets.token_bytes(FLASH_LEN - prover_bytes)
    bkp = secrets.token_bytes(SPACE_LEN[SP_BKPSRAM])
    tamp = secrets.token_bytes(SPACE_LEN[SP_TAMP])
    canary = secrets.token_bytes(SPACE_LEN[SP_CANARY])
    (sess / "r.bin").write_bytes(r)
    (sess / "bkpsram.bin").write_bytes(bkp)
    (sess / "tamp.bin").write_bytes(tamp)
    (sess / "canary.bin").write_bytes(canary)

    t0 = time.time()
    for page in range(h["prover_pages"], 256):
        p.erase(page)
    t1 = time.time()
    p.write(SP_FLASH, prover_bytes, r)
    st = p.status()
    t2 = time.time()
    p.write(SP_BKPSRAM, 0, bkp)
    p.write(SP_TAMP, 0, tamp)
    p.write(SP_CANARY, 0, canary)
    st2 = p.status()
    meta = {"hello": h, "info_before": info, "erase_s": t1 - t0, "fill_s": t2 - t1,
            "fill_bytes": len(r), "fill_status": st, "aux_status": st2, "time": time.time()}
    (sess / "fill.json").write_text(json.dumps(meta, indent=2, default=str))
    print(json.dumps({k: meta[k] for k in ("erase_s", "fill_s", "fill_bytes", "fill_status", "aux_status")},
                     indent=2))
    if st["failed"] or st2["failed"]:
        raise SystemExit("FILL FAILED")
    print("Filled. Now remove ALL power (USB-C and ST-LINK), wait 10 s, replug USB-C only, then run verify.")


def cmd_verify(args):
    sess = Path(args.session)
    r = (sess / "r.bin").read_bytes()
    image = Path(args.image).read_bytes()
    p = Prover(args.dev, wait=120)
    h, info = p.info()
    prover_bytes = h["prover_pages"] * PAGE
    if len(image) != prover_bytes or len(r) != FLASH_LEN - prover_bytes:
        raise SystemExit("session / image sizes do not match this prover")
    expected = image + r
    rng = random.SystemRandom()
    t0 = time.time()
    actual = bytearray(FLASH_LEN)
    for off, count in read_chunks(0, FLASH_LEN, rng):
        n = min(count * READ_DATA, FLASH_LEN - off)
        actual[off:off + n] = p.read(SP_FLASH, off, n)
    t1 = time.time()
    bad = mismatched_pages(expected, actual, 0)
    aux = {}
    for name, sp in (("canary", SP_CANARY), ("bkpsram", SP_BKPSRAM), ("tamp", SP_TAMP)):
        want = (sess / f"{name}.bin").read_bytes()
        got = p.read(sp, 0, len(want))
        aux[name + "_retained"] = got == want
        aux[name + "_matching_bytes"] = sum(a == b for a, b in zip(got, want))
    checks = {
        # The proof itself: every flash byte is the published prover or R.
        "flash_ok": not bad,
        "prover_region_ok": image == bytes(actual[:prover_bytes]),
        # The backup domain survives an unplug while VBAT is held (it does on
        # EVT-3D21), so it is filled and must come back, unless --no-vbat.
        "backup_domain_ok": args.no_vbat or (aux["bkpsram_retained"] and aux["tamp_retained"]),
        # Not proof against malware (which can fake it), but it stops an
        # honest run from passing when the unplug was skipped.
        "power_cycle_ok": not aux["canary_retained"],
        # Reported by the prover; only meaningful once the checks above pass.
        "option_bytes_ok": info["RDP"] == 0xAA and info["TZEN"] == 1 and info["OTP_FREE_BLANK"],
    }
    passed = all(checks.values())
    receipt = {
        "result": "PASS" if passed else "FAIL",
        "checks": checks,
        "mismatched_pages": bad,
        "readback_s": t1 - t0,
        "readback_bytes": FLASH_LEN,
        "aux": aux,
        "oem_locks_raw": info["OEM_LOCKS"],
        "info_after": info,
        "hello": h,
        "time": time.time(),
    }
    (sess / "receipt.json").write_text(json.dumps(receipt, indent=2, default=str))
    print(json.dumps({k: receipt[k] for k in ("result", "checks", "mismatched_pages", "readback_s", "aux",
                                               "oem_locks_raw")}, indent=2))
    if not passed:
        raise SystemExit(1)


def cmd_pad(args):
    raw = Path(args.input).read_bytes()
    out = pad_image(raw, PAD_FILE.read_bytes(), args.pages * PAGE)
    Path(args.output).write_bytes(out)
    print(f"{args.output}: {len(raw)} B code + {len(out) - len(raw)} B random pad")


def compressed_size(tool, data):
    cmd = {"xz": ["xz", "-9e", "-c"], "zstd": ["zstd", "--ultra", "-22", "-c"]}[tool]
    if shutil.which(cmd[0]) is None:
        return None
    return len(subprocess.run(cmd, input=data, capture_output=True, check=True).stdout)


def cmd_slack(args):
    image = Path(args.image).read_bytes()
    code = Path(args.code).read_bytes() if args.code else None
    rows = {"prover_region_bytes": len(image)}
    for tool in ("xz", "zstd"):
        rows[f"{tool}_region"] = compressed_size(tool, image)
        if code is not None:
            rows[f"{tool}_code"] = compressed_size(tool, code)
    best = min(v for k, v in rows.items() if k.endswith("_region") and v)
    rows["slack_from_prover_region"] = len(image) - best
    rows["slack_otp_free"] = len(OTP_FREE)
    rows["slack_total_without_backup_domain"] = rows["slack_from_prover_region"] + len(OTP_FREE)
    print(json.dumps(rows, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dev", help="hidraw path (default: autodetect)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    f = sub.add_parser("fill")
    f.add_argument("--session", required=True)
    f.set_defaults(fn=cmd_fill)
    v = sub.add_parser("verify")
    v.add_argument("--session", required=True)
    v.add_argument("--image", required=True, help="padded prover image (the published prover pages)")
    v.add_argument("--no-vbat", action="store_true", help="board keeps no VBAT: do not require the backup domain back")
    v.set_defaults(fn=cmd_verify)
    pd = sub.add_parser("pad")
    pd.add_argument("input")
    pd.add_argument("output")
    pd.add_argument("--pages", type=int, default=2)
    pd.set_defaults(fn=cmd_pad)
    s = sub.add_parser("slack")
    s.add_argument("--image", required=True)
    s.add_argument("--code", help="raw prover code without pad")
    s.set_defaults(fn=cmd_slack)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
