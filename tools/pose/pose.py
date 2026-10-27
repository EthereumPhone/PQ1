#!/usr/bin/env python3
"""Proof of secure erasure through ST's ROM USB bootloader (EVT experiment).

Design: docs/security/user-device-verification.md § USB path.
Procedure: tools/pose/README.md.

The device ships with the release flashed and boots it. A user who wants the
check picks "Check first" on the device's first screen; the release then sets
the check profile (boot ST's mask-ROM bootloader, USB DFU 0483:df11, with all
flash non-secure) and resets. No PQ1 code runs during the check. This tool is
the reference for what the Vault desktop app does from there:

    pose.py info
    pose.py run     --session DIR [--min-off 10]   fill, unplug, verify
    pose.py fill    --session DIR
    pose.py verify  --session DIR
    pose.py install --image 0x08000000=bank1.bin --image 0x08100000=bank2.bin
    pose.py probe

Standard library only: DfuSe over Linux usbfs (/dev/bus/usb) with ioctls.
There is deliberately no option-byte write path; option bytes are changed
with STM32_Programmer_CLI (see the README).
"""

import argparse
import ctypes
import fcntl
import glob
import json
import os
import re
import secrets
import struct
import sys
import time
from pathlib import Path

VID, PID = 0x0483, 0xDF11
PAGE = 0x2000
FLASH_BASE = 0x0800_0000
FLASH_LEN = 2 * 128 * PAGE
OB_BASE, OB_LEN = 0x4002_2040, 64
OTP_BASE, OTP_LEN = 0x0BFA_0000, 512
SEGMENT = 64  # transfer blocks per set-address, so a retry repeats little
# SRAM2 is not erased by a system reset when SRAM2_RST=1, but is lost when the
# power goes. Honest runs only: malware could fake it.
CANARY_ADDR, CANARY_LEN = 0x2003_0000, 4096

# DFU class requests and states (DFU 1.1), DfuSe commands (ST AN3156).
DNLOAD, UPLOAD, GETSTATUS, CLRSTATUS, GETSTATE, ABORT = 1, 2, 3, 4, 5, 6
IDLE, DNLOAD_SYNC, DNBUSY, DNLOAD_IDLE = 2, 3, 4, 5
UPLOAD_IDLE, ERROR = 9, 10
CMD_SET_ADDRESS, CMD_ERASE = 0x21, 0x41


class DfuError(Exception):
    pass


# ---- pure helpers (unit-tested in test_pose.py) -----------------------------


def mismatched_pages(expected, actual, base=0):
    """Flash page numbers (base = flash offset of expected[0]) that differ."""
    pages = set()
    for i in range(0, max(len(expected), len(actual)), 16):
        if expected[i:i + 16] != actual[i:i + 16]:
            pages.add((base + i) // PAGE)
    return sorted(pages)


def parse_layout(text):
    """'@Internal Flash  /0x08000000/256*08Kg' -> (name, [(addr, count, size, attr)])."""
    name, _, rest = text.partition("/")
    parts = rest.split("/")
    sectors = []
    for i in range(0, len(parts) - 1, 2):
        addr = int(parts[i], 16)
        for seg in parts[i + 1].split(","):
            m = re.fullmatch(r"\s*(\d+)\*(\d+)\s*([ KMB]?)([a-g])\s*", seg)
            if not m:
                raise ValueError(f"bad DfuSe segment {seg!r}")
            mult = {"K": 1024, "M": 1024 * 1024}.get(m.group(3), 1)
            count, size = int(m.group(1)), int(m.group(2)) * mult
            sectors.append((addr, count, size, m.group(4)))
            addr += count * size
    return name.lstrip("@").strip(), sectors


def parse_descriptors(blob):
    """Raw usbfs descriptor dump -> {serial_index, xfer, alts: {alt: iInterface}}."""
    out = {"serial_index": blob[16], "alts": {}, "xfer": None, "interface": None}
    i = blob[0]
    while i + 2 <= len(blob):
        length, kind = blob[i], blob[i + 1]
        if length < 2:
            break
        d = blob[i:i + length]
        if kind == 4:  # interface
            out["interface"] = d[2]
            out["alts"][d[3]] = d[8]
        elif kind == 0x21 and length >= 7:  # DFU functional
            out["xfer"] = struct.unpack_from("<H", d, 5)[0]
        i += length
    return out


def parse_status(b):
    """GETSTATUS reply -> (status, poll_ms, state)."""
    if len(b) != 6:
        raise DfuError(f"short GETSTATUS reply {b.hex()}")
    return b[0], b[1] | b[2] << 8 | b[3] << 16, b[4]


def set_address_cmd(addr):
    return bytes([CMD_SET_ADDRESS]) + addr.to_bytes(4, "little")


def erase_cmd(addr=None):
    """Page erase at addr, or mass erase when addr is None."""
    return bytes([CMD_ERASE]) + (b"" if addr is None else addr.to_bytes(4, "little"))


def block_address(pointer, block, xfer):
    """DfuSe data block n >= 2 lands at pointer + (n - 2) * xfer."""
    if block < 2:
        raise ValueError("data blocks start at 2")
    return pointer + (block - 2) * xfer


def _field(word, lsb, width):
    return (word >> lsb) & ((1 << width) - 1)


def decode_ob(blob):
    """The 64-byte option-byte block at 0x40022040 (RM0456 FLASH_OPTR..)."""
    if len(blob) < 48:
        raise ValueError("option-byte block too short")
    w = struct.unpack_from("<12I", blob)
    optr, nsb0, nsb1, secb0, wm1r1, wm1r2, wrp1a, wrp1b, wm2r1, wm2r2, wrp2a, wrp2b = w

    def area(r):
        return {"pstrt": _field(r, 0, 7), "pend": _field(r, 16, 7)}

    return {
        "RDP": _field(optr, 0, 8),
        "SRAM_RST": _field(optr, 15, 1),
        "SWAP_BANK": _field(optr, 20, 1),
        "DUALBANK": _field(optr, 21, 1),
        "SRAM2_RST": _field(optr, 25, 1),
        "nSWBOOT0": _field(optr, 26, 1),
        "nBOOT0": _field(optr, 27, 1),
        "TZEN": _field(optr, 31, 1),
        "NSBOOTADD0": nsb0 >> 7,
        "NSBOOTADD1": nsb1 >> 7,
        "SECBOOTADD0": secb0 >> 7,
        "BOOT_LOCK": _field(secb0, 0, 1),
        "SECWM1": area(wm1r1),
        "HDP1EN": _field(wm1r2, 31, 1),
        "HDP1_PEND": _field(wm1r2, 16, 7),
        "WRP1A": area(wrp1a),
        "WRP1B": area(wrp1b),
        "SECWM2": area(wm2r1),
        "HDP2EN": _field(wm2r2, 31, 1),
        "HDP2_PEND": _field(wm2r2, 16, 7),
        "WRP2A": area(wrp2a),
        "WRP2B": area(wrp2b),
        "raw": blob.hex(),
    }


def empty_area(a):
    """Watermark/WRP area disabled: start page above end page."""
    return a["pstrt"] > a["pend"]


def check_profile_problems(ob):
    """What differs from the check profile: RDP-0, TrustZone on, boot ST's
    ROM bootloader, every flash page non-secure and unprotected. (The shipping
    profile boots the release instead; the release switches to this one when
    the user picks "Check first".)"""
    want = {"RDP": 0xAA, "TZEN": 1, "nSWBOOT0": 0, "nBOOT0": 0, "BOOT_LOCK": 0,
            "SWAP_BANK": 0, "DUALBANK": 1, "HDP1EN": 0, "HDP2EN": 0}
    bad = [f"{k}={ob[k]:#x} (want {v:#x})" for k, v in want.items() if ob[k] != v]
    for k in ("SECWM1", "SECWM2", "WRP1A", "WRP1B", "WRP2A", "WRP2B"):
        if not empty_area(ob[k]):
            bad.append(f"{k} covers pages {ob[k]['pstrt']}..{ob[k]['pend']}")
    return bad


def evaluate(r, flash, ob, otp, otp_expected, off_time_s=None, min_off_s=None,
             reenumerated=None, canary_retained=None):
    """The verdict. PASS needs every byte of flash to be the session's R, the
    check option-byte profile and the expected OTP. When measured, it also
    needs an unplug at least min_off_s long and the SRAM2 canary gone (both
    only catch honest runs that skipped the unplug)."""
    bad_pages = mismatched_pages(r, flash)
    problems = check_profile_problems(ob)
    checks = {
        "flash_ok": len(flash) == len(r) and not bad_pages,
        "check_profile_ok": not problems,
        "otp_ok": otp == otp_expected,
        "off_time_ok": None if off_time_s is None else off_time_s >= min_off_s,
        "reenumerated": reenumerated,
        "power_cycle_ok": None if canary_retained is None else not canary_retained,
    }
    required = ["flash_ok", "check_profile_ok", "otp_ok"]
    if off_time_s is not None:
        required.append("off_time_ok")
    if canary_retained is not None:
        required.append("power_cycle_ok")
    return {
        "verdict": "PASS" if all(checks[k] for k in required) else "FAIL",
        "checks": checks,
        "mismatched_pages": bad_pages,
        "profile_problems": problems,
        "otp_differs_at": [i for i in range(min(len(otp), len(otp_expected)))
                           if otp[i] != otp_expected[i]][:32],
        "off_time_s": off_time_s,
        "min_off_s": min_off_s,
    }


def absences(transitions):
    """[(t, present), ...] presence transitions -> [(gone_at, back_at)], back_at
    None while still gone. A plug that bounces shows up as several entries."""
    out, start = [], None
    for t, present in transitions:
        if not present and start is None:
            start = t
        elif present and start is not None:
            out.append((start, t))
            start = None
    if start is not None:
        out.append((start, None))
    return out


def unplug_summary(gaps):
    """Off time = the last continuous absence before the device stayed back:
    a bounce on re-insertion powers the MCU again, so earlier gaps do not count."""
    return {"off_time_s": round(gaps[-1][1] - gaps[-1][0], 2),
            "absences_s": [round(b - a, 2) for a, b in gaps],
            "first_gone_to_last_back_s": round(gaps[-1][1] - gaps[0][0], 2)}


# ---- DfuSe client ------------------------------------------------------------


class Dfu:
    """DfuSe on top of a transport with ctrl_out(req, value, data),
    ctrl_in(req, value, length) and set_alt(alt)."""

    def __init__(self, t, xfer):
        self.t = t
        self.xfer = xfer

    def status(self):
        return parse_status(self.t.ctrl_in(GETSTATUS, 0, 6))

    def clear(self):
        st, _, state = self.status()
        if state == ERROR:
            self.t.ctrl_out(CLRSTATUS, 0, b"")
        self.t.ctrl_out(ABORT, 0, b"")

    def _dnload(self, block, data):
        self.t.ctrl_out(DNLOAD, block, data)
        for _ in range(100000):
            st, poll, state = self.status()
            if state == ERROR or st != 0:
                raise DfuError(f"block {block}: status {st:#x} state {state}")
            if state == DNBUSY or state == DNLOAD_SYNC:
                time.sleep(poll / 1000)
                continue
            return
        raise DfuError("device stayed busy")

    def set_address(self, addr):
        self._dnload(0, set_address_cmd(addr))

    def mass_erase(self):
        self.clear()
        self._dnload(0, erase_cmd())

    def write(self, addr, data, progress=None):
        for seg in range(0, len(data), SEGMENT * self.xfer):
            chunk = data[seg:seg + SEGMENT * self.xfer]
            for attempt in range(3):
                try:
                    self.clear()
                    self.set_address(addr + seg)
                    for i in range(0, len(chunk), self.xfer):
                        self._dnload(2 + i // self.xfer, chunk[i:i + self.xfer])
                    break
                except DfuError:
                    if attempt == 2:
                        raise
                    time.sleep(0.2)
            if progress:
                progress(seg + len(chunk), len(data))

    def read(self, addr, length, progress=None):
        out = bytearray()
        while len(out) < length:
            base = addr + len(out)
            n = min(SEGMENT * self.xfer, length - len(out))
            self.clear()
            self.set_address(base)
            self.t.ctrl_out(ABORT, 0, b"")
            for i in range(0, n, self.xfer):
                want = min(self.xfer, n - i)
                got = self.t.ctrl_in(UPLOAD, 2 + i // self.xfer, want)
                if len(got) != want:
                    raise DfuError(f"short upload at {base + i:#x}: {len(got)}/{want}")
                out += got
            if progress:
                progress(len(out), length)
        self.t.ctrl_out(ABORT, 0, b"")
        return bytes(out)

    def read_alt(self, alt, addr, length):
        self.t.set_alt(alt)
        try:
            return self.read(addr, length)
        finally:
            self.t.set_alt(0)


# ---- Linux usbfs transport ---------------------------------------------------


def _ioc(direction, nr, size):
    return direction << 30 | size << 16 | ord("U") << 8 | nr


class _Ctrl(ctypes.Structure):
    _fields_ = [("bRequestType", ctypes.c_uint8), ("bRequest", ctypes.c_uint8),
                ("wValue", ctypes.c_uint16), ("wIndex", ctypes.c_uint16),
                ("wLength", ctypes.c_uint16), ("timeout", ctypes.c_uint32),
                ("data", ctypes.c_void_p)]


class _SetIntf(ctypes.Structure):
    _fields_ = [("interface", ctypes.c_uint), ("altsetting", ctypes.c_uint)]


USBDEVFS_CONTROL = _ioc(3, 0, ctypes.sizeof(_Ctrl))
USBDEVFS_SETINTERFACE = _ioc(2, 4, ctypes.sizeof(_SetIntf))
USBDEVFS_CLAIMINTERFACE = _ioc(2, 15, 4)
USBDEVFS_RELEASEINTERFACE = _ioc(2, 16, 4)


def find_device():
    """(sysfs dir, busnum, devnum, serial) of the ROM DFU device, or None."""
    for d in glob.glob("/sys/bus/usb/devices/*"):
        try:
            if (int(Path(d, "idVendor").read_text(), 16), int(Path(d, "idProduct").read_text(), 16)) == (VID, PID):
                serial = Path(d, "serial").read_text().strip() if Path(d, "serial").exists() else ""
                return d, int(Path(d, "busnum").read_text()), int(Path(d, "devnum").read_text()), serial
        except (OSError, ValueError):
            continue
    return None


def watch_unplug(settle=3.0, timeout=600):
    """Absence intervals of the DFU device, once it has been back for `settle`
    seconds without dropping out again; None on timeout."""
    transitions, last = [], True
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        now = time.monotonic()
        present = find_device() is not None
        if present != last:
            transitions.append((now, present))
            last = present
        gaps = absences(transitions)
        if gaps and gaps[-1][1] is not None and now - gaps[-1][1] >= settle:
            return gaps
        time.sleep(0.05)
    return None


def wait_device(present, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if (find_device() is not None) == present:
            return time.monotonic()
        time.sleep(0.05)
    return None


class Usbfs:
    def __init__(self, busnum, devnum):
        path = f"/dev/bus/usb/{busnum:03d}/{devnum:03d}"
        self.fd = os.open(path, os.O_RDWR)
        self.desc = parse_descriptors(os.read(self.fd, 4096))
        self.intf = self.desc["interface"]
        fcntl.ioctl(self.fd, USBDEVFS_CLAIMINTERFACE, ctypes.c_uint(self.intf))
        self.set_alt(0)

    def close(self):
        try:
            fcntl.ioctl(self.fd, USBDEVFS_RELEASEINTERFACE, ctypes.c_uint(self.intf))
        finally:
            os.close(self.fd)

    def _control(self, rtype, req, value, index, data, length, timeout=5000):
        buf = ctypes.create_string_buffer(bytes(data) if data else length or 1)
        c = _Ctrl(rtype, req, value, index, len(data) if data else length, timeout,
                  ctypes.addressof(buf))
        n = fcntl.ioctl(self.fd, USBDEVFS_CONTROL, c)
        return buf.raw[:n]

    def ctrl_out(self, req, value, data):
        self._control(0x21, req, value, self.intf, data, 0)

    def ctrl_in(self, req, value, length):
        return self._control(0xA1, req, value, self.intf, b"", length)

    def set_alt(self, alt):
        fcntl.ioctl(self.fd, USBDEVFS_SETINTERFACE, _SetIntf(self.intf, alt))

    def string(self, index):
        if not index:
            return ""
        b = self._control(0x80, 6, 0x0300 | index, 0x0409, b"", 255)
        return b[2:b[0]].decode("utf-16-le", "replace")


def open_device():
    found = find_device()
    if not found:
        sys.exit("no ST ROM DFU device (0483:df11): is the device plugged in and set to boot ST's bootloader?")
    _, bus, dev, serial = found
    for attempt in range(50):  # udev applies the 0666 mode just after the node appears
        try:
            t = Usbfs(bus, dev)
            break
        except (PermissionError, FileNotFoundError):
            if attempt == 49:
                raise
            time.sleep(0.1)
    layouts = {alt: t.string(i) for alt, i in t.desc["alts"].items()}
    return t, Dfu(t, t.desc["xfer"]), {"busnum": bus, "devnum": dev, "serial": serial,
                                         "xfer": t.desc["xfer"], "layouts": layouts}


def alt_for(ident, base):
    for alt, text in ident["layouts"].items():
        if parse_layout(text)[1][0][0] == base:
            return alt
    sys.exit(f"the ROM exposes no DfuSe alt setting at {base:#010x}: {ident['layouts']}")


def read_state(dfu, ident, progress=None):
    flash = dfu.read(FLASH_BASE, FLASH_LEN, progress)
    ob = dfu.read_alt(alt_for(ident, OB_BASE), OB_BASE, OB_LEN)
    otp = dfu.read_alt(alt_for(ident, OTP_BASE), OTP_BASE, OTP_LEN)
    return flash, ob, otp


def _progress(label):
    t0 = time.monotonic()

    def p(done, total):
        print(f"\r  {label}: {done * 100 // total:3d}%  {done / max(time.monotonic() - t0, 1e-3) / 1024:6.0f} KiB/s",
              end="", file=sys.stderr, flush=True)
        if done == total:
            print(file=sys.stderr)
    return p


# ---- commands ----------------------------------------------------------------


def cmd_info(args):
    t, dfu, ident = open_device()
    try:
        ob = decode_ob(dfu.read_alt(alt_for(ident, OB_BASE), OB_BASE, OB_LEN))
        otp = dfu.read_alt(alt_for(ident, OTP_BASE), OTP_BASE, OTP_LEN)
    finally:
        t.close()
    print(json.dumps({**ident, "option_bytes": ob,
                      "check_profile_problems": check_profile_problems(ob),
                      "otp_blank": otp == b"\xff" * OTP_LEN, "otp": otp.hex()}, indent=2))


def do_fill(session):
    session.mkdir(parents=True, exist_ok=True)
    t, dfu, ident = open_device()
    try:
        r = secrets.token_bytes(FLASH_LEN)
        (session / "r.bin").write_bytes(r)
        t0 = time.monotonic()
        dfu.mass_erase()
        t1 = time.monotonic()
        dfu.write(FLASH_BASE, r, _progress("fill"))
        t2 = time.monotonic()
        canary = secrets.token_bytes(CANARY_LEN)
        (session / "canary.bin").write_bytes(canary)
        dfu.write(CANARY_ADDR, canary)
    finally:
        t.close()
    meta = {**ident, "erase_s": round(t1 - t0, 2), "fill_s": round(t2 - t1, 2),
            "filled_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (session / "fill.json").write_text(json.dumps(meta, indent=2))
    print(f"filled {FLASH_LEN} B: erase {meta['erase_s']} s, write {meta['fill_s']} s")
    return meta


def do_verify(session, otp_expected, off_time_s=None, min_off_s=None, unplug=None):
    r = (session / "r.bin").read_bytes()
    before = json.loads((session / "fill.json").read_text())
    if find_device() is None and wait_device(True, 30) is None:
        result = {"verdict": "FAIL", "reason": "the device did not come back as ST's ROM DFU (0483:df11)"}
        (session / "receipt.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        return result
    t, dfu, ident = open_device()
    try:
        t0 = time.monotonic()
        flash, ob, otp = read_state(dfu, ident, _progress("readback"))
        read_s = round(time.monotonic() - t0, 2)
        sram2 = dfu.read(CANARY_ADDR, CANARY_LEN)
    finally:
        t.close()
    reenum = (ident["busnum"], ident["devnum"]) != (before["busnum"], before["devnum"])
    canary = (session / "canary.bin").read_bytes()
    result = evaluate(r, flash, decode_ob(ob), otp, otp_expected, off_time_s, min_off_s, reenum,
                      sram2 == canary)
    result.update({"device": ident, "read_s": read_s, "option_bytes": decode_ob(ob), "unplug": unplug,
                   "canary_matching_bytes": sum(a == b for a, b in zip(sram2, canary)),
                   "fill": before, "verified_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    (session / "receipt.json").write_text(json.dumps(result, indent=2))
    summary = {k: result[k] for k in ("verdict", "checks", "mismatched_pages", "profile_problems", "off_time_s")}
    print(json.dumps(summary, indent=2))
    return result


def _otp_expected(args):
    return Path(args.otp_expected).read_bytes() if args.otp_expected else b"\xff" * OTP_LEN


def cmd_fill(args):
    do_fill(Path(args.session))


def cmd_verify(args):
    res = do_verify(Path(args.session), _otp_expected(args))
    sys.exit(0 if res["verdict"] == "PASS" else 1)


def cmd_run(args):
    session = Path(args.session)
    do_fill(session)
    print(f"\nUnplug the USB-C cable now (on the bench also the ST-LINK, which can back-power the MCU).\n"
          f"Wait at least {args.min_off} s, then plug USB-C back in.", flush=True)
    gaps = watch_unplug(timeout=args.wait)
    if gaps is None:
        sys.exit(f"no unplug and stable replug within {args.wait:.0f} s: run `verify` once it is done, "
                 "or start again")
    unplug = unplug_summary(gaps)
    print(f"device was off for {unplug['off_time_s']} s (all absences: {unplug['absences_s']})")
    res = do_verify(session, _otp_expected(args), unplug["off_time_s"], args.min_off, unplug)
    sys.exit(0 if res["verdict"] == "PASS" else 1)


def cmd_install(args):
    images = []
    for spec in args.image:
        addr, _, path = spec.partition("=")
        images.append((int(addr, 0), Path(path).read_bytes()))
    t, dfu, ident = open_device()
    try:
        dfu.mass_erase()
        for addr, data in images:
            if not (FLASH_BASE <= addr and addr + len(data) <= FLASH_BASE + FLASH_LEN):
                sys.exit(f"image at {addr:#x} leaves flash")
            dfu.write(addr, data, _progress(f"write {addr:#x}"))
            back = dfu.read(addr, len(data), _progress(f"verify {addr:#x}"))
            if back != data:
                sys.exit(f"readback mismatch at pages {mismatched_pages(data, back, addr - FLASH_BASE)[:16]}")
    finally:
        t.close()
    print("installed and read back. Now switch the option bytes back to the shipping profile, so the\n"
          "device boots the release and shows its first screen again (Set up / Check first).\n"
          "The design boots flash with the BOOT0 pin ignored (nSWBOOT0=0 nBOOT0=1). Restoring the EVT,\n"
          "which shipped with its pin-selected setting:\n"
          "  STM32_Programmer_CLI -c port=USB1 -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F\n"
          "  STM32_Programmer_CLI -c port=USB1 -ob nSWBOOT0=1 nBOOT0=1")


def cmd_probe(args):
    """What else can ST's ROM reach? Only reads, and one SRAM2 write."""
    t, dfu, ident = open_device()
    out = {"device": ident}
    try:
        for name, alt_base, n in (("option_bytes", OB_BASE, OB_LEN), ("otp", OTP_BASE, OTP_LEN)):
            try:
                out[name] = dfu.read_alt(alt_for(ident, alt_base), alt_base, n).hex()
            except (DfuError, OSError) as e:
                out[name] = f"error: {e}"
        canary = secrets.token_bytes(16)
        for name, addr, data in (("sram2_write", 0x2003_0000, canary),
                                 ("sram2_read", 0x2003_0000, None),
                                 ("bkpsram_read", 0x4003_6400, None)):
            try:
                if data is None:
                    got = dfu.read(addr, 16)
                    out[name] = got.hex() + (" (canary)" if got == canary else "")
                else:
                    dfu.write(addr, data)
                    out[name] = "accepted"
            except (DfuError, OSError) as e:
                out[name] = f"refused: {e}"
                try:
                    dfu.clear()
                except (DfuError, OSError):
                    pass
    finally:
        t.close()
    print(json.dumps(out, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sub.add_parser("probe").set_defaults(fn=cmd_probe)
    for name, fn in (("fill", cmd_fill), ("verify", cmd_verify), ("run", cmd_run)):
        p = sub.add_parser(name)
        p.add_argument("--session", required=True)
        p.add_argument("--otp-expected", help="expected 512-B OTP image (default: all 0xFF)")
        if name == "run":
            p.add_argument("--min-off", type=float, default=10.0, help="minimum unplugged seconds")
            p.add_argument("--wait", type=float, default=3600.0, help="how long to wait for the unplug")
        p.set_defaults(fn=fn)
    i = sub.add_parser("install")
    i.add_argument("--image", action="append", required=True, help="ADDR=FILE, e.g. 0x08000000=bank1.bin")
    i.set_defaults(fn=cmd_install)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
