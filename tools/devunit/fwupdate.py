#!/usr/bin/env python3
"""Install a dev-unit firmware release (`.pq1fw`) on a PQ1 over USB.

    tools/devunit/fwupdate.py pq1-devunit-26.10.21.2.pq1fw
    tools/devunit/fwupdate.py --info                     # what is installed?

Dev units only (`devunit-ab` firmware). The device must be unlocked; it then
asks twice on its own screen — "verify the package?" and the install screen
with the new version and fingerprint words — and only after both does it
erase anything. The streamed images go to the slot the device is NOT running
from, so a failure or unplug at any point leaves the running firmware intact.
After COMMIT the device restarts, shows the new fingerprint words, asks for
the PIN, and from then on boots the new release. A new release that never
reaches an unlocked wallet is abandoned after three boots and the previous one
comes back (see fw-manifest/src/devunit.rs).

Linux: talks to /dev/hidrawN directly (99-pqsigner.rules gives 0666). Other
platforms: use tools/devunit/pq1-fwupdate.html in Chrome (WebHID).
"""
from __future__ import annotations

import argparse
import glob
import os
import select
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pq1fw import Package, version_label  # noqa: E402

VID, PID = 0x1209, 0x7051
CLA = 0xF0
REPORT = 64
TAG_APDU = 0x05
FIRST_DATA = REPORT - 7
CONT_DATA = REPORT - 5
CHANNEL = 0x0001
P1_MORE, P1_LAST = 0x80, 0x00

INS_GET_DEVICE_INFO = 0x01
INS_GET_STATUS = 0x02
INS_UNLOCK = 0x10
INS_FW_BEGIN = 0x70
INS_FW_CHUNK = 0x71
INS_FW_COMMIT = 0x72
INS_FW_STATUS = 0x73
INS_FW_ABORT = 0x74

SW_OK = 0x9000
SW_TEXT = {
    0x6985: "conditions not satisfied (locked, or no update session — unlock and retry)",
    0x6982: "refused on the device (cancelled, or PIN wrong)",
    0x6A80: "the device rejected this release (bad signature, not newer, or wrong slot)",
    0x6984: "the device locked itself (idle timeout) — unlock and retry",
    0x6F00: "internal error",
    0x6D00: "command not supported (not a dev-unit image?)",
}
CHUNK = 240          # QW-aligned, fits one short APDU with the 8-byte header
# Words of the dev-unit firmware-signing key (config/devunit-firmware-vendor-
# pubkey.bin); the device shows them on its SIGNER screen during an update.
SIGNER_WORDS = "popular shift evoke mass shoulder spoon mushroom cotton".split()
KIND_SECURE, KIND_NS = 0, 1


def sw_text(sw: int) -> str:
    return f"0x{sw:04X} — {SW_TEXT.get(sw, 'unknown status')}"


def find_hidraw() -> str | None:
    for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
        try:
            c = open(uevent).read().upper()
        except OSError:
            continue
        if f"{VID:04X}" in c and f"{PID:04X}" in c:
            return "/dev/" + os.path.basename(os.path.dirname(os.path.dirname(uevent)))
    return None


def wait_device(present: bool, timeout_s: float) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if (find_hidraw() is not None) == present:
            return True
        time.sleep(0.25)
    return False


class Device:
    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR)

    def close(self) -> None:
        os.close(self.fd)

    def _write(self, frame: bytes) -> None:
        os.write(self.fd, b"\x00" + frame)  # hidraw: leading report id

    def _read(self, timeout_s: float) -> bytes:
        r, _, _ = select.select([self.fd], [], [], timeout_s)
        if not r:
            raise TimeoutError(f"no answer from the device within {timeout_s:.0f} s")
        return os.read(self.fd, REPORT)

    def apdu(self, ins: int, p1: int, data: bytes, timeout_s: float = 30.0) -> tuple[int, bytes]:
        assert len(data) <= 255
        msg = bytes([CLA, ins, p1, 0, len(data)]) + data
        seq, off = 0, 0
        while off < len(msg) or seq == 0:
            f = bytearray(REPORT)
            f[0:3] = bytes([CHANNEL >> 8, CHANNEL & 0xFF, TAG_APDU])
            f[3:5] = seq.to_bytes(2, "big")
            if seq == 0:
                f[5:7] = len(msg).to_bytes(2, "big")
                n = min(FIRST_DATA, len(msg))
                f[7:7 + n] = msg[:n]
            else:
                n = min(CONT_DATA, len(msg) - off)
                f[5:5 + n] = msg[off:off + n]
            self._write(bytes(f))
            off += n
            seq += 1
        buf, want, seq = bytearray(), 0, 0
        while True:
            f = self._read(timeout_s)
            if len(f) < 5 or f[2] != TAG_APDU:
                continue
            if (f[3] << 8 | f[4]) != seq:
                raise IOError("HID sequence error")
            if seq == 0:
                want = f[5] << 8 | f[6]
                buf += f[7:7 + min(FIRST_DATA, want)]
            else:
                buf += f[5:5 + min(CONT_DATA, want - len(buf))]
            seq += 1
            if len(buf) >= want:
                break
        if len(buf) < 2:
            raise IOError("short APDU response")
        return (buf[-2] << 8) | buf[-1], bytes(buf[:-2])

    def chained(self, ins: int, payload: bytes, timeout_s: float) -> tuple[int, bytes]:
        off = 0
        while True:
            part = payload[off:off + 255]
            off += len(part)
            last = off >= len(payload)
            sw, resp = self.apdu(ins, P1_LAST if last else P1_MORE, part, timeout_s if last else 30.0)
            if last or sw != SW_OK:
                return sw, resp


def device_info(dev: Device) -> dict:
    sw, r = dev.apdu(INS_GET_DEVICE_INFO, 0, b"")
    if sw != SW_OK or len(r) < 40:
        raise RuntimeError(f"GET_DEVICE_INFO failed: {sw_text(sw)}")
    info = {"protocol": r[0] << 8 | r[1], "devunit": False}
    t = r[40:48]
    if len(t) == 8 and t[:2] == b"DU" and t[2] == 1:
        info.update(devunit=True, slot="AB"[t[3]] if t[3] < 2 else "?",
                    fw_version=struct.unpack(">I", t[4:8])[0])
    return info


def unlocked(dev: Device) -> bool:
    sw, r = dev.apdu(INS_GET_STATUS, 0, b"")
    return sw == SW_OK and len(r) >= 1 and r[0] == 0


def open_device(timeout_s: float = 10.0) -> Device:
    if not wait_device(True, timeout_s):
        sys.exit("no PQ1 found on USB (1209:7051). Is it plugged in and past the PIN screen?")
    return Device(find_hidraw())


def show_info(_args: argparse.Namespace) -> None:
    dev = open_device()
    try:
        info = device_info(dev)
        print(f"protocol 0x{info['protocol']:04X}, unlocked: {unlocked(dev)}")
        if info["devunit"]:
            print(f"dev-unit firmware {version_label(info['fw_version'])} running from slot {info['slot']}")
        else:
            print("not a dev-unit image (no update layout): flash it with tools/devunit/flash.sh first")
    finally:
        dev.close()


def send_image(dev: Device, kind: int, image: bytes, label: str) -> None:
    t0, off = time.monotonic(), 0
    while off < len(image):
        n = min(CHUNK, len(image) - off)
        sw, _ = dev.apdu(INS_FW_CHUNK, P1_LAST, struct.pack(">IBBH", off, kind, 0, n) + image[off:off + n])
        if sw != SW_OK:
            raise RuntimeError(f"{label}: chunk at {off} refused: {sw_text(sw)}")
        off += n
        if off == len(image) or (off // CHUNK) % 64 == 0:
            pct = 100 * off // len(image)
            print(f"\r    {label}: {off:7d}/{len(image)} B ({pct:3d}%)", end="", flush=True)
    print(f"  [{time.monotonic() - t0:.1f} s]")


def install(args: argparse.Namespace) -> None:
    pkg = Package.load(args.package)
    print(f"package: release {pkg.label} ({pkg.header['profile']}), git {pkg.header['git'][:12]}")
    dev = open_device()
    try:
        info = device_info(dev)
        if not info["devunit"]:
            sys.exit("this device does not run dev-unit firmware; flash it once with tools/devunit/flash.sh")
        running, slot = info["fw_version"], info["slot"]
        print(f"device:  release {version_label(running)} running from slot {slot}")
        if pkg.fw_version <= running and not args.force:
            sys.exit(f"the device already runs {version_label(running)}; the package must be newer "
                     f"(the device refuses older or equal releases)")
        target = "B" if slot == "A" else "A"
        manifest = pkg.image(target, "manifest")
        secure = pkg.image(target, "secure")
        nonsecure = pkg.image(target, "nonsecure")
        if not unlocked(dev):
            print("the device is locked — enter the PIN on the device")
            dev.apdu(INS_UNLOCK, 0, b"", timeout_s=300)
            if not unlocked(dev):
                sys.exit("still locked; unlock the device and run this again")
        print(f"==> installing {pkg.label} into slot {target}")
        print("    on the device: UPDATE FIRMWARE? — tap RIGHT through the new version and its 8 words,")
        print("    then press BOTH buttons on the last screen (hold LEFT to cancel). The words must be:")
        print(f"      {' '.join(pkg.fingerprint(target))}")
        print("    (firmware 26.10.21.9 and older asks twice and also shows the signer words:")
        print(f"      {' '.join(SIGNER_WORDS)})")
        sw, _ = dev.chained(INS_FW_BEGIN, manifest, timeout_s=600)
        if sw != SW_OK:
            sys.exit(f"FW_BEGIN: {sw_text(sw)}")
        print("    accepted; streaming")
        try:
            send_image(dev, KIND_SECURE, secure, "secure    ")
            send_image(dev, KIND_NS, nonsecure, "non-secure")
        except Exception:
            try:
                dev.apdu(INS_FW_ABORT, P1_LAST, b"")
            except Exception:
                pass
            raise
        try:
            sw, _ = dev.apdu(INS_FW_COMMIT, P1_LAST, b"", timeout_s=60)
        except (OSError, TimeoutError):
            # The device resets right after a successful COMMIT; if its answer
            # was lost on the way, only the version it comes back with says
            # whether the install happened.
            print("==> no answer to COMMIT — checking what the device runs after its restart")
            sw = SW_OK
        if sw != SW_OK:
            sys.exit(f"FW_COMMIT: {sw_text(sw)} — the running firmware is unchanged")
        print("==> installed; the device restarts now")
    finally:
        dev.close()

    if not wait_device(False, 15):
        print("    (the device did not drop off USB — check its screen)")
    print("    waiting for it to come back: it shows the fingerprint words, then asks for the PIN")
    if not wait_device(True, args.wait):
        sys.exit(f"the device did not come back within {args.wait:.0f} s — enter the PIN on it, then run --info")
    time.sleep(1.0)
    dev = open_device()
    try:
        info = device_info(dev)
    finally:
        dev.close()
    if info.get("fw_version") == pkg.fw_version and info.get("slot") == target:
        print(f"==> OK: release {version_label(pkg.fw_version)} is running from slot {target}")
    else:
        sys.exit(f"!! the device runs {version_label(info.get('fw_version', 0))} from slot "
                 f"{info.get('slot')} — the update did not take (the previous release kept running)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package", nargs="?", help=".pq1fw update package")
    ap.add_argument("--info", action="store_true", help="show what the connected device runs")
    ap.add_argument("--wait", type=float, default=600.0, help="seconds to wait for the device after the restart")
    ap.add_argument("--force", action="store_true", help="send even if the package is not newer (the device still refuses it)")
    a = ap.parse_args()
    try:
        if a.info or not a.package:
            show_info(a)
        else:
            install(a)
    except (OSError, TimeoutError) as e:
        sys.exit(f"!! lost the connection to the device ({e}). The firmware it was running is "
                 f"unchanged: reconnect it, unlock it, and run this again.")


if __name__ == "__main__":
    main()
