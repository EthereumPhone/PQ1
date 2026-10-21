#!/usr/bin/env python3
"""`.pq1fw` — the dev-unit firmware update package (both slot variants).

A dev-unit release is linked twice (secure+non-secure for slot A, and for
slot B) and each variant is signed; the updater sends the variant for the slot
the device is NOT running from. This file carries both in one download.

Layout (all integers little-endian):

    0   8   magic b"PQ1DEVFW"
    8   4   header length H
    12  H   header, UTF-8 JSON (below)
    12+H    blob area: the six images back to back

Header:

    {"format": 1, "layout": "devunit-ab-1",
     "fw_version": <u32>, "label": "26.10.21.1", "profile": "investor",
     "git": "<sha>", "features": "<secure features>",
     "vendor_key_sha256": "<hex>",
     "slots": {"A": {"manifest":  {"offset": o, "length": n, "sha256": h},
                     "secure":    {...}, "nonsecure": {...},
                     "fingerprint": ["word1", ..., "word8"]},
               "B": {...}}}

Offsets are relative to the blob area. The package is NOT the security
boundary: the device verifies the vendor C10 signature in the manifest, the
image hashes and the slot binding itself. The sha256 fields only let the host
tools notice a damaged download early.

    pq1fw.py pack --out F --version V --label L ... --slot-a DIR --slot-b DIR
    pq1fw.py inspect F
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

MAGIC = b"PQ1DEVFW"
FORMAT = 1
LAYOUT = "devunit-ab-1"
MANIFEST_SIZE = 8192
OFF_FW_VERSION = 8
OFF_SECURE_LEN = 12
OFF_NONSECURE_LEN = 16
SECURE_CAPACITY = 80 * 8192
NS_CAPACITY = 24 * 8192


def _words(measurement_txt: str) -> list[str]:
    """The 8 secure-image words from fwsign's measurement.txt."""
    words: list[str] = []
    take = False
    for line in measurement_txt.splitlines():
        if line.startswith("Secure image measurement"):
            take = True
            continue
        if take:
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit():
                words.append(parts[1])
            elif line.strip().startswith("SHA-256"):
                break
    return words


def pack(args: argparse.Namespace) -> None:
    blobs = bytearray()
    slots = {}
    for name, d in (("A", args.slot_a), ("B", args.slot_b)):
        d = Path(d)
        entry = {}
        m = (d / "manifest.bin").read_bytes()
        if len(m) != MANIFEST_SIZE:
            sys.exit(f"{d}/manifest.bin is {len(m)} bytes")
        ver = struct.unpack(">I", m[OFF_FW_VERSION:OFF_FW_VERSION + 4])[0]
        if ver != args.version:
            sys.exit(f"slot {name} manifest version {ver} != {args.version}")
        for part in ("manifest", "secure", "nonsecure"):
            data = (d / f"{part}.bin").read_bytes()
            entry[part] = {
                "offset": len(blobs),
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            blobs += data
        s_len = struct.unpack(">I", m[OFF_SECURE_LEN:OFF_SECURE_LEN + 4])[0]
        n_len = struct.unpack(">I", m[OFF_NONSECURE_LEN:OFF_NONSECURE_LEN + 4])[0]
        if s_len != entry["secure"]["length"] or n_len != entry["nonsecure"]["length"]:
            sys.exit(f"slot {name}: manifest lengths do not match the images")
        if s_len > SECURE_CAPACITY or n_len > NS_CAPACITY:
            sys.exit(f"slot {name}: image exceeds the dev-unit slot capacity")
        entry["fingerprint"] = _words((d / "measurement.txt").read_text())
        slots[name] = entry
    header = {
        "format": FORMAT,
        "layout": LAYOUT,
        "fw_version": args.version,
        "label": args.label,
        "profile": args.profile,
        "git": args.git,
        "features": args.features,
        "vendor_key_sha256": hashlib.sha256(Path(args.pubkey).read_bytes()).hexdigest(),
        "slots": slots,
    }
    hb = json.dumps(header, indent=1, sort_keys=True).encode()
    out = MAGIC + struct.pack("<I", len(hb)) + hb + bytes(blobs)
    Path(args.out).write_bytes(out)
    print(f"wrote {args.out} ({len(out)} bytes)")


class Package:
    """A parsed `.pq1fw`; `image(slot, part)` returns verified bytes."""

    def __init__(self, data: bytes) -> None:
        if data[:8] != MAGIC:
            raise ValueError("not a PQ1 dev-unit firmware package (bad magic)")
        (hlen,) = struct.unpack("<I", data[8:12])
        self.header = json.loads(data[12:12 + hlen].decode())
        if self.header.get("format") != FORMAT or self.header.get("layout") != LAYOUT:
            raise ValueError(
                f"unsupported package format {self.header.get('format')}/{self.header.get('layout')}"
            )
        self._blobs = data[12 + hlen:]

    @classmethod
    def load(cls, path: str | Path) -> "Package":
        return cls(Path(path).read_bytes())

    @property
    def fw_version(self) -> int:
        return int(self.header["fw_version"])

    @property
    def label(self) -> str:
        return str(self.header["label"])

    def image(self, slot: str, part: str) -> bytes:
        e = self.header["slots"][slot][part]
        b = self._blobs[e["offset"]:e["offset"] + e["length"]]
        if len(b) != e["length"] or hashlib.sha256(b).hexdigest() != e["sha256"]:
            raise ValueError(f"package damaged: slot {slot} {part} does not match its hash")
        return b

    def fingerprint(self, slot: str) -> list[str]:
        return list(self.header["slots"][slot].get("fingerprint", []))


def version_label(v: int) -> str:
    return ".".join(str(b) for b in v.to_bytes(4, "big"))


def inspect(args: argparse.Namespace) -> None:
    p = Package.load(args.file)
    h = p.header
    print(f"{args.file}")
    print(f"  release   {h['label']}  (fw_version {h['fw_version']} = {version_label(h['fw_version'])})")
    print(f"  profile   {h['profile']}   git {h['git']}")
    print(f"  features  {h['features']}")
    print(f"  key       {h['vendor_key_sha256']}")
    for s in ("A", "B"):
        e = h["slots"][s]
        for part in ("manifest", "secure", "nonsecure"):
            p.image(s, part)  # verifies the hash
        print(
            f"  slot {s}: secure {e['secure']['length']} B, non-secure {e['nonsecure']['length']} B, "
            f"words: {' '.join(e['fingerprint'])}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack")
    pk.add_argument("--out", required=True)
    pk.add_argument("--version", type=int, required=True)
    pk.add_argument("--label", required=True)
    pk.add_argument("--profile", required=True)
    pk.add_argument("--git", required=True)
    pk.add_argument("--features", required=True)
    pk.add_argument("--pubkey", required=True)
    pk.add_argument("--slot-a", required=True)
    pk.add_argument("--slot-b", required=True)
    ins = sub.add_parser("inspect")
    ins.add_argument("file")
    a = ap.parse_args()
    {"pack": pack, "inspect": inspect}[a.cmd](a)


if __name__ == "__main__":
    main()
