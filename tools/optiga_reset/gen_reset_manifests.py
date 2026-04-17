#!/usr/bin/env python3
"""
Drive the Infineon `protected_update_data_set` tool to generate signed CBOR
reset manifests for a set of target OIDs and bundle them into a single binary
blob consumed by the firmware.

The chip, after we provision our TA cert at OID 0xE0E3, will accept each of
these manifests via SetObjectProtected (CMD 0x83). Each manifest applies
`reset_metadata.txt` to its target OID and zeroes the data content —
rolling burned AUTHREF OIDs back to a writable state.

Output blob layout (big-endian):
    u16 num_entries
    for each:
        u16 target_oid
        u16 manifest_len
        u16 fragment_len
        u8[manifest_len] manifest_bytes
        u8[fragment_len] fragment_bytes
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = REPO_ROOT.parent / "optiga-trust-m/examples/tools/protected_update_data_set"
TOOL = TOOL_DIR / "bin/protected_update_data_set"
PRIV_KEY = TOOL_DIR / "samples/integrity/sample_ec_256_priv.pem"
META_FILE = Path(__file__).resolve().parent / "reset_metadata.txt"
OUT_DIR = Path(__file__).resolve().parent / "out"
BLOB = OUT_DIR / "reset_manifests.bin"

TRUST_ANCHOR_OID = 0xE0E3
TARGET_OIDS = list(range(0xF1D0, 0xF1E0))  # F1D0..F1DF (16 OIDs)


HEX_RE = re.compile(r"0x([0-9A-Fa-f]{2})")
MANIFEST_HEAD = re.compile(r"Manifest Data , size : \[(\d+)\]")
FRAGMENT_HEAD = re.compile(r"Fragment number:\[(\d+)\], size:\[(\d+)\]")


def run_tool(target_oid: int) -> tuple[bytes, bytes]:
    """Return (manifest_bytes, fragment_bytes) for a single target OID."""
    cmd = [
        str(TOOL),
        "payload_version=3",
        f"trust_anchor_oid={TRUST_ANCHOR_OID:04X}",
        f"target_oid={target_oid:04X}",
        "sign_algo=ES_256",
        f"priv_key={PRIV_KEY}",
        "payload_type=metadata",
        f"metadata={META_FILE}",
        "content_reset=1",
    ]
    result = subprocess.run(
        cmd, cwd=TOOL_DIR, check=True, capture_output=True, text=True
    )
    out = result.stdout

    sections = re.split(r"(Manifest Data , size : \[\d+\]|Fragment number:\[\d+\], size:\[\d+\])", out)
    manifest_bytes = None
    fragment_bytes = None

    it = iter(sections)
    for chunk in it:
        if MANIFEST_HEAD.search(chunk):
            body = next(it)
            manifest_bytes = bytes(int(h, 16) for h in HEX_RE.findall(body))
        elif FRAGMENT_HEAD.search(chunk):
            m = FRAGMENT_HEAD.search(chunk)
            idx = int(m.group(1))
            body = next(it)
            frag = bytes(int(h, 16) for h in HEX_RE.findall(body))
            if fragment_bytes is None:
                fragment_bytes = frag
            else:
                fragment_bytes += frag

    if manifest_bytes is None or fragment_bytes is None:
        sys.stderr.write("Tool output could not be parsed:\n")
        sys.stderr.write(out)
        sys.exit(1)

    return manifest_bytes, fragment_bytes


def main():
    if not TOOL.exists():
        sys.stderr.write(f"Tool not built: {TOOL}\nRun `make` in {TOOL_DIR} first.\n")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    entries = []

    for oid in TARGET_OIDS:
        manifest, fragment = run_tool(oid)
        print(f"  OID 0x{oid:04X}: manifest={len(manifest)}B, fragment={len(fragment)}B")
        entries.append((oid, manifest, fragment))

        (OUT_DIR / f"{oid:04x}.manifest.bin").write_bytes(manifest)
        (OUT_DIR / f"{oid:04x}.fragment.bin").write_bytes(fragment)

    blob = bytearray()
    blob += len(entries).to_bytes(2, "big")
    for oid, manifest, fragment in entries:
        blob += oid.to_bytes(2, "big")
        blob += len(manifest).to_bytes(2, "big")
        blob += len(fragment).to_bytes(2, "big")
        blob += manifest
        blob += fragment

    BLOB.write_bytes(blob)
    print(f"\nWrote {len(blob)} bytes to {BLOB}")


if __name__ == "__main__":
    main()
