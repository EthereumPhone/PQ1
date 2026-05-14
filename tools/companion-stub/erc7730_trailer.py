#!/usr/bin/env python3
"""Companion-stub: build an ERC-7730 sign-input trailer from a
catalog blob (`tools/companion-stub/erc7730_db.bin`).

Usage:

    python3 tools/companion-stub/erc7730_trailer.py \\
        --db tools/companion-stub/erc7730_db.bin \\
        --chain 1 \\
        --contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 \\
        --out /tmp/usdt_mainnet_trailer.bin

Writes the byte-for-byte payload the secure-world dispatcher expects
inside the `[u16 BE len][payload]` trailer envelope on
`CMD_SIGN_USEROP` / `CMD_SIGN_USEROP_BATCH` / `CMD_SIGN_OFFCHAIN`.

The output buffer is the *inner* bundle (no length prefix). The
caller wraps it as `len.to_bytes(2, 'big') + payload` when splicing
into a sign-input wire payload.

Wire layout produced (matches `pqsigner_erc7730::bundle`):

    ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof

Catalog blob layout (header is little-endian; entry array is sorted
by `(chain_id, contract, primary_type_hash, context_kind)` so binary
search works):

    "P730" || ver_le(4) || flags_le(4) || entry_cnt_le(4) ||
    ir_pool_off_le(4) || ir_pool_size_le(4) || proof_depth_le(4) ||
    proofs_off_le(4)
    [entries: each 72 B = chain_id_le(8) | contract(20) |
     primary_type_hash(32) | ctx_kind(1) | pad(3) | ir_off_le(4) |
     ir_len_le(4)]
    [ir_pool: concatenated IRs]
    [proofs: entry_cnt × proof_depth × 32 bytes]

Pure Python 3, no third-party deps — runs on any host the dev test
loop can already reach.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


HEADER_MAGIC = b"P730"
HEADER_LEN = 32
ENTRY_LEN = 72


def _parse_address(s: str) -> bytes:
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 40:
        raise ValueError(f"bad address (expected 40 hex chars): {s!r}")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"bad address hex: {s!r}") from exc


def _read_header(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError(f"catalog too short: {len(blob)} < {HEADER_LEN}")
    if blob[:4] != HEADER_MAGIC:
        raise ValueError(f"bad magic: {blob[:4]!r} != {HEADER_MAGIC!r}")
    (version,) = struct.unpack_from("<I", blob, 4)
    (flags,) = struct.unpack_from("<I", blob, 8)
    (entry_cnt,) = struct.unpack_from("<I", blob, 12)
    (ir_pool_off,) = struct.unpack_from("<I", blob, 16)
    (ir_pool_size,) = struct.unpack_from("<I", blob, 20)
    (proof_depth,) = struct.unpack_from("<I", blob, 24)
    (proofs_off,) = struct.unpack_from("<I", blob, 28)
    if version != 1:
        raise ValueError(f"unknown catalog version: {version}")
    return {
        "version": version,
        "flags": flags,
        "entry_cnt": entry_cnt,
        "ir_pool_off": ir_pool_off,
        "ir_pool_size": ir_pool_size,
        "proof_depth": proof_depth,
        "proofs_off": proofs_off,
    }


def _entry(blob: bytes, i: int) -> dict:
    """Decode entry `i` from the catalog."""
    base = HEADER_LEN + i * ENTRY_LEN
    (chain_id,) = struct.unpack_from("<Q", blob, base)
    contract = bytes(blob[base + 8 : base + 28])
    primary_type_hash = bytes(blob[base + 28 : base + 60])
    ctx_kind = blob[base + 60]
    (ir_off,) = struct.unpack_from("<I", blob, base + 64)
    (ir_len,) = struct.unpack_from("<I", blob, base + 68)
    return {
        "leaf_index": i,
        "chain_id": chain_id,
        "contract": contract,
        "primary_type_hash": primary_type_hash,
        "ctx_kind": ctx_kind,
        "ir_off": ir_off,
        "ir_len": ir_len,
    }


def _find_first(
    blob: bytes,
    hdr: dict,
    chain_id: int,
    contract: bytes,
) -> int | None:
    """Linear scan for the first entry whose (chain_id, contract)
    matches. The catalog is sorted, so binary search is possible —
    but with at most a few hundred entries the linear pass keeps the
    stub trivially auditable. Returns the leaf index or None.
    """
    for i in range(hdr["entry_cnt"]):
        e = _entry(blob, i)
        if e["chain_id"] == chain_id and e["contract"] == contract:
            return i
    return None


def build_trailer(blob: bytes, chain_id: int, contract: bytes) -> bytes:
    """Produce the trailer payload bytes for one `(chain_id, contract)`."""
    hdr = _read_header(blob)
    idx = _find_first(blob, hdr, chain_id, contract)
    if idx is None:
        raise SystemExit(
            f"no descriptor for chain={chain_id} contract=0x{contract.hex()}"
        )
    entry = _entry(blob, idx)
    proof_depth = hdr["proof_depth"]

    ir_bytes = bytes(
        blob[
            hdr["ir_pool_off"] + entry["ir_off"]
            : hdr["ir_pool_off"] + entry["ir_off"] + entry["ir_len"]
        ]
    )
    if len(ir_bytes) != entry["ir_len"]:
        raise SystemExit(f"truncated catalog: ir slice mismatch for leaf {idx}")

    proof_base = hdr["proofs_off"] + idx * proof_depth * 32
    proof_bytes = bytes(blob[proof_base : proof_base + proof_depth * 32])
    if len(proof_bytes) != proof_depth * 32:
        raise SystemExit(f"truncated catalog: proof for leaf {idx}")

    out = bytearray()
    out += struct.pack(">H", len(ir_bytes))
    out += ir_bytes
    out += struct.pack(">I", idx)
    out += struct.pack(">I", proof_depth)
    out += proof_bytes
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--db",
        default="tools/companion-stub/erc7730_db.bin",
        help="path to the ERC-7730 catalog blob",
    )
    ap.add_argument("--chain", type=int, help="EIP-155 chain id")
    ap.add_argument("--contract", help="0x-prefixed contract address")
    ap.add_argument(
        "--out",
        help="optional output file; default stdout (binary)",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="instead of emitting, print the (chain, contract) pairs in the catalog",
    )
    args = ap.parse_args()

    blob = Path(args.db).read_bytes()

    if args.list:
        hdr = _read_header(blob)
        print(
            f"# {hdr['entry_cnt']} entries, "
            f"proof_depth={hdr['proof_depth']}, "
            f"ir_pool={hdr['ir_pool_size']} B"
        )
        for i in range(hdr["entry_cnt"]):
            e = _entry(blob, i)
            ctx = {1: "Contract", 2: "EIP712"}.get(e["ctx_kind"], "?")
            print(
                f"  [{i:3d}] chain={e['chain_id']:>5} "
                f"contract=0x{e['contract'].hex()} "
                f"ctx={ctx} ir_len={e['ir_len']}"
            )
        return 0

    if args.chain is None or args.contract is None:
        ap.error("--chain and --contract are required unless --list is given")
    contract = _parse_address(args.contract)
    trailer = build_trailer(blob, args.chain, contract)

    if args.out:
        Path(args.out).write_bytes(trailer)
        print(
            f"wrote {len(trailer)} B trailer (chain={args.chain} "
            f"contract=0x{contract.hex()}) to {args.out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.buffer.write(trailer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
