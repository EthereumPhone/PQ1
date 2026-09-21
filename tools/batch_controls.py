#!/usr/bin/env python3
"""Device-side refusal controls for CMD_SIGN_USEROP_BATCH (INS 0x32).

The accept path is proven (hid_sign_batch.py + fork_submit_userop.py). A batch
parser's risk is on the reject side: a miscounted member, a stale wire version,
a trailer routed at a member that does not exist, or bytes past the end. Each
case below changes ONE thing from a request the device signs, so a refusal can
only be explained by that change.

SW 0x9000 = signed. Anything else = refused (all refusals surface as the
generic 0x6f00 on the wire, so this shows THAT the device refused, not which
check fired).

Needs an `e2e-test` image (auto-confirm) and slot 0 registered for the chain.

Usage: ./batch_controls.py --chain 8453 [--nonce N]
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hid_sign import (  # noqa: E402
    ENTRY_POINT_V06, INS_GET_WALLET_ADDRESS, SHA256_EMPTY,
    drain_response, send_chained, u16, u32, u64, u256,
)
from hid_smoke import SW_OK, HidRaw, find_hidraw, send  # noqa: E402

INS_V2_SIGN_USEROP_BATCH = 0x32
WIRE_VERSION = 2
TX_A = (bytes([0x11] * 20), 1_000_000_000_000_000, b"")
TX_B = (bytes([0x22] * 20), 2_000_000_000_000_000, b"")


def build(sender, chain, nonce, txs, *, wire_version=WIRE_VERSION, count_override=None,
          trailers=b"\x00", trailing=b"", slot=0):
    head = b"".join([
        u64(chain), u32(slot), sender, ENTRY_POINT_V06, u256(nonce),
        u256(400_000), u256(1_000_000), u256(200_000),
        u256(1_000_000_000), u256(100_000_000), SHA256_EMPTY,
        bytes([wire_version]),
        bytes([len(txs) if count_override is None else count_override]),
    ])
    body = b"".join(to + u256(v) + u16(len(d)) + d for to, v, d in txs)
    return head + body + trailers + trailing


def fire(label, payload, expect_ok):
    node = find_hidraw()
    if node is None:
        print(f"  {label:<52} !! device absent")
        return False
    hid = HidRaw(node, 60.0)
    try:
        sw, _ = send_chained(hid, INS_V2_SIGN_USEROP_BATCH, payload)
    except Exception as e:
        print(f"  {label:<52} EXCEPTION {type(e).__name__}")
        return False
    finally:
        hid.close()
    signed = sw == SW_OK
    ok = signed == expect_ok
    print(f"  {label:<52} SW=0x{sw:04x} {'signed' if signed else 'REFUSED':<8} "
          f"{'OK' if ok else '!! UNEXPECTED'}")
    time.sleep(1.5)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", type=int, required=True)
    ap.add_argument("--nonce", type=int, default=0)
    args = ap.parse_args()

    hid = HidRaw(find_hidraw(), 12.0)
    try:
        sw, d = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, d = drain_response(hid, sw, d)
        sender = d
        print(f"wallet 0x{sender.hex()}  chain {args.chain}  nonce {args.nonce}\n")
    finally:
        hid.close()

    B = lambda **kw: build(sender, args.chain, args.nonce, kw.pop("txs", [TX_A, TX_B]), **kw)
    r = []
    r.append(fire("POSITIVE: 2-member batch", B(), True))
    r.append(fire("wire_version = 1 (stale companion)", B(wire_version=1), False))
    r.append(fire("wire_version = 3 (future)", B(wire_version=3), False))
    r.append(fire("batch_count = 0", B(txs=[], count_override=0), False))
    r.append(fire("batch_count = 5 (> MAX_BATCH_TXS 4)", B(count_override=5), False))
    r.append(fire("batch_count says 2, only 1 member present", B(txs=[TX_A], count_override=2), False))
    r.append(fire("trailing byte past the trailer list", B(trailing=b"\x00"), False))
    # Trailer kinds 1..=7 must route at a member that exists; kind 1 (ERC-20)
    # at tx_idx 5 is out of range for a 2-member batch.
    r.append(fire("trailer routed at tx_idx 5 (out of range)",
                  B(trailers=bytes([1, 1, 5]) + u16(4) + b"\xde\xad\xbe\xef"), False))
    r.append(fire("sender not the wallet address", build(bytes([0x33] * 20), args.chain,
                                                         args.nonce, [TX_A, TX_B]), False))
    r.append(fire("POSITIVE again (session still healthy)", B(), True))

    print(f"\n{'=== PASS ===' if all(r) else '=== FAIL ==='} {sum(r)}/{len(r)} as expected")
    return 0 if all(r) else 1


if __name__ == "__main__":
    sys.exit(main())
