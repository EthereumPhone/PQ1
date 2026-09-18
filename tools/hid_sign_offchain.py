#!/usr/bin/env python3
"""Exercise CMD_SIGN_OFFCHAIN (INS 0x62) over USB HID on a live pq1 board.

EIP-1271 / ERC-6492 off-chain signatures. The FIRMWARE, not this client,
applies the wallet's Solady PersonalSign replay-safe nesting to the hash; this
client only sends the dapp-level input:
  * --kind raw32:    32 opaque bytes H (what a dapp passes to isValidSignature)
  * --kind personal: a UTF-8 message; the firmware applies EIP-191, then nests

Two response layouts, chosen by --deployed / --counterfactual:
  * deployed        -> [count u64 BE][C10 sig 4008]        = 4016 B
  * counterfactual  -> [count u64 BE][ERC-6492 blob 8608]  = 8616 B (slot 0 only)

Writes the raw response and a JSON record (<out>.json) of the request and the
parsed response, for tools/fork_verify_offchain.py.

Wire (docs/companion/usb-protocol-v2.md §0x62, proto SIGN_OFFCHAIN_INPUT_*):
  header 17 B = account(1) | chain(8 BE) | slot(4 BE) | kind(1) | payload_len(2 BE) | flags(1)

Usage: ./hid_sign_offchain.py --chain 8453 (--deployed|--counterfactual)
                              (--raw32 HEX | --personal TEXT) [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import sys

from hid_sign import (
    INS_GET_WALLET_ADDRESS,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
)
from hid_smoke import SW_OK, HidRaw, find_hidraw, send

INS_V2_SIGN_OFFCHAIN = 0x62
OFFCHAIN_KIND_RAW32 = 0
OFFCHAIN_KIND_PERSONAL_SIGN = 1
OFFCHAIN_FLAG_ACCOUNT_DEPLOYED = 0x01
C10_SIG_LEN = 4008
EIP6492_BLOB_LEN = 8608
EIP6492_MAGIC = bytes.fromhex("6492649264926492649264926492649264926492649264926492649264926492")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", type=int, required=True)
    ap.add_argument("--slot", type=int, default=0)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--deployed", action="store_true")
    mode.add_argument("--counterfactual", action="store_true")
    kind = ap.add_mutually_exclusive_group(required=True)
    kind.add_argument("--raw32", help="32-byte hex hash H")
    kind.add_argument("--personal", help="UTF-8 message")
    ap.add_argument("--out", default="offchain_response.bin")
    args = ap.parse_args()

    if args.raw32 is not None:
        k = OFFCHAIN_KIND_RAW32
        payload = bytes.fromhex(args.raw32.removeprefix("0x"))
        if len(payload) != 32:
            print(f"!! --raw32 must be exactly 32 bytes, got {len(payload)}")
            return 2
    else:
        k = OFFCHAIN_KIND_PERSONAL_SIGN
        payload = args.personal.encode()
    flags = OFFCHAIN_FLAG_ACCOUNT_DEPLOYED if args.deployed else 0
    want_len = 8 + (C10_SIG_LEN if args.deployed else EIP6492_BLOB_LEN)

    req = (bytes([0]) + u64(args.chain) + u32(args.slot) + bytes([k])
           + u16(len(payload)) + bytes([flags]) + payload)
    assert len(req) == 17 + len(payload)

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — board not enumerated")
        return 2
    hid = HidRaw(node, 12.0)
    try:
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        if sw != SW_OK or len(data) != 20:
            print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x}, {len(data)} B)")
            return 1
        sender = data
        print(f"==> wallet 0x{sender.hex()}  chain {args.chain}  slot {args.slot}  "
              f"kind {'raw32' if k == 0 else 'personal'}  "
              f"{'deployed' if args.deployed else 'counterfactual (ERC-6492)'}")
        hid.timeout_s = 45.0
        sw, resp = send_chained(hid, INS_V2_SIGN_OFFCHAIN, req)
    finally:
        hid.close()

    print(f"    SW=0x{sw:04x}  response={len(resp)} B (want {want_len})")
    with open(args.out, "wb") as fh:
        fh.write(resp)
    if sw != SW_OK or len(resp) != want_len:
        print("=== FAIL === device refused or returned an unexpected length")
        return 1

    count = int.from_bytes(resp[0:8], "big")
    body = resp[8:]
    rec = {
        "chain_id": args.chain,
        "slot": args.slot,
        "kind": "raw32" if k == 0 else "personal",
        "payload": "0x" + payload.hex(),
        "message": args.personal,
        "accountDeployed": bool(args.deployed),
        "sender": "0x" + sender.hex(),
        "newLocalOffchainCount": count,
    }
    if args.deployed:
        rec["c10Sig"] = "0x" + body.hex()
        nonzero = sum(1 for b in body if b)
        print(f"    local_offchain_count={count}  sig nonzero {nonzero}/{C10_SIG_LEN}")
    else:
        magic_ok = body[-32:] == EIP6492_MAGIC
        print(f"    local_offchain_count={count}  ERC-6492 magic suffix {'OK' if magic_ok else 'MISSING'}")
        if not magic_ok:
            print("=== FAIL === counterfactual blob lacks the ERC-6492 magic suffix")
            return 1
        rec["erc6492Blob"] = "0x" + body.hex()
    with open(args.out + ".json", "w") as fh:
        json.dump(rec, fh, indent=1)
    print(f"    record -> {args.out}.json")
    print("=== PASS === structurally valid off-chain response (verify on a fork)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
