#!/usr/bin/env python3
"""Exercise CMD_SIGN_USEROP_BATCH (INS 0x32) over USB HID on a live pq1 board.

A batch is ONE UserOp carrying several inner transactions, confirmed once and
signed once — not several UserOps. The companion turns the response into
`executeBatchWithOffchainCount(ownerIndex, newOffchainCount, targets, values,
datas)` calldata at the base nonce (docs/companion/companion-batch-sign-integration.md).

Request payload (wire v2, big-endian):
  [0..8) chain_id | [8..12) flags | [12..32) sender | [32..52) entry_point
  [52..84) nonce  | [84..244) five u256 gas fields | [244..276) sha256(paymasterAndData)
  [276] wire_version = 2 | [277] batch_count
  then batch_count × { to(20) | value(32) | data_len(2) | data }
  then [u8 trailer_count]  (0 here: no clear-signing trailers)

Response is the same shape as the single-tx path:
  [count(8)][init_len(4)][init][type1_len(4)][type1][type2_len(4)][type2]

Writes <out>.json for tools/fork_submit_userop.py, which rebuilds the batch
calldata with an independent encoder and submits it through EntryPoint v0.6.

Usage: ./hid_sign_batch.py --chain 8453 [--nonce N]
                           [--tx 0xTO:WEI:0xDATA ...]   (default: two ETH sends)
"""
from __future__ import annotations

import argparse
import json
import sys

from hid_sign import (
    ENTRY_POINT_V06,
    INS_GET_WALLET_ADDRESS,
    SHA256_EMPTY,
    SIG_WRAPPER_LEN,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
    u256,
)
from hid_smoke import SW_OK, HidRaw, find_hidraw, send

INS_V2_SIGN_USEROP_BATCH = 0x32
WIRE_VERSION = 2
MAX_BATCH_TXS = 4


def parse_tx(spec: str) -> tuple[bytes, int, bytes]:
    to, value, *rest = spec.split(":")
    data = bytes.fromhex(rest[0].removeprefix("0x")) if rest and rest[0] else b""
    return bytes.fromhex(to.removeprefix("0x")), int(value), data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", type=int, required=True)
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--nonce", type=int, default=0)
    ap.add_argument("--tx", action="append", metavar="TO:WEI[:DATA]",
                    help="inner transaction; repeat up to 4 times")
    ap.add_argument("--call-gas", type=int, default=400_000)
    ap.add_argument("--ver-gas", type=int, default=1_000_000)
    ap.add_argument("--pre-ver-gas", type=int, default=200_000)
    ap.add_argument("--max-fee", type=int, default=1_000_000_000)
    ap.add_argument("--max-prio", type=int, default=100_000_000)
    ap.add_argument("--out", default="batch_response.bin")
    args = ap.parse_args()

    specs = args.tx or ["0x" + "11" * 20 + ":1000000000000000",
                        "0x" + "22" * 20 + ":2000000000000000"]
    if not 1 <= len(specs) <= MAX_BATCH_TXS:
        print(f"!! batch_count must be 1..{MAX_BATCH_TXS}, got {len(specs)}")
        return 2
    txs = [parse_tx(s) for s in specs]

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — board not enumerated")
        return 2
    hid = HidRaw(node, 12.0)
    try:
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        if sw != SW_OK or len(data) != 20:
            print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x})")
            return 1
        sender = data

        flags = (args.slot & 0x3F_FFFF)  # account 0, no INIT_CODE, no REGISTER_SLOT
        payload = b"".join([
            u64(args.chain), u32(flags), sender, ENTRY_POINT_V06, u256(args.nonce),
            u256(args.call_gas), u256(args.ver_gas), u256(args.pre_ver_gas),
            u256(args.max_fee), u256(args.max_prio), SHA256_EMPTY,
            bytes([WIRE_VERSION]), bytes([len(txs)]),
        ])
        assert len(payload) == 278, len(payload)
        for to, value, d in txs:
            payload += to + u256(value) + u16(len(d)) + d
        payload += bytes([0])  # empty TLV trailer list

        print(f"==> wallet 0x{sender.hex()}  chain {args.chain}  slot {args.slot}  "
              f"nonce {args.nonce}  {len(txs)} inner txs  payload {len(payload)} B")
        for i, (to, value, d) in enumerate(txs):
            print(f"    tx[{i}] to=0x{to.hex()} value={value} data={len(d)} B")
        hid.timeout_s = 60.0
        sw, resp = send_chained(hid, INS_V2_SIGN_USEROP_BATCH, payload)
    finally:
        hid.close()

    print(f"    SW=0x{sw:04x}  response={len(resp)} B")
    with open(args.out, "wb") as fh:
        fh.write(resp)
    want = 8 + 4 + 4 + 4 + SIG_WRAPPER_LEN
    if sw != SW_OK or len(resp) != want:
        print(f"=== FAIL === device refused or unexpected length (want {want})")
        return 1

    count = int.from_bytes(resp[0:8], "big")
    init_len = int.from_bytes(resp[8:12], "big")
    off = 12 + init_len
    t1_len = int.from_bytes(resp[off:off + 4], "big")
    off += 4 + t1_len
    t2_len = int.from_bytes(resp[off:off + 4], "big")
    off += 4
    t2 = resp[off:off + t2_len]
    owner_index = int.from_bytes(t2[0:32], "big")
    print(f"    new_offchain_count={count}  init_len={init_len}  type1_len={t1_len}  "
          f"type2_len={t2_len}  ownerIndex={owner_index}")
    if init_len or t1_len or t2_len != SIG_WRAPPER_LEN or owner_index != args.slot + 1:
        print("=== FAIL === unexpected response shape for a normal-mode batch")
        return 1

    rec = {
        "kind": "batch",
        "chain_id": args.chain,
        "slot": args.slot,
        "sender": "0x" + sender.hex(),
        "entryPoint": "0x" + ENTRY_POINT_V06.hex(),
        "nonce": args.nonce,
        "callGasLimit": args.call_gas,
        "verificationGasLimit": args.ver_gas,
        "preVerificationGas": args.pre_ver_gas,
        "maxFeePerGas": args.max_fee,
        "maxPriorityFeePerGas": args.max_prio,
        "paymasterAndData": "0x",
        "newOffchainCount": count,
        "initCode": "0x",
        "type2Wrapper": "0x" + t2.hex(),
        "txs": [{"to": "0x" + to.hex(), "value": v, "data": "0x" + d.hex()} for to, v, d in txs],
    }
    with open(args.out + ".json", "w") as fh:
        json.dump(rec, fh, indent=1)
    print(f"    record -> {args.out}.json")
    print("=== PASS === device signed a well-formed batch UserOp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
