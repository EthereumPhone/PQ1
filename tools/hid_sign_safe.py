#!/usr/bin/env python3
"""Drive the Safe `approveHash` clear-sign flow over USB HID on a live pq1.

Host twin of QEMU e2e Scenario 5 (`nonsecure/src/e2e_test.rs`): builds a
synthetic SafeTx whose inner call is `IERC20.transfer(recipient, amount)` on
`--token`, computes the Safe EIP-712 `safeTxHash` exactly as the secure world
does, and sends a normal-mode UserOp whose inner calldata is
`approveHash(safeTxHash)` on the Safe, with the `safe_v1` trailer
(canonical(281) || u16 raw_data_len || raw_data) appended so the firmware can
re-derive the hash and clear-sign the Safe screens.

With a `ui-px` image the device walks the pixel Safe flow
(`APPROVE SAFE TX?` hero → NETWORK → SAFE ACCT → TX INFO → ... → Confirm?);
the human drives it with the two buttons. Any refusal comes back as a
non-0x9000 SW; a signed reply is parsed structurally like hid_sign.py.

Usage:
  tools/hid_sign_safe.py --confirm-timeout 300            # Base, USDC 250.0, nonce 17
  tools/hid_sign_safe.py --chain 1 --safe 0x... --token 0x... --amount 1000000
  tools/hid_sign_safe.py --safe-value 1000000000000000     # inner ETH value on the SafeTx too
  tools/hid_sign_safe.py --decline-expected                # exit 0 when the device refuses
"""
from __future__ import annotations

import argparse
import json
import sys

from Crypto.Hash import keccak as _keccak

from hid_sign import (
    C10_SIG_LEN,
    ENTRY_POINT_V06,
    INS_GET_WALLET_ADDRESS,
    INS_SIGN_USEROP,
    SHA256_EMPTY,
    SIG_WRAPPER_LEN,
    SIGN_USEROP_HEADER_LEN,
    check,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
    u256,
)
from hid_sign import FAILURES
from hid_smoke import HidRaw, SW_OK, find_hidraw, send

# ── proto/src/lib.rs ──────────────────────────────────────────────────────
SAFE_V1_CANONICAL_LEN = 281
SAFE_OFF_CHAIN_ID = 0
SAFE_OFF_SAFE_ADDRESS = 8
SAFE_OFF_TO = 28
SAFE_OFF_VALUE = 48
SAFE_OFF_DATA_HASH = 80
SAFE_OFF_OPERATION = 112
SAFE_OFF_SAFE_TX_GAS = 113
SAFE_OFF_BASE_GAS = 145
SAFE_OFF_GAS_PRICE = 177
SAFE_OFF_GAS_TOKEN = 209
SAFE_OFF_REFUND_RECEIVER = 229
SAFE_OFF_NONCE = 249
APPROVE_HASH_SELECTOR = bytes.fromhex("d4d9bdcd")
ERC20_TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")

# Defaults mirror e2e Scenario 5 (250 USDC to 0xab..ab, Safe nonce 17), but
# on Base so the NETWORK screen has a chain mark and the token is the real
# Base USDC.
CHAIN_ID = 8453
SAFE_ADDRESS = "0x5afe000000000000000000000000000000000001"
TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
RECIPIENT = "0x" + "ab" * 20
AMOUNT = 250_000_000
SAFE_NONCE = 17

CALL_GAS = 120_000
VER_GAS = 800_000
PRE_VER_GAS = 150_000
MAX_FEE = 1_000_000_000
MAX_PRIORITY_FEE = 100_000_000


def keccak256(b: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


SAFE_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)")
SAFE_TX_TYPEHASH = keccak256(
    b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
    b"uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
)


def addr(s: str) -> bytes:
    b = bytes.fromhex(s[2:] if s.startswith("0x") else s)
    assert len(b) == 20, f"bad address {s}"
    return b


def build_safe_canonical(chain_id: int, safe: bytes, to: bytes, value: int,
                         raw_data: bytes, nonce: int, operation: int) -> bytes:
    c = bytearray(SAFE_V1_CANONICAL_LEN)
    c[SAFE_OFF_CHAIN_ID:SAFE_OFF_CHAIN_ID + 8] = u64(chain_id)
    c[SAFE_OFF_SAFE_ADDRESS:SAFE_OFF_SAFE_ADDRESS + 20] = safe
    c[SAFE_OFF_TO:SAFE_OFF_TO + 20] = to
    c[SAFE_OFF_VALUE:SAFE_OFF_VALUE + 32] = u256(value)
    c[SAFE_OFF_DATA_HASH:SAFE_OFF_DATA_HASH + 32] = keccak256(raw_data)
    c[SAFE_OFF_OPERATION] = operation
    c[SAFE_OFF_NONCE:SAFE_OFF_NONCE + 32] = u256(nonce)
    return bytes(c)


def compute_safe_tx_hash(c: bytes) -> bytes:
    """Mirror of secure/src/tx/eip712/safe::compute_safe_tx_hash."""
    domain = keccak256(
        SAFE_DOMAIN_TYPEHASH
        + b"\0" * 24 + c[SAFE_OFF_CHAIN_ID:SAFE_OFF_CHAIN_ID + 8]
        + b"\0" * 12 + c[SAFE_OFF_SAFE_ADDRESS:SAFE_OFF_SAFE_ADDRESS + 20]
    )
    struct_hash = keccak256(
        SAFE_TX_TYPEHASH
        + b"\0" * 12 + c[SAFE_OFF_TO:SAFE_OFF_TO + 20]
        + c[SAFE_OFF_VALUE:SAFE_OFF_VALUE + 32]
        + c[SAFE_OFF_DATA_HASH:SAFE_OFF_DATA_HASH + 32]
        + b"\0" * 31 + bytes([c[SAFE_OFF_OPERATION]])
        + c[SAFE_OFF_SAFE_TX_GAS:SAFE_OFF_SAFE_TX_GAS + 32]
        + c[SAFE_OFF_BASE_GAS:SAFE_OFF_BASE_GAS + 32]
        + c[SAFE_OFF_GAS_PRICE:SAFE_OFF_GAS_PRICE + 32]
        + b"\0" * 12 + c[SAFE_OFF_GAS_TOKEN:SAFE_OFF_GAS_TOKEN + 20]
        + b"\0" * 12 + c[SAFE_OFF_REFUND_RECEIVER:SAFE_OFF_REFUND_RECEIVER + 20]
        + c[SAFE_OFF_NONCE:SAFE_OFF_NONCE + 32]
    )
    return keccak256(b"\x19\x01" + domain + struct_hash)


def build_payload(sender: bytes, req: dict, inner_data: bytes,
                  canonical: bytes, raw_data: bytes) -> bytes:
    head = b"".join([
        u64(req["chain_id"]),
        u32(req["flags"]),
        sender,
        ENTRY_POINT_V06,
        u256(req["nonce"]),
        u256(req["callGasLimit"]),
        u256(req["verificationGasLimit"]),
        u256(req["preVerificationGas"]),
        u256(req["maxFeePerGas"]),
        u256(req["maxPriorityFeePerGas"]),
        SHA256_EMPTY,
        addr(req["to"]),
        u256(req["value"]),
        u16(len(inner_data)),
    ])
    assert len(head) == SIGN_USEROP_HEADER_LEN
    # Trailer framing (cmd_sign_userop.rs 5a..5a-bis): erc20=absent,
    # reserved=absent, cow=absent, safe_v1=present. No selector trailer and
    # no names count byte — the parser treats end-of-buffer as absent/0.
    safe_payload = canonical + u16(len(raw_data)) + raw_data
    trailers = u16(0) + u16(0) + u16(0) + u16(len(safe_payload)) + safe_payload
    return head + inner_data + trailers


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sign_safe_response.bin")
    ap.add_argument("--chain", type=int, default=CHAIN_ID)
    ap.add_argument("--safe", default=SAFE_ADDRESS, help="Safe address (verifyingContract + UserOp target)")
    ap.add_argument("--token", default=TOKEN, help="ERC-20 the SafeTx calls transfer() on")
    ap.add_argument("--recipient", default=RECIPIENT)
    ap.add_argument("--amount", type=int, default=AMOUNT, help="raw token units")
    ap.add_argument("--safe-nonce", type=int, default=SAFE_NONCE)
    ap.add_argument("--safe-value", type=int, default=0, help="SafeTx.value in wei (inner ETH)")
    ap.add_argument("--nonce", type=int, default=0, help="UserOp nonce")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--confirm-timeout", type=float, default=300.0)
    ap.add_argument("--decline-expected", action="store_true",
                    help="treat a device refusal (SW != 0x9000) as the PASS outcome")
    args = ap.parse_args()

    safe = addr(args.safe)
    token = addr(args.token)
    recipient = addr(args.recipient)
    raw_data = ERC20_TRANSFER_SELECTOR + b"\0" * 12 + recipient + u256(args.amount)
    canonical = build_safe_canonical(args.chain, safe, token, args.safe_value,
                                     raw_data, args.safe_nonce, 0)
    safe_tx_hash = compute_safe_tx_hash(canonical)
    inner_data = APPROVE_HASH_SELECTOR + safe_tx_hash

    req = {
        "chain_id": args.chain,
        "flags": args.slot & 0x3F_FFFF,
        "nonce": args.nonce,
        "callGasLimit": CALL_GAS,
        "verificationGasLimit": VER_GAS,
        "preVerificationGas": PRE_VER_GAS,
        "maxFeePerGas": MAX_FEE,
        "maxPriorityFeePerGas": MAX_PRIORITY_FEE,
        "paymasterAndData": "0x",
        "to": "0x" + safe.hex(),
        "value": 0,
        "data": "0x" + inner_data.hex(),
        "safeTx": {
            "safe": "0x" + safe.hex(),
            "to": "0x" + token.hex(),
            "value": args.safe_value,
            "data": "0x" + raw_data.hex(),
            "operation": 0,
            "nonce": args.safe_nonce,
            "safeTxHash": "0x" + safe_tx_hash.hex(),
        },
    }
    print(f"==> SafeTx: transfer({args.recipient}, {args.amount}) on token 0x{token.hex()}")
    print(f"    safe=0x{safe.hex()} chain={args.chain} nonce={args.safe_nonce} value={args.safe_value}")
    print(f"    safeTxHash = 0x{safe_tx_hash.hex()}")

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — unlock the device first (USB enumerates after PIN)")
        return 2
    print(f"==> device node: {node}")
    hid = HidRaw(node, 12.0)
    try:
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        if sw != SW_OK or len(data) != 20:
            print(f"!! cannot get sender address (SW=0x{sw:04x}, {len(data)} B) — aborting")
            return 1
        sender = data
        print(f"    sender = 0x{sender.hex()}")

        payload = build_payload(sender, req, inner_data, canonical, raw_data)
        hid.timeout_s = args.confirm_timeout
        print(f"\n==> INS 0x30 SIGN_USEROP — {len(payload)} B payload; confirm on the DEVICE "
              f"(up to {args.confirm_timeout:.0f}s)")
        sw, resp = send_chained(hid, INS_SIGN_USEROP, payload)
        print(f"    SW=0x{sw:04x}  response={len(resp)} B")
        if resp:
            with open(args.out, "wb") as fh:
                fh.write(resp)
            print(f"    raw response saved -> {args.out}")

        if args.decline_expected:
            check("device refused (decline expected)", sw != SW_OK, True)
            return 1 if FAILURES else 0

        check("SW", sw, SW_OK)
        if sw != SW_OK:
            print("!! device refused the sign (declined on the screen, or a page/verify gate fired)")
            return 1
        expected_total = 8 + 4 + 0 + 4 + 4 + SIG_WRAPPER_LEN
        check("total length", len(resp), expected_total)
        count = int.from_bytes(resp[0:8], "big")
        init_len = int.from_bytes(resp[8:12], "big")
        check("init_code_len", init_len, 0)
        off = 12 + init_len
        t1_len = int.from_bytes(resp[off:off + 4], "big")
        check("type1_len", t1_len, 0)
        off += 4 + t1_len
        t2_len = int.from_bytes(resp[off:off + 4], "big")
        check("type2_len", t2_len, SIG_WRAPPER_LEN)
        off += 4
        t2 = resp[off:off + t2_len]
        if len(t2) == SIG_WRAPPER_LEN:
            owner_index = int.from_bytes(t2[0:32], "big")
            print(f"    ..    wrapper.ownerIndex = {owner_index}   new_offchain_count = {count}")
            check("wrapper sig length", int.from_bytes(t2[64:96], "big"), C10_SIG_LEN)
            sig = t2[96:96 + C10_SIG_LEN]
            check("sig is not all zeros", sum(1 for b in sig if b) > C10_SIG_LEN // 2, True)
        rec = dict(req)
        rec.update({"sender": "0x" + sender.hex(), "entryPoint": "0x" + ENTRY_POINT_V06.hex(),
                    "newOffchainCount": count, "type2Wrapper": "0x" + t2.hex()})
        with open(args.out + ".json", "w") as fh:
            json.dump(rec, fh, indent=1)
        print(f"    request + parsed response -> {args.out}.json")
    except TimeoutError as e:
        print(f"\n!! TIMEOUT: {e}")
        return 2
    finally:
        hid.close()

    print()
    if FAILURES:
        print(f"=== FAIL === {len(FAILURES)} check(s): " + "; ".join(FAILURES))
        return 1
    print("=== PASS === Safe approveHash clear-signed over USB (Type-2 wrapper well-formed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
