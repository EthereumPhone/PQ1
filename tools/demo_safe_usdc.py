#!/usr/bin/env python3
"""Demo driver: wait for an unlocked pq1, then send a Safe USDC transfer.

Polls the USB HID bus until the device enumerates (it does so after PIN
unlock) and GET_STATUS reports UNLOCKED, then sends the Safe `approveHash`
UserOp for an ERC-20 `transfer(recipient, amount)` — the same request as
`hid_sign_safe.py` — so the device clear-signs the Safe flow on its screen
(APPROVE SAFE TX? → NETWORK → SAFE ACCT → TX INFO → … → Confirm?).

Start it BEFORE unlocking the device; it waits quietly. Confirm with the
two-button chord on the device (hold-left declines).

Usage:
  tools/demo_safe_usdc.py                       # Base USDC, 250.0 → 0xab..ab, Safe nonce 17
  tools/demo_safe_usdc.py --amount 1500000000   # 1500.0 USDC (6 decimals)
  tools/demo_safe_usdc.py --repeat              # after each take, wait and run again
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "companion-stub"))
from db_trailers import build_erc20_bundle  # noqa: E402

from hid_sign import (
    ENTRY_POINT_V06,
    SHA256_EMPTY,
    C10_SIG_LEN,
    INS_GET_WALLET_ADDRESS,
    INS_SIGN_USEROP,
    SIG_WRAPPER_LEN,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
    u256,
)
from hid_sign_safe import (
    AMOUNT,
    APPROVE_HASH_SELECTOR,
    CALL_GAS,
    CHAIN_ID,
    ERC20_TRANSFER_SELECTOR,
    MAX_FEE,
    MAX_PRIORITY_FEE,
    PRE_VER_GAS,
    RECIPIENT,
    SAFE_ADDRESS,
    SAFE_NONCE,
    TOKEN,
    VER_GAS,
    addr,
    build_safe_canonical,
    compute_safe_tx_hash,
)
from hid_smoke import INS_GET_STATUS, SW_OK, HidRaw, find_hidraw, send

USDC_DECIMALS = 6
ERC20_DB_BLOB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "companion-stub", "erc20_db.bin")


def build_payload_with_erc20(sender: bytes, req: dict, inner_data: bytes,
                             canonical: bytes, raw_data: bytes, erc20_bundle: bytes) -> bytes:
    """Same wire layout as hid_sign_safe.build_payload, but with the ERC-20
    metadata bundle present in trailer slot 1 so the device can Merkle-verify
    the token's name/symbol/decimals against its pinned ERC20_DB_ROOT and
    clear-sign the inner transfer instead of rendering "token unknown"."""
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
    # Trailers (cmd_sign_userop.rs §5): erc20 | reserved | cow | safe_v1.
    safe_payload = canonical + u16(len(raw_data)) + raw_data
    trailers = (u16(len(erc20_bundle)) + erc20_bundle
                + u16(0) + u16(0)
                + u16(len(safe_payload)) + safe_payload)
    return head + inner_data + trailers


def fmt_usdc(raw: int) -> str:
    whole, frac = divmod(raw, 10 ** USDC_DECIMALS)
    return f"{whole}.{frac:0{USDC_DECIMALS}d}".rstrip("0").rstrip(".") if frac else f"{whole}.0"


def wait_for_unlocked(poll_s: float) -> HidRaw:
    """Block until the device enumerates and reports UNLOCKED; return an open handle."""
    announced_absent = False
    announced_locked = False
    announced_silent = False
    while True:
        node = find_hidraw()
        if node is None:
            if not announced_absent:
                print("... waiting for the pq1 to enumerate over USB (unlock it with the PIN)")
                announced_absent = True
                announced_locked = announced_silent = False
            time.sleep(poll_s)
            continue
        try:
            hid = HidRaw(node, 1.5)
        except OSError as e:
            print(f"... {node} not ready yet ({e.strerror}); retrying")
            time.sleep(poll_s)
            continue
        try:
            sw, d = send(hid, INS_GET_STATUS)
        except (OSError, TimeoutError):
            hid.close()
            if not announced_silent:
                print(f"... device {node} is enumerated but not answering (relocked?); "
                      "enter the PIN on the device")
                announced_silent = True
                announced_absent = announced_locked = False
            time.sleep(poll_s)
            continue
        if sw == SW_OK and len(d) >= 1 and d[0] == 0:
            print(f"==> device {node} is UNLOCKED (remaining PIN attempts: {d[1] if len(d) > 1 else '?'})")
            return hid
        hid.close()
        if not announced_locked:
            print(f"... device {node} present but LOCKED; waiting for PIN unlock")
            announced_locked = True
            announced_absent = announced_silent = False
        time.sleep(poll_s)


def run_take(hid: HidRaw, args: argparse.Namespace, safe_nonce: int, userop_nonce: int) -> str:
    """Send one Safe USDC transfer; return 'signed', 'declined' or 'timeout'."""
    safe = addr(args.safe)
    token = addr(args.token)
    recipient = addr(args.recipient)
    raw_data = ERC20_TRANSFER_SELECTOR + b"\0" * 12 + recipient + u256(args.amount)
    canonical = build_safe_canonical(args.chain, safe, token, 0, raw_data, safe_nonce, 0)
    safe_tx_hash = compute_safe_tx_hash(canonical)
    inner_data = APPROVE_HASH_SELECTOR + safe_tx_hash
    req = {
        "chain_id": args.chain,
        "flags": args.slot & 0x3F_FFFF,
        "nonce": userop_nonce,
        "callGasLimit": CALL_GAS,
        "verificationGasLimit": VER_GAS,
        "preVerificationGas": PRE_VER_GAS,
        "maxFeePerGas": MAX_FEE,
        "maxPriorityFeePerGas": MAX_PRIORITY_FEE,
        "to": "0x" + safe.hex(),
        "value": 0,
    }

    # First call after unlock runs the master keygen (up to a few seconds on
    # silicon); the poll handle is still on its short status timeout.
    hid.timeout_s = 15.0
    sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
    sw, data = drain_response(hid, sw, data)
    if sw != SW_OK or len(data) != 20:
        print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x}); is the device still unlocked?")
        return "error"
    sender = data
    print(f"    wallet  = 0x{sender.hex()}")
    print(f"    Safe    = {args.safe}  (chain {args.chain}, Safe nonce {safe_nonce})")
    print(f"    action  = transfer {fmt_usdc(args.amount)} USDC -> {args.recipient}")
    print(f"    safeTxHash = 0x{safe_tx_hash.hex()}")

    try:
        with open(ERC20_DB_BLOB, "rb") as fh:
            erc20_bundle = build_erc20_bundle(fh.read(), args.chain, token)
        print(f"    ERC-20 proof attached ({len(erc20_bundle)} B) -> device renders the token name")
    except SystemExit as e:
        print(f"!! {e}\n!! no ERC-20 DB entry for this token: the device will show 'token unknown'")
        erc20_bundle = b""
    payload = build_payload_with_erc20(sender, req, inner_data, canonical, raw_data, erc20_bundle)
    hid.timeout_s = args.confirm_timeout
    print(f"\n==> sent SIGN_USEROP ({len(payload)} B). Confirm on the device "
          f"(chord = both buttons; hold-left = decline; {args.confirm_timeout:.0f}s)")
    try:
        sw, resp = send_chained(hid, INS_SIGN_USEROP, payload)
    except TimeoutError:
        print("!! no answer from the device before the timeout")
        return "timeout"
    if sw != SW_OK:
        print(f"    device refused (SW=0x{sw:04x}) — declined on the screen or a gate fired")
        return "declined"

    ok = len(resp) == 8 + 4 + 4 + 4 + SIG_WRAPPER_LEN
    t2 = resp[20:20 + SIG_WRAPPER_LEN] if ok else b""
    ok = ok and int.from_bytes(t2[64:96], "big") == C10_SIG_LEN
    count = int.from_bytes(resp[0:8], "big")
    if not ok:
        print(f"!! SW=0x9000 but the response is malformed ({len(resp)} B)")
        return "error"
    print(f"    SIGNED: Type-2 SPHINCS+C10 wrapper, ownerIndex={int.from_bytes(t2[0:32], 'big')}, "
          f"sig={C10_SIG_LEN} B, new_offchain_count={count}")
    if args.out:
        with open(args.out, "wb") as fh:
            fh.write(resp)
        print(f"    raw response -> {args.out}")
    return "signed"


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chain", type=int, default=CHAIN_ID)
    ap.add_argument("--safe", default=SAFE_ADDRESS)
    ap.add_argument("--token", default=TOKEN, help="ERC-20 address (default Base USDC)")
    ap.add_argument("--recipient", default=RECIPIENT)
    ap.add_argument("--amount", type=int, default=AMOUNT, help="raw units; USDC has 6 decimals")
    ap.add_argument("--safe-nonce", type=int, default=SAFE_NONCE)
    ap.add_argument("--nonce", type=int, default=0, help="UserOp nonce")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--poll", type=float, default=0.5, help="seconds between USB polls")
    ap.add_argument("--settle", type=float, default=1.0, help="seconds to wait after unlock before sending")
    ap.add_argument("--confirm-timeout", type=float, default=300.0)
    ap.add_argument("--repeat", action="store_true", help="run another take after each result")
    ap.add_argument("--pause", type=float, default=5.0, help="seconds between takes with --repeat")
    ap.add_argument("--out", default="", help="save the raw signed response here")
    args = ap.parse_args()

    take = 0
    while True:
        print(f"\n===== take {take + 1} =====")
        hid = wait_for_unlocked(args.poll)
        try:
            time.sleep(args.settle)
            result = run_take(hid, args, args.safe_nonce + take, args.nonce + take)
        except OSError as e:
            print(f"!! USB error: {e}; device relocked or unplugged?")
            result = "error"
        finally:
            hid.close()
        print(f"===== take {take + 1}: {result.upper()} =====")
        if not args.repeat:
            return 0 if result == "signed" else 1
        take += 1
        time.sleep(args.pause)


if __name__ == "__main__":
    sys.exit(main())
