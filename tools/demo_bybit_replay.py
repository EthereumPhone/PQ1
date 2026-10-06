#!/usr/bin/env python3
"""Demo driver: replay the Feb 2025 Bybit Safe transaction against a pq1.

On 2025-02-21 Bybit's Ethereum cold wallet (a Safe multisig) lost ~$1.5B.
A compromised Safe{Wallet} front-end showed the signers a routine transfer,
but handed their hardware wallets this SafeTx:

    Safe       0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4   (Bybit cold wallet)
    to         0x96221423681A6d52E184D440a8eFCEbB105C7242   (attacker contract)
    value      0
    data       transfer(0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516, 0)
    operation  1  (DELEGATECALL)
    safeTxGas  45746
    nonce      71

The DELEGATECALL ran the attacker's code inside the Safe, overwrote its
implementation slot, and handed the attacker the vault. The signers' devices
showed only a hash, so they signed.

This script sends that exact SafeTx to the pq1 the way a companion would ask
a Safe owner to approve it (`Safe.approveHash(safeTxHash)` + the `safe_v1`
trailer carrying the full SafeTx). The firmware hashes the SafeTx itself,
sees DELEGATECALL to a contract that is not one of the three pinned
MultiSendCallOnly deployments, and refuses before any confirm screen. The
user has nothing to approve, and no signature leaves the device.

Start it BEFORE unlocking the device; it waits.

Usage:
  tools/demo_bybit_replay.py
  tools/demo_bybit_replay.py --repeat      # another take after each one
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "companion-stub"))

from demo_safe_usdc import build_payload_with_erc20, wait_for_unlocked  # noqa: E402
from hid_sign import (  # noqa: E402
    C10_SIG_LEN,
    INS_GET_WALLET_ADDRESS,
    INS_SIGN_USEROP,
    drain_response,
    send_chained,
    u32,
    u256,
)
from hid_sign_safe import (  # noqa: E402
    APPROVE_HASH_SELECTOR,
    CALL_GAS,
    ERC20_TRANSFER_SELECTOR,
    MAX_FEE,
    MAX_PRIORITY_FEE,
    PRE_VER_GAS,
    SAFE_OFF_SAFE_TX_GAS,
    VER_GAS,
    addr,
    build_safe_canonical,
    compute_safe_tx_hash,
)
from hid_smoke import SW_OK, HidRaw, send  # noqa: E402

# The malicious SafeTx, as recorded by Safe's transaction service and the
# public post-mortems (NCC Group, Safe/Bybit). baseGas, gasPrice, gasToken
# and refundReceiver were all zero.
MAINNET = 1
BYBIT_SAFE = "0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4"
ATTACKER_CONTRACT = "0x96221423681A6d52E184D440a8eFCEbB105C7242"
ATTACKER_SWEEPER = "0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516"
OPERATION_DELEGATECALL = 1
SAFE_TX_GAS = 45746
SAFE_NONCE = 71


def bybit_safe_tx() -> tuple[bytes, bytes, bytes]:
    """(canonical safe_v1 bytes, raw inner data, safeTxHash)."""
    raw = ERC20_TRANSFER_SELECTOR + b"\0" * 12 + addr(ATTACKER_SWEEPER) + u256(0)
    canonical = bytearray(build_safe_canonical(
        MAINNET, addr(BYBIT_SAFE), addr(ATTACKER_CONTRACT), 0, raw, SAFE_NONCE,
        OPERATION_DELEGATECALL))
    canonical[SAFE_OFF_SAFE_TX_GAS:SAFE_OFF_SAFE_TX_GAS + 32] = u256(SAFE_TX_GAS)
    canonical = bytes(canonical)
    return canonical, raw, compute_safe_tx_hash(canonical)


def banner(text: str) -> None:
    print("\n" + "=" * 64 + f"\n  {text}\n" + "=" * 64)


def run_take(hid: HidRaw, args: argparse.Namespace, userop_nonce: int) -> str:
    """Send the Bybit SafeTx; return 'refused', 'signed', 'timeout' or 'error'."""
    hid.timeout_s = 15.0
    sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
    sw, data = drain_response(hid, sw, data)
    if sw != SW_OK or len(data) != 20:
        print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x}); is the device still unlocked?")
        return "error"
    sender = data

    canonical, raw, safe_tx_hash = bybit_safe_tx()
    banner("BYBIT HACK, REPLAYED  -  21 Feb 2025, ~$1.5B stolen")
    print(f"  What the signers' screens showed:  a routine transfer")
    print(f"  What they actually signed:")
    print(f"    Safe        {BYBIT_SAFE}  (Bybit cold wallet)")
    print(f"    to          {ATTACKER_CONTRACT}  (attacker)")
    print(f"    data        transfer({ATTACKER_SWEEPER}, 0)")
    print(f"    operation   1 = DELEGATECALL  <- runs attacker code AS the Safe")
    print(f"    safeTxGas   {SAFE_TX_GAS}   nonce {SAFE_NONCE}")
    print(f"    hash PQ1 is asked to approve  0x{safe_tx_hash.hex()}")
    print(f"\n  Sending it to PQ1 as Safe owner {('0x' + sender.hex())} ...")

    req = {
        "chain_id": MAINNET,
        "flags": args.slot & 0x3F_FFFF,
        "nonce": userop_nonce,
        "callGasLimit": CALL_GAS,
        "verificationGasLimit": VER_GAS,
        "preVerificationGas": PRE_VER_GAS,
        "maxFeePerGas": MAX_FEE,
        "maxPriorityFeePerGas": MAX_PRIORITY_FEE,
        "to": BYBIT_SAFE,
        "value": 0,
    }
    payload = build_payload_with_erc20(sender, req, APPROVE_HASH_SELECTOR + safe_tx_hash,
                                       canonical, raw, b"")
    hid.timeout_s = args.confirm_timeout
    try:
        sw, resp = send_chained(hid, INS_SIGN_USEROP, payload)
    except TimeoutError:
        print("!! no answer from the device before the timeout")
        return "timeout"

    if sw != SW_OK:
        banner(f"PQ1 REFUSED  (SW=0x{sw:04x})  -  no signature produced")
        print("  The device decoded the SafeTx on its own screen, saw a DELEGATECALL")
        print("  to an unknown contract, and refused. There was nothing to approve.")
        return "refused"
    # Must never happen: a signature over the Bybit payload.
    t2_ok = len(resp) >= 20 + 96 and int.from_bytes(resp[20 + 64:20 + 96], "big") == C10_SIG_LEN
    print(f"!! UNEXPECTED: device returned SW=0x9000 ({len(resp)} B, sig={'yes' if t2_ok else '?'})")
    return "signed"


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nonce", type=int, default=0, help="UserOp nonce")
    ap.add_argument("--slot", type=int, default=0)
    ap.add_argument("--poll", type=float, default=0.5, help="seconds between USB polls")
    ap.add_argument("--settle", type=float, default=1.0, help="seconds to wait after unlock before sending")
    ap.add_argument("--confirm-timeout", type=float, default=300.0)
    ap.add_argument("--repeat", action="store_true", help="run another take after each result")
    ap.add_argument("--pause", type=float, default=5.0, help="seconds between takes with --repeat")
    ap.add_argument("--dry-run", action="store_true", help="print the SafeTx and hash, no device")
    args = ap.parse_args()

    if args.dry_run:
        canonical, raw, h = bybit_safe_tx()
        print(f"inner data  0x{raw.hex()}\nsafeTxHash  0x{h.hex()}")
        return 0

    take = 0
    while True:
        print(f"\n===== take {take + 1} =====")
        hid = wait_for_unlocked(args.poll)
        try:
            time.sleep(args.settle)
            result = run_take(hid, args, args.nonce + take)
        except OSError as e:
            print(f"!! USB error: {e}; device relocked or unplugged?")
            result = "error"
        finally:
            hid.close()
        print(f"===== take {take + 1}: {result.upper()} =====")
        if not args.repeat:
            return 0 if result == "refused" else 1
        take += 1
        time.sleep(args.pause)


if __name__ == "__main__":
    sys.exit(main())
