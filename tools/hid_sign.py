#!/usr/bin/env python3
"""Exercise CMD_SIGN_USEROP (INS 0x30) over USB HID on a live pq1 board.

Closes the third v1 goal ("secure elements, FSBL and signing") at the
transport + firmware level: builds a minimal normal-mode UserOp, sends it
with APDU command chaining, drains the chunked response, and validates the
returned Type-2 wrapper structurally. The raw bytes are ALSO written to
disk so the C10 signature can be verified cryptographically offline,
without holding the device's narrow window open.

WHY STRUCTURAL + OFFLINE, NOT CRYPTOGRAPHIC INLINE: the device only stays
reachable for ~120 s after unlock (secure/src/main.rs:4090 pends PendSV
once timeout::is_idle(), and enter_pin() has no e2e-test short-circuit, so
NS never runs again). Cryptographic verification needs the C10 verifier and
a keccak userOpHash computation; doing that inside the window risks losing
the response entirely. Get the bytes out first, verify at leisure.

Protocol (docs/companion/usb-protocol-v2.md + nonsecure/src/usb/commands.rs):
  * Request chaining: P1=0x80 "more blocks follow", P1=0x00 last block
    (triggers execute). LC <= 255 per APDU.
  * Chunked response: a reply longer than APDU_MAX_RESP (253) returns its
    first 253 bytes with SW1=0x61 and SW2=bytes-remaining (0xFF if >255).
    The host then issues GET_RESPONSE (INS 0xC0, CLA-agnostic) repeatedly,
    concatenating payloads, until SW1 != 0x61.

Usage: ./hid_sign.py [--out FILE]
"""
from __future__ import annotations

import argparse
import hashlib
import sys

from hid_smoke import (
    APDU_CLA_V2,
    HidRaw,
    P1_LAST,
    SW_OK,
    find_hidraw,
    frame_apdu,
    read_response,
    send,
)

P1_MORE = 0x80
INS_GET_RESPONSE = 0xC0
INS_SIGN_USEROP = 0x30
INS_GET_WALLET_ADDRESS = 0x60
SW1_MORE_DATA = 0x61

# ── wire constants (proto/src/lib.rs, tools/webhid_test.html) ────────────
SIGN_USEROP_HEADER_LEN = 330          # data starts at 330 (CLAUDE.md table)
C10_SIG_LEN = 4008
SIG_WRAPPER_LEN = 32 + 32 + 32 + 4032  # 4128
ENTRY_POINT_V06 = bytes.fromhex("5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
SHA256_EMPTY = hashlib.sha256(b"").digest()

CHAIN_ID = 84532                      # Base Sepolia, matches webhid defaults
# Gas: order on the wire is call, verification, preVerification, maxFee,
# maxPriorityFee (CLAUDE.md "Unified sign input", offset 84, 5x32).
CALL_GAS = 50_000
VER_GAS = 800_000
PRE_VER_GAS = 150_000
MAX_FEE = 1_000_000_000
MAX_PRIORITY_FEE = 100_000_000

TO_ADDRESS = bytes.fromhex("1111111111111111111111111111111111111111")
VALUE_WEI = 1_000_000_000_000_000     # 0.001 ETH


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def u64(n: int) -> bytes:
    return n.to_bytes(8, "big")


def u256(n: int) -> bytes:
    return n.to_bytes(32, "big")


def drain_response(hid: HidRaw, sw: int, data: bytes) -> tuple[int, bytes]:
    """Follow SW1=0x61 with GET_RESPONSE until the reply is complete."""
    collected = bytearray(data)
    rounds = 0
    while (sw >> 8) == SW1_MORE_DATA:
        rounds += 1
        if rounds > 200:
            raise IOError("GET_RESPONSE drain exceeded 200 rounds")
        apdu = bytes([APDU_CLA_V2, INS_GET_RESPONSE, 0x00, 0x00, 0x00])
        for f in frame_apdu(apdu):
            hid.write(f)
        sw, data = read_response(hid)
        collected.extend(data)
    return sw, bytes(collected)


def send_chained(hid: HidRaw, ins: int, payload: bytes) -> tuple[int, bytes]:
    """Send `payload` as chained APDUs; return the final (sw, data)."""
    off = 0
    total = len(payload)
    while off < total:
        chunk = min(255, total - off)
        is_last = (off + chunk) >= total
        p1 = P1_LAST if is_last else P1_MORE
        block = payload[off : off + chunk]
        apdu = bytes([APDU_CLA_V2, ins, p1, 0x00, len(block)]) + block
        for f in frame_apdu(apdu):
            hid.write(f)
        sw, data = read_response(hid)
        sw, data = drain_response(hid, sw, data)
        if is_last:
            return sw, data
        if sw != SW_OK:
            return sw, data
        off += chunk
    raise AssertionError("empty payload")


def build_payload(sender: bytes) -> bytes:
    """Minimal normal-mode UserOp: neither INIT_CODE nor REGISTER_SLOT,
    account 0, slot 0, no inner calldata, no trailers."""
    flags = 0  # bit31 INIT_CODE=0, bit30 REG_SLOT=0, account 0, slot 0
    p = b"".join(
        [
            u64(CHAIN_ID),          # 0
            u32(flags),             # 8
            sender,                 # 12  (20)
            ENTRY_POINT_V06,        # 32  (20)
            u256(0),                # 52  nonce
            u256(CALL_GAS),         # 84
            u256(VER_GAS),          # 116
            u256(PRE_VER_GAS),      # 148
            u256(MAX_FEE),          # 180
            u256(MAX_PRIORITY_FEE), # 212
            SHA256_EMPTY,           # 244 paymaster_and_data_hash
            TO_ADDRESS,             # 276 (20)
            u256(VALUE_WEI),        # 296
            u16(0),                 # 328 data_len = 0
        ]
    )
    assert len(p) == SIGN_USEROP_HEADER_LEN, f"payload is {len(p)} B, want {SIGN_USEROP_HEADER_LEN}"
    return p


FAILURES: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    fmt = lambda v: f"0x{v:x}" if isinstance(v, int) else (v.hex() if isinstance(v, bytes) else str(v))
    print(f"    {'OK  ' if ok else 'FAIL'}  {label:<24} got={fmt(got)} want={fmt(want)}")
    if not ok:
        FAILURES.append(f"{label}: got {fmt(got)}, want {fmt(want)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sign_response.bin")
    args = ap.parse_args()

    node = find_hidraw()
    if node is None:
        print("!! no PQSigner hidraw node — board not enumerated")
        return 2
    print(f"==> device node: {node}")

    # Two different timeouts on purpose. The window is only ~2-4 minutes
    # wide and cannot be extended, so a DEAD device must fail fast rather
    # than burning 45 s of it on the first call; but a LIVE device needs
    # real slack for the sign itself (master + slot keygen on a cold
    # cache, CLAUDE.md budgets <= 3 s, plus FI double-sign + verify).
    # GET_WALLET_ADDRESS is <1 s after unlock, so 12 s is generous for it
    # while still failing fast when NS is not running.
    hid = HidRaw(node, 12.0)
    try:
        print("\n==> INS 0x60 GET_WALLET_ADDRESS (account 0, show=0: no trusted-UI round-trip)")
        sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
        sw, data = drain_response(hid, sw, data)
        print(f"    SW=0x{sw:04x} data={len(data)} B")
        if sw != SW_OK or len(data) != 20:
            print(f"!! cannot get sender address (SW=0x{sw:04x}, {len(data)} B) — aborting")
            print("!! if SW=0x6982/0x6984 the secure world locked or zeroized: power-cycle and retry")
            return 1
        sender = data
        print(f"    sender = 0x{sender.hex()}")

        payload = build_payload(sender)
        hid.timeout_s = 45.0  # generous slack for keygen + FI double-sign
        print(f"\n==> INS 0x30 SIGN_USEROP — {len(payload)} B payload, "
              f"{(len(payload) + 254) // 255} chained APDU(s)")
        sw, resp = send_chained(hid, INS_SIGN_USEROP, payload)
        print(f"    SW=0x{sw:04x}  response={len(resp)} B")

        if resp:
            with open(args.out, "wb") as fh:
                fh.write(resp)
            print(f"    raw response saved -> {args.out}")

        check("SW", sw, SW_OK)
        if sw != SW_OK:
            print("\n!! device refused the sign; response bytes (if any) saved for analysis")
            return 1

        # Expected: [count(8)][init_len(4)=0][t1_len(4)=0][t2_len(4)=4128][t2]
        expected_total = 8 + 4 + 4 + 4 + SIG_WRAPPER_LEN
        check("total length", len(resp), expected_total)
        if len(resp) < 20:
            print("!! response too short to parse")
            return 1

        count = int.from_bytes(resp[0:8], "big")
        init_len = int.from_bytes(resp[8:12], "big")
        print(f"    ..    new_offchain_count       = {count}")
        check("init_code_len (no flag)", init_len, 0)
        off = 12 + init_len
        t1_len = int.from_bytes(resp[off : off + 4], "big")
        check("type1_len (no flag)", t1_len, 0)
        off += 4 + t1_len
        t2_len = int.from_bytes(resp[off : off + 4], "big")
        check("type2_len", t2_len, SIG_WRAPPER_LEN)
        off += 4
        t2 = resp[off : off + t2_len]

        if len(t2) == SIG_WRAPPER_LEN:
            # abi.encode(uint256 ownerIndex, bytes c10Sig)
            owner_index = int.from_bytes(t2[0:32], "big")
            bytes_off = int.from_bytes(t2[32:64], "big")
            sig_len = int.from_bytes(t2[64:96], "big")
            print(f"    ..    wrapper.ownerIndex       = {owner_index}")
            check("wrapper bytes offset", bytes_off, 0x40)
            check("wrapper sig length", sig_len, C10_SIG_LEN)
            sig = t2[96 : 96 + C10_SIG_LEN]
            nonzero = sum(1 for b in sig if b)
            print(f"    ..    c10 sig first 16 B      = {sig[:16].hex()}")
            print(f"    ..    c10 sig nonzero bytes   = {nonzero}/{C10_SIG_LEN}")
            # An all-zero or near-constant signature would mean a stub, not a sign.
            check("sig is not all zeros", nonzero > C10_SIG_LEN // 2, True)
    except TimeoutError as e:
        print(f"\n!! TIMEOUT: {e}")
        print("!! The window likely closed (PendSV holds the CPU in secure state).")
        print("!! Power-cycle the board and re-run via wait_and_smoke.sh timing.")
        return 2
    finally:
        hid.close()

    print()
    if FAILURES:
        print(f"=== FAIL === {len(FAILURES)} check(s):")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("=== PASS === device produced a well-formed C10 Type-2 signature over USB")
    print(f"    (cryptographic verification still pending — bytes in {args.out})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
