#!/usr/bin/env python3
"""Demo driver: walk every pixel-UI flow (port steps 1-4) on a live pq1.

The multi-flow twin of `demo_safe_usdc.py`. It waits for the device to be
unlocked, then sends one request per flow so the pixel trusted UI draws that
flow's screens. Confirm each one with the two-button chord, or decline by
holding the left button. Declining is a valid result: it shows the red
ending.

Every request mirrors a QEMU `make e2e-px` scenario or a host fixture, but
uses the production trust roots that the EVT dev image pins (no
`e2e-test`): the ERC-20 and ERC-7730 proofs come from
`tools/companion-stub/*.bin`, the same blobs whose roots are compiled in.

Flows (name -> what the device should show):
  send          ETH value transfer on Base                  SEND hero
  call          zero-value call, empty calldata             CALL (contract_call)
  erc20         USDC transfer on Base + ERC-20 proof        TRANSFER, token named
  approve       unlimited USDC approve on Base + proof      APPROVE, unlimited
  unknown       transfer of a token with no proof           UNKNOWN (placeholder ramp)
  blind         opaque calldata + ETH value                 BLIND
  typed-call    self-attested `stake(address,uint256)`      typed args, ! UNVERIFIED
  rotate        register a new slot (Type 1 + Type 2)       ROTATE consent
  deploy        first UserOp with initCode (slot 0)         ! DEPLOY trailer
  safe          Safe approveHash, USDC transfer             APPROVE SAFE TX (pilot flow)
  cow           direct CoW order WETH->USDC, mainnet        CoW hero, decoded legs
  erc7730       Uniswap V3 exactInputSingle, mainnet        SIGN ... INTENT (7730 lift)
  personal      personal_sign, counterfactual (ERC-6492)    message on screen
  raw32         RAW32 off-chain hash                        ! BLIND RAW32 + full hash
  typed         EIP-712 Lombard feeApproval, mainnet        SIGN ... (7730 typed)
  batch         3-tx atomic batch (ETH, USDC, blind)        3 member asks + SIGN 3 TXS?
  address       show the wallet address on the device       address consent
  lock          lock the device                             LOCKED padlock -> PIN row

Start the script BEFORE unlocking; it waits. Between flows it pauses for
--pause seconds (or waits for Enter with --step). If the device relocks
(120 s idle), the script waits for the next unlock and carries on.

Usage:
  tools/demo_px_flows.py --list
  tools/demo_px_flows.py                       # every flow except lock, in order
  tools/demo_px_flows.py erc20 cow batch       # just these
  tools/demo_px_flows.py --step all            # every flow incl. lock, Enter between
  tools/demo_px_flows.py --repeat personal     # loop one flow
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "companion-stub"))
from db_trailers import build_erc20_bundle  # noqa: E402
import erc7730_trailer  # noqa: E402

from demo_safe_usdc import build_payload_with_erc20, wait_for_unlocked  # noqa: E402
from hid_sign import (  # noqa: E402
    C10_SIG_LEN,
    ENTRY_POINT_V06,
    FLAG_INCLUDE_INIT_CODE,
    INIT_CODE_LEN,
    INS_GET_WALLET_ADDRESS,
    INS_SIGN_USEROP,
    SHA256_EMPTY,
    SIG_WRAPPER_LEN,
    drain_response,
    send_chained,
    u16,
    u32,
    u64,
    u256,
)
from hid_sign_safe import (  # noqa: E402
    APPROVE_HASH_SELECTOR,
    addr,
    build_safe_canonical,
    compute_safe_tx_hash,
    keccak256,
)
from hid_smoke import SW_OK, HidRaw, send  # noqa: E402

INS_SIGN_USEROP_BATCH = 0x32
INS_SIGN_OFFCHAIN = 0x62
INS_LOCK = 0x11
FLAG_REGISTER_SLOT = 0x4000_0000
BATCH_WIRE_VERSION = 2
TRAILER_KIND_ERC20 = 1
OFFCHAIN_KIND_RAW32 = 0
OFFCHAIN_KIND_PERSONAL = 1
OFFCHAIN_KIND_EIP712 = 2
OFFCHAIN_FLAG_DEPLOYED = 0x01
EIP6492_BLOB_LEN = 8608
EIP6492_MAGIC = bytes.fromhex("64926492" * 8)

ERC20_DB = os.path.join(HERE, "companion-stub", "erc20_db.bin")
ERC7730_DB = os.path.join(HERE, "companion-stub", "erc7730_db.bin")

BASE = 8453
MAINNET = 1
USDC_BASE = addr("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
WETH_MAINNET = addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
USDC_MAINNET = addr("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
GPV2_SETTLEMENT = addr("0x9008D19f58AAbD9eD0D60971565AA8510560ab41")
UNI_V3_ROUTER02 = addr("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
LOMBARD_LBTC = addr("0x8236a87084f8B84306f72007F36F2618A5634494")
SAFE = addr("0x5afe000000000000000000000000000000000001")
ALICE = addr("0x" + "ab" * 20)
BOB = addr("0x" + "cd" * 20)
CONTRACT = addr("0x9e3b5c0f7a1d24e86c3f0b7d5a2e4c6f8b1d3a7c")   # e2e 4a
UNKNOWN_TOKEN = addr("0x3ca9e5f1b72d04e8a6c1d9b3f57e28a0c4d6b1e9")  # e2e 4b
OPAQUE_TARGET = addr("0x" + "fe" * 20)

TRANSFER = bytes.fromhex("a9059cbb")
APPROVE = bytes.fromhex("095ea7b3")
SET_PRESIGNATURE = bytes.fromhex("ec6cb13f")
EXACT_INPUT_SINGLE_SIG = b"exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"

GAS = dict(call=120_000, ver=800_000, pre=150_000, max_fee=1_000_000_000, prio=100_000_000)


# ── wire builders ────────────────────────────────────────────────────────

def word_addr(a: bytes) -> bytes:
    return b"\0" * 12 + a


def erc20_call(selector: bytes, who: bytes, amount: int) -> bytes:
    return selector + word_addr(who) + u256(amount)


def erc20_proof(chain_id: int, token: bytes) -> bytes:
    with open(ERC20_DB, "rb") as fh:
        return build_erc20_bundle(fh.read(), chain_id, token)


def userop_head(sender: bytes, chain_id: int, flags: int, nonce: int,
                to: bytes, value: int, data: bytes) -> bytes:
    return b"".join([
        u64(chain_id), u32(flags), sender, ENTRY_POINT_V06, u256(nonce),
        u256(GAS["call"]), u256(GAS["ver"]), u256(GAS["pre"]),
        u256(GAS["max_fee"]), u256(GAS["prio"]), SHA256_EMPTY,
        to, u256(value), u16(len(data)), data,
    ])


def trailers(erc20: bytes = b"", cow: bytes = b"", safe: bytes = b"",
             selector: bytes = b"", self_attest: bytes = b"", erc7730: bytes = b"") -> bytes:
    """Positional sign-input trailers (cmd_sign_userop.rs): erc20 | reserved |
    cow_order | safe_v1 | selector | self_attest | erc7730; names count absent."""
    out = b""
    for t in (erc20, b"", cow, safe, selector, self_attest, erc7730):
        out += u16(len(t)) + t
    return out


def cow_digest(c: bytes) -> bytes:
    """Mirror of secure/src/tx/eip712/cowswap::compute_digest (e2e twin)."""
    order_th = keccak256(
        b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"
        b"uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,"
        b"bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)")
    domain = keccak256(
        keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        + keccak256(b"Gnosis Protocol") + keccak256(b"v2")
        + b"\0" * 24 + c[0:8] + word_addr(GPV2_SETTLEMENT))
    kind = keccak256(b"sell" if c[168] == 0 else b"buy")
    sell_bal = keccak256({0: b"erc20", 1: b"external"}.get(c[170], b"internal"))
    buy_bal = keccak256(b"erc20" if c[171] == 0 else b"internal")
    struct = keccak256(
        order_th + word_addr(c[8:28]) + word_addr(c[28:48]) + word_addr(c[48:68])
        + c[68:100] + c[100:132] + b"\0" * 28 + c[164:168] + c[172:204] + c[132:164]
        + kind + b"\0" * 31 + bytes([c[169]]) + sell_bal + buy_bal)
    return keccak256(b"\x19\x01" + domain + struct)


def erc7730_leaf(chain_id: int, contract: bytes, context: str = "contract",
                 primary_type_hash: bytes | None = None) -> tuple[bytes, dict]:
    """(trailer, parsed IR) for the unique catalogue leaf. The EVT dev image
    pins this blob's root (db_roots::ERC7730_DESCRIPTORS_ROOT, non-e2e)."""
    blob = open(ERC7730_DB, "rb").read()
    hdr = erc7730_trailer._read_header(blob)
    ds = None
    if context == "eip712":
        for i in range(hdr["entry_cnt"]):
            _, _, p = erc7730_trailer._parsed_entry(blob, hdr, i)
            if (p["context_kind"] == erc7730_trailer.CTX_EIP712 and p["chain_id"] == chain_id
                    and p["contract"] == contract and primary_type_hash in p["type_hashes"]):
                ds = p["domain_separator"]
                break
        if ds is None:
            raise SystemExit(f"no EIP-712 leaf for chain {chain_id} 0x{contract.hex()}")
    t = erc7730_trailer.build_trailer(blob, chain_id, contract, context=context,
                                      domain_separator=ds, primary_type_hash=primary_type_hash)
    return t, {"domain_separator": ds}


# ── requests ─────────────────────────────────────────────────────────────

@dataclass
class Request:
    ins: int
    payload: bytes
    kind: str                 # userop | batch | offchain | address | lock
    lines: list[str]
    want_init: bool = False
    want_t1: bool = False
    deployed: bool = False


@dataclass
class Ctx:
    sender: bytes
    args: argparse.Namespace
    nonce: int


def f_send(c: Ctx) -> Request:
    amt = 12_500_000_000_000_000  # 0.0125 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, ALICE, amt, b"") + trailers(),
                   "userop", [f"send 0.0125 ETH -> 0x{ALICE.hex()} on Base"])


def f_call(c: Ctx) -> Request:
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, CONTRACT, 0, b"") + trailers(),
                   "userop", [f"zero-value call to 0x{CONTRACT.hex()} (empty calldata)"])


def f_erc20(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, BOB, 1_234_560_000)  # 1234.56 USDC
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, USDC_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDC_BASE)),
                   "userop", ["transfer 1234.56 USDC (Base) -> 0x" + BOB.hex(), "ERC-20 proof attached"])


def f_approve(c: Ctx) -> Request:
    spender = addr("0x000000000022D473030F116dDEE9F6B43aC78BA3")  # Permit2
    data = erc20_call(APPROVE, spender, (1 << 256) - 1)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, USDC_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDC_BASE)),
                   "userop", ["approve UNLIMITED USDC (Base) to Permit2", "ERC-20 proof attached"])


def f_unknown(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, ALICE, 12_345_678_901_234_567_890)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, UNKNOWN_TOKEN, 0, data) + trailers(),
                   "userop", [f"transfer raw 12345678901234567890 of 0x{UNKNOWN_TOKEN.hex()} (no proof)"])


def f_blind(c: Ctx) -> Request:
    data = bytes.fromhex("123456789abcdef042") + bytes(range(40))
    amt = 30_000_000_000_000_000  # 0.03 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, OPAQUE_TARGET, amt, data) + trailers(),
                   "userop", [f"opaque {len(data)} B calldata + 0.03 ETH -> 0x{OPAQUE_TARGET.hex()}"])


def f_typed_call(c: Ctx) -> Request:
    sig = b"stake(address,uint256)"
    sel = keccak256(sig)[:4]
    data = sel + word_addr(BOB) + u256(42_000)
    attest = sel + bytes([len(sig)]) + sig
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.args.slot, c.nonce, OPAQUE_TARGET, 0, data)
                   + trailers(self_attest=attest),
                   "userop", [f"self-attested {sig.decode()} (0x{sel.hex()}) on 0x{OPAQUE_TARGET.hex()}"])


def f_rotate(c: Ctx) -> Request:
    slot = c.args.rotate_slot
    flags = FLAG_REGISTER_SLOT | slot
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, flags, c.nonce, ALICE, 1_000_000_000_000_000, b"") + trailers(),
                   "userop", [f"REGISTER slot {slot} on Base + send 0.001 ETH",
                              "(re-running on a registered slot may refuse; use --rotate-slot N)"],
                   want_t1=True)


def f_deploy(c: Ctx) -> Request:
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, FLAG_INCLUDE_INIT_CODE, 0, ALICE, 10_000_000_000_000_000, b"")
                   + trailers(),
                   "userop", ["first UserOp with initCode (slot 0, nonce 0) + send 0.01 ETH"],
                   want_init=True)


def f_safe(c: Ctx) -> Request:
    raw = erc20_call(TRANSFER, ALICE, 250_000_000)
    canonical = build_safe_canonical(BASE, SAFE, USDC_BASE, 0, raw, 17 + c.nonce, 0)
    h = compute_safe_tx_hash(canonical)
    inner = APPROVE_HASH_SELECTOR + h
    req = {"chain_id": BASE, "flags": c.args.slot, "nonce": c.nonce,
           "callGasLimit": GAS["call"], "verificationGasLimit": GAS["ver"],
           "preVerificationGas": GAS["pre"], "maxFeePerGas": GAS["max_fee"],
           "maxPriorityFeePerGas": GAS["prio"], "to": "0x" + SAFE.hex(), "value": 0}
    payload = build_payload_with_erc20(c.sender, req, inner, canonical, raw, erc20_proof(BASE, USDC_BASE))
    return Request(INS_SIGN_USEROP, payload, "userop",
                   [f"Safe 0x{SAFE.hex()} approveHash: transfer 250 USDC -> 0x{ALICE.hex()}",
                    f"safeTxHash 0x{h.hex()}"])


def f_cow(c: Ctx) -> Request:
    order = bytearray(204)
    order[0:8] = u64(MAINNET)
    order[8:28] = WETH_MAINNET
    order[28:48] = USDC_MAINNET
    # receiver = 0 → the owner (the wallet)
    order[68:100] = u256(500_000_000_000_000_000)   # sell 0.5 WETH
    order[100:132] = u256(1_842_310_000)            # buy >= 1842.31 USDC
    order[132:164] = u256(1_000_000_000_000_000)    # fee 0.001 WETH
    order[164:168] = u32(int(time.time()) + 3600)   # validTo
    order[168] = 0                                  # SELL
    order[172:204] = b"\xa7" * 32                   # appData
    order = bytes(order)
    uid = cow_digest(order) + c.sender + order[164:168]
    presign = (SET_PRESIGNATURE + u256(0x40) + u256(1) + u256(56) + uid + b"\0" * 8)
    assert len(presign) == 164
    sell_b, buy_b = erc20_proof(MAINNET, WETH_MAINNET), erc20_proof(MAINNET, USDC_MAINNET)
    cow = order + u16(len(sell_b)) + sell_b + u16(len(buy_b)) + buy_b
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.args.slot, c.nonce, GPV2_SETTLEMENT, 0, presign)
                   + trailers(cow=cow),
                   "userop", ["CoW: SELL 0.5 WETH for at least 1842.31 USDC (mainnet), fee 0.001 WETH",
                              "both legs carry ERC-20 proofs -> decoded"])


def f_erc7730(c: Ctx) -> Request:
    t, _ = erc7730_leaf(MAINNET, UNI_V3_ROUTER02)
    token_in, token_out = b"\x11" * 20, b"\x22" * 20   # the host golden's tokens
    data = (keccak256(EXACT_INPUT_SINGLE_SIG)[:4] + word_addr(token_in) + word_addr(token_out)
            + u256(3000) + word_addr(ALICE) + u256(1_500_000) + u256(1_000_000) + u256(0))
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.args.slot, c.nonce, UNI_V3_ROUTER02, 0, data)
                   + trailers(erc7730=t),
                   "userop", ["Uniswap V3 Router02 exactInputSingle (mainnet), ERC-7730 proof "
                              f"{len(t)} B"])


def offchain(c: Ctx, chain_id: int, kind: int, payload: bytes, lines: list[str]) -> Request:
    deployed = c.args.deployed
    slot = c.args.slot if deployed else 0
    flags = OFFCHAIN_FLAG_DEPLOYED if deployed else 0
    req = (bytes([0]) + u64(chain_id) + u32(slot) + bytes([kind]) + u16(len(payload))
           + bytes([flags]) + payload)
    mode = "deployed" if deployed else "counterfactual ERC-6492, slot 0"
    return Request(INS_SIGN_OFFCHAIN, req, "offchain", lines + [mode], deployed=deployed)


def f_personal(c: Ctx) -> Request:
    msg = c.args.message.encode()
    return offchain(c, BASE, OFFCHAIN_KIND_PERSONAL, msg, [f"personal_sign on Base: {msg.decode()!r}"])


def f_raw32(c: Ctx) -> Request:
    h = keccak256(b"pq1 raw32 demo")
    return offchain(c, BASE, OFFCHAIN_KIND_RAW32, h, [f"RAW32 on Base: 0x{h.hex()}"])


def f_typed(c: Ctx) -> Request:
    th = keccak256(b"feeApproval(uint256 chainId,uint256 fee,uint256 expiry)")
    trailer, p = erc7730_leaf(MAINNET, LOMBARD_LBTC, "eip712", th)
    expiry = 1_798_761_600  # 2027-01-01
    enc = u256(1) + u256(25_000) + u256(expiry)
    payload = (u16(1) + p["domain_separator"] + th + u16(len(enc)) + enc
               + u16(len(trailer)) + trailer)
    return offchain(c, MAINNET, OFFCHAIN_KIND_EIP712, payload,
                    ["EIP-712 Lombard LBTC feeApproval (mainnet): chainId 1, fee 25000, expiry 2027-01-01"])


def f_batch(c: Ctx) -> Request:
    txs = [
        (ALICE, 100_000_000_000_000_000, b""),                          # 0.1 ETH
        (USDC_BASE, 0, erc20_call(TRANSFER, BOB, 250_000_000)),         # 250 USDC
        (OPAQUE_TARGET, 0, bytes.fromhex("123456789abcdef042")),        # blind
    ]
    body = b"".join([
        u64(BASE), u32(c.args.slot), c.sender, ENTRY_POINT_V06, u256(c.nonce),
        u256(400_000), u256(1_000_000), u256(200_000), u256(GAS["max_fee"]), u256(GAS["prio"]),
        SHA256_EMPTY, bytes([BATCH_WIRE_VERSION, len(txs)]),
    ])
    for to, v, d in txs:
        body += to + u256(v) + u16(len(d)) + d
    proof = erc20_proof(BASE, USDC_BASE)
    body += bytes([1]) + bytes([TRAILER_KIND_ERC20, 1]) + u16(len(proof)) + proof
    return Request(INS_SIGN_USEROP_BATCH, body, "batch",
                   ["batch on Base: 0.1 ETH -> alice | 250 USDC -> bob (proof) | 9 B opaque call",
                    "3 member asks, then the final SIGN 3 TXS? ask"])


def f_address(c: Ctx) -> Request:
    return Request(INS_GET_WALLET_ADDRESS, u32(0) + b"\x01", "address",
                   [f"show wallet address (expect 0x{c.sender.hex()})"])


def f_lock(c: Ctx) -> Request:
    return Request(INS_LOCK, b"", "lock", ["lock: LOCKED padlock, then the PIN row"])


FLOWS: dict[str, Callable[[Ctx], Request]] = {
    "send": f_send, "call": f_call, "erc20": f_erc20, "approve": f_approve,
    "unknown": f_unknown, "blind": f_blind, "typed-call": f_typed_call,
    "rotate": f_rotate, "deploy": f_deploy, "safe": f_safe, "cow": f_cow,
    "erc7730": f_erc7730, "personal": f_personal, "raw32": f_raw32, "typed": f_typed,
    "batch": f_batch, "address": f_address, "lock": f_lock,
}
DEFAULT = [n for n in FLOWS if n != "lock"]


# ── running ──────────────────────────────────────────────────────────────

def check_userop(resp: bytes, r: Request) -> str | None:
    try:
        off = 8
        ic = int.from_bytes(resp[off:off + 4], "big"); off += 4 + ic
        t1 = int.from_bytes(resp[off:off + 4], "big"); off += 4 + t1
        t2 = int.from_bytes(resp[off:off + 4], "big"); off += 4
        wrap = resp[off:off + t2]
    except IndexError:
        return f"truncated response ({len(resp)} B)"
    if off + t2 != len(resp):
        return f"length mismatch ({len(resp)} B)"
    if ic != (INIT_CODE_LEN if r.want_init else 0):
        return f"init_code_len={ic}"
    if t1 != (SIG_WRAPPER_LEN if r.want_t1 else 0):
        return f"type1_len={t1}"
    if t2 != SIG_WRAPPER_LEN or int.from_bytes(wrap[64:96], "big") != C10_SIG_LEN:
        return f"type2_len={t2}"
    owner = int.from_bytes(wrap[0:32], "big")
    print(f"    SIGNED: count={int.from_bytes(resp[:8], 'big')} initCode={ic} B "
          f"type1={'yes' if t1 else 'no'} type2 ownerIndex={owner}")
    return None


def check_offchain(resp: bytes, r: Request) -> str | None:
    want = 8 + (C10_SIG_LEN if r.deployed else EIP6492_BLOB_LEN)
    if len(resp) != want:
        return f"{len(resp)} B, want {want}"
    if not r.deployed and resp[-32:] != EIP6492_MAGIC:
        return "ERC-6492 magic missing"
    print(f"    SIGNED: local_offchain_count={int.from_bytes(resp[:8], 'big')} ({len(resp)} B)")
    return None


def run_flow(hid: HidRaw, name: str, args: argparse.Namespace, nonce: int) -> str:
    hid.timeout_s = 15.0
    sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(0))
    sw, data = drain_response(hid, sw, data)
    if sw != SW_OK or len(data) != 20:
        print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x})")
        return "error"
    r = FLOWS[name](Ctx(data, args, nonce))
    for line in r.lines:
        print(f"    {line}")
    hid.timeout_s = args.confirm_timeout
    if r.kind != "lock":
        print(f"==> sent ({len(r.payload)} B). Chord = confirm, hold-left = decline "
              f"({args.confirm_timeout:.0f}s)")
    try:
        if r.kind in ("address", "lock"):
            sw, resp = send(hid, r.ins, r.payload)
            sw, resp = drain_response(hid, sw, resp)
        else:
            sw, resp = send_chained(hid, r.ins, r.payload)
    except TimeoutError:
        print("!! no answer before the timeout")
        return "timeout"
    if sw != SW_OK:
        print(f"    device refused (SW=0x{sw:04x}): declined on screen, or a gate fired "
              "(the screen says which)")
        return "declined"
    err = None
    if r.kind in ("userop", "batch"):
        err = check_userop(resp, r)
    elif r.kind == "offchain":
        err = check_offchain(resp, r)
    elif r.kind == "address":
        err = None if resp == data else f"address mismatch 0x{resp.hex()}"
        if not err:
            print(f"    CONFIRMED: 0x{resp.hex()}")
    elif r.kind == "lock":
        print("    LOCKED: enter the PIN to continue")
        return "locked"
    if err:
        print(f"!! SW=0x9000 but malformed: {err}")
        return "error"
    return "signed" if r.kind != "address" else "confirmed"


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("flows", nargs="*", help="flow names (default: all but lock; 'all' adds lock)")
    ap.add_argument("--list", action="store_true", help="list the flows and exit")
    ap.add_argument("--slot", type=int, default=0, help="slot for normal-mode UserOps")
    ap.add_argument("--rotate-slot", type=int, default=1, help="slot the rotate flow registers")
    ap.add_argument("--nonce", type=int, default=0, help="first UserOp nonce (bumped per flow)")
    ap.add_argument("--deployed", action="store_true",
                    help="off-chain flows as deployed (needs a registered --slot) instead of ERC-6492")
    ap.add_argument("--message", default="Sign in to app.example.com - nonce 8f3a9c2e1b",
                    help="personal_sign message")
    ap.add_argument("--poll", type=float, default=0.5)
    ap.add_argument("--settle", type=float, default=1.0)
    ap.add_argument("--pause", type=float, default=3.0, help="seconds between flows")
    ap.add_argument("--step", action="store_true", help="wait for Enter between flows")
    ap.add_argument("--repeat", action="store_true", help="loop the selection forever")
    ap.add_argument("--confirm-timeout", type=float, default=300.0)
    args = ap.parse_args()

    if args.list:
        for n in FLOWS:
            print(n)
        return 0
    names = DEFAULT if not args.flows else (list(FLOWS) if args.flows == ["all"] else args.flows)
    bad = [n for n in names if n not in FLOWS]
    if bad:
        ap.error(f"unknown flow(s) {bad}; --list shows them")

    results: list[tuple[str, str]] = []
    nonce = args.nonce
    try:
        while True:
            for i, name in enumerate(names):
                print(f"\n===== [{i + 1}/{len(names)}] {name} =====")
                hid = wait_for_unlocked(args.poll)
                try:
                    time.sleep(args.settle)
                    result = run_flow(hid, name, args, nonce)
                except OSError as e:
                    print(f"!! USB error: {e}; relocked or unplugged?")
                    result = "error"
                finally:
                    hid.close()
                nonce += 1
                results.append((name, result))
                print(f"===== {name}: {result.upper()} =====")
                if i + 1 < len(names):
                    if args.step:
                        input("    [Enter] for the next flow ")
                    else:
                        time.sleep(args.pause)
            if not args.repeat:
                break
    except KeyboardInterrupt:
        print("\n(interrupted)")
    print("\nsummary:")
    for name, result in results:
        print(f"  {name:11s} {result}")
    return 0 if all(r in ("signed", "confirmed", "locked", "declined") for _, r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
