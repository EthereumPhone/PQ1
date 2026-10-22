#!/usr/bin/env python3
"""Demo driver: walk every pixel-UI flow (port steps 1-4) on a live pq1.

The multi-flow twin of `demo_safe_usdc.py`. It waits for the device to be
unlocked, then sends one request per flow so the pixel trusted UI draws that
flow's screens. Confirm each one with the two-button chord, or decline by
holding the left button. Declining is a valid result: it shows the red
ending.

Every request mirrors a QEMU `make e2e-px` scenario or a host fixture, but
uses the production trust roots that the EVT dev image pins (no
`e2e-test`): the ERC-20, names, selector and ERC-7730 proofs come from
`tools/companion-stub/*.bin`, the same blobs whose roots are compiled in.

`--list` prints every flow with what the device should show, the flow
groups (`@safe`, `@offchain`, `@new`, ...) and the screens only a human can
reach (boot, PIN, wizard). Nothing is broadcast: every flow only asks the
device for a signature or a consent.

The `off-*` flows are the structured off-chain kinds (2026-10-19): an
EIP-1271 SafeTx (kind 4) and a CoW order (kind 5), clear-signed. Both refuse
ERC-6492, so they always go out as deployed on --slot, which the device must
have registered: on a fresh wallet run `personal` first (it registers slot 0;
the default walk does).

Flows that change device state: every sign adds one to its slot's count;
`rotate` registers --rotate-slot; `sync` raises --sync-slot's floor by one
and `sync-warn` by 1,500 (default slot 9, so the wallet's real slots are
never touched); `lock` and `idle` lock the device. `sync-refuse` asks to use
up --rotate-slot and must be refused without a dialog; that needs the slot to
have signed (run `rotate` first), otherwise the device shows ! CAREFUL and you
should DECLINE. Nothing writes firmware: `fw-verify` sends an unsigned
all-zero manifest, which the verifier rejects, so neither answer touches flash.

Start the script BEFORE unlocking; it waits. Between flows it pauses for
--pause seconds (or waits for Enter with --step). If the device relocks
(120 s idle), the script waits for the next unlock and carries on.

Usage:
  tools/demo_px_flows.py --list
  tools/demo_px_flows.py                       # every flow except sync-warn, sync-refuse, lock, idle
  tools/demo_px_flows.py @offchain             # one group (@new: the flows not yet walked on glass)
  tools/demo_px_flows.py @safe cow-addr        # groups and flow names mix
  tools/demo_px_flows.py --step all            # every flow, Enter between
  tools/demo_px_flows.py --repeat personal     # loop one flow
  tools/demo_px_flows.py --dry-run --dump DIR  # build every request offline, save the bytes
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import time
from dataclasses import dataclass
from typing import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "companion-stub"))
from db_trailers import build_erc20_bundle, build_names_bundle  # noqa: E402
import erc7730_trailer  # noqa: E402
import structured_offchain  # noqa: E402

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
    SAFE_OFF_BASE_GAS,
    SAFE_OFF_GAS_PRICE,
    SAFE_OFF_GAS_TOKEN,
    SAFE_OFF_REFUND_RECEIVER,
    SAFE_OFF_SAFE_TX_GAS,
    addr,
    build_safe_canonical,
    compute_safe_tx_hash,
    keccak256,
)
from hid_smoke import INS_GET_STATUS, SW_OK, HidRaw, send  # noqa: E402

INS_SIGN_USEROP_BATCH = 0x32
INS_GET_INIT_CODE = 0x61
INS_SIGN_OFFCHAIN = 0x62
INS_OFFCHAIN_STATUS = 0x63
INS_OFFCHAIN_SYNC = 0x64
INS_FW_BEGIN = 0x70
# Protocol 0x0203 (#353): the Type-1 section is new_owner_bytes(64) || wrapper.
OWNER_BYTES_LEN = 64
TYPE1_ROTATION_SECTION_LEN = OWNER_BYTES_LEN + SIG_WRAPPER_LEN
INS_LOCK = 0x11
FLAG_REGISTER_SLOT = 0x4000_0000
ACCOUNT_INDEX_SHIFT = 22
BATCH_WIRE_VERSION = 2
TRAILER_KIND_ERC20 = 1
OFFCHAIN_KIND_RAW32 = 0
OFFCHAIN_KIND_PERSONAL = 1
OFFCHAIN_KIND_EIP712 = 2
OFFCHAIN_KIND_SAFE_TX = structured_offchain.OFFCHAIN_KIND_SAFE_TX      # 4
OFFCHAIN_KIND_COW_ORDER = structured_offchain.OFFCHAIN_KIND_COW_ORDER  # 5
OFFCHAIN_FLAG_DEPLOYED = 0x01
EIP6492_BLOB_LEN = 8608
EIP6492_MAGIC = bytes.fromhex("64926492" * 8)
FW_MANIFEST_SIZE = 8192
SYNC_WARN_STEP = 1_500        # > aa::offchain_gate::SYNC_WARN_JUMP (1,000): the ! CAREFUL page
SYNC_REFUSE_TARGET = 65_535   # OFFCHAIN_COUNT_CEILING: leaves 0 once the slot has one UserOp sig

# Status words (proto/src/lib.rs; nonsecure/src/usb/commands.rs nsc_status_to_sw).
SW_DECLINED = 0x6982       # UserRejected (hold-left on the device)
SW_IDLE_WIPED = 0x6984     # the 120 s idle timer fired during the ask
SW_NOT_READY = 0x6985      # locked, off-chain gate, firmware-update state
SW_WRONG_DATA = 0x6A80     # firmware-update manifest rejected
SW_REFUSED = 0x6F00        # a firmware gate refused (the NOTICE screen names it)

ERC20_DB = os.path.join(HERE, "companion-stub", "erc20_db.bin")
ERC7730_DB = os.path.join(HERE, "companion-stub", "erc7730_db.bin")
NAMES_DB = os.path.join(HERE, "companion-stub", "names_db.bin")
SELECTORS_DB = os.path.join(HERE, "companion-stub", "selectors_db.bin")

BASE = 8453
MAINNET = 1
USDC_BASE = addr("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
USDT_BASE = addr("0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2")   # mainnet USDT is a known call (7730)
DAI_BASE = addr("0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb")
WETH_BASE = addr("0x4200000000000000000000000000000000000006")
TOSHI_BASE = addr("0xAC1Bd2486aAf3B5C0fc3Fd868558b082a531B2B4")
WETH_MAINNET = addr("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
USDC_MAINNET = addr("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
GPV2_SETTLEMENT = addr("0x9008D19f58AAbD9eD0D60971565AA8510560ab41")
VAULT_RELAYER = addr("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110")
MULTISEND_CALL_ONLY_V150 = addr("0xA83c336B20401aF773B6219BA5027174338D1836")
UNI_V3_ROUTER = addr("0xE592427A0AEce92De3Edee1F18E0157C05861564")   # names DB: "Uniswap V3 Router"
UNI_V3_ROUTER02 = addr("0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
LOMBARD_LBTC = addr("0x8236a87084f8B84306f72007F36F2618A5634494")
SAFE = addr("0x5afe000000000000000000000000000000000001")
ALICE = addr("0x" + "ab" * 20)
BOB = addr("0x" + "cd" * 20)
CAROL = addr("0x" + "99" * 20)          # new Safe owner
MODULE = addr("0x" + "7e" * 20)         # Safe module
REFUND_TO = addr("0x" + "77" * 20)      # Safe gas-refund receiver
INNER = addr("0x" + "44" * 20)          # Safe inner call target
PULL_FROM = addr("0x" + "42" * 20)      # transferFrom source
CONTRACT = addr("0x9e3b5c0f7a1d24e86c3f0b7d5a2e4c6f8b1d3a7c")   # e2e 4a
UNKNOWN_TOKEN = addr("0x3ca9e5f1b72d04e8a6c1d9b3f57e28a0c4d6b1e9")  # e2e 4b
OPAQUE_TARGET = addr("0x" + "fe" * 20)
ZERO = bytes(20)
# A synthetic paymasterAndData; the device only ever sees its sha256.
PAYMASTER_AND_DATA = addr("0x" + "9a" * 20) + b"pq1-demo-sponsor"

TRANSFER = bytes.fromhex("a9059cbb")
TRANSFER_FROM = bytes.fromhex("23b872dd")
APPROVE = bytes.fromhex("095ea7b3")
SET_PRESIGNATURE = bytes.fromhex("ec6cb13f")
EXEC_TRANSACTION = bytes.fromhex("6a761202")
MULTI_SEND = bytes.fromhex("8d80ff0a")
ADD_OWNER_WITH_THRESHOLD = bytes.fromhex("0d582f13")
ENABLE_MODULE = bytes.fromhex("610b5925")
EXACT_INPUT_SINGLE_SIG = b"exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"

GAS = dict(call=120_000, ver=800_000, pre=150_000, max_fee=1_000_000_000, prio=100_000_000)


# ── wire builders ────────────────────────────────────────────────────────

def word_addr(a: bytes) -> bytes:
    return b"\0" * 12 + a


def pad32(b: bytes) -> bytes:
    return b + bytes(-len(b) % 32)


def erc20_call(selector: bytes, who: bytes, amount: int) -> bytes:
    return selector + word_addr(who) + u256(amount)


def erc20_proof(chain_id: int, token: bytes) -> bytes:
    with open(ERC20_DB, "rb") as fh:
        return build_erc20_bundle(fh.read(), chain_id, token)


def names_proof(chain_id: int, address: bytes) -> bytes:
    with open(NAMES_DB, "rb") as fh:
        return build_names_bundle(fh.read(), chain_id, address)


def selector_proof(sel: bytes) -> bytes:
    """Curated selector bundle `selector | len | text_sig | leaf_index LE |
    depth LE | proof` from selectors_db.bin — the twin of the webhid
    companion's `selectorsDb.buildBundle` / NS `selectors_db::build_bundle`."""
    with open(SELECTORS_DB, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"SEL4":
        raise SystemExit(f"{SELECTORS_DB}: bad magic")
    count, pool, _, depth, proofs = struct.unpack_from("<IIIII", blob, 12)
    lo, hi = 0, count
    while lo < hi:
        mid = (lo + hi) // 2
        key = blob[32 + mid * 8:36 + mid * 8]
        if key < sel:
            lo = mid + 1
        elif key > sel:
            hi = mid
        else:
            at = pool + struct.unpack_from("<I", blob, 36 + mid * 8)[0]
            text = blob[at + 1:at + 1 + blob[at]]
            proof = blob[proofs + mid * depth * 32:proofs + (mid + 1) * depth * 32]
            return sel + bytes([len(text)]) + text + struct.pack("<II", mid, depth) + proof
    raise SystemExit(f"selector 0x{sel.hex()} is not in {SELECTORS_DB}")


def userop_head(sender: bytes, chain_id: int, flags: int, nonce: int,
                to: bytes, value: int, data: bytes, paymaster_hash: bytes = SHA256_EMPTY) -> bytes:
    return b"".join([
        u64(chain_id), u32(flags), sender, ENTRY_POINT_V06, u256(nonce),
        u256(GAS["call"]), u256(GAS["ver"]), u256(GAS["pre"]),
        u256(GAS["max_fee"]), u256(GAS["prio"]), paymaster_hash,
        to, u256(value), u16(len(data)), data,
    ])


def trailers(erc20: bytes = b"", cow: bytes = b"", safe: bytes = b"", selector: bytes = b"",
             self_attest: bytes = b"", erc7730: bytes = b"", names: tuple[bytes, ...] = ()) -> bytes:
    """Positional sign-input trailers (cmd_sign_userop.rs): erc20 | reserved |
    cow_order | safe_v1 | selector | self_attest | erc7730, then the names
    section (count byte + u16-prefixed bundles; absent = count 0)."""
    out = b""
    for t in (erc20, b"", cow, safe, selector, self_attest, erc7730):
        out += u16(len(t)) + t
    if names:
        out += bytes([len(names)]) + b"".join(u16(len(n)) + n for n in names)
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
    struct_ = keccak256(
        order_th + word_addr(c[8:28]) + word_addr(c[28:48]) + word_addr(c[48:68])
        + c[68:100] + c[100:132] + b"\0" * 28 + c[164:168] + c[172:204] + c[132:164]
        + kind + b"\0" * 31 + bytes([c[169]]) + sell_bal + buy_bal)
    return keccak256(b"\x19\x01" + domain + struct_)


def cow_order(chain_id: int, sell: bytes, buy: bytes, sell_amount: int, buy_amount: int,
              fee: int = 0) -> bytes:
    """A SELL order; receiver 0 = the owner (the wallet, or the Safe when wrapped)."""
    o = bytearray(204)
    o[0:8] = u64(chain_id)
    o[8:28] = sell
    o[28:48] = buy
    o[68:100] = u256(sell_amount)
    o[100:132] = u256(buy_amount)
    o[132:164] = u256(fee)
    o[164:168] = u32(int(time.time()) + 3600)       # validTo
    o[168] = 0                                      # SELL
    o[172:204] = b"\xa7" * 32                       # appData
    return bytes(o)


def presign(order: bytes, owner: bytes) -> bytes:
    """`setPreSignature(orderUid, true)`; orderUid = digest | owner | validTo."""
    uid = cow_digest(order) + owner + order[164:168]
    cd = SET_PRESIGNATURE + u256(0x40) + u256(1) + u256(56) + uid + b"\0" * 8
    assert len(cd) == 164
    return cd


def cow_trailer(order: bytes, decoded: bool = True) -> bytes:
    """The kind-3 order trailer: the bare canonical renders both legs as
    addresses; with the legs' ERC-20 proofs the device decodes them."""
    if not decoded:
        return order
    chain_id = int.from_bytes(order[0:8], "big")
    sell_b, buy_b = erc20_proof(chain_id, order[8:28]), erc20_proof(chain_id, order[28:48])
    return order + u16(len(sell_b)) + sell_b + u16(len(buy_b)) + buy_b


def safe_tx(to: bytes, value: int, data: bytes, nonce: int, operation: int = 0, *,
            safe_tx_gas: int = 0, base_gas: int = 0, gas_price: int = 0,
            gas_token: bytes = ZERO, refund: bytes = ZERO) -> bytes:
    """281-byte canonical SafeTx for SAFE on Base (safe_v1 trailer layout)."""
    c = bytearray(build_safe_canonical(BASE, SAFE, to, value, data, nonce, operation))
    c[SAFE_OFF_SAFE_TX_GAS:SAFE_OFF_SAFE_TX_GAS + 32] = u256(safe_tx_gas)
    c[SAFE_OFF_BASE_GAS:SAFE_OFF_BASE_GAS + 32] = u256(base_gas)
    c[SAFE_OFF_GAS_PRICE:SAFE_OFF_GAS_PRICE + 32] = u256(gas_price)
    c[SAFE_OFF_GAS_TOKEN:SAFE_OFF_GAS_TOKEN + 20] = gas_token
    c[SAFE_OFF_REFUND_RECEIVER:SAFE_OFF_REFUND_RECEIVER + 20] = refund
    return bytes(c)


def safe_exec_calldata(to: bytes, value: int, data: bytes, signatures: bytes) -> bytes:
    """Canonical ABI `execTransaction(to, value, data, 0, 0, 0, 0, 0, 0, sigs)`."""
    data_off = 10 * 32
    sigs_off = data_off + 32 + len(pad32(data))
    return (EXEC_TRANSACTION + word_addr(to) + u256(value) + u256(data_off) + u256(0)
            + u256(0) + u256(0) + u256(0) + word_addr(ZERO) + word_addr(ZERO) + u256(sigs_off)
            + u256(len(data)) + pad32(data) + u256(len(signatures)) + pad32(signatures))


def multisend(*records: bytes) -> bytes:
    """`multiSend(bytes)` over packed `op | to | value | len | data` records."""
    packed = b"".join(records)
    return MULTI_SEND + u256(0x20) + u256(len(packed)) + pad32(packed)


def ms_record(to: bytes, data: bytes, value: int = 0) -> bytes:
    return b"\0" + to + u256(value) + u256(len(data)) + data   # op 0 (CALL) only


def exact_input_single() -> bytes:
    """Uniswap V3 Router02 exactInputSingle with the host golden's tokens."""
    token_in, token_out = b"\x11" * 20, b"\x22" * 20
    return (keccak256(EXACT_INPUT_SINGLE_SIG)[:4] + word_addr(token_in) + word_addr(token_out)
            + u256(3000) + word_addr(ALICE) + u256(1_500_000) + u256(1_000_000) + u256(0))


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
    kind: str                 # userop | batch | offchain | address | lock | refuse | sync | fw | idle
    lines: list[str]
    want_init: bool = False
    want_t1: bool = False
    deployed: bool = False
    sync: str = ""            # sync flows: plain | warn | refuse


@dataclass
class Ctx:
    sender: bytes
    args: argparse.Namespace
    nonce: int

    def flags(self, slot: int | None = None, extra: int = 0) -> int:
        """Wire flags: extra bits | account_index (bits 29..22) | slot_index."""
        s = self.args.slot if slot is None else slot
        return extra | (self.args.account << ACCOUNT_INDEX_SHIFT) | s


def f_send(c: Ctx) -> Request:
    amt = 12_500_000_000_000_000  # 0.0125 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, ALICE, amt, b"") + trailers(),
                   "userop", [f"send 0.0125 ETH -> 0x{ALICE.hex()} on Base"])


def f_call(c: Ctx) -> Request:
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, CONTRACT, 0, b"") + trailers(),
                   "userop", [f"zero-value call to 0x{CONTRACT.hex()} (empty calldata)"])


def f_named(c: Ctx) -> Request:
    amt = 1_000_000_000_000_000  # 0.001 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, UNI_V3_ROUTER, amt, b"")
                   + trailers(names=(names_proof(BASE, UNI_V3_ROUTER),)),
                   "userop", [f"send 0.001 ETH -> 0x{UNI_V3_ROUTER.hex()} on Base",
                              "names proof attached -> the recipient reads 'Uniswap V3 Router'"])


def f_extras(c: Ctx) -> Request:
    lane = (int.from_bytes(b"\x5a" * 24, "big") << 64) | c.nonce
    pm = hashlib.sha256(PAYMASTER_AND_DATA).digest()
    amt = 2_000_000_000_000_000  # 0.002 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), lane, ALICE, amt, b"", paymaster_hash=pm)
                   + trailers(),
                   "userop", ["send 0.002 ETH -> alice with a paymaster set and a non-zero nonce lane key",
                              f"! PAYMASTER SET (hash 0x{pm.hex()}), LANE key 0x{'5a' * 24}"])


def f_erc20(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, BOB, 1_234_560_000)  # 1234.56 USDC
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, USDC_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDC_BASE)),
                   "userop", ["transfer 1234.56 USDC (Base) -> 0x" + BOB.hex(), "ERC-20 proof attached"])


def f_approve(c: Ctx) -> Request:
    spender = addr("0x000000000022D473030F116dDEE9F6B43aC78BA3")  # Permit2
    data = erc20_call(APPROVE, spender, (1 << 256) - 1)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, USDC_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDC_BASE)),
                   "userop", ["approve UNLIMITED USDC (Base) to Permit2", "ERC-20 proof attached"])


def f_unknown(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, ALICE, 12_345_678_901_234_567_890)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, UNKNOWN_TOKEN, 0, data) + trailers(),
                   "userop", [f"transfer raw 12345678901234567890 of 0x{UNKNOWN_TOKEN.hex()} (no proof)"])


def f_usdt(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, ALICE, 42_500_000)  # 42.5 USDT (6 decimals)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, USDT_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDT_BASE)),
                   "userop", ["transfer 42.5 USDT (Base) -> 0x" + ALICE.hex(), "ERC-20 proof -> USDT disc mark"])


def f_dai_wrap(c: Ctx) -> Request:
    data = erc20_call(TRANSFER, BOB, 1_234_987_654_321_098_765_432)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, DAI_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, DAI_BASE)),
                   "userop", ["transfer 1234.987654321098765432 DAI (Base) -> 0x" + BOB.hex(),
                              "every digit, wrapped over two lines (no rounding); DAI disc mark"])


def f_pull(c: Ctx) -> Request:
    data = TRANSFER_FROM + word_addr(PULL_FROM) + word_addr(BOB) + u256(12_500 * 10 ** 18)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, TOSHI_BASE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, TOSHI_BASE)),
                   "userop", [f"transferFrom 12500 TOSHI (Base) 0x{PULL_FROM.hex()} -> 0x{BOB.hex()}",
                              "FROM screen; TOSHI has no baked mark -> placeholder-ramp disc"])


def f_blind(c: Ctx) -> Request:
    data = bytes.fromhex("123456789abcdef042") + bytes(range(40))
    amt = 30_000_000_000_000_000  # 0.03 ETH
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, OPAQUE_TARGET, amt, data) + trailers(),
                   "userop", [f"opaque {len(data)} B calldata + 0.03 ETH -> 0x{OPAQUE_TARGET.hex()}"])


def f_typed_call(c: Ctx) -> Request:
    sig = b"stake(address,uint256)"
    sel = keccak256(sig)[:4]
    data = sel + word_addr(BOB) + u256(42_000)
    attest = sel + bytes([len(sig)]) + sig
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, OPAQUE_TARGET, 0, data)
                   + trailers(self_attest=attest),
                   "userop", [f"self-attested {sig.decode()} (0x{sel.hex()}) on 0x{OPAQUE_TARGET.hex()}"])


def f_typed_rich(c: Ctx) -> Request:
    # Six args, one of each type the typed walker renders in full (the page
    # budget's maximum): a non-empty string / bytes, bytes16+ or an array of
    # more than one element would drop the call to BLIND on purpose.
    sig = b"configure(address,uint256,bool,int64,bytes8,uint256[])"
    sel = keccak256(sig)[:4]
    data = (sel + word_addr(BOB) + u256(10 ** 18) + u256(1) + u256((1 << 256) - 42)
            + pad32(bytes.fromhex("deadbeefcafef00d")) + u256(6 * 32) + u256(1) + u256(42))
    attest = sel + bytes([len(sig)]) + sig
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, OPAQUE_TARGET, 0, data)
                   + trailers(self_attest=attest),
                   "userop", [f"self-attested {sig.decode()} (0x{sel.hex()})",
                              "ARG 0..5: bob, 1000000000000000000, true, -42, 0xdeadbeefcafef00d, [1 items] first: 42"])


def f_typed_curated(c: Ctx) -> Request:
    sel = keccak256(b"setApprovalForAll(address,bool)")[:4]
    data = sel + word_addr(BOB) + u256(1)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, CONTRACT, 0, data)
                   + trailers(selector=selector_proof(sel)),
                   "userop", [f"setApprovalForAll(0x{BOB.hex()}, true) on 0x{CONTRACT.hex()}",
                              "curated selector proof -> typed args under the curated (not UNVERIFIED) banner"])


def f_blind_named(c: Ctx) -> Request:
    sel = keccak256(b"multiTransfer(address[],uint256[])")[:4]
    data = (sel + u256(0x40) + u256(0x40 + 32 + 2 * 32)
            + u256(2) + word_addr(ALICE) + word_addr(BOB)
            + u256(2) + u256(10 ** 18) + u256(2 * 10 ** 18))
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, CONTRACT, 0, data)
                   + trailers(selector=selector_proof(sel)),
                   "userop", ["curated multiTransfer(address[],uint256[]) with two recipients",
                              "arrays of 2+ are never half-decoded -> BLIND with the FUNCTION screen"])


def f_rotate(c: Ctx) -> Request:
    slot = c.args.rotate_slot
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(slot, FLAG_REGISTER_SLOT), c.nonce, ALICE,
                               1_000_000_000_000_000, b"") + trailers(),
                   "userop", [f"REGISTER slot {slot} on Base + send 0.001 ETH",
                              "(re-running on a registered slot may refuse; use --rotate-slot N)"],
                   want_t1=True)


def f_deploy(c: Ctx) -> Request:
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(0, FLAG_INCLUDE_INIT_CODE), 0, ALICE,
                               10_000_000_000_000_000, b"")
                   + trailers(),
                   "userop", ["first UserOp with initCode (slot 0, nonce 0) + send 0.01 ETH"],
                   want_init=True)


def f_safe(c: Ctx) -> Request:
    raw = erc20_call(TRANSFER, ALICE, 250_000_000)
    canonical = build_safe_canonical(BASE, SAFE, USDC_BASE, 0, raw, 17 + c.nonce, 0)
    h = compute_safe_tx_hash(canonical)
    inner = APPROVE_HASH_SELECTOR + h
    req = {"chain_id": BASE, "flags": c.flags(), "nonce": c.nonce,
           "callGasLimit": GAS["call"], "verificationGasLimit": GAS["ver"],
           "preVerificationGas": GAS["pre"], "maxFeePerGas": GAS["max_fee"],
           "maxPriorityFeePerGas": GAS["prio"], "to": "0x" + SAFE.hex(), "value": 0}
    payload = build_payload_with_erc20(c.sender, req, inner, canonical, raw, erc20_proof(BASE, USDC_BASE))
    return Request(INS_SIGN_USEROP, payload, "userop",
                   [f"Safe 0x{SAFE.hex()} approveHash: transfer 250 USDC -> 0x{ALICE.hex()}",
                    f"safeTxHash 0x{h.hex()}"])


def safe_request(c: Ctx, to: bytes, value: int, data: bytes, lines: list[str], operation: int = 0,
                 erc20: bytes = b"", cow: bytes = b"", **gas: int | bytes) -> Request:
    """`approveHash(safeTxHash)` on SAFE with the safe_v1 trailer (+ optional
    ERC-20 proof for the inner token and the CoW order trailer)."""
    canonical = safe_tx(to, value, data, 17 + c.nonce, operation, **gas)
    h = compute_safe_tx_hash(canonical)
    payload = (userop_head(c.sender, BASE, c.flags(), c.nonce, SAFE, 0, APPROVE_HASH_SELECTOR + h)
               + trailers(erc20=erc20, cow=cow, safe=canonical + u16(len(data)) + data))
    return Request(INS_SIGN_USEROP, payload, "userop",
                   [f"Safe 0x{SAFE.hex()} (nonce {17 + c.nonce}) approveHash: " + lines[0]]
                   + lines[1:] + [f"safeTxHash 0x{h.hex()}"])


def f_safe_exec(c: Ctx) -> Request:
    raw = erc20_call(TRANSFER, ALICE, 250_000_000)
    # A pre-validated owner signature (r = the wallet, s = 0, v = 1): the
    # wallet is msg.sender of execTransaction.
    sigs = word_addr(c.sender) + bytes(32) + b"\x01"
    data = safe_exec_calldata(USDC_BASE, 0, raw, sigs)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, BASE, c.flags(), c.nonce, SAFE, 0, data)
                   + trailers(erc20=erc20_proof(BASE, USDC_BASE)),
                   "userop", [f"Safe 0x{SAFE.hex()} execTransaction: transfer 250 USDC -> 0x{ALICE.hex()}",
                              "the EXECUTE route (SafeTx decoded from the calldata, no safe_v1 trailer)"])


def f_safe_owner(c: Ctx) -> Request:
    data = ADD_OWNER_WITH_THRESHOLD + word_addr(CAROL) + u256(2)
    return safe_request(c, SAFE, 0, data, [f"addOwnerWithThreshold(0x{CAROL.hex()}, 2)"])


def f_safe_module(c: Ctx) -> Request:
    data = ENABLE_MODULE + word_addr(MODULE)
    return safe_request(c, SAFE, 0, data, [f"enableModule(0x{MODULE.hex()}) - a module can move every asset"])


def f_safe_refund(c: Ctx) -> Request:
    raw = erc20_call(TRANSFER, ALICE, 5_000_000)
    return safe_request(c, USDC_BASE, 0, raw,
                        ["transfer 5 USDC + a native gas refund",
                         f"baseGas 43776, gasPrice 1 gwei, refund -> 0x{REFUND_TO.hex()}"],
                        erc20=erc20_proof(BASE, USDC_BASE), base_gas=43_776, gas_price=1_000_000_000,
                        refund=REFUND_TO)


def f_safe_eth(c: Ctx) -> Request:
    return safe_request(c, ALICE, 1_500_000_000_000_000_000, b"",
                        ["send 1.5 ETH from the Safe with safeTxGas 120000", "expect 'inner may no-op'"],
                        safe_tx_gas=120_000)


def f_safe_blind(c: Ctx) -> Request:
    return safe_request(c, INNER, 0, bytes.fromhex("deadbeef"),
                        [f"unknown inner call 0xdeadbeef on 0x{INNER.hex()}", "BLIND SIGN + full data hash"])


def f_safe_unverified(c: Ctx) -> Request:
    return safe_request(c, USDC_BASE, 0, erc20_call(TRANSFER, ALICE, 250_000_000),
                        ["token transfer WITHOUT the ERC-20 proof", "Token (UNVERIFIED), 250000000 units"])


def f_safe_empty(c: Ctx) -> Request:
    return safe_request(c, INNER, 0, b"", [f"EMPTY CALL to 0x{INNER.hex()}"])


def f_safe_cow(c: Ctx) -> Request:
    order = cow_order(BASE, WETH_BASE, USDC_BASE, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return safe_request(c, GPV2_SETTLEMENT, 0, presign(order, SAFE),
                        ["CoW presign owned by the Safe: SELL 0.5 WETH for >= 1842.31 USDC (Base)",
                         "order headline before Confirm?, receiver '= the Safe', decoded legs"],
                        cow=cow_trailer(order))


def f_safe_msend(c: Ctx) -> Request:
    sell = 1_250_000_000  # 1250 USDC
    order = cow_order(BASE, USDC_BASE, DAI_BASE, sell, 1_234_987_654_321_098_765_432)
    data = multisend(ms_record(USDC_BASE, erc20_call(APPROVE, VAULT_RELAYER, sell)),
                     ms_record(GPV2_SETTLEMENT, presign(order, SAFE)))
    return safe_request(c, MULTISEND_CALL_ONLY_V150, 0, data,
                        ["Safe UI shape via MultiSendCallOnly v1.5.0 (DELEGATECALL):",
                         "RECORD 1/2 approve 1250 USDC to the CoW VaultRelayer,",
                         "RECORD 2/2 SELL 1250 USDC for >= 1234.987654321098765432 DAI (wrapped, exact)"],
                        operation=1, erc20=erc20_proof(BASE, USDC_BASE), cow=cow_trailer(order))


def f_cow(c: Ctx) -> Request:
    order = cow_order(MAINNET, WETH_MAINNET, USDC_MAINNET, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.flags(), c.nonce, GPV2_SETTLEMENT, 0,
                               presign(order, c.sender))
                   + trailers(cow=cow_trailer(order)),
                   "userop", ["CoW: SELL 0.5 WETH for at least 1842.31 USDC (mainnet), fee 0.001 WETH",
                              "both legs carry ERC-20 proofs -> decoded"])


def f_cow_addr(c: Ctx) -> Request:
    order = cow_order(MAINNET, WETH_MAINNET, USDC_MAINNET, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.flags(), c.nonce, GPV2_SETTLEMENT, 0,
                               presign(order, c.sender))
                   + trailers(cow=cow_trailer(order, decoded=False)),
                   "userop", ["the same CoW order WITHOUT leg proofs (address mode)",
                              "legs shown as full token contracts + raw amount words"])


def f_erc7730(c: Ctx) -> Request:
    t, _ = erc7730_leaf(MAINNET, UNI_V3_ROUTER02)
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.flags(), c.nonce, UNI_V3_ROUTER02, 0,
                               exact_input_single())
                   + trailers(erc7730=t),
                   "userop", ["Uniswap V3 Router02 exactInputSingle (mainnet), ERC-7730 proof "
                              f"{len(t)} B"])


def f_refuse(c: Ctx) -> Request:
    return Request(INS_SIGN_USEROP,
                   userop_head(c.sender, MAINNET, c.flags(), c.nonce, UNI_V3_ROUTER02, 0,
                               exact_input_single())
                   + trailers(),
                   "refuse", ["the erc7730 call WITHOUT its ERC-7730 proof (a registry-known call)",
                              "expect a SIGN REFUSED notice ('7730 proof needed', then 'render refused');"
                              " nothing to confirm"])


def offchain(c: Ctx, chain_id: int, kind: int, payload: bytes, lines: list[str],
             deployed: bool | None = None) -> Request:
    deployed = c.args.deployed if deployed is None else deployed
    slot = c.args.slot if deployed else 0
    flags = OFFCHAIN_FLAG_DEPLOYED if deployed else 0
    req = (bytes([c.args.account]) + u64(chain_id) + u32(slot) + bytes([kind]) + u16(len(payload))
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


# Structured off-chain kinds (UPDATE 2026-10-19, usb-protocol-v2.md §0x62 kinds
# 4/5): the device recomputes H from the bytes it shows and signs
# replay_safe_hash(H). Both refuse ERC-6492, so they always go out as
# deployed on --slot, which must be registered on the device (`personal`
# registers slot 0 on a fresh wallet; it runs first in the walk).

def structured(c: Ctx, chain_id: int, kind: int, payload: bytes, lines: list[str]) -> Request:
    h = structured_offchain.structured_digest(kind, payload, chain_id)
    return offchain(c, chain_id, kind, payload,
                    lines + [f"H 0x{h.hex()} (the device signs replay_safe_hash(H))"], deployed=True)


def safe_offchain(c: Ctx, to: bytes, value: int, data: bytes, lines: list[str], operation: int = 0,
                  erc20: bytes = b"", cow: bytes = b"") -> Request:
    canonical = safe_tx(to, value, data, 17 + c.nonce, operation)
    payload = structured_offchain.build_safe_tx_payload(canonical, data, erc20, cow)
    return structured(c, BASE, OFFCHAIN_KIND_SAFE_TX, payload,
                      [f"EIP-1271 SafeTx on Base: this wallet co-signs Safe 0x{SAFE.hex()} "
                       f"(nonce {17 + c.nonce})"] + lines)


def f_off_safe(c: Ctx) -> Request:
    return safe_offchain(c, USDC_BASE, 0, erc20_call(TRANSFER, ALICE, 250_000_000),
                         [f"inner: transfer 250 USDC -> 0x{ALICE.hex()} (ERC-20 proof)"],
                         erc20=erc20_proof(BASE, USDC_BASE))


def f_off_safe_cow(c: Ctx) -> Request:
    order = cow_order(BASE, WETH_BASE, USDC_BASE, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return safe_offchain(c, GPV2_SETTLEMENT, 0, presign(order, SAFE),
                         ["inner: CoW presign owned by the Safe, SELL 0.5 WETH for >= 1842.31 USDC"],
                         cow=cow_trailer(order))


def f_off_safe_msend(c: Ctx) -> Request:
    sell = 1_250_000_000  # 1250 USDC
    order = cow_order(BASE, USDC_BASE, DAI_BASE, sell, 1_234_987_654_321_098_765_432)
    data = multisend(ms_record(USDC_BASE, erc20_call(APPROVE, VAULT_RELAYER, sell)),
                     ms_record(GPV2_SETTLEMENT, presign(order, SAFE)))
    return safe_offchain(c, MULTISEND_CALL_ONLY_V150, 0, data,
                         ["inner: MultiSendCallOnly v1.5.0 [approve 1250 USDC, presign 1250 USDC -> DAI]"],
                         operation=1, erc20=erc20_proof(BASE, USDC_BASE), cow=cow_trailer(order))


def f_off_cow(c: Ctx) -> Request:
    order = cow_order(BASE, WETH_BASE, USDC_BASE, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return structured(c, BASE, OFFCHAIN_KIND_COW_ORDER, cow_trailer(order),
                      ["EIP-1271 CoW order on Base (owner = this wallet, receiver 0 = this wallet):",
                       "SELL 0.5 WETH for >= 1842.31 USDC, fee 0.001 WETH, both legs proven"])


def f_off_cow_addr(c: Ctx) -> Request:
    order = cow_order(BASE, WETH_BASE, USDC_BASE, 500_000_000_000_000_000, 1_842_310_000,
                      fee=1_000_000_000_000_000)
    return structured(c, BASE, OFFCHAIN_KIND_COW_ORDER, cow_trailer(order, decoded=False) + u16(0) + u16(0),
                      ["the same EIP-1271 CoW order WITHOUT leg proofs",
                       "legs shown as token contracts + raw amounts"])


def batch_head(c: Ctx, count: int) -> bytes:
    return b"".join([
        u64(BASE), u32(c.flags()), c.sender, ENTRY_POINT_V06, u256(c.nonce),
        u256(400_000), u256(1_000_000), u256(200_000), u256(GAS["max_fee"]), u256(GAS["prio"]),
        SHA256_EMPTY, bytes([BATCH_WIRE_VERSION, count]),
    ])


def f_batch(c: Ctx) -> Request:
    txs = [
        (ALICE, 100_000_000_000_000_000, b""),                          # 0.1 ETH
        (USDC_BASE, 0, erc20_call(TRANSFER, BOB, 250_000_000)),         # 250 USDC
        (OPAQUE_TARGET, 0, bytes.fromhex("123456789abcdef042")),        # blind
    ]
    body = batch_head(c, len(txs))
    for to, v, d in txs:
        body += to + u256(v) + u16(len(d)) + d
    proof = erc20_proof(BASE, USDC_BASE)
    body += bytes([1]) + bytes([TRAILER_KIND_ERC20, 1]) + u16(len(proof)) + proof
    return Request(INS_SIGN_USEROP_BATCH, body, "batch",
                   ["batch on Base: 0.1 ETH -> alice | 250 USDC -> bob (proof) | 9 B opaque call",
                    "3 member asks, then the final SIGN 3 TXS? ask"])


def f_batch1(c: Ctx) -> Request:
    body = batch_head(c, 1) + ALICE + u256(50_000_000_000_000_000) + u16(0) + bytes([0])
    return Request(INS_SIGN_USEROP_BATCH, body, "batch",
                   ["degenerate 1-tx batch: 0.05 ETH -> alice", "TX 1 OF 1, then the final ask for one tx"])


def sync_key(c: Ctx, slot: int) -> bytes:
    return bytes([c.args.account]) + u64(BASE) + u32(slot)


def f_sync(c: Ctx) -> Request:
    slot = c.args.sync_slot
    return Request(INS_OFFCHAIN_SYNC, sync_key(c, slot), "sync",
                   [f"off-chain counter sync, slot {slot} on Base (account {c.args.account})",
                    "reads the counters, then asks to raise the count by one (plain confirm)"],
                   sync="plain")


def f_sync_warn(c: Ctx) -> Request:
    slot = c.args.sync_slot
    return Request(INS_OFFCHAIN_SYNC, sync_key(c, slot), "sync",
                   [f"off-chain counter sync, slot {slot} on Base: a jump of {SYNC_WARN_STEP:,} (> 1,000)",
                    "expect the plain confirm plus the ! CAREFUL screen"],
                   sync="warn")


def f_sync_refuse(c: Ctx) -> Request:
    slot = c.args.rotate_slot
    return Request(INS_OFFCHAIN_SYNC, sync_key(c, slot), "sync",
                   [f"off-chain counter sync, slot {slot} on Base -> 65535 (would use up the slot)",
                    "expect NO dialog and 'Can't update' (if ! CAREFUL appears: DECLINE, run rotate first)"],
                   sync="refuse")


def f_address(c: Ctx) -> Request:
    return Request(INS_GET_WALLET_ADDRESS, u32(c.args.account) + b"\x01", "address",
                   [f"show wallet address (expect 0x{c.sender.hex()})"])


def f_fw_verify(c: Ctx) -> Request:
    return Request(INS_FW_BEGIN, bytes(FW_MANIFEST_SIZE), "fw",
                   ["firmware-update VERIFY consent (FW_BEGIN, unsigned all-zero 8 KiB manifest)",
                    "confirm: the verifier rejects it (SW 6A80); decline: 6982; flash untouched either way",
                    "dev-unit (devunit-ab) images show no ask here: the update consent comes after the verifier"])


def f_lock(c: Ctx) -> Request:
    return Request(INS_LOCK, b"", "lock", ["lock: LOCKED padlock, then the PIN row"])


def f_idle(c: Ctx) -> Request:
    return Request(INS_GET_STATUS, b"", "idle",
                   ["idle lock: do NOT press a button; the device locks itself 120 s after the last press",
                    "then the LOCKED padlock and the PIN row; unlock to continue"])


@dataclass(frozen=True)
class Flow:
    build: Callable[[Ctx], Request]
    group: str
    shows: str                # what the device should show


# Walk order. Groups: value erc20 calls account safe cow 7730 offchain batch device.
FLOWS: dict[str, Flow] = {
    "send": Flow(f_send, "value", "SEND hero, 0.0125 ETH on Base"),
    "call": Flow(f_call, "value", "CALL hero (contract_call), zero value, empty calldata"),
    "named": Flow(f_named, "value", "SEND to a named recipient: 'Uniswap V3 Router' (names proof)"),
    "extras": Flow(f_extras, "value", "SEND + loud trailers: ! PAYMASTER SET, nonce LANE key"),
    "erc20": Flow(f_erc20, "erc20", "TRANSFER 1234.56 USDC, token named, USDC mark"),
    "approve": Flow(f_approve, "erc20", "APPROVE USDC? to Permit2, AMOUNT unlimited"),
    "unknown": Flow(f_unknown, "erc20", "TRANSFER UNKNOWN TOKEN? placeholder ramp, raw units"),
    "usdt": Flow(f_usdt, "erc20", "TRANSFER 42.5 USDT, USDT mark"),
    "dai-wrap": Flow(f_dai_wrap, "erc20", "1234.987654321098765432 DAI wrapped exact over 2 lines, DAI mark"),
    "pull": Flow(f_pull, "erc20", "transferFrom 12500 TOSHI: FROM screen, placeholder-ramp disc"),
    "blind": Flow(f_blind, "calls", "CONFIRM UNKNOWN CALL? + 0.03 ETH, full data hash"),
    "typed-call": Flow(f_typed_call, "calls", "self-attested stake(address,uint256), ! UNVERIFIED"),
    "typed-rich": Flow(f_typed_rich, "calls", "self-attested 6-arg call: ARG 0..5 of six types"),
    "typed-curated": Flow(f_typed_curated, "calls", "curated setApprovalForAll(address,bool), typed args"),
    "blind-named": Flow(f_blind_named, "calls", "curated multiTransfer, 2 entries: BLIND + FUNCTION screen"),
    "rotate": Flow(f_rotate, "account", "ROTATE consent (Type 1 + Type 2)"),
    "deploy": Flow(f_deploy, "account", "! DEPLOY trailer (initCode, slot 0)"),
    "safe": Flow(f_safe, "safe", "APPROVE SAFE TX? USDC transfer (approveHash)"),
    "safe-exec": Flow(f_safe_exec, "safe", "EXECUTE hero: execTransaction, USDC transfer"),
    "safe-owner": Flow(f_safe_owner, "safe", "Safe addOwnerWithThreshold: NEW OWNER, Threshold: 2"),
    "safe-module": Flow(f_safe_module, "safe", "Safe enableModule: loud module warning"),
    "safe-refund": Flow(f_safe_refund, "safe", "Safe gas refund: REFUND TOKEN / REFUND MAX / REFUND TO"),
    "safe-eth": Flow(f_safe_eth, "safe", "Safe inner 1.5 ETH + safeTxGas: 'inner may no-op'"),
    "safe-blind": Flow(f_safe_blind, "safe", "Safe inner unknown call: BLIND SIGN, full data hash"),
    "safe-unverified": Flow(f_safe_unverified, "safe", "Safe inner transfer, no proof: UNVERIFIED, raw units"),
    "safe-empty": Flow(f_safe_empty, "safe", "Safe inner EMPTY CALL"),
    "safe-cow": Flow(f_safe_cow, "safe", "Safe-wrapped CoW presign: headline, '= the Safe', decoded legs"),
    "safe-msend": Flow(f_safe_msend, "safe", "multiSend v1.5.0 [approve, presign]: RECORD 1/2, 2/2, DAI wrap"),
    "cow": Flow(f_cow, "cow", "SIGN COWSWAP? hero, decoded legs (mainnet)"),
    "cow-addr": Flow(f_cow_addr, "cow", "SIGN COWSWAP? address mode: token contracts + raw amounts"),
    "erc7730": Flow(f_erc7730, "7730", "SIGN ... INTENT: Uniswap V3 exactInputSingle (7730 lift)"),
    "refuse": Flow(f_refuse, "7730", "the same call without its proof: SIGN REFUSED notice, no ask"),
    "personal": Flow(f_personal, "offchain", "SIGN EIP-1271? personal_sign message (ERC-6492)"),
    "raw32": Flow(f_raw32, "offchain", "! BLIND RAW32 + the full hash"),
    "typed": Flow(f_typed, "offchain", "SIGN ... EIP-712 Lombard feeApproval (7730 typed)"),
    "off-safe": Flow(f_off_safe, "offchain", "EIP-1271 SafeTx (kind 4): Safe banner, USDC transfer decoded"),
    "off-safe-cow": Flow(f_off_safe_cow, "offchain", "EIP-1271 SafeTx (kind 4) wrapping a CoW presign: legs decoded"),
    "off-safe-msend": Flow(f_off_safe_msend, "offchain", "EIP-1271 SafeTx (kind 4) multiSend v1.5.0: RECORD 1/2, 2/2"),
    "off-cow": Flow(f_off_cow, "offchain", "EIP-1271 CoW order (kind 5): SIGN COWSWAP?, decoded legs"),
    "off-cow-addr": Flow(f_off_cow_addr, "offchain", "EIP-1271 CoW order (kind 5), no proofs: address mode"),
    "sync": Flow(f_sync, "sync", "UPDATE SIGNATURE COUNT? +1 on --sync-slot (plain)"),
    "sync-warn": Flow(f_sync_warn, "sync", "UPDATE SIGNATURE COUNT? +1,500, plus the ! CAREFUL screen"),
    "sync-refuse": Flow(f_sync_refuse, "sync", "no dialog: refused, would use up --rotate-slot (run rotate first)"),
    "batch": Flow(f_batch, "batch", "3 member asks (TX i OF 3 CONFIRMED) + SIGN 3 TXS?"),
    "batch1": Flow(f_batch1, "batch", "1-tx batch: one member ask + the final ask"),
    "address": Flow(f_address, "device", "wallet-address consent, the address whole"),
    "fw-verify": Flow(f_fw_verify, "device", "firmware-update verify consent, then the rejection (devunit-ab: no ask)"),
    "lock": Flow(f_lock, "device", "LOCKED padlock -> PIN row"),
    "idle": Flow(f_idle, "device", "hands off 120 s: LOCKED padlock -> PIN row"),
}
# Not in the default walk: lock/idle lock the device; sync-warn spends 1,500 of
# --sync-slot's budget per run; sync-refuse needs a rotated slot.
SPECIAL = ("sync-warn", "sync-refuse", "lock", "idle")
DEFAULT = [n for n in FLOWS if n not in SPECIAL]
# Flows not yet walked on glass at the first EVT walk (2026-09-23, e6a8dd97), plus later additions.
NEW = ["named", "extras", "usdt", "dai-wrap", "pull", "typed-rich", "typed-curated", "blind-named",
       "safe-exec", "safe-owner", "safe-module", "safe-refund", "safe-eth", "safe-blind",
       "safe-unverified", "safe-empty", "safe-cow", "safe-msend", "cow-addr", "refuse", "sync",
       "batch1", "fw-verify", "idle",
       # 2026-10-13 / 10-19: sync policy and the structured off-chain kinds
       "sync-warn", "sync-refuse", "off-safe", "off-safe-cow", "off-safe-msend", "off-cow", "off-cow-addr"]
GROUPS: dict[str, list[str]] = {}
for _name, _flow in FLOWS.items():
    GROUPS.setdefault(_flow.group, []).append(_name)
GROUPS["new"] = NEW

MANUAL = """\
Screens no USB request can reach (walk them by hand):
  power-cycle        boot splash, then the 8-word firmware fingerprint grid
  PIN entry          the PIN row (entered digits masked), UNLOCKED padlock, READY
  wrong PIN          enter one wrong PIN at unlock: WRONG PIN verdict (spends one attempt)
  decline endings    hold-left on any ask: the red ending; decline member 2 of `batch`:
                     BATCH DECLINED
  idle lock          the `idle` flow, or leave the device 120 s: LOCKED -> PIN row
  seed wizard        only on a wiped device (destructive; not scripted here)"""


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
    if t1 != (TYPE1_ROTATION_SECTION_LEN if r.want_t1 else 0):
        return f"type1_len={t1} (a 0x0203 rotation section is {TYPE1_ROTATION_SECTION_LEN})"
    if t1:
        t1_off = 8 + 4 + ic + 4
        owner = resp[t1_off:t1_off + OWNER_BYTES_LEN]
        t1_wrap = resp[t1_off + OWNER_BYTES_LEN:t1_off + t1]
        if any(owner[16:32]) or int.from_bytes(t1_wrap[0:32], "big") != 0:
            return "Type-1 section malformed (owner pkSeed not N-masked or ownerIndex != 0)"
        print(f"    NEW SLOT KEY: pkSeed=0x{owner[:32].hex()}")
        print(f"                  pkRoot=0x{owner[32:].hex()}")
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


def refusal(sw: int) -> str:
    """Name a non-9000 status word; the device screen carries the detail."""
    if sw == SW_DECLINED:
        print("    declined on the device")
        return "declined"
    if sw == SW_REFUSED:
        print("!! the device REFUSED (SW=0x6F00): a firmware gate fired; the NOTICE on the screen names it")
        return "REFUSED"
    if sw == SW_IDLE_WIPED:
        print("!! idle timeout during the ask (SW=0x6984): the device locked itself")
        return "idle-wiped"
    if sw == SW_NOT_READY:
        print("!! conditions not satisfied (SW=0x6985): locked, or an off-chain / update gate")
        return "not-ready"
    print(f"!! unexpected SW=0x{sw:04x}")
    return "error"


def counters(st: bytes) -> tuple[int, int, int]:
    return int.from_bytes(st[0:8], "big"), int.from_bytes(st[8:16], "big"), st[16]


def run_sync(hid: HidRaw, r: Request, args: argparse.Namespace) -> str:
    key = r.payload
    sw, st = send(hid, INS_OFFCHAIN_STATUS, key)
    if sw != SW_OK or len(st) != 24:
        print(f"!! OFFCHAIN_STATUS failed (SW=0x{sw:04x}, {len(st)} B)")
        return "error"
    local, last, reg = counters(st)
    # The device measures a jump from max(local, last) (aa::offchain_gate::sync_jump).
    eff = max(local, last)
    target = {"plain": eff + 1, "warn": eff + SYNC_WARN_STEP, "refuse": SYNC_REFUSE_TARGET}[r.sync]
    print(f"    now: local_offchain_count={local} last_userop_count={last} registered={reg}")
    if r.sync == "refuse":
        print(f"==> asking to raise last_userop_count {last} -> {target}. The device should refuse on its own")
    else:
        print(f"==> asking to raise last_userop_count {last} -> {target}. Chord = confirm, hold-left = decline "
              f"({args.confirm_timeout:.0f}s)")
    hid.timeout_s = args.confirm_timeout
    try:
        sw, _ = send(hid, INS_OFFCHAIN_SYNC, key + u64(target))
    except TimeoutError:
        print("!! no answer before the timeout")
        return "timeout"
    if r.sync == "refuse":
        if sw == SW_NOT_READY:
            print("    REFUSED as intended (SW=0x6985): the sync would have left the slot 0 signatures")
            return "refused (expected)"
        if sw == SW_OK:
            print("!! sync-refuse was ACCEPTED: the device wrote the floor (expected a refusal)")
            return "error"
        return refusal(sw)
    if sw != SW_OK:
        return refusal(sw)
    hid.timeout_s = 15.0
    sw, st = send(hid, INS_OFFCHAIN_STATUS, key)
    if sw != SW_OK or len(st) != 24 or counters(st)[1] != target:
        print(f"!! confirmed but the floor did not move (SW=0x{sw:04x})")
        return "error"
    print(f"    CONFIRMED: last_userop_count={target}")
    return "confirmed"


def run_idle(hid: HidRaw, args: argparse.Namespace) -> str:
    hid.timeout_s = 3.0
    t0 = time.monotonic()
    while (elapsed := time.monotonic() - t0) < args.idle_wait:
        try:
            sw, d = send(hid, INS_GET_STATUS)
        except (TimeoutError, OSError):
            print(f"    no answer after {elapsed:.0f}s: the PIN entry owns the device -> LOCKED")
            return "locked"
        if sw == SW_OK and len(d) >= 1 and d[0] == 1:
            print(f"    LOCKED after {elapsed:.0f}s: the padlock, then the PIN row")
            return "locked"
        print(f"    {elapsed:3.0f}s still unlocked", end="\r", flush=True)
        time.sleep(5)
    print(f"!! still unlocked after {args.idle_wait:.0f}s (a button press restarts the 120 s timer)")
    return "timeout"


def dump(args: argparse.Namespace, name: str, r: Request) -> None:
    if args.dump:
        os.makedirs(args.dump, exist_ok=True)
        with open(os.path.join(args.dump, f"{name}.{r.ins:02x}.bin"), "wb") as fh:
            fh.write(r.payload)


def save_rotation(hid: HidRaw, args: argparse.Namespace, sender: bytes, nonce: int,
                  resp: bytes) -> None:
    """Write the rotation response + this chain's initCode (bootstrap key)
    and print the offline check a seedless companion would run (#353)."""
    os.makedirs(args.save_dir, exist_ok=True)
    rp = os.path.join(args.save_dir, "rotate_resp.bin")
    with open(rp, "wb") as fh:
        fh.write(resp)
    sw, ic = send(hid, INS_GET_INIT_CODE, u32(args.account) + u64(BASE))
    sw, ic = drain_response(hid, sw, ic)
    if sw != SW_OK or len(ic) != INIT_CODE_LEN:
        print(f"!! GET_INIT_CODE failed (SW=0x{sw:04x}); response saved to {rp}")
        return
    ip = os.path.join(args.save_dir, "init_code.bin")
    with open(ip, "wb") as fh:
        fh.write(ic)
    gas = ",".join(str(GAS[k]) for k in ("call", "ver", "pre", "max_fee", "prio"))
    print("    verify offline (no seed needed):")
    print("      env -u RUSTFLAGS cargo run --release --manifest-path tools/verify-c10-sig/Cargo.toml --"
          f" rotation {rp} chain={BASE} slot={args.rotate_slot} sender={sender.hex()} nonce={nonce}"
          f" to={ALICE.hex()} value=1000000000000000 gas={gas} initcode={ip}")


def run_flow(hid: HidRaw, name: str, args: argparse.Namespace, nonce: int) -> str:
    hid.timeout_s = 15.0
    sw, data = send(hid, INS_GET_WALLET_ADDRESS, u32(args.account))
    sw, data = drain_response(hid, sw, data)
    if sw != SW_OK or len(data) != 20:
        print(f"!! GET_WALLET_ADDRESS failed (SW=0x{sw:04x})")
        return "error"
    r = FLOWS[name].build(Ctx(data, args, nonce))
    for line in r.lines:
        print(f"    {line}")
    dump(args, name, r)
    if r.kind == "idle":
        return run_idle(hid, args)
    if r.kind == "sync":
        return run_sync(hid, r, args)
    hid.timeout_s = args.confirm_timeout
    if r.kind == "refuse":
        print(f"==> sent ({len(r.payload)} B). The device should refuse on its own")
    elif r.kind != "lock":
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
    if r.kind == "refuse":
        if sw == SW_REFUSED:
            print("    REFUSED as expected (the NOTICE names the reason)")
            return "refused (expected)"
        if sw == SW_OK:
            print("!! the device SIGNED a request it must refuse")
            return "error"
        return refusal(sw)
    if r.kind == "fw":
        if sw == SW_WRONG_DATA:
            print("    the verifier rejected the unsigned manifest (SW 6A80), as intended; flash untouched")
            return "confirmed"
        if sw == SW_OK:
            print("!! FW_BEGIN accepted an unsigned manifest - stop and investigate")
            return "error"
        return refusal(sw)
    if sw != SW_OK:
        return refusal(sw)
    err = None
    if r.kind in ("userop", "batch"):
        err = check_userop(resp, r)
        if not err and r.want_t1 and args.save_dir:
            save_rotation(hid, args, data, nonce, resp)
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


def select(tokens: list[str], ap: argparse.ArgumentParser) -> list[str]:
    if not tokens:
        return list(DEFAULT)
    names: list[str] = []
    for t in tokens:
        if t == "all":
            picked = list(FLOWS)
        elif t.startswith("@"):
            if t[1:] not in GROUPS:
                ap.error(f"unknown group {t}; --list shows them")
            picked = GROUPS[t[1:]]
        elif t in FLOWS:
            picked = [t]
        else:
            ap.error(f"unknown flow {t!r}; --list shows them")
        names += [n for n in picked if n not in names]
    return names


def print_list() -> None:
    print(f"{'flow':16s}{'group':10s}the device should show")
    for n, f in FLOWS.items():
        tag = " (not in the default walk)" if n in SPECIAL else ""
        print(f"{n:16s}{f.group:10s}{f.shows}{tag}")
    print("\ngroups: " + " ".join(f"@{g}" for g in GROUPS) + "  (all = every flow incl. the special ones)")
    print(f"@new: {' '.join(NEW)}\n")
    print(MANUAL)


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("flows", nargs="*", help="flow names and @groups (default: all but sync-warn/sync-refuse/lock/idle; 'all' adds them)")
    ap.add_argument("--list", action="store_true", help="list flows, groups and the manual checks, then exit")
    ap.add_argument("--account", type=int, default=0, choices=range(256), metavar="0..255",
                    help="account index for every flow (the SIGNER screen names it)")
    ap.add_argument("--slot", type=int, default=0, help="slot for normal-mode UserOps")
    ap.add_argument("--rotate-slot", type=int, default=1, help="slot the rotate flow registers")
    ap.add_argument("--save-dir", default="",
                    help="rotate: save the response + initCode here and print the offline check")
    ap.add_argument("--sync-slot", type=int, default=9, help="slot the sync / sync-warn flows raise (keep it off the wallet's real slots)")
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
    ap.add_argument("--idle-wait", type=float, default=200.0, help="how long the idle flow waits for the lock")
    ap.add_argument("--dry-run", action="store_true", help="build the requests without a device")
    ap.add_argument("--sender", default="0x" + "51" * 20, help="wallet address for --dry-run")
    ap.add_argument("--dump", metavar="DIR", help="save every request as DIR/<flow>.<ins>.bin")
    args = ap.parse_args()

    if args.list:
        print_list()
        return 0
    names = select(args.flows, ap)

    if args.dry_run:
        sender = addr(args.sender)
        for i, name in enumerate(names):
            r = FLOWS[name].build(Ctx(sender, args, args.nonce + i))
            dump(args, name, r)
            print(f"  {name:16s} INS 0x{r.ins:02x} {len(r.payload):5d} B  {r.lines[0]}")
        return 0

    results: list[tuple[str, str]] = []
    nonce = args.nonce
    try:
        while True:
            for i, name in enumerate(names):
                print(f"\n===== [{i + 1}/{len(names)}] {name}: {FLOWS[name].shows} =====")
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
        print(f"  {name:16s} {result}")
    ok = ("signed", "confirmed", "locked", "declined", "refused (expected)")
    return 0 if all(r in ok for _, r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
