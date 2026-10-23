#!/usr/bin/env python3
"""Build and check SIGN_OFFCHAIN kind-4 (SafeTx) / 5 (CoW order) / 6 (Permit2) payloads.

An INDEPENDENT host implementation of the structured off-chain wire format
(proto `MAX_OFFCHAIN_SAFE_TX_LEN` / `MAX_OFFCHAIN_COW_ORDER_LEN` /
`MAX_OFFCHAIN_PERMIT2_LEN`, `docs/companion/usb-protocol-v2.md` §0x62 kinds
4-6) and of the value the device signs for it:

    H      = safeTxHash (Safe >= v1.3.0 domain {chainId, verifyingContract})
             | GPv2 order digest (domain "Gnosis Protocol" / "v2" / GPv2Settlement)
             | Permit2 permit digest (domain "Permit2" / chainId / Permit2, no version)
    signed = replay_safe_hash(chain, wallet, H)
           = keccak(0x1901 || PQSmartWallet domain(chain, wallet)
                    || keccak(PersonalSign typehash || H))

— the same value `OFFCHAIN_KIND_RAW32` signs when given H. Shared by:

  * `tools/hid_sign_offchain.py --safe-tx / --cow-order` (builds the request,
    records H for `tools/fork_verify_offchain.py`);
  * the companion's tests: `--emit-goldens FILE` writes golden vectors
    (payload hex, H, signed value) built from the ethers-checked mainnet
    references the firmware's host tests pin
    (`secure/src/tx/eip712/offchain_structured.rs`).

Usage:
  structured_offchain.py --emit-goldens goldens.json
  structured_offchain.py --check PAYLOAD_HEX --kind 4|5|6 --chain N [--wallet 0x..]
"""
from __future__ import annotations

import argparse
import json
import sys

from Crypto.Hash import keccak as _keccak

OFFCHAIN_KIND_SAFE_TX = 4
OFFCHAIN_KIND_COW_ORDER = 5
OFFCHAIN_KIND_PERMIT2 = 6
PERMIT2 = bytes.fromhex("000000000022D473030F116dDEE9F6B43aC78BA3")
PERMIT2_SINGLE, PERMIT2_BATCH, PERMIT2_TRANSFER, PERMIT2_BATCH_TRANSFER = 0, 1, 2, 3
PERMIT2_MAX_TOKENS = 6
PERMIT2_ENTRY_LEN = 52
PERMIT2_MAX_NAME_BUNDLES = 1
SAFE_V1_CANONICAL_LEN = 281
EIP712_CANONICAL_LEN = 204
SAFE_V1_RAW_DATA_MAX = 4096
ERC20_BUNDLE_MAX = 1120
COW_ORDER_TRAILER_MAX_LEN = EIP712_CANONICAL_LEN + 2 * (2 + ERC20_BUNDLE_MAX)
NAME_BUNDLE_MAX = 1093
MAX_NAME_BUNDLES = 4
GPV2_SETTLEMENT = bytes.fromhex("9008D19f58AAbD9eD0D60971565AA8510560ab41")
MULTISEND_CALL_ONLY = [
    bytes.fromhex(a) for a in (
        "40A2aCCbd92BCA938b02010E17A5b8929b49130D",  # v1.3.0 canonical
        "A1dabEF33b3B82c7814B6D82A79e50F4AC44102B",  # v1.3.0 eip155
        "9641d764fc13c8B624c04430C7356C1C7C8102e2",  # v1.4.1
        "A83c336B20401Af773B6219BA5027174338D1836",  # v1.5.0
    )
]


def keccak256(b: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(b)
    return h.digest()


SAFE_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)")
SAFE_TX_TYPEHASH = keccak256(
    b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,"
    b"uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
)
EIP712_DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
ORDER_TYPEHASH = keccak256(
    b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,"
    b"uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,"
    b"bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)"
)
PERSONAL_SIGN_TYPEHASH = keccak256(b"PersonalSign(bytes prefixed)")
PERMIT2_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(string name,uint256 chainId,address verifyingContract)")
_PERMIT_DETAILS = b"PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
_TOKEN_PERMISSIONS = b"TokenPermissions(address token,uint256 amount)"
PERMIT_DETAILS_TYPEHASH = keccak256(_PERMIT_DETAILS)
TOKEN_PERMISSIONS_TYPEHASH = keccak256(_TOKEN_PERMISSIONS)
PERMIT2_PRIMARY_TYPEHASH = {
    PERMIT2_SINGLE: keccak256(b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)" + _PERMIT_DETAILS),
    PERMIT2_BATCH: keccak256(b"PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)" + _PERMIT_DETAILS),
    PERMIT2_TRANSFER: keccak256(b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,"
                                b"uint256 deadline)" + _TOKEN_PERMISSIONS),
    PERMIT2_BATCH_TRANSFER: keccak256(b"PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,"
                                      b"uint256 nonce,uint256 deadline)" + _TOKEN_PERMISSIONS),
}


def u16(n: int) -> bytes:
    return n.to_bytes(2, "big")


def word(b: bytes) -> bytes:
    return b.rjust(32, b"\0")


def safe_tx_hash(c: bytes) -> bytes:
    """safeTxHash of a 281-byte canonical (layout: proto SAFE_OFF_*)."""
    assert len(c) == SAFE_V1_CANONICAL_LEN
    if c[112] > 1:
        raise ValueError("operation out of range")
    chain, safe = c[0:8], c[8:28]
    dom = keccak256(SAFE_DOMAIN_TYPEHASH + word(chain) + word(safe))
    sh = keccak256(
        SAFE_TX_TYPEHASH + word(c[28:48]) + c[48:80] + c[80:112] + word(c[112:113])
        + c[113:145] + c[145:177] + c[177:209] + word(c[209:229]) + word(c[229:249]) + c[249:281]
    )
    return keccak256(b"\x19\x01" + dom + sh)


def cow_order_digest(c: bytes) -> bytes:
    """GPv2 order digest of a 204-byte canonical (layout: proto EIP712_CANONICAL_LEN)."""
    assert len(c) == EIP712_CANONICAL_LEN
    kind = {0: b"sell", 1: b"buy"}[c[168]]
    if c[169] > 1:
        raise ValueError("partiallyFillable out of range")
    sell_bal = {0: b"erc20", 1: b"external", 2: b"internal"}[c[170]]
    buy_bal = {0: b"erc20", 1: b"internal"}[c[171]]
    chain = c[0:8]
    dom = keccak256(EIP712_DOMAIN_TYPEHASH + keccak256(b"Gnosis Protocol") + keccak256(b"v2")
                    + word(chain) + word(GPV2_SETTLEMENT))
    sh = keccak256(
        ORDER_TYPEHASH + word(c[8:28]) + word(c[28:48]) + word(c[48:68]) + c[68:100] + c[100:132]
        + word(c[164:168]) + c[172:204] + c[132:164] + keccak256(kind) + word(c[169:170])
        + keccak256(sell_bal) + keccak256(buy_bal)
    )
    return keccak256(b"\x19\x01" + dom + sh)


def replay_safe_hash(chain_id: int, wallet: bytes, h: bytes) -> bytes:
    dom = keccak256(EIP712_DOMAIN_TYPEHASH + keccak256(b"PQSmartWallet") + keccak256(b"1")
                    + chain_id.to_bytes(32, "big") + word(wallet))
    return keccak256(b"\x19\x01" + dom + keccak256(PERSONAL_SIGN_TYPEHASH + h))


def permit2_head_len(variant: int) -> int:
    return {PERMIT2_SINGLE: 62, PERMIT2_BATCH: 62, PERMIT2_TRANSFER: 94, PERMIT2_BATCH_TRANSFER: 94}[variant]


def build_permit2_core(variant: int, chain_id: int, spender: bytes, entries: list[tuple],
                       deadline: int, nonce: int = 0) -> bytes:
    """Packed permit. `entries`: (token, amount, expiration, nonce) for the
    allowance variants 0/1, (token, amount) for the transfer variants 2/3.
    `deadline` is sigDeadline (allowance) or deadline (transfer); `nonce` is
    the SignatureTransfer nonce (transfer variants only)."""
    allowance = variant in (PERMIT2_SINGLE, PERMIT2_BATCH)
    out = bytes([variant]) + chain_id.to_bytes(8, "big") + spender
    out += deadline.to_bytes(32, "big") if allowance else nonce.to_bytes(32, "big") + deadline.to_bytes(32, "big")
    out += bytes([len(entries)])
    for e in entries:
        if allowance:
            token, amount, expiration, a_nonce = e
            out += token + amount.to_bytes(20, "big") + expiration.to_bytes(6, "big") + a_nonce.to_bytes(6, "big")
        else:
            token, amount = e
            out += token + amount.to_bytes(32, "big")
    return out


def build_permit2_payload(core: bytes, erc20: list[bytes] | None = None, name: bytes = b"") -> bytes:
    count = core[permit2_head_len(core[0]) - 1]
    erc20 = erc20 if erc20 is not None else [b""] * count
    assert len(erc20) == count and all(len(b) <= ERC20_BUNDLE_MAX for b in erc20)
    assert len(name) <= NAME_BUNDLE_MAX
    out = core + b"".join(u16(len(b)) + b for b in erc20)
    return out + (bytes([1]) + u16(len(name)) + name if name else bytes([0]))


def permit2_digest(core: bytes, chain_id: int) -> bytes:
    """Permit2 digest of a packed permit, with the device's decode refusals."""
    variant = core[0]
    if variant not in PERMIT2_PRIMARY_TYPEHASH:
        raise ValueError("permit2 variant")
    head = permit2_head_len(variant)
    if len(core) < head:
        raise ValueError("permit2 length")
    count = core[head - 1]
    batch = variant in (PERMIT2_BATCH, PERMIT2_BATCH_TRANSFER)
    if not (1 <= count <= PERMIT2_MAX_TOKENS if batch else count == 1):
        raise ValueError("permit2 count")
    if len(core) != head + count * PERMIT2_ENTRY_LEN:
        raise ValueError("permit2 length")
    if int.from_bytes(core[1:9], "big") != chain_id:
        raise ValueError("permit2 chain")
    spender = core[9:29]
    if spender == bytes(20):
        raise ValueError("permit2 zero adr")
    allowance = variant in (PERMIT2_SINGLE, PERMIT2_BATCH)
    hashes, tokens = [], []
    for i in range(count):
        e = core[head + i * PERMIT2_ENTRY_LEN:head + (i + 1) * PERMIT2_ENTRY_LEN]
        token = e[:20]
        if token == bytes(20) or token in tokens:
            raise ValueError("permit2 zero tok" if token == bytes(20) else "permit2 dup tok")
        tokens.append(token)
        if allowance:
            ed = word(token) + word(e[20:40]) + word(e[40:46]) + word(e[46:52])
            hashes.append(keccak256(PERMIT_DETAILS_TYPEHASH + ed))
        else:
            hashes.append(keccak256(TOKEN_PERMISSIONS_TYPEHASH + word(token) + e[20:52]))
    member = hashes[0] if not batch else keccak256(b"".join(hashes))
    tail = core[29:61] if allowance else core[29:61] + core[61:93]
    sh = keccak256(PERMIT2_PRIMARY_TYPEHASH[variant] + member + word(spender) + tail)
    dom = keccak256(PERMIT2_DOMAIN_TYPEHASH + keccak256(b"Permit2") + chain_id.to_bytes(32, "big") + word(PERMIT2))
    return keccak256(b"\x19\x01" + dom + sh)


def build_safe_tx_payload(canonical: bytes, raw: bytes, erc20: bytes = b"", cow: bytes = b"",
                          names: list[bytes] | None = None) -> bytes:
    names = names or []
    assert len(canonical) == SAFE_V1_CANONICAL_LEN and len(raw) <= SAFE_V1_RAW_DATA_MAX
    assert len(erc20) <= ERC20_BUNDLE_MAX and len(cow) <= COW_ORDER_TRAILER_MAX_LEN
    assert len(names) <= MAX_NAME_BUNDLES and all(0 < len(n) <= NAME_BUNDLE_MAX for n in names)
    safe = canonical + u16(len(raw)) + raw
    out = u16(len(safe)) + safe + u16(len(erc20)) + erc20 + u16(len(cow)) + cow + bytes([len(names)])
    for n in names:
        out += u16(len(n)) + n
    return out


def build_cow_order_payload(canonical: bytes, sell: bytes = b"", buy: bytes = b"") -> bytes:
    assert len(canonical) == EIP712_CANONICAL_LEN
    assert len(sell) <= ERC20_BUNDLE_MAX and len(buy) <= ERC20_BUNDLE_MAX
    return canonical + u16(len(sell)) + sell + u16(len(buy)) + buy


def _take(p: bytes, off: int, cap: int) -> tuple[bytes, int]:
    if off + 2 > len(p):
        raise ValueError("truncated")
    n = int.from_bytes(p[off:off + 2], "big")
    if n > cap or off + 2 + n > len(p):
        raise ValueError("bad section length")
    return p[off + 2:off + 2 + n], off + 2 + n


def structured_digest(kind: int, payload: bytes, chain_id: int) -> bytes:
    """H for a kind-4/5 payload, with the device's framing and verify rules."""
    if kind == OFFCHAIN_KIND_SAFE_TX:
        safe, o = _take(payload, 0, SAFE_V1_CANONICAL_LEN + 2 + SAFE_V1_RAW_DATA_MAX)
        if len(safe) < SAFE_V1_CANONICAL_LEN + 2:
            raise ValueError("short safe section")
        c, raw_len = safe[:SAFE_V1_CANONICAL_LEN], int.from_bytes(safe[281:283], "big")
        raw = safe[283:]
        if raw_len != len(raw):
            raise ValueError("raw_len does not end the safe section")
        _, o = _take(payload, o, ERC20_BUNDLE_MAX)
        cow, o = _take(payload, o, COW_ORDER_TRAILER_MAX_LEN)
        if cow and len(cow) < EIP712_CANONICAL_LEN:
            raise ValueError("short cow section")
        count = payload[o]
        o += 1
        if count > MAX_NAME_BUNDLES:
            raise ValueError("too many names")
        for _ in range(count):
            n, o = _take(payload, o, NAME_BUNDLE_MAX)
            if not n:
                raise ValueError("empty name")
        if o != len(payload):
            raise ValueError("trailing bytes")
        if int.from_bytes(c[0:8], "big") != chain_id or c[8:28] == bytes(20):
            raise ValueError("chain / safe address")
        if c[112] == 1 and not (c[28:48] in MULTISEND_CALL_ONLY and raw[:4] == bytes.fromhex("8d80ff0a")):
            raise ValueError("delegatecall outside MultiSendCallOnly")
        if keccak256(raw) != c[80:112]:
            raise ValueError("dataHash")
        return safe_tx_hash(c)
    if kind == OFFCHAIN_KIND_COW_ORDER:
        c = payload[:EIP712_CANONICAL_LEN]
        if len(c) != EIP712_CANONICAL_LEN:
            raise ValueError("truncated")
        _, o = _take(payload, EIP712_CANONICAL_LEN, ERC20_BUNDLE_MAX)
        _, o = _take(payload, o, ERC20_BUNDLE_MAX)
        if o != len(payload):
            raise ValueError("trailing bytes")
        if int.from_bytes(c[0:8], "big") != chain_id:
            raise ValueError("chain")
        return cow_order_digest(c)
    if kind == OFFCHAIN_KIND_PERMIT2:
        if not payload or payload[0] not in PERMIT2_PRIMARY_TYPEHASH:
            raise ValueError("permit2 variant")
        head = permit2_head_len(payload[0])
        if len(payload) < head:
            raise ValueError("truncated")
        core_len = head + payload[head - 1] * PERMIT2_ENTRY_LEN
        core, o = payload[:core_len], core_len
        for _ in range(payload[head - 1]):
            _, o = _take(payload, o, ERC20_BUNDLE_MAX)
        if o >= len(payload) or payload[o] > PERMIT2_MAX_NAME_BUNDLES:
            raise ValueError("names")
        names, o = payload[o], o + 1
        if names:
            n, o = _take(payload, o, NAME_BUNDLE_MAX)
            if not n:
                raise ValueError("empty name")
        if o != len(payload):
            raise ValueError("trailing bytes")
        return permit2_digest(core, chain_id)
    raise ValueError(f"kind {kind} is not structured")


# The ethers-checked mainnet references (secure/src/tx/eip712/cowswap/e2e_decode_tests.rs).
REF_COW_CANONICAL = bytes.fromhex(
    "0000000000000001a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
    "742d35cc6634c0532925a3b844bc454e4438f44e00000000000000000000000000000000000000000000000000000000"
    "3b9aca0000000000000000000000000000000000000000000000000006f05b59d3b20000000000000000000000000000"
    "0000000000000000000000000000000000000000680000000000000083b9dcb2316e54fc04c10f74c9a3d5dd66a9e4c4"
    "3c04ccefb9c0c03e61e5fb28")
REF_ORDER_DIGEST = bytes.fromhex("f97aaf408259debcbe9b251ac5e1097174cf0084fb2f382d8056617068eaa43a")
REF_SAFE_CANONICAL = bytes.fromhex(
    "00000000000000015afe3855358e112b5647b952709e6165e1c1eeee9008d19f58aabd9ed0d60971565aa8510560ab41"
    "0000000000000000000000000000000000000000000000000000000000000000720774a1e1bb52a564f0c33e0ba05c1b"
    "ac850d236bd19a8f1c4173364de236640000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000")
REF_SAFE_PRESIGN = bytes.fromhex(
    "ec6cb13f0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000"
    "000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000"
    "00000038f97aaf408259debcbe9b251ac5e1097174cf0084fb2f382d8056617068eaa43a5afe3855358e112b5647b952"
    "709e6165e1c1eeee680000000000000000000000")
REF_SAFE_TX_HASH = bytes.fromhex("0e436954453310227409c573f988f1b7ff49cfe3588e493320396da72791bfaa")
GOLDEN_WALLET = bytes([0xfb] * 20)

# Permit2 references: viem 2.56.3 `hashTypedData` over the equivalent typed
# data (secure/src/tx/eip712/permit2/test_vectors.rs builds the same permits).
USDC_BASE = bytes.fromhex("833589fcd6edb6e08f4c7c32d4f71b54bda02913")
WETH_BASE = bytes.fromhex("4200000000000000000000000000000000000006")
USDC_ETH = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
UR_BASE = bytes.fromhex("6ff5693b99212da76ad316178a184ab56d299b43")
UR_ETH = bytes.fromhex("3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad")
MAX160, MAX256 = (1 << 160) - 1, (1 << 256) - 1
REF_PERMIT2 = (
    ("permit2_single", 8453, build_permit2_core(
        PERMIT2_SINGLE, 8453, UR_BASE, [(USDC_BASE, 1_000_000_000, 1_798_761_600, 3)], 1_767_225_600),
     "497c41366bda0e8bb4d9744d263a0979a0eeb5df293ced92d4aba868ac946888"),
    ("permit2_batch", 8453, build_permit2_core(
        PERMIT2_BATCH, 8453, UR_BASE,
        [(USDC_BASE, 1_000_000_000, 1_798_761_600, 3), (WETH_BASE, MAX160, 0, 0)], 1_767_225_600),
     "83e5dfb254dc96d7dfda2ea103d5063b019939ec087e15862bee88d416c7a4ba"),
    ("permit2_transfer", 1, build_permit2_core(
        PERMIT2_TRANSFER, 1, UR_ETH, [(USDC_ETH, 500_000_000)], 1_767_225_600, nonce=42),
     "17146f9e0b8c3404e9e667f3655b031304f4ef59e2052b36f674e27c1515e8fe"),
    ("permit2_batch_transfer", 8453, build_permit2_core(
        PERMIT2_BATCH_TRANSFER, 8453, UR_BASE,
        [(USDC_BASE, MAX256), (WETH_BASE, 123_456_789_012_345_678)], MAX256, nonce=(1 << 200) + 7),
     "a13082a184d56e9a727c02b337098b02c57c3fe4e8f78f01a554b2f7f11ebede"),
)


def goldens() -> dict:
    assert safe_tx_hash(REF_SAFE_CANONICAL) == REF_SAFE_TX_HASH, "Safe reference drifted"
    assert cow_order_digest(REF_COW_CANONICAL) == REF_ORDER_DIGEST, "CoW reference drifted"
    safe_payload = build_safe_tx_payload(REF_SAFE_CANONICAL, REF_SAFE_PRESIGN,
                                         cow=build_cow_order_payload(REF_COW_CANONICAL))
    cow_payload = build_cow_order_payload(REF_COW_CANONICAL)
    out = {"wallet": "0x" + GOLDEN_WALLET.hex(), "chainId": 1, "vectors": []}
    cases = [("safe_tx_cow_presign", OFFCHAIN_KIND_SAFE_TX, 1, safe_payload),
             ("cow_order", OFFCHAIN_KIND_COW_ORDER, 1, cow_payload)]
    for name, chain, core, want in REF_PERMIT2:
        assert permit2_digest(core, chain).hex() == want, f"{name} reference drifted"
        cases.append((name, OFFCHAIN_KIND_PERMIT2, chain, build_permit2_payload(core)))
    for name, kind, chain, payload in cases:
        h = structured_digest(kind, payload, chain)
        out["vectors"].append({
            "name": name,
            "kind": kind,
            "chainId": chain,
            "payload": "0x" + payload.hex(),
            "digest": "0x" + h.hex(),
            "signedValue": "0x" + replay_safe_hash(chain, GOLDEN_WALLET, h).hex(),
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--emit-goldens", metavar="FILE")
    ap.add_argument("--check", metavar="PAYLOAD_HEX")
    ap.add_argument("--kind", type=int, choices=(4, 5, 6))
    ap.add_argument("--chain", type=int, default=1)
    ap.add_argument("--wallet", default="0x" + GOLDEN_WALLET.hex())
    a = ap.parse_args()
    if a.emit_goldens:
        with open(a.emit_goldens, "w") as fh:
            json.dump(goldens(), fh, indent=1)
            fh.write("\n")
        print(f"wrote {a.emit_goldens}")
        return 0
    if a.check:
        if a.kind is None:
            ap.error("--check needs --kind")
        h = structured_digest(a.kind, bytes.fromhex(a.check.removeprefix("0x")), a.chain)
        wallet = bytes.fromhex(a.wallet.removeprefix("0x"))
        print(f"H      = 0x{h.hex()}")
        print(f"signed = 0x{replay_safe_hash(a.chain, wallet, h).hex()}")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
