#!/usr/bin/env python3
"""ENS name check: the DEVICE half of the block-hash-anchored design (PoC).

MVP — not firmware, not reviewed. It shows, against real mainnet data, what
the PQ1 would have to do offline to show "alice.eth" for an address, and how
many bytes that takes. The on-chain half is
`contracts/smart-wallet/src/ens/BlockHashAnchor.sol`.

    companion (untrusted)                 device (this script's role)
    ---------------------                 ---------------------------
    header RLP of block B          --->   H = keccak(header); stateRoot, number
    eth_getProof(ENS Registry)     --->   account -> storage: owner != 0,
                                          resolver = records[node].resolver
    eth_getProof(resolver)         --->   account codehash = a pinned layout;
                                          recordVersions[node] -> address slot
                                          -> the 20-byte ETH address
                                   <---   signs [anchor <- B || H, payment]

Every value is taken from the proof nodes, never from the RPC's own `value`
fields (those are only cross-checked at the end). If the companion lied about
the header, H is no block's hash and the anchor reverts the whole batch.

    python3 tools/ens_proof_check.py vitalik.eth
    python3 tools/ens_proof_check.py vitalik.eth --rpc https://... --block 26300000
    python3 tools/ens_proof_check.py vitalik.eth --selftest   # tampering must fail

Some RPC nodes (reth) serve proofs for the latest block only; if a proof call
fails with "maximum proof window", rerun or pass a provider that keeps more.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request

from Crypto.Hash import keccak

DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"

# ENSRegistryWithFallback, Ethereum mainnet. `records` is its slot 0:
# owner at keccak(node . 0), resolver (+ ttl) at that slot + 1.
REGISTRY = bytes.fromhex("00000000000C2E074eC69A0dFb2997BA6C7d2e1e")
REGISTRY_CODEHASH = bytes.fromhex("d6bfd5d6f1384a1f6ea57b8a8412de5552f138d42021cf7c4941e33206f529e4")

# Resolver layouts the device would pin, by code hash. Only these resolvers'
# storage can be read safely from a proof; any other resolver means "no
# name", shown as the bare address. Slots measured with forge `vm.record`
# (vitalik.eth, ens.eth) on a mainnet fork.
RESOLVER_LAYOUTS = {
    # 0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63, PublicResolver (2023):
    #   recordVersions  mapping(bytes32 => uint64)                         slot 0
    #   addresses       mapping(uint64 => mapping(bytes32 =>
    #                       mapping(uint256 => bytes)))                    slot 2
    bytes.fromhex("19257636fde18e27704b400659de2cbaab55488586c18cd5b6d67f6417c8c19a"): {
        "name": "PublicResolver 2023 (0x231b0Ee1...)",
        "record_versions_slot": 0,
        "addresses_slot": 2,
    },
    # 0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41, PublicResolver (2020):
    #   _addresses      mapping(bytes32 => mapping(uint256 => bytes))      slot 1
    bytes.fromhex("0370d116c18db61a2f90643faa12e3ae22a0b7d518ce868fe3f85e2f0d299fe5"): {
        "name": "PublicResolver 2020 (0x4976fb03...)",
        "record_versions_slot": None,
        "addresses_slot": 1,
    },
}
COIN_TYPE_ETH = 60

# What the device would display: lowercase ASCII labels only, so the bytes it
# hashes are exactly the characters it shows (no confusables, no Unicode).
LABEL = re.compile(r"^[a-z0-9-]+$")


def k(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def u256(n: int) -> bytes:
    return n.to_bytes(32, "big")


# --- RLP --------------------------------------------------------------------


def rlp_encode(item) -> bytes:
    if isinstance(item, (bytes, bytearray)):
        b = bytes(item)
        if len(b) == 1 and b[0] < 0x80:
            return b
        return _rlp_len(len(b), 0x80) + b
    payload = b"".join(rlp_encode(x) for x in item)
    return _rlp_len(len(payload), 0xC0) + payload


def _rlp_len(n: int, offset: int) -> bytes:
    if n < 56:
        return bytes([offset + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(nb)]) + nb


def rlp_decode(data: bytes):
    item, end = _rlp_item(data, 0)
    if end != len(data):
        raise ValueError("RLP: trailing bytes")
    return item


def _rlp_item(d: bytes, i: int):
    if i >= len(d):
        raise ValueError("RLP: truncated")
    p = d[i]
    if p < 0x80:
        return d[i : i + 1], i + 1
    if p < 0xB8:
        n = p - 0x80
        if n == 1 and i + 1 < len(d) and d[i + 1] < 0x80:
            raise ValueError("RLP: non-canonical single byte")
        return _take(d, i + 1, n), i + 1 + n
    if p < 0xC0:
        ll = p - 0xB7
        n = _long_len(d, i + 1, ll)
        return _take(d, i + 1 + ll, n), i + 1 + ll + n
    if p < 0xF8:
        n = p - 0xC0
        return _rlp_list(d, i + 1, n), i + 1 + n
    ll = p - 0xF7
    n = _long_len(d, i + 1, ll)
    return _rlp_list(d, i + 1 + ll, n), i + 1 + ll + n


def _long_len(d: bytes, i: int, ll: int) -> int:
    raw = _take(d, i, ll)
    if raw[0] == 0:
        raise ValueError("RLP: leading zero in length")
    n = int.from_bytes(raw, "big")
    if n < 56:
        raise ValueError("RLP: long form for short payload")
    return n


def _take(d: bytes, i: int, n: int) -> bytes:
    if i + n > len(d):
        raise ValueError("RLP: truncated")
    return d[i : i + n]


def _rlp_list(d: bytes, i: int, n: int):
    end = i + n
    if end > len(d):
        raise ValueError("RLP: truncated list")
    out = []
    while i < end:
        item, i = _rlp_item(d, i)
        out.append(item)
    if i != end:
        raise ValueError("RLP: list overrun")
    return out


# --- Merkle-Patricia proof ----------------------------------------------------


def nibbles(b: bytes) -> list[int]:
    out = []
    for x in b:
        out += [x >> 4, x & 0x0F]
    return out


def mpt_get(root: bytes, key: bytes, proof: list[bytes], stats: dict) -> bytes | None:
    """Value at `key` (raw leaf bytes), or None for a proven absence.

    Raises on anything that is not a complete, exact proof: a node whose hash
    is not the one referenced, a missing node, or proof nodes left over."""
    path = nibbles(k(key))
    ref = root  # a 32-byte hash, or an embedded node (a decoded list)
    used = 0
    while True:
        if isinstance(ref, list):
            node = ref
        else:
            if len(ref) != 32:
                raise ValueError("MPT: bad child reference")
            if used >= len(proof):
                raise ValueError("MPT: proof ends early")
            raw = proof[used]
            used += 1
            if k(raw) != ref:
                raise ValueError("MPT: node hash mismatch")
            stats["nodes"] += 1
            stats["bytes"] += len(raw)
            stats.setdefault("unique", {})[ref] = len(raw)
            node = rlp_decode(raw)
        result = None
        if len(node) == 17:
            if not path:
                raise ValueError("MPT: key ends at a branch")
            child = node[path[0]]
            path = path[1:]
            if child == b"":
                result = ("absent",)
            else:
                ref = child
                continue
        elif len(node) == 2:
            hp = nibbles(node[0])
            flag = hp[0]
            if flag > 3:
                raise ValueError("MPT: bad hex-prefix flag")
            seg = hp[1:] if flag & 1 else hp[2:]
            if path[: len(seg)] != seg:
                result = ("absent",)
            elif flag & 2:  # leaf
                if len(seg) != len(path):
                    raise ValueError("MPT: leaf path length")
                result = ("value", node[1])
            else:  # extension
                path = path[len(seg) :]
                ref = node[1]
                continue
        else:
            raise ValueError("MPT: node is neither branch nor leaf/extension")
        if used != len(proof):
            raise ValueError("MPT: unused proof nodes")
        return None if result[0] == "absent" else result[1]


def account(state_root, address, proof, stats):
    raw = mpt_get(state_root, address, proof, stats)
    if raw is None:
        raise ValueError(f"account 0x{address.hex()} does not exist")
    nonce, balance, storage_root, code_hash = rlp_decode(raw)
    return storage_root, code_hash


def storage_word(storage_root, slot: bytes, proof, stats) -> int:
    raw = mpt_get(storage_root, slot, proof, stats)
    if raw is None:
        return 0
    v = rlp_decode(raw)
    if not isinstance(v, bytes) or v[:1] == b"\x00":
        raise ValueError("storage value not a canonical integer")
    return int.from_bytes(v, "big")


# --- chain access (the companion's job) -------------------------------------


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "pq1-ens-proof"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.load(r)
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


HEADER_FIELDS = [
    ("parentHash", "b"), ("sha3Uncles", "b"), ("miner", "b"), ("stateRoot", "b"),
    ("transactionsRoot", "b"), ("receiptsRoot", "b"), ("logsBloom", "b"),
    ("difficulty", "i"), ("number", "i"), ("gasLimit", "i"), ("gasUsed", "i"),
    ("timestamp", "i"), ("extraData", "b"), ("mixHash", "b"), ("nonce", "b"),
    # optional, in fork order
    ("baseFeePerGas", "i"), ("withdrawalsRoot", "b"), ("blobGasUsed", "i"),
    ("excessBlobGas", "i"), ("parentBeaconBlockRoot", "b"), ("requestsHash", "b"),
]


def header_rlp(block: dict) -> bytes:
    items = []
    for name, kind in HEADER_FIELDS:
        if name not in block:
            break
        if kind == "i":  # JSON quantities are minimal hex ("0x0", "0x1a")
            n = int(block[name], 16)
            raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        else:
            raw = bytes.fromhex(block[name][2:])
        items.append(raw)
    return rlp_encode(items)


def proof_nodes(p: list[str]) -> list[bytes]:
    return [bytes.fromhex(x[2:]) for x in p]


# --- the check ----------------------------------------------------------------


def selftest(root: bytes, key: bytes, proof: list[bytes], other_key: bytes) -> None:
    """A verifier nobody has watched refuse is not a verifier: each tampered
    proof must raise or prove absence, never yield a value."""
    s = {"nodes": 0, "bytes": 0}
    good = mpt_get(root, key, proof, s)
    assert good is not None
    flipped = proof[:-1] + [proof[-1][:-1] + bytes([proof[-1][-1] ^ 1])]
    cases = {
        "flipped byte in leaf": (key, flipped),
        "proof truncated": (key, proof[:-1]),
        "extra trailing node": (key, proof + [proof[-1]]),
        "proof of another slot": (other_key, proof),
        "wrong root": (key, proof),
    }
    for label, (kk, pf) in cases.items():
        r = bytes(32) if label == "wrong root" else root
        try:
            v = mpt_get(r, kk, pf, {"nodes": 0, "bytes": 0})
        except ValueError:
            continue
        if v is not None:
            raise SystemExit(f"selftest FAILED: {label} yielded a value")
    print(f"selftest        {len(cases)} tampered proofs refused")


def namehash(name: str) -> bytes:
    labels = name.split(".")
    if not all(LABEL.match(lb) for lb in labels):
        raise SystemExit(f"{name!r}: the device would show no name (only lowercase a-z 0-9 - labels)")
    node = bytes(32)
    for lb in reversed(labels):
        node = k(node + k(lb.encode()))
    return node


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", nargs="?", default="vitalik.eth")
    ap.add_argument("--rpc", default=DEFAULT_RPC)
    ap.add_argument("--block", type=int, help="default: latest - 2")
    ap.add_argument("--selftest", action="store_true", help="also check that tampered proofs are refused")
    a = ap.parse_args()

    node = namehash(a.name)
    number = a.block if a.block is not None else int(rpc(a.rpc, "eth_blockNumber", []), 16) - 2
    tag = hex(number)
    stats = {"nodes": 0, "bytes": 0}

    # 1. Header: the device hashes the bytes it was given.
    block = rpc(a.rpc, "eth_getBlockByNumber", [tag, False])
    hdr = header_rlp(block)
    H = k(hdr)
    fields = rlp_decode(hdr)
    state_root = fields[3]
    if int.from_bytes(fields[8], "big") != number:
        raise SystemExit("header number mismatch")
    if H.hex() != block["hash"][2:]:
        raise SystemExit("header RLP does not hash to the block hash (new header field?)")

    # 2. Registry: owner must be set (else the registry falls back to the
    #    old one, which the device does not follow), then the resolver.
    rec = k(node + u256(0))
    owner_slot, resolver_slot = rec, u256(int.from_bytes(rec, "big") + 1)
    pr = rpc(a.rpc, "eth_getProof", ["0x" + REGISTRY.hex(), ["0x" + owner_slot.hex(), "0x" + resolver_slot.hex()], tag])
    reg_root, reg_code = account(state_root, REGISTRY, proof_nodes(pr["accountProof"]), stats)
    if reg_code != REGISTRY_CODEHASH:
        raise SystemExit("registry code hash is not the pinned one")
    owner = storage_word(reg_root, owner_slot, proof_nodes(pr["storageProof"][0]["proof"]), stats)
    if owner == 0:
        raise SystemExit(f"{a.name}: no record in the registry (or only in the old one): no name shown")
    resolver_word = storage_word(reg_root, resolver_slot, proof_nodes(pr["storageProof"][1]["proof"]), stats)
    resolver = (resolver_word & ((1 << 160) - 1)).to_bytes(20, "big")

    # 3. Resolver: pinned layout by its code hash, then (if versioned) the
    #    record version, then the address. The address slot depends on the
    #    version, so the version is proven first and the address key derived
    #    from the PROVEN value. (The script needs extra RPC round trips for
    #    that; the device would receive all proofs at once.)
    pa = rpc(a.rpc, "eth_getProof", ["0x" + resolver.hex(), [], tag])
    _, res_code = account(state_root, resolver, proof_nodes(pa["accountProof"]), {"nodes": 0, "bytes": 0})
    layout = RESOLVER_LAYOUTS.get(res_code)
    if layout is None:
        raise SystemExit(f"{a.name}: resolver 0x{resolver.hex()} has no pinned layout: no name shown")
    slots = []
    version_hint = None
    if layout["record_versions_slot"] is not None:
        vslot = k(node + u256(layout["record_versions_slot"]))
        pv = rpc(a.rpc, "eth_getProof", ["0x" + resolver.hex(), ["0x" + vslot.hex()], tag])
        version_hint = int(pv["storageProof"][0]["value"], 16)
        slots.append(vslot)
        inner = k(node + k(u256(version_hint) + u256(layout["addresses_slot"])))
    else:
        inner = k(node + u256(layout["addresses_slot"]))
    aslot = k(u256(COIN_TYPE_ETH) + inner)
    slots.append(aslot)
    pp = rpc(a.rpc, "eth_getProof", ["0x" + resolver.hex(), ["0x" + x.hex() for x in slots], tag])
    res_root, res_code2 = account(state_root, resolver, proof_nodes(pp["accountProof"]), stats)
    if res_code2 != res_code:
        raise SystemExit("resolver code changed between round trips; retry")
    version = None
    if version_hint is not None:
        version = storage_word(res_root, vslot, proof_nodes(pp["storageProof"][0]["proof"]), stats)
        if version != version_hint:
            raise SystemExit("record version changed between round trips; retry")
    word = storage_word(res_root, aslot, proof_nodes(pp["storageProof"][-1]["proof"]), stats)
    # Solidity short `bytes` (< 32 B): data left-aligned, zero fill, and
    # length*2 in the low byte. Anything else is not a 20-byte address.
    if word & 1 or (word & 0xFF) // 2 != 20 or (word >> 8) & ((1 << 88) - 1):
        raise SystemExit(f"{a.name}: no 20-byte ETH address record: no name shown")
    addr = (word >> 96).to_bytes(20, "big")

    if a.selftest:
        selftest(reg_root, resolver_slot, proof_nodes(pr["storageProof"][1]["proof"]), owner_slot)

    # Cross-check against the RPC's own claims (not used above).
    claimed = int(pp["storageProof"][-1]["value"], 16)
    assert claimed == word, "proof-derived value differs from the RPC's claim"

    anchor = number.to_bytes(4, "big") + H
    total = len(hdr) + stats["bytes"]
    uniq = stats["unique"]
    total_unique = len(hdr) + sum(uniq.values())
    print(f"name            {a.name}")
    print(f"namehash        0x{node.hex()}")
    print(f"block           {number}  hash 0x{H.hex()}")
    print(f"resolver        0x{resolver.hex()}  ({layout['name']})")
    print(f"record version  {'n/a (unversioned layout)' if version is None else version}")
    print(f"ETH address     0x{addr.hex()}   <- what the device would show with the name")
    print()
    print(f"device input    {total:,} B  (header {len(hdr)} B + {stats['nodes']} proof nodes {stats['bytes']:,} B)")
    print(f"  deduplicated  {total_unique:,} B  ({len(uniq)} distinct nodes; the proofs share upper nodes)")
    print(f"keccak calls    {len(uniq) + 1 + 6} over ~{total_unique:,} B (each distinct node, the header, slot keys)")
    print(f"anchor calldata 0x{anchor.hex()}  ({len(anchor)} B: uint32 number || block hash)")
    print(f"window          valid on-chain while block {number} is among the last 256 (~51 min)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
