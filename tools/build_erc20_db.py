#!/usr/bin/env python3
"""
Build secure/data/erc20.json from curated upstream token lists.

Pipeline:
  1. Read fetched token lists from build/token_lists/ (run fetch_token_lists.sh
     first). Sources used: Uniswap Labs default, Optimism Superchain.
  2. Expand Uniswap's `extensions.bridgeInfo` so each cross-chain deployment
     becomes its own (chain_id, address) row.
  3. Filter to TARGET_CHAINS, dedupe by (chain_id, address) merging source sets.
  4. Per-chain cap with deterministic priority ordering:
       * tokens endorsed by both lists win first
       * then hand-curated PRIORITY_SYMBOLS (blue chips)
       * then shorter symbol length (proxy for established tokens)
       * then alphabetical (deterministic)
  5. NFC-normalize name/symbol; clamp to Uniswap-spec lengths (60/20 chars).
  6. Re-emit addresses in EIP-55 checksum form via a bundled pure-Python
     keccak-256 (no pip deps).
  7. Sort final output by (chain_id, address) — same as dbgen sort — for
     stable git diffs, then write secure/data/erc20.json.

The resulting file is consumed by `cargo run -p dbgen`, which builds
nonsecure/src/erc20_db.bin and updates secure/src/db_roots.rs::ERC20_DB_ROOT.

Size budget rationale: nonsecure flash is 256 KB total (memory.x). The
current per-entry cost is ~40 B + proof_depth*32 B (proof_depth = ceil log2
padded entry count) plus the interned string pool. Targeting ~200 tokens
puts the blob at roughly 60–70 KB, leaving ample room for code and the VK
DB. Tune PER_CHAIN_CAP if you have more flash to spare.
"""

from __future__ import annotations

import json
import pathlib
import struct
import sys
import unicodedata
from collections import Counter, defaultdict
from typing import Iterable

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Per-chain inclusion caps. Total across all chains drives the blob size.
# See module docstring for the size budget reasoning.
PER_CHAIN_CAP: dict[int, int] = {
    1:     80,    # Ethereum mainnet
    10:    20,    # Optimism
    56:    15,    # BNB Chain
    130:   10,    # Unichain
    137:   15,    # Polygon PoS
    8453:  35,    # Base
    42161: 30,    # Arbitrum One
    43114: 10,    # Avalanche C-chain
}
TARGET_CHAINS = set(PER_CHAIN_CAP)

# Tiered blue-chip symbols. Lower tier = higher priority within the cap.
# Stables and wrapped natives sit at tier 0 because they're the actual
# transactions a wallet user is most likely to sign — losing WETH from a
# chain so we can fit BAL is a bad trade.
PRIORITY_TIERS: list[set[str]] = [
    # tier 0: stables + wrapped native + WBTC. Non-negotiable.
    {
        "USDC", "USDT", "DAI", "FRAX", "LUSD", "TUSD", "USDP", "GUSD",
        "PYUSD", "USDE", "SUSDE", "CRVUSD", "MIM", "SUSD", "USDD",
        "WETH", "STETH", "WSTETH", "RETH", "CBETH", "WEETH", "EETH",
        "WBTC", "TBTC", "CBBTC",
        "WBNB", "WMATIC", "WAVAX", "WPOL",
    },
    # tier 1: major DeFi governance + L2 / native gas tokens.
    {
        "LINK", "UNI", "AAVE", "MKR", "SNX", "COMP", "CRV", "CVX", "LDO",
        "ARB", "OP", "MATIC", "POL", "BNB", "AVAX",
    },
    # tier 2: well-known but more niche.
    {
        "BAL", "YFI", "1INCH", "SUSHI", "GMX", "GRT", "ENS", "RPL",
        "PEPE", "SHIB", "DOGE",
        "PENDLE", "FXS", "RDNT", "MAGIC",
    },
]
PRIORITY_SYMBOLS = set().union(*PRIORITY_TIERS)


def _tier(symbol: str) -> int:
    """Lower is better. 99 = not a priority symbol."""
    s = symbol.upper()
    for i, tier in enumerate(PRIORITY_TIERS):
        if s in tier:
            return i
    return 99


# Manual additions for blue-chip tokens the curated upstream lists genuinely
# omit. Each entry MUST be cross-checked against a block explorer before
# being added — these bypass the dual-source consensus filter, so a typo
# here ships a wrong token to users.
#
# Verified against Etherscan-family explorers (April 2026).
MANUAL_ADDITIONS = [
    # Uniswap default omits Arbitrum's canonical USDT despite it being one
    # of the highest-volume tokens on the chain. Confirmed via arbiscan.io.
    {"chain_id": 42161, "address": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
     "name": "Tether USD", "symbol": "USDT", "decimals": 6},
    # Native Tether on Base — issued by Tether in 2024, missing from Uniswap.
    # Confirmed via basescan.org.
    {"chain_id": 8453, "address": "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",
     "name": "Tether USD", "symbol": "USDT", "decimals": 6},
    # Unichain WETH is in Uniswap default but only with one source, so it
    # falls behind dual-sourced niche tokens at the cap boundary. Add
    # explicitly. Confirmed via uniscan.xyz.
    {"chain_id": 130, "address": "0x4200000000000000000000000000000000000006",
     "name": "Wrapped Ether", "symbol": "WETH", "decimals": 18},
]

# Hermetic tooling: no pip deps. ~70 lines of pure-Python keccak-256 below.

REPO = pathlib.Path(__file__).resolve().parent.parent
LISTS_DIR = REPO / "build" / "token_lists"
OUT_PATH = REPO / "secure" / "data" / "erc20.json"

# Uniswap Token List spec caps (https://github.com/Uniswap/token-lists).
NAME_MAX_CHARS = 60
SYMBOL_MAX_CHARS = 20

# ---------------------------------------------------------------------------
# Pure-Python keccak-256 for EIP-55 address checksumming.
# This is the pre-FIPS Keccak (padding byte 0x01), NOT NIST SHA3-256.
# Validated against the known empty-input vector at module load.
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_R = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
]
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(A: list[list[int]]) -> None:
    for rc in _KECCAK_RC:
        # theta
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        # rho + pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], _KECCAK_R[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & _MASK64) & B[(x + 2) % 5][y])
        # iota
        A[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes (1600 - 512) / 8
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data) + bytearray(rate - (len(data) % rate))
    padded[len(data)] = 0x01
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        for i in range(rate // 8):
            lane = struct.unpack_from("<Q", padded, off + i * 8)[0]
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)
    out = bytearray()
    for i in range(4):  # 32 bytes
        out += struct.pack("<Q", state[i % 5][i // 5])
    return bytes(out)


# Self-test: keccak256(b"") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
_EMPTY_DIGEST = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"").hex() == _EMPTY_DIGEST, "keccak256 self-test failed"


def to_checksum_address(addr: str) -> str:
    """EIP-55 checksum (mixed-case) representation of a 20-byte address."""
    a = addr.lower().removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdef" for c in a):
        raise ValueError(f"not a 20-byte hex address: {addr!r}")
    digest = keccak256(a.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if int(digest[i], 16) >= 8 else c
        for i, c in enumerate(a)
    )


# Self-test for to_checksum_address using Vitalik's published vectors.
assert to_checksum_address("0x52908400098527886e0f7030069857d2e4169ee7") == \
    "0x52908400098527886E0F7030069857D2E4169EE7"
assert to_checksum_address("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359") == \
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"

# ---------------------------------------------------------------------------
# Token list ingestion
# ---------------------------------------------------------------------------

def _expand_token(t: dict, source: str) -> Iterable[tuple]:
    """
    Yield (chain_id, lower_addr, name, symbol, decimals, source, canonical)
    rows for one token list entry, including Uniswap-style
    `extensions.bridgeInfo` cross-chain pointers.

    `canonical` is True for the entry whose top-level `chainId` matches the
    yielded chain — i.e. the row that was authored *for* that chain. Bridge
    expansions are non-canonical: they tell us a deployment exists, but they
    borrow the parent token's name/symbol, which can be wrong (e.g. Uniswap
    lists Avalanche's "DAI.e Token" with a bridgeInfo entry pointing back at
    mainnet DAI; the bridge metadata names mainnet DAI as "DAI.e Token",
    which it isn't).
    """
    name = str(t["name"])
    symbol = str(t["symbol"])
    decimals = int(t["decimals"])
    primary_chain = int(t["chainId"])
    primary_addr = str(t["address"]).lower()

    yield (primary_chain, primary_addr, name, symbol, decimals, source, True)

    bridge = ((t.get("extensions") or {}).get("bridgeInfo") or {})
    for chain_str, info in bridge.items():
        try:
            cid = int(chain_str)
        except (TypeError, ValueError):
            continue
        if not isinstance(info, dict):
            continue
        addr = info.get("tokenAddress")
        if not isinstance(addr, str):
            continue
        yield (cid, addr.lower(), name, symbol, decimals, source, False)


def load_source(path: pathlib.Path, source_name: str):
    blob = json.loads(path.read_text())
    tokens = blob.get("tokens") or []
    rows = []
    for t in tokens:
        try:
            rows.extend(_expand_token(t, source_name))
        except (KeyError, TypeError, ValueError) as e:
            print(f"WARN: skipping malformed entry in {source_name}: {e}",
                  file=sys.stderr)
    return rows


def normalize_string(s: str, max_chars: int) -> str:
    s = unicodedata.normalize("NFC", s)
    # Strip control chars / non-printables that occasionally sneak in.
    s = "".join(c for c in s if unicodedata.category(c)[0] != "C")
    return s[:max_chars]


def main() -> int:
    if not LISTS_DIR.exists():
        print(f"error: {LISTS_DIR} not found — run tools/fetch_token_lists.sh first",
              file=sys.stderr)
        return 1

    sources = {
        "uniswap": LISTS_DIR / "uniswap.json",
        "optimism": LISTS_DIR / "optimism.json",
    }
    raw_rows: list[tuple] = []
    for name, p in sources.items():
        if not p.exists():
            print(f"error: missing source {p}", file=sys.stderr)
            return 1
        rows = load_source(p, name)
        print(f"  {name:10s} {len(rows):6d} rows (after bridgeInfo expansion)",
              file=sys.stderr)
        raw_rows.extend(rows)

    # Dedupe by (chain_id, lower_addr). Source set accumulates across all
    # hits. For name/symbol/decimals we prefer entries authored *for* this
    # chain (canonical=True) — bridge-info expansions borrow the parent
    # token's strings and can be misleading (Uniswap's Avalanche "DAI.e
    # Token" entry has a bridgeInfo pointer back to mainnet DAI; we don't
    # want that to overwrite the real mainnet DAI row).
    pool: dict[tuple[int, str], dict] = {}
    for cid, addr, name, symbol, decimals, source, canonical in raw_rows:
        if cid not in TARGET_CHAINS:
            continue
        if not (addr.startswith("0x") and len(addr) == 42):
            continue
        try:
            int(addr, 16)
        except ValueError:
            continue
        if not (0 <= decimals <= 255):
            continue
        slot = pool.setdefault((cid, addr), {
            "name": name, "symbol": symbol, "decimals": decimals,
            "sources": set(), "canonical": False,
        })
        slot["sources"].add(source)
        if canonical and not slot["canonical"]:
            # First canonical hit for this (chain, addr) — adopt its strings.
            slot["name"] = name
            slot["symbol"] = symbol
            slot["decimals"] = decimals
            slot["canonical"] = True
        elif canonical and source == "uniswap":
            # Both canonical sources agree on existence; prefer Uniswap's
            # strings since OP occasionally uses noisier bridge-suffixed
            # names like "USD Coin (Bridged)".
            slot["name"] = name
            slot["symbol"] = symbol
            slot["decimals"] = decimals

    print(f"  pool: {len(pool)} unique (chain_id, address) pairs across "
          f"{len(TARGET_CHAINS)} target chains", file=sys.stderr)

    # Per-chain selection with priority ordering.
    by_chain: dict[int, list[dict]] = defaultdict(list)
    for (cid, addr), slot in pool.items():
        by_chain[cid].append({
            "chain_id": cid, "address": addr,
            "name": slot["name"], "symbol": slot["symbol"],
            "decimals": slot["decimals"], "sources": slot["sources"],
        })

    def rank(r: dict) -> tuple:
        sym_upper = r["symbol"].upper()
        return (
            -len(r["sources"]),                 # endorsed by both lists first
            _tier(sym_upper),                   # 0=stables/WETH, 1=DeFi, 2=...
            len(r["symbol"]),                   # shorter symbol = blue chip
            sym_upper,                          # alphabetical for determinism
            r["address"],
        )

    selected: list[dict] = []
    selected_keys: set[tuple[int, str]] = set()
    dropped = 0
    for cid in sorted(by_chain):
        cap = PER_CHAIN_CAP[cid]
        ranked = sorted(by_chain[cid], key=rank)
        keep = ranked[:cap]
        dropped += len(ranked) - len(keep)
        print(f"    chain {cid:6d}: kept {len(keep):3d} / {len(ranked):4d} "
              f"(cap={cap})", file=sys.stderr)
        for r in keep:
            r["name"] = normalize_string(r["name"], NAME_MAX_CHARS)
            r["symbol"] = normalize_string(r["symbol"], SYMBOL_MAX_CHARS)
            if not r["name"] or not r["symbol"]:
                continue
            r["address"] = to_checksum_address(r["address"])
            selected.append(r)
            selected_keys.add((r["chain_id"], r["address"].lower()))

    # Force-include manual additions even if they would otherwise miss the
    # cap, since they exist precisely because the upstream curated lists
    # don't carry them.
    added_manual = 0
    for entry in MANUAL_ADDITIONS:
        cid = int(entry["chain_id"])
        addr_lower = entry["address"].lower()
        if (cid, addr_lower) in selected_keys:
            continue  # already supplied by upstream — nothing to do
        checksummed = to_checksum_address(entry["address"])
        selected.append({
            "chain_id": cid,
            "address":  checksummed,
            "name":     normalize_string(entry["name"], NAME_MAX_CHARS),
            "symbol":   normalize_string(entry["symbol"], SYMBOL_MAX_CHARS),
            "decimals": int(entry["decimals"]),
        })
        selected_keys.add((cid, addr_lower))
        added_manual += 1

    print(f"  total kept: {len(selected)} (upstream "
          f"{len(selected) - added_manual}, manual {added_manual}), "
          f"dropped by caps: {dropped}", file=sys.stderr)

    # Same-chain symbol-collision check (warn loudly — likely scam impersonator
    # in one of the inputs, or two real tokens sharing a ticker).
    sym_idx: dict[tuple[int, str], list[str]] = defaultdict(list)
    for r in selected:
        sym_idx[(r["chain_id"], r["symbol"].upper())].append(r["address"])
    collisions = {k: v for k, v in sym_idx.items() if len(v) > 1}
    if collisions:
        print("WARN: same-chain symbol collisions in output:", file=sys.stderr)
        for (cid, sym), addrs in collisions.items():
            print(f"  chain {cid} {sym}: {addrs}", file=sys.stderr)

    # Final sort by (chain_id, address) — matches dbgen's internal sort, so
    # the JSON file order mirrors the on-disk blob order. Stable git diffs.
    selected.sort(key=lambda r: (r["chain_id"], r["address"].lower()))

    # Drop the bookkeeping `sources` field before serializing.
    out = [
        {
            "chain_id": r["chain_id"],
            "address":  r["address"],
            "name":     r["name"],
            "symbol":   r["symbol"],
            "decimals": r["decimals"],
        }
        for r in selected
    ]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # One token per line, ASCII-safe escaping off so non-Latin names render.
    body_lines = [
        "  " + json.dumps(r, ensure_ascii=False, separators=(", ", ": "))
        for r in out
    ]
    OUT_PATH.write_text("[\n" + ",\n".join(body_lines) + "\n]\n",
                        encoding="utf-8")
    print(f"==> wrote {len(out)} tokens to {OUT_PATH.relative_to(REPO)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
