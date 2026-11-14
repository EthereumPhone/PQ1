#!/usr/bin/env python3
"""
Build secure/data/erc20.json — the curated, EXHAUSTIVE ERC-20 metadata set
that drives on-device clear-signing (ERC-20 transfers AND CoW Swap order
legs, which decode token symbol/decimals against the firmware-pinned
ERC20_DB_ROOT).

The DB blob is host/companion-side only (`tools/companion-stub/erc20_db.bin`);
the firmware embeds just the 32-byte root, so the entry count is effectively
unbounded (on-device Merkle proof depth caps at 32 ⇒ up to 2^32 entries).
We therefore cast a WIDE net: every actively-traded token CoinGecko lists
on the supported chains, plus curated DEX/aggregator overlays.

Pipeline:
  1. Ingest EVERY *.json under build/token_lists/ (run fetch_token_lists.sh
     first). Auto-detects the three upstream shapes:
       * Uniswap-style token list: {"tokens": [ {chainId,address,name,...} ]}
         (+ Uniswap `extensions.bridgeInfo` cross-chain expansion)
       * 1inch v1.2: bare { "<addr>": {chainId,address,name,...}, ... } map
       * Sushi: bare [ {chainId,address,name,...}, ... ] array
     Every entry carries its own chainId, so chains are assigned by field.
  2. Filter to TARGET_CHAINS, dedupe by (chain_id, address) accumulating the
     contributing source set, preferring the highest-priority source's
     name/symbol/decimals.
  3. Sanitize name/symbol with tools/erc20_text.py (the ONE sanitizer, shared
     with tools/verify_erc20_decimals.py) — the on-device verifier
     (tx/src/erc20/bundle.rs) REJECTS any non-ASCII byte and any field outside
     1..=64 bytes, and dbgen refuses to build a DB holding such a row. Safe
     folds (`₮`->`T`, `€`->`EUR`, accents dropped, ...) are applied; a row
     whose name or symbol still holds a non-ASCII character (Cyrillic/Greek
     look-alikes, CJK, emoji) is DROPPED, never folded to Latin.
  4. Resolve cross-chain same-address metadata conflicts. dbgen HARD-ERRORS
     if one contract appears on multiple chains with different name/symbol
     (copy-paste guard). With multichain data this is common (deterministic
     CREATE2 deploys share an address across chains). Rule:
       * same symbol across chains → unify the name (canonical pick) — same
         token, naming noise.
       * different symbols across chains → genuine ambiguity (or a coincident
         address) → DROP the whole address group (loud warning).
  5. Optional per-chain cap with priority ranking (default: unlimited).
  6. EIP-55 checksum every address (bundled pure-Python keccak-256; no deps).
  7. Sort by (chain_id, address) — same order dbgen uses — for stable diffs,
     then write secure/data/erc20.json.

`secure/data/erc20-e2e.json` is a SEPARATE, small fixture (the prior curated
set) consumed only by `--features e2e-test` QEMU builds; it is NOT touched by
this script. Keeping it small is what lets `make e2e` bake a companion-stub
blob into the 256 KB NS flash without overflow while production uses the full
multi-MB blob. See dbgen/src/main.rs (ERC20_DB_ROOT / ERC20_DB_ROOT_E2E split).

Run:  python3 tools/build_erc20_db.py   then   cargo run -p dbgen

Normalize the checked-in DBs in place (no token lists needed; re-applies the
shared sanitizer to every row, drops rows that cannot be made
device-verifiable, and drops a row whose FOLDED symbol newly equals a
blue-chip ticker — e.g. a scam "USD₮" folding to "USDT"):

      python3 tools/build_erc20_db.py --normalize            # both DBs
      python3 tools/build_erc20_db.py --normalize --check    # exit 1 if not normal
"""

from __future__ import annotations

import json
import pathlib
import struct
import sys
from collections import Counter, defaultdict
from typing import Iterable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import erc20_text  # noqa: E402  (the shared name/symbol sanitizer)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Supported chains. The first 8 are the user-facing target set (the most-used
# EVM chains); Avalanche + Unichain are retained so we don't regress the
# coverage the prior DB already shipped.
CHAIN_NAMES: dict[int, str] = {
    1:     "Ethereum",
    10:    "Optimism",
    56:    "BNB Chain",
    130:   "Unichain",
    137:   "Polygon PoS",
    8453:  "Base",
    42161: "Arbitrum One",
    43114: "Avalanche C-Chain",
    59144: "Linea",
    999:   "Hyperliquid (HyperEVM)",
}
TARGET_CHAINS = set(CHAIN_NAMES)

# Per-chain inclusion caps. None = unlimited (include the full vetted
# universe). Set an int to bound a chain when trimming toward a size budget;
# ranking (see rank()) keeps the most-relevant tokens.
PER_CHAIN_CAP: dict[int, int | None] = {cid: None for cid in TARGET_CHAINS}

# Source priority for metadata (name/symbol/decimals) when several lists
# describe the same (chain, address). Higher wins. CoinGecko is the most
# internally-consistent; Uniswap/Optimism next; the rest fill gaps.
def _source_priority(source: str) -> int:
    s = source.lower()
    if s.startswith("coingecko"):
        return 100
    if s.startswith("uniswap"):
        return 90
    if s.startswith("optimism"):
        return 85
    if s.startswith("pancakeswap"):
        return 70
    if s.startswith("sushi"):
        return 60
    if s.startswith("1inch"):
        return 55
    if s.startswith("quickswap"):
        return 50
    if s.startswith("gemini"):
        return 45
    return 10


# Tiered blue-chip symbols. Lower tier = higher priority within a per-chain
# cap (only consulted when a cap is set). Stables + wrapped natives first.
PRIORITY_TIERS: list[set[str]] = [
    {
        "USDC", "USDT", "DAI", "FRAX", "LUSD", "TUSD", "USDP", "GUSD",
        "PYUSD", "USDE", "SUSDE", "CRVUSD", "MIM", "SUSD", "USDD", "USDC.E",
        "USDS", "GHO", "FDUSD", "USD1", "DOLA",
        "WETH", "STETH", "WSTETH", "RETH", "CBETH", "WEETH", "EETH", "EZETH",
        "WBTC", "TBTC", "CBBTC", "LBTC",
        "WBNB", "WMATIC", "WAVAX", "WPOL", "WHYPE", "WLINEA",
    },
    {
        "LINK", "UNI", "AAVE", "MKR", "SNX", "COMP", "CRV", "CVX", "LDO",
        "ARB", "OP", "MATIC", "POL", "BNB", "AVAX", "HYPE", "CAKE",
    },
    {
        "BAL", "YFI", "1INCH", "SUSHI", "GMX", "GRT", "ENS", "RPL",
        "PEPE", "SHIB", "DOGE", "PENDLE", "FXS", "RDNT", "MAGIC", "AERO",
        "VELO", "MORPHO", "ENA",
    },
]


def _tier(symbol: str) -> int:
    s = symbol.upper()
    for i, tier in enumerate(PRIORITY_TIERS):
        if s in tier:
            return i
    return 99


# Manual additions for blue-chip tokens upstream lists may omit. Each MUST be
# cross-checked against a block explorer — these bypass source consensus.
MANUAL_ADDITIONS = [
    {"chain_id": 42161, "address": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
     "name": "Tether USD", "symbol": "USDT", "decimals": 6},
    {"chain_id": 8453, "address": "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",
     "name": "Tether USD", "symbol": "USDT", "decimals": 6},
    {"chain_id": 130, "address": "0x4200000000000000000000000000000000000006",
     "name": "Wrapped Ether", "symbol": "WETH", "decimals": 18},
    # ERC-7730 descriptor-pinned tokenAmount constants (dbgen constant-token
    # gate, dbgen/src/token_constant_exceptions.rs). name/symbol/decimals read
    # on-chain over two independent public RPCs on 2026-11-14; a bogus-selector
    # probe reverted on each (real getters). Chain 1116 (Core) is outside
    # TARGET_CHAINS: manual rows are added on any chain.
    {"chain_id": 1, "address": "0x7751E2F4b8ae93EF6B79d86419d42FE3295A4559",
     "name": "Wrapped USDL", "symbol": "wUSDL", "decimals": 6},
    {"chain_id": 1, "address": "0xaf37c1167910ebC994e266949387d2c7C326b879",
     "name": "Ondo U.S. Dollar Yield (Rebasing)", "symbol": "rUSDY", "decimals": 18},
    {"chain_id": 1116, "address": "0xb3A8F0f0da9ffC65318aA39E55079796093029AD",
     "name": "Liquid staked CORE", "symbol": "stCORE", "decimals": 18},
]

REPO = pathlib.Path(__file__).resolve().parent.parent
LISTS_DIR = REPO / "build" / "token_lists"
OUT_PATH = REPO / "secure" / "data" / "erc20.json"

# Token (chain, address) pairs to exclude unconditionally. Two denylists, both
# applied; without them a rebuild from upstream lists would silently re-add the
# entries. Missing files -> no exclusions.
#   * erc20_impersonator_denylist.txt — SECURITY: look-alikes wearing a curated
#     ticker at a non-canonical address (tools/scan_erc20_impersonators.py).
#   * erc20_inactive_denylist.txt — QUALITY: dead tokens (0 recent transfers +
#     low provenance) from the Alchemy activity screen / triage. Re-evaluable.
DENYLIST_PATHS = [
    REPO / "tools" / "erc20_impersonator_denylist.txt",
    REPO / "tools" / "erc20_inactive_denylist.txt",
]


def load_denylist() -> set[tuple[int, str]]:
    """Return {(chain_id, address_lower)} parsed from every DENYLIST_PATHS file.
    Lines are `<chain_id> <address>  # optional comment`; blank/`#` lines ignored."""
    deny: set[tuple[int, str]] = set()
    for path in DENYLIST_PATHS:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                cid = int(parts[0])
            except ValueError:
                continue
            deny.add((cid, parts[1].lower()))
    return deny

E2E_PATH = REPO / "secure" / "data" / "erc20-e2e.json"

# A row whose symbol was CHANGED by folding and now equals one of these tickers
# (case-insensitive) is dropped: folding must never manufacture a blue-chip
# ticker ("USD₮" -> "USDT"). Derived tickers such as "USDT0" or "aUSDT" are
# not in this set and are kept.
FOLD_PROTECTED_SYMBOLS = frozenset({"USDT", "USDC", "WETH", "DAI", "WBTC", "ETH"})

# ---------------------------------------------------------------------------
# Pure-Python keccak-256 for EIP-55 address checksumming.
# Pre-FIPS Keccak (padding byte 0x01), NOT NIST SHA3-256.
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
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f(A: list[list[int]]) -> None:
    for rc in _KECCAK_RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl(A[x][y], _KECCAK_R[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & _MASK64) & B[(x + 2) % 5][y])
        A[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
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
    for i in range(4):
        out += struct.pack("<Q", state[i % 5][i // 5])
    return bytes(out)


_EMPTY_DIGEST = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"").hex() == _EMPTY_DIGEST, "keccak256 self-test failed"


def to_checksum_address(addr: str) -> str:
    a = addr.lower().removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdef" for c in a):
        raise ValueError(f"not a 20-byte hex address: {addr!r}")
    digest = keccak256(a.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(a)
    )


assert to_checksum_address("0x52908400098527886e0f7030069857d2e4169ee7") == \
    "0x52908400098527886E0F7030069857D2E4169EE7"
assert to_checksum_address("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359") == \
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"

# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


def sanitize_row_text(name, symbol) -> tuple[str, str] | None:
    """Device-verifiable (name, symbol) via tools/erc20_text.py, or None if
    the row must be dropped (see that module for the policy)."""
    n = erc20_text.clean_name(name)
    sym = erc20_text.clean_symbol(symbol)
    if n is None or sym is None:
        return None
    if (sym != symbol and sym.upper() in FOLD_PROTECTED_SYMBOLS
            and str(symbol).strip().upper() != sym.upper()):
        return None
    return n, sym


# ---------------------------------------------------------------------------
# Token list ingestion (multi-shape)
# ---------------------------------------------------------------------------


def _emit(cid, addr, name, symbol, decimals, source, canonical):
    """Yield a normalized row tuple if it is well-formed and on-target."""
    try:
        cid = int(cid)
        decimals = int(decimals)
    except (TypeError, ValueError):
        return
    if cid not in TARGET_CHAINS:
        return
    if not isinstance(addr, str):
        return
    a = addr.lower()
    if not (a.startswith("0x") and len(a) == 42):
        return
    try:
        int(a, 16)
    except ValueError:
        return
    # Reject native-token sentinels (some lists, e.g. Li.Fi, list native gas
    # as the zero address or 0xeee..eee). These are not ERC-20 contracts.
    if a == "0x" + "0" * 40 or a == "0x" + "e" * 40:
        return
    if not (0 <= decimals <= 255):
        return
    yield (cid, a, str(name), str(symbol), decimals, source, canonical)


def _expand_tokenlist_entry(t: dict, source: str) -> Iterable[tuple]:
    """One Uniswap/Sushi/CoinGecko/Li.Fi/1inch entry → its CANONICAL row.

    We deliberately do NOT expand Uniswap `extensions.bridgeInfo` cross-chain
    pointers: those rows borrow the parent token's name/symbol and would
    MISLABEL the (chain, address) they point at (the bridged deployment can be
    a different token, or just carry a different canonical name). Every target
    chain is already covered directly by per-chain sources (CoinGecko / Li.Fi /
    1inch / Sushi), each entry carrying its own authoritative chainId, symbol
    and decimals — so bridge expansion is redundant as well as hazardous."""
    if not isinstance(t, dict):
        return
    name, symbol = t.get("name"), t.get("symbol")
    decimals = t.get("decimals")
    chain = t.get("chainId")
    addr = t.get("address")
    if chain is not None and addr is not None:
        yield from _emit(chain, addr, name, symbol, decimals, source, True)


def load_source(path: pathlib.Path) -> list[tuple]:
    source = path.stem
    try:
        blob = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"  WARN: skipping unreadable {source}: {e}", file=sys.stderr)
        return []
    rows: list[tuple] = []

    if isinstance(blob, dict) and isinstance(blob.get("tokens"), list):
        # Uniswap / CoinGecko / PancakeSwap / Optimism token-list shape.
        for t in blob["tokens"]:
            rows.extend(_expand_tokenlist_entry(t, source))
    elif isinstance(blob, dict) and isinstance(blob.get("tokens"), dict):
        # Li.Fi shape: {"tokens": {"<chainId>": [ {chainId,address,...} ]}}.
        for arr in blob["tokens"].values():
            if isinstance(arr, list):
                for t in arr:
                    rows.extend(_expand_tokenlist_entry(t, source))
    elif isinstance(blob, list):
        # Sushi bare-array shape.
        for t in blob:
            rows.extend(_expand_tokenlist_entry(t, source))
    elif isinstance(blob, dict):
        # 1inch v1.2 addr->token map shape.
        for v in blob.values():
            if isinstance(v, dict) and "chainId" in v and "address" in v:
                rows.extend(_expand_tokenlist_entry(v, source))
    else:
        print(f"  WARN: {source}: unrecognized JSON shape", file=sys.stderr)
    return rows


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def main() -> int:
    if not LISTS_DIR.exists():
        print(f"error: {LISTS_DIR} not found — run tools/fetch_token_lists.sh first",
              file=sys.stderr)
        return 1

    files = sorted(LISTS_DIR.glob("*.json"))
    if not files:
        print(f"error: no token lists in {LISTS_DIR} — run fetch_token_lists.sh",
              file=sys.stderr)
        return 1

    raw_rows: list[tuple] = []
    for p in files:
        rows = load_source(p)
        print(f"  {p.stem:28s} {len(rows):7d} rows", file=sys.stderr)
        raw_rows.extend(rows)
    print(f"  total raw rows: {len(raw_rows)}", file=sys.stderr)

    # Drop known impersonators before they enter the pool.
    denylist = load_denylist()
    denied = 0

    # Dedupe by (chain_id, addr). Prefer the highest-priority *canonical*
    # source's metadata; accumulate the contributing source set.
    pool: dict[tuple[int, str], dict] = {}
    for cid, addr, name, symbol, decimals, source, canonical in raw_rows:
        if (cid, addr) in denylist:
            denied += 1
            continue
        prio = _source_priority(source) + (5 if canonical else 0)
        slot = pool.get((cid, addr))
        if slot is None:
            pool[(cid, addr)] = {
                "name": name, "symbol": symbol, "decimals": decimals,
                "sources": {source}, "prio": prio,
            }
        else:
            slot["sources"].add(source)
            if prio > slot["prio"]:
                slot.update(name=name, symbol=symbol, decimals=decimals, prio=prio)

    if denylist:
        print(f"  excluded {denied} rows via impersonator denylist "
              f"({len(denylist)} entries)", file=sys.stderr)
    print(f"  unique (chain, address): {len(pool)}", file=sys.stderr)

    # Sanitize name/symbol; drop rows that don't survive the ASCII/length gate.
    entries: dict[tuple[int, str], dict] = {}
    dropped_sanitize = 0
    for (cid, addr), slot in pool.items():
        cleaned = sanitize_row_text(slot["name"], slot["symbol"])
        if cleaned is None:
            dropped_sanitize += 1
            continue
        name, symbol = cleaned
        entries[(cid, addr)] = {
            "chain_id": cid, "address": addr, "name": name,
            "symbol": symbol, "decimals": slot["decimals"],
            "sources": slot["sources"],
        }
    if dropped_sanitize:
        print(f"  dropped {dropped_sanitize} rows (not device-verifiable after "
              f"erc20_text sanitize)",
              file=sys.stderr)

    # Resolve cross-chain same-address metadata conflicts (dbgen hard-errors
    # on a contract that appears on multiple chains with different name/symbol).
    by_addr: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for key in entries:
        by_addr[key[1]].append(key)

    # The DB is keyed by (chain_id, contract) and every Merkle leaf is
    # chain-bound, so the SAME address legitimately hosting DIFFERENT tokens
    # on different chains (coincidental cross-chain address reuse — e.g.
    # 0x50c5..0cb is DAI on Optimism but LYRA on Base) is unambiguous and
    # safe. We KEEP all such entries (dbgen warns, doesn't reject — see
    # dbgen/src/erc20.rs). To keep that warning signal meaningful, we only
    # normalize the BENIGN case: when the same address carries the same
    # SYMBOL across chains (same token, naming noise like "Wrapped Ether" vs
    # "WETH"), unify to one canonical spelling so it doesn't trip the warning.
    distinct_symbol_groups = 0
    unified = 0
    for addr, keys in by_addr.items():
        if len(keys) < 2:
            continue
        symbols = {entries[k]["symbol"].upper() for k in keys}
        if len(symbols) > 1:
            # Genuinely different tokens at a shared address — keep each
            # chain's metadata as-is (chain-bound leaf ⇒ no ambiguity).
            distinct_symbol_groups += 1
            continue
        # Same symbol across chains → same token, unify name+symbol to one
        # canonical spelling (most common; tie → lowest chain_id).
        names = Counter(entries[k]["name"] for k in keys)
        canon_name = sorted(names.items(),
                            key=lambda kv: (-kv[1], min(k[0] for k in keys if entries[k]["name"] == kv[0])))[0][0]
        syms = Counter(entries[k]["symbol"] for k in keys)
        canon_symbol = sorted(syms.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        changed = False
        for k in keys:
            if entries[k]["name"] != canon_name or entries[k]["symbol"] != canon_symbol:
                entries[k]["name"] = canon_name
                entries[k]["symbol"] = canon_symbol
                changed = True
        if changed:
            unified += 1
    print(f"  unified {unified} same-token cross-chain address groups; kept "
          f"{distinct_symbol_groups} shared-address groups with distinct tokens",
          file=sys.stderr)

    # Per-chain selection (cap optional) with priority ranking.
    by_chain: dict[int, list[dict]] = defaultdict(list)
    for e in entries.values():
        by_chain[e["chain_id"]].append(e)

    def rank(r: dict) -> tuple:
        sym_upper = r["symbol"].upper()
        return (
            -len(r["sources"]),
            _tier(sym_upper),
            len(r["symbol"]),
            sym_upper,
            r["address"],
        )

    selected: list[dict] = []
    selected_keys: set[tuple[int, str]] = set()
    for cid in sorted(by_chain):
        cap = PER_CHAIN_CAP.get(cid)
        ranked = sorted(by_chain[cid], key=rank)
        keep = ranked if cap is None else ranked[:cap]
        dropped = len(ranked) - len(keep)
        print(f"    chain {cid:6d} {CHAIN_NAMES[cid]:24s}: kept {len(keep):5d}"
              f" / {len(ranked):5d}" + (f"  (cap {cap}, dropped {dropped})" if cap else ""),
              file=sys.stderr)
        for r in keep:
            r["address"] = to_checksum_address(r["address"])
            selected.append(r)
            selected_keys.add((r["chain_id"], r["address"].lower()))

    # Force-include manual additions (sanitized; must already pass the gate).
    added_manual = 0
    for entry in MANUAL_ADDITIONS:
        cid = int(entry["chain_id"])
        addr_lower = entry["address"].lower()
        if (cid, addr_lower) in selected_keys:
            continue
        cleaned = sanitize_row_text(entry["name"], entry["symbol"])
        if cleaned is None:
            continue
        name, symbol = cleaned
        selected.append({
            "chain_id": cid, "address": to_checksum_address(entry["address"]),
            "name": name, "symbol": symbol, "decimals": int(entry["decimals"]),
        })
        selected_keys.add((cid, addr_lower))
        added_manual += 1

    print(f"  total kept: {len(selected)} (manual additions: {added_manual})",
          file=sys.stderr)

    # Final safety net: dbgen hard-rejects a duplicate (chain_id, contract)
    # key (a true ambiguity), so surface it here with a clear message rather
    # than as a dbgen panic. (Cross-chain same-address-different-metadata is
    # intentionally allowed — see the conflict-handling note above.)
    seen_pair: set[tuple[int, str]] = set()
    for r in selected:
        key = (r["chain_id"], r["address"].lower())
        if key in seen_pair:
            print(f"  FATAL: duplicate (chain,address) {key}", file=sys.stderr)
            return 1
        seen_pair.add(key)

    # Per-chain symbol-collision report (informational — two real tokens can
    # share a ticker at different addresses; the order references a specific
    # address so the render stays correct).
    sym_idx: dict[tuple[int, str], int] = Counter(
        (r["chain_id"], r["symbol"].upper()) for r in selected)
    collisions = sum(1 for c in sym_idx.values() if c > 1)
    if collisions:
        print(f"  note: {collisions} same-chain symbol groups have >1 address "
              f"(bridged variants / shared tickers — expected at this scale)",
              file=sys.stderr)

    # Sort by (chain_id, address) to mirror dbgen's on-disk order.
    selected.sort(key=lambda r: (r["chain_id"], r["address"].lower()))

    out = [
        {"chain_id": r["chain_id"], "address": r["address"],
         "name": r["name"], "symbol": r["symbol"], "decimals": r["decimals"]}
        for r in selected
    ]

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(format_db(out), encoding="utf-8")
    per_chain = Counter(r["chain_id"] for r in out)
    print(f"==> wrote {len(out)} tokens to {OUT_PATH.relative_to(REPO)}", file=sys.stderr)
    for cid in sorted(per_chain):
        print(f"      chain {cid:6d} {CHAIN_NAMES.get(cid, '?'):24s}: {per_chain[cid]:5d}",
              file=sys.stderr)
    return 0


def format_db(rows: list[dict]) -> str:
    """The checked-in on-disk format (one JSON object per line), shared by
    every writer so diffs stay row-local."""
    body = [
        "  " + json.dumps(
            {"chain_id": r["chain_id"], "address": r["address"],
             "name": r["name"], "symbol": r["symbol"], "decimals": r["decimals"]},
            ensure_ascii=False, separators=(", ", ": "))
        for r in rows
    ]
    return "[\n" + ",\n".join(body) + "\n]\n"


def normalize_rows(rows: list[dict]) -> tuple[list[dict], dict[str, list]]:
    """Re-apply the shared sanitizer to already-built rows, preserving order.

    Returns (kept_rows, report) where report has the lists `folded`,
    `truncated` (name shortened) and `dropped` (row removed), each entry
    `(chain_id, address, old_name, old_symbol, new_name, new_symbol)`."""
    report: dict[str, list] = {"folded": [], "truncated": [], "dropped": []}
    kept: list[dict] = []
    for r in rows:
        cleaned = sanitize_row_text(r["name"], r["symbol"])
        if cleaned is None:
            report["dropped"].append(
                (r["chain_id"], r["address"], r["name"], r["symbol"], None, None))
            continue
        name, symbol = cleaned
        if (name, symbol) != (r["name"], r["symbol"]):
            folded_name = erc20_text.fold_ascii(r["name"])
            entry = (r["chain_id"], r["address"], r["name"], r["symbol"], name, symbol)
            if folded_name is not None and name != folded_name:
                report["truncated"].append(entry)
            if (folded_name != r["name"]) or (symbol != r["symbol"]):
                report["folded"].append(entry)
        kept.append({**r, "name": name, "symbol": symbol})
    return kept, report


def normalize_main(argv: list[str]) -> int:
    check = "--check" in argv
    paths = [pathlib.Path(a) for a in argv if not a.startswith("--")]
    if not paths:
        paths = [OUT_PATH, E2E_PATH]
    dirty = False
    for path in paths:
        raw = path.read_text(encoding="utf-8")
        rows = json.loads(raw)
        kept, report = normalize_rows(rows)
        out = format_db(kept)
        rel = path.relative_to(REPO) if path.is_absolute() and REPO in path.parents else path
        print(f"==> {rel}: {len(rows)} rows; folded {len(report['folded'])}, "
              f"truncated {len(report['truncated'])}, dropped {len(report['dropped'])}"
              f" -> {len(kept)} rows", file=sys.stderr)
        for kind in ("folded", "truncated", "dropped"):
            for cid, addr, on, osym, nn, nsym in report[kind]:
                arrow = "DROP" if nn is None else f"-> {nn!r} / {nsym!r}"
                print(f"    {kind:9s} {cid:6d} {addr}  {on!r} / {osym!r}  {arrow}",
                      file=sys.stderr)
        if out != raw:
            dirty = True
            if not check:
                path.write_text(out, encoding="utf-8")
                print(f"    wrote {rel}", file=sys.stderr)
    if check and dirty:
        print("error: ERC-20 DB is not normalized; run "
              "`python3 tools/build_erc20_db.py --normalize`", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if "--normalize" in sys.argv[1:]:
        sys.exit(normalize_main([a for a in sys.argv[1:] if a != "--normalize"]))
    sys.exit(main())
