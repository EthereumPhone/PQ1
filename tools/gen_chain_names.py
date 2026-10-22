#!/usr/bin/env python3
"""Generate the device's chain-name table from chainlist.org.

    curl -sSL -o rpcs.json https://chainlist.org/rpcs.json
    python3 -I tools/gen_chain_names.py rpcs.json            # writes the table
    python3 -I tools/gen_chain_names.py rpcs.json --check    # CI-style diff

Output: `pqsigner-erc7730/src/display/chain_names_gen.rs`, read by
`display::primitives::chain_name`. A chain name is shown on the NETWORK
screen ("on Linea") and in the 16-column rows ("(Linea)"); a chain that is
not in the table shows its number ("Chain 12345"), which is always safe. So
the table only takes a name when showing it cannot mislead:

  * HAND-PICKED names (`CURATED` below) always win for their ids.
  * Other chains: a mainnet (`isTestnet` false) with at least MIN_TVL_USD of
    TVL in the chainlist entry, i.e. a chain people actually use.
  * The name, minus a trailing "Mainnet", is at most MAX_NAME_LEN bytes:
    "(" + name + ")" must fit a 16-column row, which cuts longer text.
  * Only letters, digits, space, "." and "-", and every one of them baked
    at every regular tier a chain line can be fitted at (22/28/32/36,
    `pqsigner-ui-px/src/metrics_gen.rs`): a glyph the font lacks would make
    the screen unfittable, i.e. a refusal to sign.
  * Unique after case/punctuation folding, across the whole table; a name
    two chains share is dropped for both.
  * Not borrowing a hand-picked name: a candidate whose words contain one
    ("Crynux on Base", "SKALE Base", "Arbitrum Nova") could be read as that
    chain, so it is dropped and keeps showing its number. Nor a testnet word
    ("Berachain Bepolia" is listed as a mainnet).

Testnets (2026-10-22) follow their own rules, because a testnet's name is
its parent's name plus a testnet word ("Linea Sepolia"):

  * HAND-PICKED testnets (`CURATED_TESTNETS`) win for their ids; they cover
    well-known testnets chainlist gives no TVL, and shorten a few names
    ("Arbitrum Sepolia" is 16 bytes: "Arb Sepolia").
  * Other testnets: chainlist copies the parent chain's TVL onto its
    testnets, so the same MIN_TVL_USD picks testnets of chains people use.
  * Retired networks (Goerli, Rinkeby, Kovan, Ropsten, Mumbai) are dropped.
  * "Testnet" is removed when another testnet word names the network
    ("Base Sepolia Testnet" -> "Base Sepolia"), and so is "Network".
  * The result must still contain a testnet word (`TESTNET_WORDS`), so a
    testnet can never read as a mainnet; length, glyphs and uniqueness as
    above.

The source is third-party data. The generated file records its sha256; the
table itself is what the firmware signs over, so review its diff like code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "pqsigner-erc7730/src/display/chain_names_gen.rs"
METRICS = ROOT / "pqsigner-ui-px/src/metrics_gen.rs"

MIN_TVL_USD = 1_000_000
MAX_NAME_LEN = 14

# The names the device showed before this table, kept verbatim (Base Sepolia
# gains its space). They win over chainlist for their ids.
CURATED: dict[int, str] = {
    1: "Mainnet",
    10: "Optimism",
    14: "Flare",
    30: "Rootstock",
    56: "BSC",
    100: "Gnosis",
    137: "Polygon",
    146: "Sonic",
    250: "Fantom",
    324: "zkSync Era",
    999: "HyperEVM",
    1329: "Sei",
    8217: "Kaia",
    8453: "Base",
    42161: "Arbitrum",
    42220: "Celo",
    43114: "Avalanche",
    59144: "Linea",
    534352: "Scroll",
    11155111: "Sepolia",
    84532: "Base Sepolia",
}
# Hand-picked testnets: well-known ones chainlist gives no TVL, and short
# forms of names over MAX_NAME_LEN.
CURATED_TESTNETS: dict[int, str] = {
    97: "BSC Testnet",
    17000: "Holesky",
    80002: "Polygon Amoy",
    10200: "Gnosis Chiado",
    1328: "Sei Testnet",
    421614: "Arb Sepolia",
}
# A testnet's name must contain one of these; a mainnet's must not.
TESTNET_WORDS = {
    "testnet", "sepolia", "hoodi", "holesky", "fuji", "amoy", "chiado", "minato",
    "coston2", "bepolia", "aeneid", "blaze",
}
RETIRED_WORDS = {"goerli", "rinkeby", "kovan", "ropsten", "mumbai"}
# Words a mainnet candidate may not contain: the hand-picked names, plus the
# names people know those chains by.
PROTECTED_WORDS = {w.lower() for n in CURATED.values() for w in n.split()} | {
    "ethereum", "eth", "op", "bnb", "binance", "arbitrum", "zksync", "avax", "matic",
}
CHARSET = re.compile(r"^[A-Za-z0-9 .\-]+$")


def fold(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def baked_glyphs() -> set[str]:
    """Characters with a non-zero advance at every tier a chain line can be
    drawn at (regular 22/28/32/36: `fit::fit_tier` picks one)."""
    src = METRICS.read_text()
    tiers = re.findall(r"px: (\d+),\s*semibold: (true|false),.*?advance_q6: \[(\d[^\]]*)\]", src, re.S)
    ok = None
    for px, semibold, t in tiers:
        if semibold == "true" or int(px) not in (22, 28, 32, 36):
            continue
        adv = [int(x) for x in t.split(",") if x.strip()]
        have = {chr(0x20 + i) for i, a in enumerate(adv) if a}
        ok = have if ok is None else ok & have
    if ok is None:
        sys.exit(f"no regular 22/28/32/36 advance tables in {METRICS}")
    return ok


def capitalise(n: str) -> str:
    """Capital first letter for an all-lowercase first word ("katana"); a
    brand's own casing ("zkSync", "opBNB") is kept."""
    first = n.split(" ", 1)[0]
    return n[:1].upper() + n[1:] if first.islower() else n


def display_name(raw: str) -> str:
    """Chainlist name minus a trailing "Mainnet" (and the " - " some entries
    put before it), see `capitalise`."""
    n = " ".join(raw.split())
    n = re.sub(r"[\s\-]*\bMainnet$", "", n).rstrip(" -")
    return capitalise(n)


def testnet_name(raw: str) -> str:
    """Chainlist testnet name minus "Network", and minus "Testnet" when
    another testnet word names the network."""
    words = [w for w in raw.split() if w.lower() != "network"]
    if any(w.lower() in TESTNET_WORDS - {"testnet"} for w in words):
        words = [w for w in words if w.lower() != "testnet"]
    return capitalise(" ".join(words))


def build(entries: list[dict]) -> tuple[dict[int, str], list[str]]:
    glyphs = baked_glyphs()
    hand = {**CURATED, **CURATED_TESTNETS}
    assert len(hand) == len(CURATED) + len(CURATED_TESTNETS)
    for cid, name in hand.items():
        assert len(name) <= MAX_NAME_LEN and set(name) <= glyphs, (cid, name)
    for cid, name in CURATED_TESTNETS.items():
        assert {w.lower() for w in name.split()} & TESTNET_WORDS, (cid, name)
    dropped: list[str] = []
    cand: dict[int, str] = {}
    for e in entries:
        cid = e.get("chainId")
        if not isinstance(cid, int) or cid <= 0 or cid >= 1 << 64 or cid in hand:
            continue
        if (e.get("tvl") or 0) < MIN_TVL_USD:
            continue
        testnet = bool(e.get("isTestnet"))
        raw = str(e.get("name", ""))
        name = testnet_name(raw) if testnet else display_name(raw)
        words = {w.lower() for w in name.split()}
        why = None
        if len(name) > MAX_NAME_LEN:
            why = "too long"
        elif not CHARSET.match(name) or not set(name) <= glyphs:
            why = "characters"
        elif testnet and words & RETIRED_WORDS:
            why = "retired testnet"
        elif testnet and not words & TESTNET_WORDS:
            why = "testnet without a testnet word"
        elif not testnet and words & PROTECTED_WORDS:
            why = "borrows a hand-picked name"
        elif not testnet and words & TESTNET_WORDS:
            why = "mainnet named like a testnet"
        if why:
            dropped.append(f"{cid} {e.get('name')!r}: {why}")
            continue
        cand[cid] = name
    # Uniqueness across curated + candidates.
    seen: dict[str, list[int]] = {}
    for cid, name in {**hand, **cand}.items():
        seen.setdefault(fold(name), []).append(cid)
    for key, ids in seen.items():
        if len(ids) > 1:
            assert sum(cid in hand for cid in ids) <= 1, f"hand-picked names collide: {ids}"
            for cid in ids:
                if cid in cand:
                    dropped.append(f"{cid} {cand.pop(cid)!r}: name shared with {ids}")
    return {**hand, **cand}, dropped


def render(table: dict[int, str], sha: str, n_in: int) -> str:
    rows = "\n".join(f'    ({cid}, "({name})"),' for cid, name in sorted(table.items()))
    return f"""// @generated by tools/gen_chain_names.py — do not edit by hand.
// Source: https://chainlist.org/rpcs.json, sha256 {sha}, {n_in} entries.
// Rules (see the generator): hand-picked names first; then mainnets with
// TVL >= ${MIN_TVL_USD:,} not borrowing a hand-picked name, and testnets of such chains
// named with a testnet word; every name <= {MAX_NAME_LEN} bytes in baked glyphs, unique.

/// `(chain id, "(display name)")`, sorted by id for binary search.
pub(crate) const CHAIN_NAMES: [(u64, &str); {len(table)}] = [
{rows}
];
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rpcs_json", type=Path)
    ap.add_argument("--check", action="store_true", help="fail if the committed table differs")
    ap.add_argument("--verbose", action="store_true", help="list the dropped candidates")
    args = ap.parse_args()
    raw = args.rpcs_json.read_bytes()
    entries = json.loads(raw)
    table, dropped = build(entries)
    text = render(table, hashlib.sha256(raw).hexdigest(), len(entries))
    if args.verbose:
        print("\n".join(sorted(dropped)))
    print(f"{len(table)} names ({len(CURATED) + len(CURATED_TESTNETS)} hand-picked), {len(dropped)} candidates dropped")
    if args.check:
        if OUT.read_text() != text:
            print(f"{OUT} differs from the generator output", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
