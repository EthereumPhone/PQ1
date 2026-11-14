#!/usr/bin/env python3
"""Find impersonator / look-alike tokens in the PQ1 ERC-20 db — fully OFFLINE,
no API, no rate limit, deterministic.

Why this works without any API:
    Per CLAUDE.md: "scam tokens can copy the name and symbol but never the real
    contract address." Impersonation is therefore a symbol-collision check, not
    a reputation lookup. The db was built (tools/build_erc20_db.py) by merging
    curated token lists already on disk under build/token_lists/. Those sources
    have a trust ranking (build_erc20_db._source_priority): CoinGecko 100,
    Uniswap 90, Optimism 85, PancakeSwap 70, Sushi 60, 1inch 55, QuickSwap 50,
    Gemini 45 ... and Li.Fi (the broad, least-curated bridge aggregator) 10.

    An impersonator is a token that wears a CURATED token's ticker at an address
    that only a LOW-TRUST source vouches for. Concretely, for a db token
    (chain, address, SYMBOL):
        * trusted sources (priority >= --trust-threshold, default 45) associate
          SYMBOL on this chain with one or more addresses, AND
        * this token's address is NOT one of them.
    -> it is claiming a known ticker at a non-canonical address = impersonator.

    Blue-chip tickers (build_erc20_db.PRIORITY_TIERS: USDC/USDT/WETH/UNI/PEPE/
    ...) are escalated to severity HIGH — these are the USDC/UNI/PEPE spoofs you
    already found and dropped by hand.

This reuses build_erc20_db's own loaders / priorities / blue-chip tiers /
manual canonical additions, so the verdict is consistent with how the db was
actually built. Re-fetch the lists with `bash tools/fetch_token_lists.sh` if
build/token_lists/ is stale.

Limitations (be honest):
    * Catches impersonation by COLLISION with a curated ticker. A scam that
      invents a brand-new ticker no curated list uses is NOT impersonation and
      won't appear here (there's nothing to impersonate).
    * If a HIGH-trust source (e.g. CoinGecko) itself lists a look-alike under
      the same ticker, it's treated as legit — we trust CoinGecko by ranking.
    * Honeypots / malicious bytecode are a different scam class needing
      simulation (e.g. honeypot.is) — out of scope here.

Examples:
    tools/scan_erc20_impersonators.py                 # scan whole db
    tools/scan_erc20_impersonators.py --chain 1       # one chain
    tools/scan_erc20_impersonators.py --high-only     # blue-chip spoofs only
    tools/scan_erc20_impersonators.py --trust-threshold 55   # stricter (>=1inch)

Outputs (under --out-dir, default build/impersonator_scan/):
    impersonators.json        structured findings
    impersonators.md          human-readable, grouped by chain + severity
    impersonators_addresses.txt   drop list: "<chain> <address>  # ..."
"""

import argparse
import json
import os
import sys
import pathlib
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_erc20_db as bdb  # noqa: E402  (reuse the real build loaders/priorities)
import erc20_text  # noqa: E402  (the DB's own name/symbol sanitizer)


def symbol_key(sym):
    """Compare tickers in the DB's sanitized form: the DB stores the folded
    symbol (tools/erc20_text.py, e.g. "USD₮0" -> "USDT0"), so a raw upstream
    ticker must be folded the same way or a folded collision is missed."""
    return (erc20_text.fold_ascii(sym) or str(sym)).upper()

CHAIN_NAMES = {
    1: "Ethereum", 10: "Optimism", 56: "BNB Chain", 130: "Unichain",
    137: "Polygon", 8453: "Base", 42161: "Arbitrum", 43114: "Avalanche",
    59144: "Linea", 999: "Hyperliquid",
}


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_trust_maps(trust_threshold):
    """Scan build/token_lists/ and return:
       trusted[(chain, SYMBOL)]   -> {addr_lower: best_priority}  (priority >= threshold)
       any_src[(chain, SYMBOL, addr_lower)] -> {source_stem: priority}
       meta[(chain, addr_lower)]  -> (name, symbol) from the highest-priority source
    """
    if not bdb.LISTS_DIR.exists():
        sys.exit(f"error: {bdb.LISTS_DIR} not found. Run `bash tools/fetch_token_lists.sh` first.")

    trusted = defaultdict(dict)
    any_src = defaultdict(dict)
    meta_prio = {}
    meta = {}
    n_rows = 0
    files = sorted(bdb.LISTS_DIR.glob("*.json"))
    if not files:
        sys.exit(f"error: no token lists in {bdb.LISTS_DIR}.")

    for p in files:
        stem = p.stem
        prio = bdb._source_priority(stem)
        try:
            rows = bdb.load_source(p)
        except Exception as e:  # noqa: BLE001
            print(f"  WARN: skipping {stem}: {e}", file=sys.stderr)
            continue
        for (cid, addr, name, sym, dec, source, canon) in rows:
            al = addr.lower()
            SYM = symbol_key(sym)
            n_rows += 1
            any_src[(cid, SYM, al)][stem] = prio
            if prio >= trust_threshold:
                cur = trusted[(cid, SYM)].get(al)
                if cur is None or prio > cur:
                    trusted[(cid, SYM)][al] = prio
            if meta_prio.get((cid, al), -1) < prio:
                meta_prio[(cid, al)] = prio
                meta[(cid, al)] = (name, sym)

    # Manual canonical additions bypass source consensus (highest trust).
    for m in bdb.MANUAL_ADDITIONS:
        cid = m["chain_id"]
        al = m["address"].lower()
        SYM = symbol_key(m["symbol"])
        trusted[(cid, SYM)][al] = 10_000
        meta.setdefault((cid, al), (m["name"], m["symbol"]))

    print(f"Loaded {len(files)} source lists, {n_rows} rows; "
          f"{len(trusted)} (chain,symbol) groups have a trusted address.")
    return trusted, any_src, meta


def canonical_for(trusted, cid, SYM):
    """Return list of (addr_lower, priority) for the trusted address(es) of a
    (chain, symbol), highest priority first."""
    d = trusted.get((cid, SYM))
    if not d:
        return []
    return sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))


def scan(db, trusted, any_src, meta, trust_threshold):
    findings = []
    for t in db:
        cid = t["chain_id"]
        al = t["address"].lower()
        SYM = symbol_key(t["symbol"])
        tset = trusted.get((cid, SYM), {})
        if not tset:
            continue                      # symbol unknown to curated lists -> nothing to impersonate
        if al in tset:
            continue                      # this exact address IS the/a canonical -> legit

        # Impersonator: claims a curated ticker at a non-vouched address.
        canon = canonical_for(trusted, cid, SYM)
        canon_addr, canon_prio = canon[0]
        canon_name = meta.get((cid, canon_addr), ("?", SYM))[0]
        vouchers = sorted(any_src.get((cid, SYM, al), {}).items(), key=lambda kv: -kv[1])
        voucher_names = [s for s, _ in vouchers] or ["<none / only db>"]
        tier = bdb._tier(SYM)
        severity = "HIGH" if tier < 99 else "MEDIUM"
        findings.append({
            "chain_id": cid,
            "address": t["address"],
            "symbol": t["symbol"],
            "name": t["name"],
            "severity": severity,
            "blue_chip_tier": (tier if tier < 99 else None),
            "impersonates_symbol": SYM,
            "canonical_address": bdb.to_checksum_address(canon_addr),
            "canonical_name": canon_name,
            "canonical_source_priority": canon_prio,
            "n_canonical_addresses": len(canon),
            "vouched_by": voucher_names,
        })
    findings.sort(key=lambda f: (f["severity"] != "HIGH", f["chain_id"],
                                 f["impersonates_symbol"], f["address"]))
    return findings


def write_reports(findings, db_count, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "impersonators.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
        fh.write("\n")

    with open(os.path.join(out_dir, "impersonators_addresses.txt"), "w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(f'{f["chain_id"]} {f["address"]}  # {f["severity"]} {f["symbol"]} '
                     f'"{f["name"]}" impersonates {f["impersonates_symbol"]} '
                     f'(real {f["canonical_address"]}) via {",".join(f["vouched_by"])}\n')

    high = [f for f in findings if f["severity"] == "HIGH"]
    lines = ["# Impersonator / look-alike tokens (offline symbol-collision scan)", ""]
    lines.append(f"Scanned {db_count} tokens. Found **{len(findings)}** impersonators "
                 f"(**{len(high)}** HIGH = blue-chip ticker spoofs).")
    lines.append("")
    lines.append("HIGH = the spoofed ticker is a blue-chip (stable/wrapped-native/major). "
                 "MEDIUM = a curated but non-blue-chip ticker. `vouched_by` shows which "
                 "source(s) carried the fake — usually `lifi` (least-curated).")
    lines.append("")
    by = defaultdict(list)
    for f in findings:
        by[f["chain_id"]].append(f)
    for cid in sorted(by):
        cname = CHAIN_NAMES.get(cid, f"chain {cid}")
        chf = by[cid]
        nh = sum(1 for f in chf if f["severity"] == "HIGH")
        lines.append(f"## {cname} (chain_id {cid}) — {len(chf)} ({nh} HIGH)")
        lines.append("")
        lines.append("| sev | fake address | symbol | name | impersonates | real address | vouched_by |")
        lines.append("|---|---|---|---|---|---|---|")
        esc = lambda s: str(s or "").replace("|", "\\|")
        for f in chf:
            lines.append("| {sev} | `{addr}` | {sym} | {name} | {imp} | `{real}` | {v} |".format(
                sev=f["severity"], addr=f["address"], sym=esc(f["symbol"]),
                name=esc(f["name"]), imp=esc(f["impersonates_symbol"]),
                real=f["canonical_address"], v=esc(",".join(f["vouched_by"]))))
        lines.append("")
    with open(os.path.join(out_dir, "impersonators.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return len(findings), len(high)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=None,
                    help="token JSON (default: secure/data/erc20.json under repo root)")
    ap.add_argument("--out-dir", default=None,
                    help="output dir (default: build/impersonator_scan/ under repo root)")
    ap.add_argument("--trust-threshold", type=int, default=45,
                    help="min source priority to count as 'trusted/canonical' "
                         "(default 45 = Gemini+; Li.Fi=10 is always untrusted). "
                         "Raise to 55 to require 1inch-or-better.")
    ap.add_argument("--chain", type=int, action="append", default=None,
                    help="only scan this chain_id (repeatable)")
    ap.add_argument("--high-only", action="store_true",
                    help="report only HIGH severity (blue-chip ticker spoofs)")
    args = ap.parse_args()

    root = repo_root()
    input_path = args.input or os.path.join(root, "secure", "data", "erc20.json")
    out_dir = args.out_dir or os.path.join(root, "build", "impersonator_scan")

    with open(input_path, "r", encoding="utf-8") as fh:
        db = json.load(fh)
    if args.chain:
        chains = set(args.chain)
        db = [t for t in db if t.get("chain_id") in chains]

    trusted, any_src, meta = build_trust_maps(args.trust_threshold)
    findings = scan(db, trusted, any_src, meta, args.trust_threshold)
    if args.high_only:
        findings = [f for f in findings if f["severity"] == "HIGH"]

    n, nh = write_reports(findings, len(db), out_dir)
    print(f"\nFound {n} impersonators ({nh} HIGH) among {len(db)} tokens.")
    print(f"Reports in {out_dir}:")
    print("  impersonators.md              (human-readable)")
    print("  impersonators.json            (structured)")
    print("  impersonators_addresses.txt   (drop list)")


if __name__ == "__main__":
    main()
