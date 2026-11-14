#!/usr/bin/env python3
"""
verify_erc20_decimals.py — cross-check every token in the ERC-20 metadata DBs
against its ON-CHAIN metadata (name / symbol / decimals + contract existence)
and correct the DB in place.

WHAT IT CHECKS
--------------
For each `{chain_id, address, name, symbol, decimals}` entry the tool reads the
contract's real state over public RPC and compares EVERY field:

  * decimals()  — `amount / 10^decimals` is the rendered magnitude; a DB value
                  LARGER than the chain value makes a full-balance drain show as
                  dust (FLUX/MEME shipped 18, chain 8 ⇒ 1e10 understatement; see
                  docs/VULN-erc20-decimals-inflation-flux-meme.md).
  * symbol()    — the identity string the user reads on the OLED.
  * name()      — the human-readable token name.
  * eth_getCode — if the code is `0x` the address is NOT a contract at all (a
                  wrong/typo address from the upstream token list); such an
                  entry can never match a real transfer and is REMOVED.

`tools/build_erc20_db.py` takes all of these VERBATIM from third-party token
lists (CoinGecko / Li.Fi / 1inch / Sushi / Uniswap) with no on-chain check.
This tool is that missing gate.

MODES
-----
  # verify ONE token (input: address + chain id) against on-chain, print a diff:
  python3 tools/verify_erc20_decimals.py --token 0xABC... --chain 1

  # report the whole DB (no writes), built-in public RPC pools:
  python3 tools/verify_erc20_decimals.py

  # correct BOTH DBs (update wrong fields, drop non-contracts) + next step:
  python3 tools/verify_erc20_decimals.py --fix --all-dbs
  cargo run -p dbgen        # regenerates ERC20_DB_ROOT(_E2E) in db_roots.rs

  # restrict which fields are compared/fixed (default: all four):
  python3 tools/verify_erc20_decimals.py --fix --fields decimals,symbol

  # use your own endpoints (overrides/extends the built-in pool):
  python3 tools/verify_erc20_decimals.py --init-rpc-config
  $EDITOR tools/erc20_rpc.json    # chain_id -> URL or [URLs]

ROBUSTNESS
----------
Each chain has a POOL of public RPC endpoints. A batch that hits a rate-limit
(HTTP 429/503), a forbidden/whitelist error, a timeout, or a connection drop is
transparently retried on the NEXT endpoint in the pool; rate-limited endpoints
cool down, hard-dead ones are dropped for the run. Batches a node rejects as
"too large" are split in half recursively down to single calls. Tokens still
unresolved after the first pass are retried in additional passes. A field is
only ever written — and a token is only ever removed — after a SECOND,
independent reading on a FRESH pool agrees (and, for `eth_call` fields, a bogus
selector probe does NOT return the same value, which would mean the contract is
a constant-returning fallback like the 2016 TheDAO rather than a real getter).

Stdlib only (urllib) — no pip deps, matching the other tools/ scripts.
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import erc20_text  # noqa: E402  (the ONE name/symbol sanitizer, shared with build_erc20_db.py)

REPO = Path(__file__).resolve().parent.parent
DB_PATH = REPO / "secure" / "data" / "erc20.json"
E2E_DB_PATH = REPO / "secure" / "data" / "erc20-e2e.json"
RPC_CONFIG_PATH = REPO / "tools" / "erc20_rpc.json"

# ERC-20 getter selectors  ->  keccak256("<sig>")[:4]
DECIMALS_SELECTOR = "0x313ce567"  # decimals()
NAME_SELECTOR = "0x06fdde03"      # name()
SYMBOL_SELECTOR = "0x95d89b41"    # symbol()

# A selector no real ERC-20 implements. A standards-compliant token REVERTS on
# it (eth_call -> "0x"); a non-standard contract with a constant-returning
# fallback (e.g. the 2016 TheDAO) returns the SAME word it returns for the real
# getter. If a probe selector yields the same value, the reading is a fallback
# artifact, NOT real metadata — we refuse to trust it.
PROBE_SELECTOR = "0xdeadbeef"

# bundle.rs MAX_DISPLAY_DECIMALS: the on-device verifier REJECTS decimals > 36
# (a rejected entry fails safe to AddrHex/raw, it does not mis-render).
MAX_DISPLAY_DECIMALS = 36
MAX_U8 = 255  # dbgen stores decimals as a single byte

# Strings written back from chain go through tools/erc20_text.py, the same
# sanitizer build_erc20_db.py uses: every written name/symbol is 1..=64 bytes of
# printable ASCII (the device rule in tx/src/erc20/bundle.rs, which dbgen
# enforces). An on-chain name/symbol that has no safe ASCII form (Cyrillic or
# Greek look-alikes, CJK, emoji, an over-long symbol) cannot be written; under
# --fix that row is REMOVED from the DB instead (the device then shows the raw
# amount and the address as UNVERIFIED). Comparing DB vs chain is done on the
# sanitized form so an already-folded row ("USDT0" for on-chain "USD₮0") is
# not reported as a mismatch.
DROP_ROW = object()  # writable_fix(): the on-chain value cannot be stored

CHAIN_NAMES = {
    1: "ethereum", 10: "optimism", 56: "bnb-chain", 130: "unichain",
    137: "polygon", 999: "hyperevm", 8453: "base", 42161: "arbitrum",
    43114: "avalanche", 59144: "linea",
}

# Built-in pools of keyless public RPC endpoints, multiple per chain so a
# rate-limited or dead node fails over to the next. Dead/whitelist-restricted
# endpoints are dropped automatically at run time.
DEFAULT_RPC_POOL = {
    1: ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com",
        "https://eth-mainnet.public.blastapi.io", "https://eth.drpc.org",
        "https://eth.merkle.io", "https://1rpc.io/eth", "https://rpc.mevblocker.io"],
    10: ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io",
         "https://optimism.llamarpc.com", "https://op-mainnet.public.blastapi.io",
         "https://optimism.drpc.org", "https://1rpc.io/op"],
    56: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org",
         "https://bsc-dataseed1.defibit.io", "https://bsc-dataseed1.ninicoin.io",
         "https://binance.llamarpc.com", "https://bsc.drpc.org", "https://1rpc.io/bnb"],
    130: ["https://unichain-rpc.publicnode.com", "https://mainnet.unichain.org",
          "https://unichain.drpc.org", "https://0xrpc.io/uni"],
    137: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com",
          "https://polygon.llamarpc.com", "https://polygon-mainnet.public.blastapi.io",
          "https://polygon.drpc.org", "https://1rpc.io/matic"],
    999: ["https://rpc.hyperliquid.xyz/evm", "https://hyperliquid.drpc.org",
          "https://rpc.hypurrscan.io"],
    8453: ["https://base-rpc.publicnode.com", "https://mainnet.base.org",
           "https://base.llamarpc.com", "https://base-mainnet.public.blastapi.io",
           "https://base.drpc.org", "https://1rpc.io/base"],
    42161: ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc",
            "https://arbitrum.llamarpc.com", "https://arbitrum-one.public.blastapi.io",
            "https://arbitrum.drpc.org", "https://1rpc.io/arb"],
    43114: ["https://avalanche-c-chain-rpc.publicnode.com",
            "https://api.avax.network/ext/bc/C/rpc", "https://avalanche.drpc.org",
            "https://avax.meowrpc.com", "https://1rpc.io/avax"],
    59144: ["https://linea-rpc.publicnode.com", "https://rpc.linea.build",
            "https://linea.drpc.org", "https://1rpc.io/linea"],
}


def rel(p):
    """Path relative to the repo for display, or the bare path if outside it."""
    try:
        return Path(p).resolve().relative_to(REPO)
    except ValueError:
        return Path(p)


# --------------------------------------------------------------------------- #
# RPC config
# --------------------------------------------------------------------------- #
def init_rpc_config():
    template = {"_comment": "chain_id -> JSON-RPC URL or list of URLs. Empty = use "
                            "built-in public pool. Do not commit secret RPC keys."}
    template.update({str(cid): "" for cid in sorted(DEFAULT_RPC_POOL)})
    if RPC_CONFIG_PATH.exists():
        print(f"refusing to overwrite existing {rel(RPC_CONFIG_PATH)}", file=sys.stderr)
        return 1
    RPC_CONFIG_PATH.write_text(json.dumps(template, indent=2) + "\n")
    print(f"wrote template {rel(RPC_CONFIG_PATH)} — fill in URLs (or leave blank "
          f"to use the built-in public pool)")
    return 0


def load_pools(path):
    """chain_id -> [urls]. Starts from the built-in pool; config entries (str or
    list) PREPEND the user's endpoints for that chain."""
    pools = {cid: list(urls) for cid, urls in DEFAULT_RPC_POOL.items()}
    cfg = {}
    if path.exists():
        raw = json.loads(path.read_text())
        for k, v in raw.items():
            try:
                cid = int(k)
            except ValueError:
                continue
            urls = [v] if isinstance(v, str) else list(v)
            urls = [u for u in urls if u]
            if urls:
                cfg[cid] = urls
    for k, v in os.environ.items():
        if k.startswith("ERC20_RPC_") and v:
            try:
                cfg[int(k[len("ERC20_RPC_"):])] = [u for u in v.split(",") if u]
            except ValueError:
                pass
    for cid, urls in cfg.items():
        existing = pools.get(cid, [])
        pools[cid] = urls + [u for u in existing if u not in urls]
    return pools


# --------------------------------------------------------------------------- #
# field abstraction — each DB column maps to an on-chain read
# --------------------------------------------------------------------------- #
def decode_decimals(result_hex):
    """Decode a uint return into a decimals int. ABI puts the value in the FIRST
    32-byte word; some non-standard contracts (Curve LP proxies, etc.) return
    extra trailing words, so we must NOT int-parse the whole blob (that yields a
    huge number that we'd wrongly reject). Take the first word only."""
    if not result_hex:
        return None
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if not h:
        return None
    word = h[:64] if len(h) >= 64 else h  # first 32-byte word (or short return)
    try:
        v = int(word, 16)
    except ValueError:
        return None
    return v if 0 <= v <= MAX_U8 else None  # >u8 can't be stored → unresolved


def _clean_str(s):
    """Raw on-chain string for reporting: control characters stripped,
    whitespace collapsed, Unicode kept (tools/erc20_text.basic_clean).
    '' -> None. The DB form is erc20_text.clean_name / clean_symbol."""
    return erc20_text.basic_clean(s)


def _db_form(field, oc_val):
    """The value the DB would store for an on-chain reading, or None."""
    if field == "symbol":
        return erc20_text.clean_symbol(oc_val)
    if field == "name":
        return erc20_text.clean_name(oc_val)
    return oc_val


def decode_string(result_hex):
    """Decode an ERC-20 name()/symbol() return. Handles BOTH the ABI-dynamic
    `string` encoding (offset|length|data) AND the legacy fixed `bytes32`
    encoding (MKR, original DAI-era tokens). Returns a cleaned str or None."""
    if not result_hex:
        return None
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if not h:
        return None  # "0x" -> revert
    try:
        b = bytes.fromhex(h if len(h) % 2 == 0 else "0" + h)
    except ValueError:
        return None
    # Dynamic string: head word is the offset (canonically 0x20), then length,
    # then the UTF-8 bytes.
    if len(b) >= 64:
        offset = int.from_bytes(b[:32], "big")
        if offset == 32 and len(b) >= 64:
            length = int.from_bytes(b[32:64], "big")
            if 0 < length <= len(b) - 64:
                try:
                    return _clean_str(b[64:64 + length].decode("utf-8", "strict"))
                except UnicodeDecodeError:
                    return _clean_str(b[64:64 + length].decode("latin-1", "replace"))
    # Fixed bytes32: a right-padded string in a single word.
    if len(b) == 32:
        raw = b.rstrip(b"\x00")
        try:
            return _clean_str(raw.decode("utf-8", "strict"))
        except UnicodeDecodeError:
            return _clean_str(raw.decode("latin-1", "replace"))
    # Some tokens return a bare short string (non-conformant). Best effort.
    if 0 < len(b) < 32:
        try:
            return _clean_str(b.decode("utf-8", "strict"))
        except UnicodeDecodeError:
            return None
    return None


def decode_code(result_hex):
    """eth_getCode result. Returns True if the address has bytecode, False if it
    is `0x` (an EOA / nonexistent contract), None if unreadable."""
    if result_hex is None:
        return None
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    return len(h) > 0  # "0x" -> "" -> False (no code)


# field -> (json-rpc method, eth_call selector or None, decoder)
FIELDS = {
    "code": ("eth_getCode", None, decode_code),
    "decimals": ("eth_call", DECIMALS_SELECTOR, decode_decimals),
    "name": ("eth_call", NAME_SELECTOR, decode_string),
    "symbol": ("eth_call", SYMBOL_SELECTOR, decode_string),
}
# fields that are actual DB columns we compare/fix (code is existence, special)
COMPARABLE = ("decimals", "symbol", "name")


def build_params(method, addr, selector):
    if method == "eth_getCode":
        return [addr, "latest"]
    return [{"to": addr, "data": selector}, "latest"]


# --------------------------------------------------------------------------- #
# RPC layer with endpoint failover
# --------------------------------------------------------------------------- #
class RpcError(Exception):
    def __init__(self, cat, msg):
        super().__init__(msg)
        self.cat = cat          # 'ratelimit' | 'toobig' | 'fatal' | 'transient'


class BatchTooBig(Exception):
    pass


class AllEndpointsDown(Exception):
    pass


class Pool:
    """Thread-safe rotating endpoint pool with per-endpoint cooldown / kill."""

    def __init__(self, urls):
        self.urls = list(urls)
        self.lock = threading.Lock()
        self.cool = {}          # url -> monotonic deadline
        self.dead = set()
        self.rr = 0

    def pick(self):
        with self.lock:
            n = len(self.urls)
            now = time.monotonic()
            for _ in range(n):
                url = self.urls[self.rr % n]
                self.rr += 1
                if url in self.dead:
                    continue
                if self.cool.get(url, 0) > now:
                    continue
                return url, 0.0
            live = [u for u in self.urls if u not in self.dead]
            if not live:
                return None, -1.0
            wait = min(self.cool.get(u, 0) for u in live) - now
            return None, max(wait, 0.5)

    def cooldown(self, url, secs):
        with self.lock:
            self.cool[url] = time.monotonic() + secs

    def kill(self, url):
        with self.lock:
            self.dead.add(url)

    def status(self):
        with self.lock:
            return len(self.urls) - len(self.dead), len(self.dead)


def rpc_batch(url, calls, timeout, method, selector):
    """One JSON-RPC batch of `method` calls. `calls` is [(id, addr), ...].
    Returns id->raw-result-hex-or-None ("0x" is KEPT, it is meaningful for
    eth_getCode), or raises RpcError(category) on a whole-batch failure."""
    payload = [
        {"jsonrpc": "2.0", "id": cid, "method": method,
         "params": build_params(method, addr, selector)}
        for cid, addr in calls
    ]
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 erc20-meta-verify/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (429, 503, 509, 502):
            raise RpcError("ratelimit", f"HTTP {e.code}")
        if e.code in (413, 400):
            raise RpcError("toobig", f"HTTP {e.code}")
        if e.code in (401, 403, 404, 405):
            raise RpcError("fatal", f"HTTP {e.code}")
        raise RpcError("transient", f"HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        raise RpcError("transient", str(e))

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RpcError("transient", f"bad json: {raw[:100]!r}")

    if isinstance(data, dict):  # node rejected the batch with one error object
        msg = str(data.get("error", data)).lower()
        if any(s in msg for s in ("too large", "batch", "exceed", "limit", "many")):
            raise RpcError("toobig", msg[:120])
        if any(s in msg for s in ("whitelist", "not allowed", "unauthorized", "api key")):
            raise RpcError("fatal", msg[:120])
        raise RpcError("transient", msg[:120])

    out = {}
    err_msgs = []
    for item in data:
        rid = item.get("id")
        if "result" in item and item["result"] not in (None, ""):
            out[rid] = item["result"]          # keep "0x" verbatim
        else:
            out[rid] = None
            if "error" in item:
                err_msgs.append(str(item["error"]).lower())
    for cid, _ in calls:
        out.setdefault(cid, None)
    # if EVERY element failed and the errors look like rate-limit/whitelist, the
    # endpoint is the problem — fail over instead of marking real tokens dead.
    if err_msgs and all(v is None for v in out.values()):
        joined = " ".join(err_msgs)
        if any(s in joined for s in ("limit", "many", "exceed", "capacity")):
            raise RpcError("ratelimit", joined[:120])
        if any(s in joined for s in ("whitelist", "not allowed", "unauthorized", "api key")):
            raise RpcError("fatal", joined[:120])
    return out


def batch_with_failover(pool, calls, timeout, max_attempts, method, selector):
    attempts = 0
    while True:
        url, wait = pool.pick()
        if url is None:
            if wait < 0:
                raise AllEndpointsDown()
            time.sleep(min(wait, 5.0))
            continue
        try:
            return rpc_batch(url, calls, timeout, method, selector)
        except BatchTooBig:
            raise
        except RpcError as e:
            if e.cat == "toobig":
                raise BatchTooBig()
            if e.cat == "ratelimit":
                pool.cooldown(url, 20.0)
            elif e.cat == "fatal":
                pool.kill(url)
            else:
                pool.cooldown(url, 4.0)
            attempts += 1
            if attempts >= max_attempts:
                raise AllEndpointsDown()


# --------------------------------------------------------------------------- #
# per-chain resolution of one field
# --------------------------------------------------------------------------- #
def resolve_field(cid, items, pool, batch_size, workers, timeout, progress, field):
    """items: list of (global_index, address). Returns {global_index: decoded|None}
    for the on-chain `field`."""
    method, selector, decode = FIELDS[field]
    results = {}

    def do(calls):
        try:
            res = batch_with_failover(pool, calls, timeout,
                                      max_attempts=len(pool.urls) * 4 + 8,
                                      method=method, selector=selector)
        except BatchTooBig:
            if len(calls) == 1:
                return {calls[0][0]: None}
            mid = len(calls) // 2
            r = do(calls[:mid])
            r.update(do(calls[mid:]))
            return r
        except AllEndpointsDown:
            return {c: None for c, _ in calls}
        return {c: decode(res.get(c)) for c, _ in calls}

    batches = [items[b:b + batch_size] for b in range(0, len(items), batch_size)]
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(do, b): b for b in batches}
        for fut in as_completed(futs):
            results.update(fut.result())
            done += 1
            live, dead = pool.status()
            progress(cid, field, done, len(batches), live, dead)
    return results


def resolve_field_multipass(cid, name, toks, urls, field, args):
    """Resolve `field` for every (idx, token) in toks, with straggler retry
    passes on a fresh pool. Returns {idx: decoded|None}."""
    pool = Pool(urls)

    def progress(c, fld, done, total, live, dead):
        print(f"\r  chain {c:6d} {name:12s} {fld:8s}: {done}/{total} batches  "
              f"[{live} live / {dead} dead endpoints]   ", end="", file=sys.stderr)

    idx_addr = [(idx, t["address"]) for idx, t in toks]
    res = resolve_field(cid, idx_addr, pool, args.batch_size, args.workers,
                        args.timeout, progress, field)
    for p in range(args.passes - 1):
        pending = [(idx, t["address"]) for idx, t in toks if res.get(idx) is None]
        if not pending:
            break
        print(f"\n  chain {cid:6d} {name:12s} {field:8s}: retry pass {p + 2} "
              f"on {len(pending)} unresolved", file=sys.stderr)
        pool2 = Pool(urls)
        bs = max(10, args.batch_size // (2 * (p + 1)))
        res.update(resolve_field(cid, pending, pool2, bs, max(2, args.workers // 2),
                                 args.timeout, progress, field))
    resolved = sum(1 for idx, _ in toks if res.get(idx) is not None)
    print(f"\n  chain {cid:6d} {name:12s} {field:8s}: resolved {resolved}/{len(toks)}",
          file=sys.stderr)
    return res


# --------------------------------------------------------------------------- #
# comparison
# --------------------------------------------------------------------------- #
def field_matches(field, db_val, oc_val):
    """True if the on-chain value AGREES with the DB value for `field`."""
    if oc_val is None:
        return True  # unresolved -> not a mismatch (left untouched)
    if field == "decimals":
        return oc_val == db_val
    if field == "symbol":
        # symbols are short identifiers; compare case-sensitively in DB form
        return str(db_val) == _db_form(field, oc_val)
    if field == "name":
        # names vary cosmetically across lists; ignore pure case/whitespace
        a = (_clean_str(str(db_val)) or "").casefold()
        b = (_db_form(field, oc_val) or "").casefold()
        return a == b
    return True


def writable_fix(field, oc_val):
    """The value we would WRITE for `field`; DROP_ROW if the on-chain
    name/symbol has no device-verifiable form (the row is removed under
    --fix); None if the reading is unusable (left as-is)."""
    if oc_val is None:
        return None
    if field == "decimals":
        return oc_val if 0 <= oc_val <= MAX_U8 else None
    if field in ("symbol", "name"):
        v = _db_form(field, oc_val)
        return DROP_ROW if v is None else v
    return None


# --------------------------------------------------------------------------- #
# whole-DB verification
# --------------------------------------------------------------------------- #
def verify_db(db, pools, args):
    """Resolve all requested fields + code for every token. Returns:
      issues:    list of (idx, token, field, db_val, oc_val)  -- field mismatches
      dead:      list of (idx, token)                          -- code == 0x
      unresolved: list of (idx, token, field)                  -- couldn't read
    Mutates nothing."""
    by_chain = {}
    for i, t in enumerate(db):
        by_chain.setdefault(t["chain_id"], []).append((i, t))

    fields = list(args.fields)
    want_code = "code" in args.checks
    oc = {f: {} for f in fields}     # field -> {idx: val|None}
    code_res = {}                    # idx -> True/False/None

    for cid in sorted(by_chain):
        if args.chains and cid not in args.chains:
            continue
        toks = by_chain[cid]
        urls = pools.get(cid)
        name = CHAIN_NAMES.get(cid, str(cid))
        if not urls:
            print(f"  chain {cid:6d} {name:12s}: SKIP (no endpoints), {len(toks)} tokens",
                  file=sys.stderr)
            continue
        if want_code:
            code_res.update(resolve_field_multipass(cid, name, toks, urls, "code", args))
        for f in fields:
            # don't waste reads on dead contracts for the other fields
            live = [(idx, t) for idx, t in toks
                    if not want_code or code_res.get(idx) is not False]
            oc[f].update(resolve_field_multipass(cid, name, live, urls, f, args))

    issues, dead, unresolved = [], [], []
    seen = set()
    for i, t in enumerate(db):
        if args.chains and t["chain_id"] not in args.chains:
            continue
        if want_code and code_res.get(i) is False:
            dead.append((i, t))
            continue  # dead token: its other fields are moot
        for f in fields:
            ocv = oc[f].get(i)
            if ocv is None:
                unresolved.append((i, t, f))
            elif not field_matches(f, t[f], ocv):
                issues.append((i, t, f, t[f], ocv))
                seen.add(i)
    return issues, dead, unresolved


def report(label, total, issues, dead, unresolved):
    print(f"\n========== {label} ==========")
    print(f"  tokens         : {total}")
    print(f"  field MISMATCH : {len(issues)}")
    print(f"  NO-CODE (drop) : {len(dead)}")
    print(f"  unresolved     : {len(unresolved)}  (left untouched)")

    by_field = {}
    for _, _, f, _, _ in issues:
        by_field[f] = by_field.get(f, 0) + 1
    if by_field:
        print("  by field       : " + ", ".join(f"{k}={v}" for k, v in sorted(by_field.items())))

    # decimals magnitude-hiding (DB > chain) is the drain-risk class — surface it
    dec_hide = sorted([m for m in issues if m[2] == "decimals" and m[3] > m[4]],
                      key=lambda m: m[3] - m[4], reverse=True)
    if dec_hide:
        print(f"  decimals magnitude-HIDING (DB>chain, drain risk): {len(dec_hide)}")
        for idx, t, _f, dbd, ocv in dec_hide[:40]:
            flag = "  <-- >MAX_DISPLAY_DECIMALS" if ocv > MAX_DISPLAY_DECIMALS else ""
            print(f"    chain {t['chain_id']:<6} {t['symbol']:<14} {t['address']}  "
                  f"DB={dbd:<3} chain={ocv:<3} hides 1e{dbd - ocv}{flag}")
        if len(dec_hide) > 40:
            print(f"    ... and {len(dec_hide) - 40} more")

    for fld in ("symbol", "name"):
        rows = [m for m in issues if m[2] == fld]
        for idx, t, _f, dbd, ocv in rows[:30]:
            print(f"    chain {t['chain_id']:<6} {fld:<8} {t['address']}  "
                  f"DB={dbd!r}  chain={ocv!r}")
        if len(rows) > 30:
            print(f"    ... and {len(rows) - 30} more {fld} mismatches")

    if dead:
        print(f"  NO-CODE addresses (not a contract — will be REMOVED on --fix):")
        for idx, t in dead[:30]:
            print(f"    chain {t['chain_id']:<6} {t['symbol']:<14} {t['address']}")
        if len(dead) > 30:
            print(f"    ... and {len(dead) - 30} more")


# --------------------------------------------------------------------------- #
# confirmation (second independent reading before any write/removal)
# --------------------------------------------------------------------------- #
def confirm_issues(issues, pools, args):
    """Re-query every would-be-changed field on a FRESH pool and require the
    second reading to agree (and a bogus-selector probe NOT to collide) before
    we overwrite. Returns (confirmed, conflicts)."""
    by_cf = {}
    for tup in issues:                       # (idx, t, field, dbv, ocv)
        by_cf.setdefault((tup[1]["chain_id"], tup[2]), []).append(tup)
    confirmed, conflicts = [], []
    for (cid, field), tups in sorted(by_cf.items()):
        urls = pools.get(cid)
        if not urls:
            conflicts.extend(tups)
            continue
        idx_addr = [(idx, t["address"]) for idx, t, _f, _d, _o in tups]
        print(f"\r  confirming {len(idx_addr)} {field} changes on chain {cid} "
              f"({CHAIN_NAMES.get(cid, cid)})...        ", end="", file=sys.stderr)
        bs, wk = max(10, args.batch_size // 2), max(2, args.workers // 2)
        nop = lambda *a: None
        res = resolve_field(cid, idx_addr, Pool(urls), bs, wk, args.timeout, nop, field)
        # bogus-selector probe (eth_call fields only): a constant-returning
        # fallback yields the same decoded value here; a real getter reverts.
        probe = {}
        if FIELDS[field][0] == "eth_call":
            method, _sel, decode = FIELDS[field]
            probe = resolve_field_probe(cid, idx_addr, Pool(urls), bs, wk,
                                        args.timeout, method, decode)
        for idx, t, _f, dbv, ocv in tups:
            again = res.get(idx)
            agrees = again is not None and field_matches(field, dbv, again) is False \
                and field_value_eq(field, again, ocv)
            if agrees and probe.get(idx) != ocv and writable_fix(field, ocv) is not None:
                confirmed.append((idx, t, field, dbv, ocv))
            else:
                tag = again if probe.get(idx) != ocv else f"{again}(probe-collision)"
                conflicts.append((idx, t, field, dbv, tag))
    print(file=sys.stderr)
    return confirmed, conflicts


def field_value_eq(field, a, b):
    """Do two on-chain readings of `field` agree?"""
    if a is None or b is None:
        return False
    if field == "name":
        return (a or "").casefold() == (b or "").casefold()
    return a == b


def resolve_field_probe(cid, items, pool, batch_size, workers, timeout, method, decode):
    """Like resolve_field but with the bogus PROBE_SELECTOR (eth_call only)."""
    results = {}

    def do(calls):
        try:
            res = batch_with_failover(pool, calls, timeout,
                                      max_attempts=len(pool.urls) * 4 + 8,
                                      method=method, selector=PROBE_SELECTOR)
        except BatchTooBig:
            if len(calls) == 1:
                return {calls[0][0]: None}
            mid = len(calls) // 2
            r = do(calls[:mid])
            r.update(do(calls[mid:]))
            return r
        except AllEndpointsDown:
            return {c: None for c, _ in calls}
        return {c: decode(res.get(c)) for c, _ in calls}

    batches = [items[b:b + batch_size] for b in range(0, len(items), batch_size)]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed({ex.submit(do, b) for b in batches}):
            results.update(fut.result())
    return results


def confirm_dead(dead, pools, args):
    """Re-read eth_getCode for every would-be-removed token; only confirm those
    that are STILL `0x` on the second reading. Returns (confirmed, conflicts)."""
    by_chain = {}
    for idx, t in dead:
        by_chain.setdefault(t["chain_id"], []).append((idx, t))
    confirmed, conflicts = [], []
    for cid, tups in sorted(by_chain.items()):
        urls = pools.get(cid)
        if not urls:
            conflicts.extend(tups)
            continue
        idx_addr = [(idx, t["address"]) for idx, t in tups]
        print(f"\r  confirming {len(idx_addr)} removals on chain {cid} "
              f"({CHAIN_NAMES.get(cid, cid)})...        ", end="", file=sys.stderr)
        bs, wk = max(10, args.batch_size // 2), max(2, args.workers // 2)
        res = resolve_field(cid, idx_addr, Pool(urls), bs, wk, args.timeout,
                            lambda *a: None, "code")
        for idx, t in tups:
            if res.get(idx) is False:      # still no code on a 2nd, fresh reading
                confirmed.append((idx, t))
            else:
                conflicts.append((idx, t))
    print(file=sys.stderr)
    return confirmed, conflicts


# --------------------------------------------------------------------------- #
# DB I/O
# --------------------------------------------------------------------------- #
def write_db(path, db):
    body = [
        "  " + json.dumps(
            {"chain_id": r["chain_id"], "address": r["address"],
             "name": r["name"], "symbol": r["symbol"], "decimals": r["decimals"]},
            ensure_ascii=False, separators=(", ", ": "))
        for r in db
    ]
    path.write_text("[\n" + ",\n".join(body) + "\n]\n", encoding="utf-8")


def process_db(path, pools, args):
    print(f"\n### verifying {rel(path)} ###", file=sys.stderr)
    db = json.loads(path.read_text())
    issues, dead, unresolved = verify_db(db, pools, args)
    report(str(rel(path)), len(db), issues, dead, unresolved)

    if args.report:
        rp = args.report.parent / f"{path.stem}.{args.report.name}"
        rp.write_text(json.dumps({
            "tokens": len(db),
            "mismatched": [{"chain_id": t["chain_id"], "address": t["address"],
                            "symbol": t["symbol"], "field": f,
                            "db": d, "onchain": o} for _, t, f, d, o in issues],
            "no_code": [{"chain_id": t["chain_id"], "address": t["address"],
                         "symbol": t["symbol"]} for _, t in dead],
            "unresolved": [{"chain_id": t["chain_id"], "address": t["address"],
                            "symbol": t["symbol"], "field": f} for _, t, f in unresolved],
        }, indent=2) + "\n")
        print(f"  report -> {rp}")

    if not args.fix:
        return len(issues) + len(dead), len(unresolved)

    changed = 0
    unstorable_idx = set()
    # 1) confirm + apply field corrections
    if issues:
        confirmed, conflicts = confirm_issues(issues, pools, args)
        fixed = 0
        for idx, t, field, _d, ocv in confirmed:
            fix = writable_fix(field, ocv)
            if fix is DROP_ROW:
                unstorable_idx.add(idx)
                print(f"  DROP chain {t['chain_id']} {t['address']}: on-chain {field} "
                      f"{ocv!r} has no device-verifiable ASCII form")
                continue
            db[idx][field] = fix
            fixed += 1
        changed += fixed
        print(f"  FIXED {fixed} field(s) (2-reading-confirmed)")
        if conflicts:
            print(f"  {len(conflicts)} field change(s) NOT applied (2nd reading "
                  f"disagreed / unwritable) — left as-is:")
            for idx, t, field, dbv, again in conflicts[:20]:
                print(f"    chain {t['chain_id']:<6} {field:<8} {t['address']}  "
                      f"DB={dbv!r} 2nd-read={again!r}")
            if len(conflicts) > 20:
                print(f"    ... and {len(conflicts) - 20} more")

    # 2) confirm + remove non-contracts
    removed_idx = set()
    if dead and "code" in args.checks:
        confirmed_dead, dead_conflicts = confirm_dead(dead, pools, args)
        removed_idx = {idx for idx, _t in confirmed_dead}
        print(f"  REMOVING {len(confirmed_dead)} non-contract entries "
              f"(eth_getCode == 0x, 2-reading-confirmed)")
        if dead_conflicts:
            print(f"  {len(dead_conflicts)} removals NOT applied (had code on 2nd "
                  f"reading) — left as-is")

    if unstorable_idx:
        removed_idx |= unstorable_idx
        changed += len(unstorable_idx)
    if removed_idx:
        changed += len(removed_idx - unstorable_idx)
        db = [r for i, r in enumerate(db) if i not in removed_idx]

    if changed:
        write_db(path, db)
        print(f"  WROTE {rel(path)}  ({len(db)} tokens; "
              f"{changed} corrections incl. {len(removed_idx)} removals)")
    return changed, len(unresolved)


# --------------------------------------------------------------------------- #
# single-token mode
# --------------------------------------------------------------------------- #
def verify_single(addr, cid, pools, args):
    urls = pools.get(cid)
    name = CHAIN_NAMES.get(cid, str(cid))
    if not urls:
        print(f"no RPC endpoints configured for chain {cid}", file=sys.stderr)
        return 2
    addr = addr if addr.startswith("0x") else "0x" + addr

    # find DB entry (any DB), if present
    db_entry, db_src = None, None
    for p in (DB_PATH, E2E_DB_PATH):
        if not p.exists():
            continue
        for t in json.loads(p.read_text()):
            if t["chain_id"] == cid and t["address"].lower() == addr.lower():
                db_entry, db_src = t, rel(p)
                break
        if db_entry:
            break

    pool = Pool(urls)
    nop = lambda *a: None
    one = [(0, addr)]
    code = resolve_field(cid, one, pool, 1, 1, args.timeout, nop, "code").get(0)
    oc = {f: resolve_field(cid, one, Pool(urls), 1, 1, args.timeout, nop, f).get(0)
          for f in ("decimals", "symbol", "name")}

    print(f"\n== {addr}  on chain {cid} ({name}) ==")
    if code is None:
        print("  eth_getCode  : UNREADABLE (all endpoints failed)")
    elif code is False:
        print("  eth_getCode  : 0x  -> NOT A CONTRACT (wrong/typo address)")
    else:
        print("  eth_getCode  : present (contract exists)")

    if db_entry:
        print(f"  DB entry     : {db_src}")
    else:
        print("  DB entry     : (not in any shipped DB)")

    for f in ("name", "symbol", "decimals"):
        ocv = oc[f]
        dbv = db_entry[f] if db_entry else None
        if ocv is None:
            verdict = "unreadable"
        elif db_entry is None:
            verdict = "no DB entry to compare"
        elif field_matches(f, dbv, ocv):
            verdict = "OK"
        else:
            verdict = "*** MISMATCH ***"
        print(f"  {f:8s}     : on-chain={ocv!r:<28} DB={dbv!r:<24} {verdict}")
    return 0


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--init-rpc-config", action="store_true")
    ap.add_argument("--rpc-config", type=Path, default=RPC_CONFIG_PATH)
    ap.add_argument("--db", type=Path, default=DB_PATH)
    ap.add_argument("--all-dbs", action="store_true",
                    help="process both erc20.json and erc20-e2e.json")
    ap.add_argument("--token", type=str, default=None,
                    help="verify a SINGLE token by address (use with --chain)")
    ap.add_argument("--chain", type=int, default=None,
                    help="chain id for --token single-token mode")
    ap.add_argument("--fields", type=str, default="decimals,symbol,name",
                    help="comma list of DB columns to compare/fix "
                         "(decimals,symbol,name); default all")
    ap.add_argument("--no-code-check", action="store_true",
                    help="do NOT eth_getCode / remove non-contract entries")
    ap.add_argument("--batch-size", type=int, default=60)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--passes", type=int, default=3,
                    help="resolution passes; later passes retry stragglers (default 3)")
    ap.add_argument("--chains", type=str, default="")
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    if args.init_rpc_config:
        return init_rpc_config()

    args.fields = [f.strip() for f in args.fields.split(",")
                   if f.strip() in COMPARABLE]
    args.checks = set(args.fields)
    if not args.no_code_check:
        args.checks.add("code")

    pools = load_pools(args.rpc_config)

    if args.token:
        if args.chain is None:
            print("--token requires --chain <id>", file=sys.stderr)
            return 2
        return verify_single(args.token, args.chain, pools, args)

    args.chains = {int(c) for c in args.chains.split(",") if c.strip()} if args.chains else None

    paths = [args.db]
    if args.all_dbs:
        paths = [DB_PATH, E2E_DB_PATH]

    total_changed, total_unres = 0, 0
    for p in paths:
        c, u = process_db(p, pools, args)
        total_changed += c
        total_unres += u

    verb = "applied" if args.fix else "pending"
    print(f"\n==== TOTAL: {total_changed} corrections {verb}, {total_unres} unresolved ====")
    if args.fix and total_changed:
        print("NEXT: cargo run -p dbgen   # regenerate ERC20_DB_ROOT(_E2E) in db_roots.rs")
    if total_unres:
        print(f"WARNING: {total_unres} field(s) could not be resolved on-chain and were "
              f"left as-is. Re-run to retry them.")
    return 1 if (total_changed and not args.fix) else 0


if __name__ == "__main__":
    sys.exit(main())
