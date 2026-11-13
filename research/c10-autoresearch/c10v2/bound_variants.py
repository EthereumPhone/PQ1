#!/usr/bin/env python3
"""bound_variants.py — the project's machine-checked EUF bound, instantiated per
v2 format variant (research, #1155; 2026-11-13).

The EasyCrypt artifact (contracts/verification/easycrypt/c10-port, split tree)
proves two explicit numerical bounds for C10 in a classical ideal-oracle byte
game:

  * ordinary game:  WotsPoolNumericalBound.physical_byte_wots_pool_euf_bound
                    (evaluated by tools/wots_pool_examples.py);
  * FI wrapper (two signs + verify, the shape the device runs):
                    WrapperRefinedNumericalBound (tools/wrapper_nonnode_examples.py).

Every constant in those formulas is either a proved hash-call budget or a proved
universe size. This script re-derives each constant from the parameters, so the
same formula can be evaluated for a variant:

  T      target sum            -> A = |{d in [0,7]^43 : sum d = T}|   (encoding term)
  layers (h0, h1)              -> build(h) = 303*2^h - 1               (DomainLayerCost:
                                  merkle build = q+155135 at h = 9; per-layer sign
                                  = build + 1 + 305 + (303 + h); recover = 303 + h)
                                  keygen = build(h_top)                (FullSessionCost: 155135)
                                  WOTS cut universe = 8 * 301 * (2^18 + 2^h_top)
                                                                       (WotsCoordinateUniverse:
                                                                        2^18 + 512 keys, 43*7 cuts)
  FORS universe 2^18 * 12 * 2^11, coverage (18-bit / 11-bit / 12 trees), verify 771,
  exceptional R = qr + 2qs + 771, accepted-call caps: unchanged by every variant here.

ANCHOR: with the v1 parameters the derived formulas must reproduce the two
project tools' exact rationals term by term; the script asserts that before
printing anything else.

SCOPE (read before quoting): the theorems are proved for v1's byte format. For any
v2 variant, draft 0.3 included, this is the same formula with re-derived
constants, i.e. what the bound becomes IF the proof ports with the same charge
structure. It is not a proof about v2. prf2 changes no constant: in the ideal
model the two halves of one uniform 256-bit output are independent uniform
128-bit secrets, so the private table has the same distribution (argued, not
proved), and length extension is outside the ideal model (see
format_options_checks.py B for the real-SHA-256 condition).

Run: python3 bound_variants.py
"""
import importlib.util
import math
import os
import sys
from fractions import Fraction
from functools import lru_cache
from math import prod

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "contracts", "verification",
                                      "easycrypt", "c10-port", "tools"))
GRIND_CAP = 10_000_000  # signing_budget in the proof; v1 wots.rs and v2 v2hash.rs both cap at 10M


@lru_cache(None)
def digit_count(length, total):
    if length == 0:
        return int(total == 0)
    if total < 0 or total > 7 * length:
        return 0
    return sum(digit_count(length - 1, total - d) for d in range(8))


@lru_cache(None)
def stirling(k, j):
    if k == 0:
        return int(j == 0)
    if j <= 0 or j > k:
        return 0
    return j * stirling(k - 1, j) + stirling(k - 1, j - 1)


def build(h):
    return 303 * 2**h - 1


def consts(T=205, layers=(9, 9)):
    h0, h1 = layers
    assert h0 + h1 == 18
    keygen = build(h1)
    fors_sign = 53386                                      # DomainForestCost; same in every variant here
    layer_sign = [build(h) + 1 + 305 + 303 + h for h in layers]
    sign = fors_sign + sum(layer_sign)                     # 364892 at (9, 9)
    verify = 1 + 146 + sum(303 + h for h in layers)        # 771 at (9, 9) and (8, 10)
    wrapper_plan = fors_sign + sum(build(h) + 5 for h in layers)   # 363666 at (9, 9)
    wrapper_wots = 2 * wrapper_plan + 2 * 301              # 727934
    return dict(T=T, layers=layers, A=digit_count(43, T), keygen=keygen, sign=sign, verify=verify,
                wrapper_wots=wrapper_wots, wots_universe=8 * 301 * (2**18 + 2**h1),
                fors_universe=2**18 * 12 * 2**11)


def coverage(n):
    return sum((Fraction(n * prod(max(0, n - 1 - i) for i in range(j)) * stirling(12, j), 2**(132 + 18 * j))
                for j in range(1, 13)), Fraction())


def ordinary(qr, qs, c):
    K, S, V0, A = c["keygen"], c["sign"], c["verify"], c["A"]
    q = K + qr + qs * (3 * GRIND_CAP + S) + V0
    cand = K + qr + qs * S + V0
    exc = qr + 2 * qs + V0
    hmsg = qr + qs + 1
    nW = qr + 4 * qs + 2
    t = {
        "node": min(Fraction(cand * (cand - 1), 2 * 2**128), Fraction(exc * (exc + 1), 2**128)),
        "zero": Fraction(q, 2**128),
        "encoding": min(Fraction(q * (q - 1) * A, 2 * 2**258), Fraction(nW * (nW - 1), 2 * A)),
        "wots": min(Fraction(c["wots_universe"] * (q + 86), 2**128), Fraction(c["wots_universe"] * (cand + 88), 2**128)),
        "fors": min(Fraction(c["fors_universe"] * (q + 12), 2**128), Fraction(c["fors_universe"] * (cand + 14), 2**128)),
        "coverage": coverage(hmsg),
        "prefix": Fraction(q, 2**256),
    }
    return q, t


def wrapper(qr, qs, c, pool=True):
    K, S, V0, A = c["keygen"], c["sign"], c["verify"], c["A"]
    q = K + qr + qs * (2 * (3 * GRIND_CAP + S) + V0) + V0
    wots = K + qr + qs * c["wrapper_wots"] + V0
    leaf = K + qr + qs * (2 * S + V0) + V0
    exc = qr + (2 * 2 + V0) * qs + V0
    n = qr + 3 * qs + 1
    retained_fors = Fraction(c["fors_universe"] * (q + 12), 2**128)
    t = {
        "node": min(Fraction(q * (q - 1), 2 * 2**128), Fraction(exc * (exc + 1), 2**128)),
        "zero": Fraction(q, 2**128),
        "encoding": Fraction(q * (q - 1), 2 * 2**129) * Fraction(A, 2**129),
        "wots": Fraction(c["wots_universe"] * (wots + 88), 2**128),
        "fors": min(retained_fors, Fraction(c["fors_universe"] * (leaf + 2 + 12), 2**128)),
        "coverage": coverage(n),
        "prefix": Fraction(q, 2**256),
    }
    if pool:  # WrapperWotsPoolNumericalBound: accepted-WOTS pool, n = qr + 10 qs + 2 accepted calls
        nw = qr + 10 * qs + 2
        t["encoding"] = min(t["encoding"], Fraction(nw * (nw - 1), 2 * A))
    return q, t


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TOOLS, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, TOOLS)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    return mod


def anchor():
    """The derived v1 formulas must equal the project's own evaluators exactly."""
    wp, wn = load("wots_pool_examples"), load("wrapper_nonnode_examples")
    c = consts()
    assert (c["keygen"], c["sign"], c["verify"], c["wrapper_wots"]) == (155135, 364892, 771, 727934), c
    assert c["wots_universe"] == 632475648 and c["fors_universe"] == 6442450944
    caps = [(0, 0), (50000, 50000), (65536, 65536), (1000000, 1000), (2**20, 2**16)]
    for qr, qs in caps:
        ref = wp.charges(qr, qs)
        q, t = ordinary(qr, qs, c)
        assert q == ref["Q"] and t == ref["refined"], ("ordinary", qr, qs)
        ref = wn.charges(qr, qs)
        q, t = wrapper(qr, qs, c, pool=False)
        assert q == ref["Q"] and t == ref["refined"], ("wrapper", qr, qs)
        ref = wp.charges(qr, qs, wrapper=True)
        q, t = wrapper(qr, qs, c)
        assert q == ref["Q"] and t == ref["refined"], ("wrapper pool", qr, qs)
    return len(caps)


VARIANTS = {
    "v1 (deployed)": dict(T=205, layers=(9, 9)),
    "v2 0.3": dict(T=205, layers=(9, 9)),
    "ts200": dict(T=200, layers=(9, 9)),
    "prf2": dict(T=205, layers=(9, 9)),
    "split810": dict(T=205, layers=(8, 10)),
    "all3": dict(T=200, layers=(8, 10)),
}
# Where the bound stops saying anything: coverage alone is ~ n^13 / 2^348 at j = 12, n = qr + qs + 1,
# so every bound here exceeds 1 once raw hash queries pass roughly 2^26.


def lg(x):
    return math.log2(x) if x > 0 else float("-inf")


def main():
    n = anchor()
    print(f"anchor: derived v1 constants (155135, 364892, 771, 727934, 632475648, 6442450944) and both bound "
          f"formulas reproduce wots_pool_examples.py and wrapper_nonnode_examples.py exactly at {n} cap pairs\n")
    for game, fn in (("ordinary game (WotsPoolNumericalBound)", ordinary),
                     ("FI wrapper game (WrapperWotsPoolNumericalBound)", wrapper)):
        for qr, qs in ((65536, 65536), (2**20, 2**16), (2**24, 2**16)):
            print(f"{game}, qr = 2^{lg(qr):.0f}, qs = 2^{lg(qs):.0f}")
            base = None
            print(f"  {'variant':15s} {'total':>11s} {'log2':>8s} {'vs v1':>9s}   changed terms (ratio to v1)")
            for name, p in VARIANTS.items():
                c = consts(**p)
                _, t = fn(qr, qs, c)
                tot = sum(t.values(), Fraction())
                if base is None:
                    base, bt = tot, t
                ch = ", ".join(f"{k} x{float(t[k] / bt[k]):.4f}" for k in t if t[k] != bt[k])
                vac = "  (VACUOUS: > 1)" if tot >= 1 else ""
                print(f"  {name:15s} {float(tot):11.4e} {lg(float(tot)):8.3f} {float(tot / base):9.5f}   {ch or '-'}{vac}")
            dom = max(bt, key=lambda k: bt[k])
            print(f"  v1 dominant term: {dom} ({float(bt[dom] / base):.1%} of the total)\n")
    for name, p in VARIANTS.items():
        c = consts(**p)
        print(f"{name:15s} T={c['T']} layers={c['layers']}: A=2^{lg(c['A']):.3f} keygen={c['keygen']} "
              f"sign={c['sign']} verify={c['verify']} wrapper_wots={c['wrapper_wots']} "
              f"wots_universe={c['wots_universe']}")


if __name__ == "__main__":
    main()
