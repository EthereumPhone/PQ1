#!/usr/bin/env python3
"""dossier_v2_03.py — the computed items of the v2 draft-0.3 security dossier against
stock C10 (research, #1155, round 16, 2026-11-14). Every number in the dossier's
"[computed]" items comes from this script; it reuses bound_variants.py and
format_options_numerics.py rather than copying their formulas.

Gate (S) items computed here:
  (a) 1. the Quantitative.lean floor min(k*a, n - qBits, n - 2*qBits) (classical) and
         its Grover-halved convention, at the slot cap (qBits = 16) and at the P14
         bootstrap cross-chain caps C x 2^16 (C = 1, 2, 16);
      2. the EasyCrypt-shape numerical EUF bound (ordinary and FI wrapper) with
         stock constants and with v2 0.3's (bound_variants.consts), at qr = qs = 2^16
         and at the bootstrap caps qs = C x 2^16.
  (c) 1. the two-use WOTS fault-fallback margin (one key signs two sum-T digests),
         same sampler as format_options_numerics.py, fixed seed;
      2. the DPA exposure count: per signing pass, how many single compressions take
         sk_seed in their message block together with attacker-known varying words
         (v1: the FORS PRF, 48 B, one block; v1's WOTS PRF is 80 B and its first block
         sk_seed || "wots" || layer || 0^24 is constant per layer, so its varying fields
         only meet a per-layer secret chaining value in block 2; v2: the FORS PRF and
         the WOTS PRF, both sk_seed || A7, one block).

Run: python3 dossier_v2_03.py [samples]   (default 2000)
"""
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bound_variants as bv  # noqa: E402

_argv = sys.argv
sys.argv = [sys.argv[0], "cross"]  # keep format_options_numerics from running its main on import
import format_options_numerics as fon  # noqa: E402
sys.argv = _argv

# Stock C10 (deployed v1) and v2 draft 0.3 share every parameter.
P = dict(h=18, d=2, a=11, k=13, w=8, l=43, T=205, n_bits=128)


def floor_bits(n, qbits, a, k):
    """Quantitative.lean securityFloorBits (Nat semantics: truncating subtraction)."""
    return min(k * a, max(0, n - qbits), max(0, n - 2 * qbits))


def lg(x):
    return math.log2(x) if x > 0 else float("-inf")


def main():
    samples = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    p = P
    print("v2 draft 0.3 vs stock C10: computed dossier items\n")

    print("(a1) Quantitative.lean floor min(k*a, n - qBits, n - 2*qBits); Grover convention = /2")
    for label, qbits in (("slot cap 2^16", 16), ("bootstrap C=2 (2^17)", 17), ("bootstrap C=16 (2^20)", 20)):
        f = floor_bits(p["n_bits"], qbits, p["a"], p["k"])
        print(f"  {label:24s} stock {f:3d} b (Grover {f/2:5.1f})   v2 0.3 {f:3d} b (Grover {f/2:5.1f})   equal: same parameters")
    print()

    print("(a2) EasyCrypt-shape bound (bound_variants.py), stock constants vs v2 0.3 constants")
    bv.anchor()  # asserts the stock formulas reproduce the project's evaluators exactly
    c_stock = bv.consts(T=205, layers=(9, 9))
    c_v2 = bv.consts(T=p["T"], layers=(p["h"] // p["d"],) * p["d"])
    assert c_stock == c_v2, "v2 0.3 changes no bound constant"
    for label, qs in (("qs = 2^16", 2**16), ("bootstrap C=2", 2 * 2**16), ("bootstrap C=16", 16 * 2**16)):
        _, to = bv.ordinary(2**16, qs, c_stock)
        _, tw = bv.wrapper(2**16, qs, c_stock)
        o, w = sum(to.values()), sum(tw.values())
        print(f"  {label:16s} ordinary 2^{lg(float(o)):7.2f}   wrapper 2^{lg(float(w)):7.2f}   (identical for v2 0.3: same constants)")
    print("  scope: the theorems are proved for v1's byte format; v2 0.3's row is the same formula,"
          " NOT a proof about v2 (bound_variants.py docstring)\n")

    print(f"(c1) two-use WOTS fault margin (l={p['l']}, w={p['w']}, T={p['T']}), {samples} samples, seed 0xD055")
    rng = random.Random(0xD055)
    ws = []
    for _ in range(samples):
        d1, d2 = fon.sample_ST(p["T"], rng), fon.sample_ST(p["T"], rng)
        m = [min(x, y) for x, y in zip(d1, d2)]
        ws.append(-lg(fon.p_dominate(m, p["T"])))
    ws.sort()
    print(f"  median 2^-{ws[len(ws)//2]:.2f} per forgery try, 1st percentile 2^-{ws[len(ws)//100]:.2f}"
          " — a function of (l, w, T) only, so identical for stock and v2 0.3\n")

    print("(c2) DPA exposure: single compressions per signing pass with sk_seed and attacker-known varying words")
    fors_prf = (p["k"] - 1) * 2**p["a"]
    wots_prf = p["d"] * 2**(p["h"] // p["d"]) * p["l"]
    v1 = fors_prf
    v2 = fors_prf + wots_prf
    print(f"  v1: FORS PRF {fors_prf:,} (one 48-B block); WOTS PRF 0 (its sk_seed block is constant per layer;"
          f" the {wots_prf:,} block-2 compressions mix the varying fields with a per-layer secret chaining value)")
    print(f"  v2 0.3: FORS PRF {fors_prf:,} + WOTS PRF {wots_prf:,} = {v2:,} (sk_seed || A7, one block each)")
    print(f"  ratio x{v2/v1:.2f} ({lg(v2/v1):.2f} bits fewer signing passes for the same sk_seed trace budget)"
          " — an exposure count, not a measured DPA margin")


if __name__ == "__main__":
    main()
