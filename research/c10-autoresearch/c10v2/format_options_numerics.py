#!/usr/bin/env python3
"""format_options_numerics.py — exact numbers behind the target_sum question
(research, #1155; format-options security check, 2026-11-13).

WOTS+C with w = 8, l = 43: a digest yields 43 base-8 digits (the low 129 bits),
and a signature is valid only if they sum to T.

Computed here, for each T:
  * |S_T|, the number of digit vectors with sum T, and p_T = |S_T| / 8^43;
  * expected count-grind tries per WOTS signature (1 / p_T) and per sign (2 layers);
  * verifier chain steps per WOTS signature (43 * 7 - T);
  * the one-time forgery probability per digest try: P[d' >= d and sum d' = T].
    Equal sums plus componentwise >= force d' = d, so this is 8^-43 for every T;
    the script checks that by DP rather than assuming it;
  * the r-time residual: if a fault (or any bug) makes ONE WOTS key sign r
    different digests d_1..d_r (each uniform on S_T, because the signer grinds
    every message to sum T), the chains are revealed down to m = min_j d_j, and a
    forger needs a fresh digest with d' >= m and sum d' = T. The per-try
    probability is exact for each sampled m (DP); the distribution over m is
    sampled (uniform sampling on S_T via the count table).

Run:  python3 format_options_numerics.py [samples]   (default 4000)
"""
import math
import random
import sys

import numpy as np

W, L = 8, 43
MAXS = (W - 1) * L  # 301


def count_table():
    # cnt[k][s] = number of length-k digit vectors (0..7) with sum s (exact ints)
    cnt = [[0] * (MAXS + 1) for _ in range(L + 1)]
    cnt[0][0] = 1
    for k in range(1, L + 1):
        for s in range(MAXS + 1):
            cnt[k][s] = sum(cnt[k - 1][s - v] for v in range(W) if s - v >= 0)
    return cnt


CNT = count_table()
TOTAL = W ** L


def sample_ST(T, rng):
    """Uniform sample from S_T (exact, sequential)."""
    d, rem = [], T
    for i in range(L):
        k = L - i - 1
        r = rng.randrange(CNT[k + 1][rem])
        for v in range(W):
            if rem - v < 0:
                raise AssertionError
            c = CNT[k][rem - v]
            if r < c:
                d.append(v)
                rem -= v
                break
            r -= c
    assert rem == 0 and sum(d) == T
    return d


def p_dominate(m, T):
    """P over uniform d' in [0,7]^43 of (d' >= m componentwise and sum d' = T)."""
    dist = np.zeros(1)
    dist[0] = 1.0
    for mi in m:
        box = np.zeros(W)
        box[mi:] = 1.0 / W
        dist = np.convolve(dist, box)
    return dist[T] if T < len(dist) else 0.0


def p_dominate_exact(m, T):
    poly = [1]
    for mi in m:
        new = [0] * (len(poly) + W - 1)
        for s, c in enumerate(poly):
            if c:
                for v in range(mi, W):
                    new[s + v] += c
        poly = new
    return poly[T] if T < len(poly) else 0


def lg(x):
    return math.log2(x) if x > 0 else float("-inf")


def main():
    samples = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    rng = random.Random(0xC10)
    print(f"w={W} l={L}: 8^43 = 2^{lg(TOTAL):.3f}; digit-sum mean {MAXS/2}, sd {math.sqrt(L*(W*W-1)/12):.3f}\n")
    print("T    |S_T| (log2)   tries/grind   tries/sign(2)   verify steps/WOTS   one-time log2(1/p)")
    for T in (190, 195, 200, 205, 208, 210):
        sT = CNT[L][T]
        p = sT / TOTAL
        # one-time: exact DP on a sampled d (must equal 8^-43 exactly)
        d = sample_ST(T, rng)
        one = p_dominate_exact(d, T)
        assert one == 1, f"T={T}: {one} vectors dominate d with sum T (expected exactly 1: d itself)"
        print(f"{T}  2^{lg(sT):8.3f}   {1/p:11.1f}   {2/p:13.1f}   {L*(W-1)-T:17d}   {lg(TOTAL):.3f} (exactly 1 vector)")
    print()
    # cross-check vs the 16-message kit figure ("about 61k tries per sign" at 205)
    print(f"check: expected tries per sign at T=205 = {2*TOTAL/CNT[L][205]:.0f} (kit mean ~61.4k)\n")

    print(f"r-time residual (fault makes one WOTS key sign r digests); {samples} sampled min-vectors per row;")
    print("work = log2(1/p) per forgery try, p = P[d' >= min(d_1..d_r), sum d' = T]")
    print("T    r   median   p10(easier)   p1    min     mean-of-p (log2)")
    for T in (195, 200, 205, 210):
        for r in (2, 3):
            ws, ps = [], []
            for _ in range(samples):
                ds = [sample_ST(T, rng) for _ in range(r)]
                m = [min(col) for col in zip(*ds)]
                p = p_dominate(m, T)
                ps.append(p)
                ws.append(-lg(p))
            ws.sort()
            mean_p = sum(ps) / len(ps)
            print(f"{T}  {r}   {ws[len(ws)//2]:6.2f}   {ws[len(ws)//10]:11.2f}   {ws[len(ws)//100]:5.2f}   "
                  f"{ws[0]:5.2f}   {-lg(mean_p):6.2f}")
    # spot-check the float DP against the exact integer DP
    for T in (200, 205):
        ds = [sample_ST(T, rng) for _ in range(2)]
        m = [min(c) for c in zip(*ds)]
        pf = p_dominate(m, T)
        pe = p_dominate_exact(m, T) / TOTAL
        assert abs(pf - pe) <= 1e-9 * pe, (pf, pe)
    print("\nfloat DP agrees with the exact integer DP on spot checks")


if __name__ == "__main__" and not (len(sys.argv) > 1 and sys.argv[1] == "cross"):
    main()


def cross_variant(samples=3000):
    """Same (sk_seed, pk_seed) used under two v2 variants (format-options check).

    ts200 keeps every key: a WOTS key that signed its (deterministic) node under
    T=205 and again under T=200 reveals both digit vectors (independent digests,
    since the counts differ), i.e. a two-time key; the forger targets either verifier.
    prf2 keeps the even-index secrets of 0.3 (same PRF input, first half) and every
    chain tweak, so a 0.3 signature at the same leaf (of a different node: the FORS
    pk differs) lowers the prf2 key's even chains to min(d1, d2); odd chains are
    only revealed by the prf2 signature itself."""
    rng = random.Random(0xC10C)
    print(f"\ncross-variant key reuse (same seed under two variants), {samples} samples; log2(1/p) per forgery try")
    print("case                                          median   p10    p1")
    cases = {
        "0.3 + ts200, forge for the T=200 verifier": (205, 200, 200, "all"),
        "0.3 + ts200, forge for the T=205 verifier": (205, 200, 205, "all"),
        "0.3 + prf2 (even chains shared), forge prf2": (205, 205, 205, "even"),
    }
    for name, (t1, t2, tf, which) in cases.items():
        ws = []
        for _ in range(samples):
            d1, d2 = sample_ST(t1, rng), sample_ST(t2, rng)
            m = [min(a, b) if (which == "all" or i % 2 == 0) else b for i, (a, b) in enumerate(zip(d1, d2))]
            ws.append(-lg(p_dominate(m, tf)))
        ws.sort()
        print(f"{name:44s}  {ws[len(ws)//2]:6.2f}  {ws[len(ws)//10]:5.2f}  {ws[len(ws)//100]:5.2f}")


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "cross":
    cross_variant()
