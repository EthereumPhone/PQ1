#!/usr/bin/env python3
"""gas_bound.py — worst/best-case verify gas of the straight-line chain blocks (#1155 gas track).

Since B4 a chain with s = 7 - digit steps runs the blocks of 4, 2 and 1 selected by the bits of
s; the total number of steps per layer is fixed (43*7 - target), but how many blocks are taken
varies. Per signature: n4, n2, n1 = number of taken 4-, 2-, 1-blocks over both layers
(4 n4 + 2 n2 + n1 = 2 * (301 - target)). This script
  1. recomputes n4, n2 for each KAT from the Python references,
  2. fits gas = a + b n4 + c n2 to the per-vector gas measured by C10GasBench.test_gas_per_vector
     (PERVEC lines on stdin; the fit must be exact to the gas unit or it says so),
  3. enumerates every (n4, n2) reachable by 43 chains per layer with the fixed step sum, and
     prints the min and max of the fitted gas over them.
Usage: forge test --match-test per_vector -vv | python3 research/c10-gas/gas_bound.py [deploy]
"""
import itertools
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(HERE, "..", "c10-autoresearch", "c10v2"))
sys.path.insert(0, os.path.join(ROOT, "contracts", "verification", "scripts"))
import c10v2_ref as v2  # noqa: E402
import independent_c10_signer as v1  # noqa: E402

TW = os.path.join(ROOT, "contracts", "smart-wallet", "test")


def v2_digests(ps, pr, m, sig):
    calls = []
    orig = v2.sha256
    v2.sha256 = lambda b: (calls.append(bytes(b)), orig(b))[1]
    try:
        assert v2.verify(ps, pr, m, sig)
    finally:
        v2.sha256 = orig
    return [orig(c) for c in calls if len(c) == 43][::2]  # verify hashes each digest twice


def v1_digests(ps, pr, m, sig):
    calls = []
    orig = v1.sha256
    v1.sha256 = lambda b: (calls.append(bytes(b)), orig(b))[1]
    try:
        assert v1.verify(ps, pr, m, sig)
    finally:
        v1.sha256 = orig
    # the digest calls are the 128-byte inputs whose ADRS type field is 0 and value word follows
    idx = [147, 254]
    return [orig(calls[i]) for i in idx]


def blocks(digest):
    D = int.from_bytes(digest, "big")
    n4 = n2 = n1 = 0
    for i in range(43):
        s = 7 - ((D >> (3 * i)) & 7)
        n4 += s >> 2 & 1
        n2 += s >> 1 & 1
        n1 += s & 1
    return n4, n2, n1


def reachable(steps=96, chains=43):
    """All (n4, n2) of one layer: chains with s_i in 0..7 and sum s_i = steps."""
    states = {(0, 0, 0)}  # (sum, n4, n2)
    for _ in range(chains):
        states = {(t + s, a + (s >> 2 & 1), b + (s >> 1 & 1)) for (t, a, b) in states for s in range(8)
                  if t + s <= steps}
    return {(a, b) for (t, a, b) in states if t == steps}


def solve3(rows):
    # least squares for gas = a + b n4 + c n2 (exact check below)
    import fractions
    F = fractions.Fraction
    X = [[F(1), F(r[0]), F(r[1])] for r in rows]
    y = [F(r[2]) for r in rows]
    XtX = [[sum(X[k][i] * X[k][j] for k in range(len(X))) for j in range(3)] for i in range(3)]
    Xty = [sum(X[k][i] * y[k] for k in range(len(X))) for i in range(3)]
    M = [XtX[i] + [Xty[i]] for i in range(3)]
    for i in range(3):
        p = next(r for r in range(i, 3) if M[r][i] != 0)
        M[i], M[p] = M[p], M[i]
        for r in range(3):
            if r != i:
                f = M[r][i] / M[i][i]
                M[r] = [M[r][c] - f * M[i][c] for c in range(4)]
    return [M[i][3] / M[i][i] for i in range(3)]


def main():
    log = sys.stdin.read()
    gas = {m.group(1): int(m.group(2)) for m in re.finditer(r"PERVEC (v[12] \S+) (\d+)", log)}
    v2.configure(())
    kat = json.load(open(os.path.join(TW, "c10v2_kat_vectors.json")))
    vec1 = json.load(open(os.path.join(TW, "c10_test_vectors.json")))["vectors"]
    lay = reachable()
    pairs = {(a1 + a2, b1 + b2) for (a1, b1) in lay for (a2, b2) in lay}
    for ver in ("v2", "v1"):
        rows = []
        for k in (range(6) if ver == "v2" else range(4)):
            if ver == "v2":
                v = kat[f"v{k}"]
                key = f"v2 v{k}"
                ds = v2_digests(*(bytes.fromhex(v[f][2:])[:n] for f, n in
                                  (("pkSeed", 16), ("pkRoot", 16), ("message", 32), ("signature", 4008))))
            else:
                v = vec1[k]
                key = f"v1 vec{k}"
                ds = v1_digests(*(bytes.fromhex(v[f][2:])[:n] for f, n in
                                  (("pkSeed", 16), ("pkRoot", 16), ("message", 32), ("signature", 4008))))
            n = [sum(x) for x in zip(*(blocks(d) for d in ds))]
            assert 4 * n[0] + 2 * n[1] + n[2] == 192, n
            rows.append((n[0], n[1], gas[key]))
        a, b, c = solve3(rows)
        exact = all(a + b * r[0] + c * r[1] == r[2] for r in rows)
        f = lambda p: a + b * p[0] + c * p[1]
        lo, hi = min(pairs, key=f), max(pairs, key=f)
        print(f"{ver}: fit gas = {float(a):.1f} + {float(b):.2f} n4 + {float(c):.2f} n2 "
              f"({'exact on all' if exact else 'NOT exact on'} {len(rows)} vectors); "
              f"sample {min(r[2] for r in rows)}..{max(r[2] for r in rows)}; "
              f"bound over all reachable patterns {float(f(lo)):.0f} (n4,n2={lo}) .. {float(f(hi)):.0f} (n4,n2={hi})")


if __name__ == "__main__":
    main()
