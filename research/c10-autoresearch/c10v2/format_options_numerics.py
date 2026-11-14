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


if __name__ == "__main__" and not (len(sys.argv) > 1 and sys.argv[1] in ("cross", "search")):
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


# ── search (2026-11-14): parameter-space search over the C10 SPHINCS+C family ──────────────
# Usage: python3 format_options_numerics.py search [samples]     (default 800)
# Bound and cost math: family_bound.py (stdlib; exact anchor against bound_variants.py).
# Here: the (c) fault-fallback estimator generalised to (l, w, T) (numpy, like the code above),
# the vectorised sweep, PASS / MINOR-LOSS / FAIL marks, Pareto frontiers, family_search.tsv.
# Gate (a) is a REPORTING device (owner, 2026-11-14): no set is dropped for being weaker than
# stock; only hard validity prunes (l*log2 w in [128, 256], H_MSG bits h + k*a <= 256, both
# grinds exhaust GRIND_CAP with probability <= 2^-40, signature <= 8000 bytes).

SEARCH_SEED = 0xC10F
SIG_CAP = 8000
CS = (1, 2, 16)
MARKS = ("PASS", "MINOR-LOSS", "FAIL")
_CUM = {}


def _st_cum(l, w):
    """cum[r][s][v] = P[next digit <= v | r digits left, remaining sum s], uniform on S_T."""
    import family_bound as fb
    if (l, w) not in _CUM:
        rows = fb.digit_rows(l, w)
        cum = np.zeros((l + 1, l * (w - 1) + 1, w))
        for r in range(1, l + 1):
            prev, cur = rows[r - 1], rows[r]
            for s in range(len(cur)):
                tot, acc = cur[s], 0
                for v in range(w):
                    if 0 <= s - v < len(prev):
                        acc += prev[s - v]
                    cum[r, s, v] = acc / tot
        _CUM[(l, w)] = cum
    return _CUM[(l, w)]


def sample_ST_batch(l, w, T, size, rng):
    """size uniform samples from S_T = {d in [0,w-1]^l : sum d = T} (sequential, vectorised)."""
    cum = _st_cum(l, w)
    rem = np.full(size, T, dtype=np.int64)
    out = np.empty((size, l), dtype=np.int64)
    for i in range(l):
        v = (rng.random(size)[:, None] >= cum[l - i][rem]).sum(axis=1)
        out[:, i] = v
        rem -= v
    assert (rem == 0).all() and out.max() < w
    return out


def p_dominate_batch(m, T, w):
    """Row-wise P over uniform d' in [0,w-1]^l of (d' >= m componentwise, sum d' = T).
    Same direct sums as p_dominate (no prefix-sum cancellation)."""
    size, l = m.shape
    dist = np.zeros((size, T + 1))
    dist[:, 0] = 1.0
    for i in range(l):
        new = np.zeros_like(dist)
        for v in range(w):
            new[:, v:] += dist[:, :T + 1 - v] * (m[:, i] <= v)[:, None]
        dist = new / w
    return dist[:, T]


def fault_margin_stats(l, w, T, samples):
    """(c): median log2(1/p) per forgery try after a fault makes one WOTS key sign two
    independent sum-T digests (r = 2 of main()), and its standard error from the order statistics
    at N/2 +- sqrt(N)/2. Every triple uses the same seed, but that does NOT couple triples with different
    l (the second digest vector's stream shifts with l), so a delta's SE is ~sqrt(se_a^2 + se_b^2): Astra's
    paired bootstrap for w4l65 T125 gave 0.104 against sqrt(0.076^2 + 0.075^2) = 0.107."""
    rng = np.random.default_rng(SEARCH_SEED)
    d1, d2 = sample_ST_batch(l, w, T, samples, rng), sample_ST_batch(l, w, T, samples, rng)
    v = np.sort(-np.log2(p_dominate_batch(np.minimum(d1, d2), T, w)))
    k = max(1, int(round(math.sqrt(samples) / 2)))
    mid = samples // 2
    return float(np.median(v)), float((v[min(samples - 1, mid + k)] - v[max(0, mid - k)]) / 2)


def fault_margin(l, w, T, samples):
    return fault_margin_stats(l, w, T, samples)[0]


def _search_triples(fb):
    out = []
    for w in (4, 8, 16):
        b = fb.log2w(w)
        lmin = -(-128 // b)
        for l in range(lmin, lmin + 5):
            if l * b > 256:
                continue
            row, top = fb.digit_rows(l, w)[l], l * (w - 1)
            mode = top // 2
            step = 2 if w == 16 else 1
            for T in range(mode - 10, top + 1, step):
                p = dict(l=l, w=w, T=T, a=8)
                if T > mode and fb.grind_fail_log2(p) > -40:
                    break
                out.append((w, l, T))
    return out


def _pareto(cyc, gas, byt, idx):
    """3-D Pareto (minimise all) over the index subset idx; returns frontier indices."""
    order = idx[np.lexsort((byt[idx], gas[idx], cyc[idx]))]
    size = SIG_CAP + 2
    tree = [math.inf] * (size + 1)
    front = []
    for j in order.tolist():
        b, g = int(byt[j]) + 1, gas[j]
        i, best = b, math.inf
        while i > 0:
            if tree[i] < best:
                best = tree[i]
            i -= i & -i
        if best <= g:
            continue
        front.append(j)
        i = b
        while i <= size:
            if g < tree[i]:
                tree[i] = g
            i += i & -i
    return np.array(front, dtype=np.int64)


def _reproof_note(fb):
    import os
    import re
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..",
                                         "contracts", "verification"))
    groups = {
        "Lean Spec/Params.lean": [os.path.join(root, "lean", "SphincsCVerify", "Spec", "Params.lean")],
        "Lean Spec/*.lean (other)": [],
        "EC c10-port cdrafts-split/*.ec": [],
        "EC c10-port other *.ec (no scratch/)": [],
        "EC c10-port tools/*.py": [],
    }
    spec = os.path.join(root, "lean", "SphincsCVerify", "Spec")
    if os.path.isdir(spec):
        groups["Lean Spec/*.lean (other)"] = [os.path.join(spec, f) for f in sorted(os.listdir(spec))
                                              if f.endswith(".lean") and f != "Params.lean"]
    port = os.path.join(root, "easycrypt", "c10-port")
    for dp, dn, fn in os.walk(port):
        dn[:] = [x for x in dn if x != "scratch"]
        for f in fn:
            path = os.path.join(dp, f)
            if f.endswith(".ec"):
                key = ("EC c10-port cdrafts-split/*.ec" if os.path.basename(dp) == "cdrafts-split"
                       else "EC c10-port other *.ec (no scratch/)")
                groups[key].append(path)
            elif f.endswith(".py") and os.path.basename(dp) == "tools":
                groups["EC c10-port tools/*.py"].append(path)
    sets = {"stock (43 205 512 2048)": ("43", "205", "512", "2048"),
            "derived (301 303 771 155135 364892 53386 262144 632475648 6442450944)":
                ("301", "303", "771", "155135", "364892", "53386", "262144", "632475648", "6442450944"),
            "small, noisy (13 11 18 9)": ("13", "11", "18", "9")}
    pats = {name: re.compile(r"(?<![\w.])(" + "|".join(v) + r")(?![\w.])") for name, v in sets.items()}
    rows = []
    for g, files in groups.items():
        files = [f for f in files if os.path.isfile(f)]
        cells = []
        for name, pat in pats.items():
            nf = no = 0
            for f in files:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    k = len(pat.findall(fh.read()))
                nf += k > 0
                no += k
            cells.append(f"{nf}/{len(files)} files, {no} hits")
        rows.append((g, cells))
    return list(sets), rows


def search_main():
    import time
    import family_bound as fb
    t0 = time.time()
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 800
    n_caps, n_terms = fb.assert_anchor()
    rng0 = random.Random(7)
    for T in (200, 205):
        for _ in range(4):
            m = [min(c) for c in zip(sample_ST(T, rng0), sample_ST(T, rng0))]
            pa, pb = p_dominate(m, T), p_dominate_batch(np.array([m]), T, W)[0]
            assert abs(pa - pb) <= 1e-12 * pa, (pa, pb)
    VEC = fb._Backend("numpy", lambda x, y: x / y, np.minimum, np.exp2)
    S0 = dict(fb.STOCK)
    X0, Y0 = (S0["w"], S0["l"], S0["T"]), (S0["k"], S0["a"])

    triples = _search_triples(fb)
    assert X0 in triples, "stock (w, l, T) must be in the enumerated space"
    kas = [(k, a) for k in range(8, 41) for a in range(8, 17)
           if 16 * (2 + (k - 1) * (a + 1)) + 4 + 33 * 16 <= SIG_CAP]
    hds = [(h, d) for h in range(16, 25) for d in (1, 2, 3, 4, 6) if h % d == 0]
    refine_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
    t_c = time.time()
    cstat = {x: fault_margin_stats(x[1], x[0], x[2], samples) for x in triples}
    cm = {x: v[0] for x, v in cstat.items()}
    t_c = time.time() - t_c
    tries = {x: x[0] ** x[1] / fb.digit_count(x[1], x[0], x[2]) for x in triples}

    def full(h, d, x, y, n=16):
        return dict(h=h, d=d, k=y[0], a=y[1], w=x[0], l=x[1], T=x[2], n=n)

    hs = sorted({h for h, _ in hds})
    cov, dbits = {}, {}
    for h in hs:
        for (k, a) in kas:
            if h + k * a > 256:
                continue
            for C in CS:
                qs = C * 2 ** 16
                cov[(h, k, a, "o", C)] = fb.coverage_g(2 ** 16 + qs + 1, h, k, a, fb.FLOAT)
                cov[(h, k, a, "w", C)] = fb.coverage_g(2 ** 16 + 3 * qs + 1, h, k, a, fb.FLOAT)
            dbits[(h, k, a)] = (fb.fors_multiuse_bits(h, k, a, 2 ** 16), fb.fors_multiuse_bits(h, k, a, 2 ** 20))

    TERMS = ("node", "zero", "encoding", "wots", "fors", "coverage", "prefix")

    def block(h, d, X, Y):
        """All metrics for the grid X (w,l,T) x Y (k,a) at (h, d); arrays of shape (len X, len Y)."""
        p00 = full(h, d, X0, Y0)
        c00, s00 = fb.consts_g(p00), fb.split_costs(p00)
        cx = [fb.consts_g(full(h, d, x, Y0)) for x in X]
        cy = [fb.consts_g(full(h, d, X0, y)) for y in Y]
        sx = [fb.split_costs(full(h, d, x, Y0))["layer"] for x in X]
        sy = [fb.split_costs(full(h, d, X0, y))["fors"] for y in Y]
        col = lambda v: np.array(v, dtype=float)[:, None]
        row = lambda v: np.array(v, dtype=float)[None, :]
        sep = lambda key: col([c[key] for c in cx]) + row([c[key] for c in cy]) - float(c00[key])
        c = dict(keygen=col([c_["keygen"] for c_ in cx]), sign=sep("sign"), verify=sep("verify"),
                 wrapper_wots=sep("wrapper_wots"), A=col([float(c_["A"]) for c_ in cx]), d=d, nbits=128,
                 digit_bits=col([c_["digit_bits"] for c_ in cx]), wots_universe=col([c_["wots_universe"] for c_ in cx]),
                 fors_universe=row([c_["fors_universe"] for c_ in cy]), dl=col([c_["dl"] for c_ in cx]),
                 km1=row([c_["km1"] for c_ in cy]))
        M = {}
        for C in CS:
            qs = C * 2 ** 16
            _, to = fb.ordinary_terms(2 ** 16, qs, c, VEC, row([cov[(h, k, a, "o", C)] for k, a in Y]))
            _, tw = fb.wrapper_terms(2 ** 16, qs, c, VEC, row([cov[(h, k, a, "w", C)] for k, a in Y]))
            if C == 1:
                M["ord"], M["wrap"] = sum(to.values()), sum(tw.values())
            for t_ in TERMS:                                   # every returned term, both games, every C
                M[f"o{t_}{C}"] = to[t_] + np.zeros((len(X), len(Y)))
                M[f"w{t_}{C}"] = tw[t_] + np.zeros((len(X), len(Y)))
            M[f"otot{C}"] = sum(to.values()) + np.zeros((len(X), len(Y)))   # the theorem's right-hand side
            M[f"wtot{C}"] = sum(tw.values()) + np.zeros((len(X), len(Y)))
        nx, ny = len(X), len(Y)
        for C in CS:
            qb = 16 + math.log2(C)
            M[f"fl{C}"] = row([fb.lean_floor_bits(128, qb, a, k) for k, a in Y]) + np.zeros((nx, 1))
            M[f"flq{C}"] = row([fb.lean_floor_bits_grover(128, qb, a, k) for k, a in Y]) + np.zeros((nx, 1))
        M["c"] = col([cm[x] for x in X]) + np.zeros((1, ny))
        # one-time digest-match exponent log2(w^l): the per-query probability that one H_MSG output hits a given
        # digit vector; it sits inside the encoding terms but is marked on its own (Astra r16: w4 2^-129 -> 2^-128)
        M["enc"] = col([c_["digit_bits"] for c_ in cx]) + np.zeros((1, ny))
        M["dq1"] = row([dbits[(h, k, a)][0] for k, a in Y]) + np.zeros((nx, 1))
        M["dq16"] = row([dbits[(h, k, a)][1] for k, a in Y]) + np.zeros((nx, 1))
        M["bytes"] = col([s["bytes"] for s in sx]) + row([s["bytes"] for s in sy])
        calls = col([s["calls"] for s in sx]) + row([s["calls"] for s in sy])
        M["gas_callee"] = (col([s["gas_floor"] for s in sx]) + row([s["gas_floor"] for s in sy])
                           + float(fb.GAS_OVERHEAD) * calls)
        M["gas_calldata"] = 16 * (M["bytes"] - d) + 4 * d
        vcyc = fb.VERIFY_CYC_STOCK * calls / fb.n_calls(fb.STOCK)
        for u, glue in (("A", fb.UNITS_BRIEF["glue"]), ("B", fb.UNITS_SHARES["glue"])):
            M[f"pass{u}"] = col([s[f"cyc{u}"] for s in sx]) + row([s[f"cyc{u}"] for s in sy]) + glue
            M[f"cyc{u}"] = 2 * M[f"pass{u}"] + vcyc
        M["valid"] = np.array([h + k * a <= 256 for k, a in Y])[None, :] & (M["bytes"] <= SIG_CAP)
        cb = lambda v: np.array([max(0, (int(z) - 1).bit_length()) for z in v], dtype=float)
        hp = h // d
        lx, wx = [x[1] for x in X], [x[0] for x in X]
        ky, ay = [y[0] for y in Y], [y[1] for y in Y]
        cpv = np.maximum(np.maximum(col(wx) - 1, row(ay)), hp) + 1
        M["addr"] = (4 + cb([d])[0] + h + np.maximum(hp, row(cb(ky))) + col(cb(lx))
                     + np.ceil(np.log2(cpv)) + np.maximum(row(ay), hp))
        M["asis"] = ((d <= 2) & (h <= 18) & (hp <= 9) & (col(lx) <= 64) & (row(ky) <= 512) & (row(ay) <= 11)
                     & (col(wx) <= 16))
        return M

    ref = {k: v[0, 0] for k, v in block(18, 2, [X0], [Y0]).items()}
    BITS = [f"fl{C}" for C in CS] + [f"flq{C}" for C in CS] + ["enc", "c"]
    RATIOS = ["ord", "wrap"] + [f"{g}{t}{C}" for C in CS for g in "ow" for t in TERMS]
    DRIVERS = BITS + RATIOS
    # the totals reading of gate (a): the bound as proved is the game total, so only the totals at the caps count
    RATIOS_T = [f"{g}tot{C}" for C in CS for g in "ow"]
    DRIVERS_T = BITS + RATIOS_T

    def mark(M, ratios=None):
        ratios = RATIOS if ratios is None else ratios
        losses = [ref[b] - M[b] for b in BITS] + [np.log2(M[r] / ref[r]) for r in ratios]
        L = np.stack(losses)
        loss = L.max(axis=0)
        mk = np.where(loss <= 0, 0, np.where(loss <= 1, 1, 2))
        return mk, loss, L.argmax(axis=0)

    Xi = {x: i for i, x in enumerate(triples)}

    def sweep():
      store = {k: [] for k in ("cycA", "cycB", "gas", "bytes", "mark", "loss", "drv", "markT", "lossT", "drvT", "hd", "xi", "yi",
                               "ord", "wrap", "cdel", "wterm", "dq1", "addr", "asis")}
      noc = np.full(len(triples), np.inf)
      stock_cell = None
      for bi, (h, d) in enumerate(hds):
          Y = [(k, a) for k, a in kas if h + k * a <= 256]
          Yi = [kas.index(y) for y in Y]
          M = block(h, d, triples, Y)
          mk, loss, drv = mark(M)
          mkT, lossT, drvT = mark(M, RATIOS_T)
          if (h, d) == (18, 2):
              ix, iy = Xi[X0], Y.index(Y0)
              stock_cell = (mk[ix, iy], loss[ix, iy])
              for key in ref:
                  assert M[key][ix, iy] == ref[key], key
          ok = M["valid"]
          xi, yi = np.nonzero(ok)
          store["cycA"].append(M["cycA"][ok]); store["cycB"].append(M["cycB"][ok])
          store["gas"].append((M["gas_callee"] + M["gas_calldata"])[ok]); store["bytes"].append(M["bytes"][ok].astype(np.int32))
          store["mark"].append(mk[ok].astype(np.int8)); store["loss"].append(loss[ok].astype(np.float32))
          store["drv"].append(drv[ok].astype(np.int8)); store["hd"].append(np.full(len(xi), bi, np.int8))
          store["markT"].append(mkT[ok].astype(np.int8)); store["lossT"].append(lossT[ok].astype(np.float32))
          store["drvT"].append(drvT[ok].astype(np.int8))
          store["xi"].append(xi.astype(np.int16)); store["yi"].append(np.array(Yi, np.int16)[yi])
          store["ord"].append((M["ord"] / ref["ord"])[ok].astype(np.float32))
          store["wrap"].append((M["wrap"] / ref["wrap"])[ok].astype(np.float32))
          store["cdel"].append((M["c"] - ref["c"])[ok].astype(np.float32))
          cf = np.stack([np.log2(M[r] / ref[r]) for r in RATIOS[2:]]).max(axis=0)
          store["wterm"].append(cf[ok].astype(np.float32))
          store["dq1"].append((M["dq1"] - ref["dq1"])[ok].astype(np.float32))
          store["addr"].append(M["addr"][ok].astype(np.int8)); store["asis"].append((M["asis"] & ok)[ok])
          losses_noc = np.stack([ref[b] - M[b] for b in BITS if b != "c"] + [np.log2(M[r] / ref[r]) for r in RATIOS])
          lnc = np.where(ok, losses_noc.max(axis=0), np.inf).min(axis=1)
          noc = np.minimum(noc, lnc)
      assert stock_cell is not None and stock_cell[0] == 0 and stock_cell[1] == 0
      return {k: np.concatenate(v) for k, v in store.items()}, noc

    # pass 1 with the coarse (c); refine (c) where it can decide a mark, then pass 2
    _, noc = sweep()
    c0 = cm[X0]
    t_r = time.time()
    csamp = {x: samples for x in triples}

    def refine(xs):
        for x in xs:
            cstat[x] = fault_margin_stats(x[1], x[0], x[2], refine_samples)
            cm[x] = cstat[x][0]
            csamp[x] = refine_samples

    near = [x for i, x in enumerate(triples) if x == X0 or
            (noc[i] <= 1 and -1.75 <= cm[x] - c0 <= 0.75)]
    refine(near)
    c_stock = cm[X0]
    ref = {k: v[0, 0] for k, v in block(18, 2, [X0], [Y0]).items()}

    def frontiers(G):
        ok = G["addr"] <= 56                                  # address > 56 bits: one-block cost model void
        idx = np.arange(len(G["mark"]), dtype=np.int64)[ok]
        sb = lambda mask: idx[mask[ok]]
        return idx, sb, dict(
            all=_pareto(G["cycA"], G["gas"], G["bytes"], idx),
            pass_=_pareto(G["cycA"], G["gas"], G["bytes"], sb(G["mark"] == 0)),
            pm=_pareto(G["cycA"], G["gas"], G["bytes"], sb(G["mark"] <= 1)),
            passB=_pareto(G["cycB"], G["gas"], G["bytes"], sb(G["mark"] == 0)),
            asis=_pareto(G["cycA"], G["gas"], G["bytes"], sb((G["mark"] == 0) & G["asis"])),
            pm_asis=_pareto(G["cycA"], G["gas"], G["bytes"], sb((G["mark"] <= 1) & G["asis"])),
            passT=_pareto(G["cycA"], G["gas"], G["bytes"], sb(G["markT"] == 0)),
            passT_asis=_pareto(G["cycA"], G["gas"], G["bytes"], sb((G["markT"] == 0) & G["asis"])))

    # close over the reported frontiers: every (w, l, T) that appears on one gets the refined (c) estimate, then
    # re-sweep, until the frontiers carry no coarse estimate (Astra r16 MEDIUM: w4 had kept its 800-sample +0.627 b
    # against the 4000-sample stock; consistent sampling gives +0.439 b)
    closure, closure_rounds = [], 0
    while True:
        G, _ = sweep()
        allidx, sub, F = frontiers(G)
        G_small = sub((G["mark"] == 0) & (G["bytes"] <= ref["bytes"]))
        F["small"] = _pareto(G["cycA"], G["gas"], G["bytes"], G_small)
        miss = sorted({triples[i] for f in F.values() for i in G["xi"][f].tolist()
                       if csamp[triples[i]] != refine_samples})
        if not miss:
            break
        assert closure_rounds < 8, "frontier closure did not converge"
        refine(miss)
        closure += miss
        closure_rounds += 1
    t_r = time.time() - t_r
    N = len(G["mark"])
    t_sweep = time.time() - t0
    f_all, f_pass, f_pm, f_passB, f_asis = F["all"], F["pass_"], F["pm"], F["passB"], F["asis"]
    f_pm_asis, f_small = F["pm_asis"], F["small"]
    f_passT, f_passT_asis = F["passT"], F["passT_asis"]
    G["csamp"] = np.array([csamp[triples[i]] for i in range(len(triples))], np.int32)[G["xi"]]
    G["cse"] = np.array([cstat[triples[i]][1] for i in range(len(triples))], np.float32)[G["xi"]]

    def params(j):
        h, d = hds[G["hd"][j]]
        x, y = triples[G["xi"][j]], kas[G["yi"][j]]
        return full(h, d, x, y)

    def scalar_row(p, mark_j=None):
        """Every reported number recomputed from the scalar family_bound functions."""
        c = fb.consts_g(p)
        x, y = (p["w"], p["l"], p["T"]), (p["k"], p["a"])
        r = dict(p=p, sig=fb.sig_bytes(p), passA=fb.pass_cycles(p), passB=fb.pass_cycles(p, fb.UNITS_SHARES),
                 cycA=fb.cached_sign_cycles(p), cycB=fb.cached_sign_cycles(p, fb.UNITS_SHARES),
                 callee=float(fb.gas_callee(p)), calldata=fb.gas_calldata(p), calls=fb.n_calls(p),
                 fl=fb.lean_floor_bits(8 * p["n"], 16, p["a"], p["k"]),
                 flq=fb.lean_floor_bits_grover(8 * p["n"], 16, p["a"], p["k"]),
                 fl16=fb.lean_floor_bits(8 * p["n"], 20, p["a"], p["k"]),
                 c=cm.get(x), tries=tries.get(x), dq1=fb.fors_multiuse_bits(p["h"], p["k"], p["a"], 2 ** 16),
                 dq16=fb.fors_multiuse_bits(p["h"], p["k"], p["a"], 2 ** 20), perm=c["perm_assumed"])
        r["ord"] = float(sum(fb.ordinary_terms(2 ** 16, 2 ** 16, c, fb.FLOAT)[1].values()))
        r["wrap"] = float(sum(fb.wrapper_terms(2 ** 16, 2 ** 16, c, fb.FLOAT)[1].values()))
        r["gas"] = r["callee"] + r["calldata"]
        r["enc"] = p["l"] * fb.log2w(p["w"])
        return r

    stock = scalar_row(full(18, 2, X0, Y0))

    def check(j, r):
        assert G["addr"][j] == fb.addr_bits_needed(r["p"]) and bool(G["asis"][j]) == fb.addr_fits_asis(r["p"]), r["p"]
        for key, val in (("cycA", r["cycA"]), ("cycB", r["cycB"]), ("gas", r["gas"]), ("bytes", r["sig"])):
            assert abs(G[key][j] - val) <= 1e-9 * abs(val), (key, G[key][j], val, r["p"])
        assert abs(G["ord"][j] - r["ord"] / stock["ord"]) <= 1e-5 * r["ord"] / stock["ord"]
        assert abs(G["wrap"][j] - r["wrap"] / stock["wrap"]) <= 1e-5 * r["wrap"] / stock["wrap"]

    # ── output ──
    lg2 = lambda v: math.log2(v) if v > 0 else float("-inf")
    print(f"search: anchor OK ({n_caps} project cap pairs via bound_variants.anchor; {n_terms} exact term-by-term "
          f"comparisons of family_bound vs bound_variants for v1/v2 0.3/ts200/prf2/split810/all3)")
    print(f"space: {len(hds)} (h,d) x {len(kas)} (k,a) x {len(triples)} (w,l,T) -> {N} valid sets "
          f"(sig <= {SIG_CAP} B, h+k*a <= 256, both grinds fail <= 2^-40, l*log2 w in [128,256], l in lmin..lmin+4, "
          f"T from mode-10 up, step 2 for w=16)")
    print(f"  compact address: {int(G['asis'].sum())} sets fit the v2 0.3 A7 layout as-is (d<=2, h<=18, h'<=9, l<=64, "
          f"a<=11); {int(((G['addr'] <= 56) & ~G['asis']).sum())} fit 56 bits only after a re-layout; "
          f"{int((G['addr'] > 56).sum())} need > 56 bits (H no longer one block: cost model void, excluded from every "
          f"frontier)\n")

    print("(1) STOCK v1 = v2 0.3 parameters: h=18 d=2 a=11 k=13 w=8 l=43 T=205 n=16 (identical rows under the v2-driver model)")
    pc = fb.pass_components(fb.STOCK)
    pcb = fb.pass_components(fb.STOCK, fb.UNITS_SHARES)
    print("  sign pass, v2 one-block driver, M cycles   model(brief units)  model(share-implied units)  measured share")
    meas = dict(keyloop=32.1, fors=7.85, search=7.32, tl=1.2, rgrind=0.95)
    for key in pc:
        ms = f"{meas[key]:.2f}" if key in meas else "-"
        print(f"    {key:9s} {pc[key] / 1e6:22.3f} {pcb[key] / 1e6:24.3f} {ms:>16s}")
    print(f"    {'total':9s} {stock['passA'] / 1e6:22.3f} {stock['passB'] / 1e6:24.3f} {50.35:16.2f}   "
          f"(brief units: {100 * (stock['passA'] / 50.35e6 - 1):+.2f}% vs measured mean 50.35 M)")
    print(f"    note: FORS counted as k=13 full trees (c10v2_ref.sign builds K trees; 13 x 6143 x 97.7 = 7.80 M vs 7.85 M"
          f" measured); the brief's (k-1)=12-tree count gives 7.20 M and a {(stock['passA'] - 6143 * 97.7) / 1e6:.2f} M pass."
          f" Search: expected {2 * tries[X0]:.0f} tries/sign x 103 = 6.32 M; the 7.32 M share implies 119 cyc/try.")
    print(f"  cached sign (2 passes + verify ~0.2 M): {stock['cycA'] / 1e6:.2f} M (brief units), {stock['cycB'] / 1e6:.2f} M "
          f"(share units) = {stock['cycA'] / 160e6:.3f} s at 160 MHz.  v1 (two-block driver, product path): measured "
          f"89.97 M/pass (research driver, opt3), not modelled.")
    print(f"  verify: {stock['calls']} SHA-256 calls; callee gas {stock['callee']:.0f} (floor {fb.gas_floor(fb.STOCK)} + "
          f"{float(fb.GAS_OVERHEAD):.2f}/call overhead, calibrated to the Track B v2 0.3 head 100,600) + calldata "
          f"{stock['calldata']} = {stock['gas']:.0f}.  v1 callee per ledger: floor 73,756, HEAD ~111.8k (not modelled)")
    print(f"  sig {stock['sig']} B; Lean floor {stock['fl']} b (Grover convention {stock['flq']}); at C=2: "
          f"{fb.lean_floor_bits(128, 17, 11, 13)}, C=16: {stock['fl16']}")
    print(f"  EC-shape bound @ qr=qs=2^16: ordinary {stock['ord']:.4e} (2^{lg2(stock['ord']):.3f}), wrapper "
          f"{stock['wrap']:.4e} (2^{lg2(stock['wrap']):.3f})")
    covs = {C: (cov[(18, 13, 11, 'o', C)], cov[(18, 13, 11, 'w', C)]) for C in CS}
    print("  coverage term (ordinary / wrapper): " + "; ".join(f"C={C}: 2^{lg2(o):.1f} / 2^{lg2(w_):.1f}" for C, (o, w_) in covs.items()))
    fine = [x for x in triples if csamp[x] == refine_samples]
    ses = [cstat[x][1] for x in fine]
    print(f"  (c) two-use WOTS margin: {c_stock:.2f} b median, SE {cstat[X0][1]:.2f} ({refine_samples} samples, fixed seed; "
          f"legacy 4000-sample main(): 55.25). {len(fine)} triples at {refine_samples} samples (SE {min(ses):.2f}.."
          f"{max(ses):.2f} b): {len(near)} within reach of a mark boundary + {len(closure)} closing the reported "
          f"frontiers ({closure_rounds} re-sweeps; every frontier row below is at {refine_samples}); the other "
          f"{len(triples) - len(fine)} at {samples} (SE ~{np.median([cstat[x][1] for x in triples if x not in fine] or [0]):.2f} b)."
          f" Row deltas print +-SE of the DIFFERENCE, ~sqrt(se_row^2 + se_stock^2) (one seed does not couple different l);"
          f" a delta within ~2 of those SEs of 0 is not an established ordering.")
    print(f"  (d, ours) FORS+C multi-use per-H_MSG-try bits: {stock['dq1']:.1f} at 2^16 sigs, {stock['dq16']:.1f} at 2^20 (C=16)")
    print(f"  grind: {tries[X0]:.1f} WOTS+C tries/WOTS sig, 2^11 R nonces; P[exhaust 10M] = 2^{fb.grind_fail_log2(fb.STOCK):.0f}\n")

    tot = np.bincount(G["mark"], minlength=3)
    totT = np.bincount(G["markT"], minlength=3)
    print(f"marks over {N} sets: PASS {tot[0]}, MINOR-LOSS {tot[1]}, FAIL {tot[2]} (every-term reading, column `mark`); "
          f"totals reading (column `mark_totals`: the same bit metrics + both games' totals at C=1,2,16 only): "
          f"PASS {totT[0]}, MINOR-LOSS {totT[1]}, FAIL {totT[2]}")
    dvec = np.array([d_ for _, d_ in hds])[G["hd"]]
    print("  PASS by d, every-term / totals: " + ", ".join(
        f"d={d_}: {int(((G['mark'] == 0) & (dvec == d_)).sum())} / {int(((G['markT'] == 0) & (dvec == d_)).sum())}"
        for d_ in sorted({d_ for _, d_ in hds})))
    print("mark rule: loss = max over [stock - set] of the bit metrics (Lean floor classical and Grover at C=1,2,16;\n"
          "  one-time digest-match exponent log2(w^l), stock 129; (c))\n"
          "  and log2(set/stock) of the bound metrics (ordinary and wrapper totals at C=1; EVERY returned term - node, zero,\n"
          "  encoding, wots, fors, coverage, prefix - of both games at C=1,2,16: a better total cannot hide a worse term). PASS: loss <= 0; MINOR-LOSS: 0 < loss <= 1 (<= 1 bit / <= 2x); FAIL: loss > 1.\n"
          "  The Lean floor is min(k*a, 112, 96) at n=16: it never moves for k*a >= 96. (d) is reported, not marked.\n")

    def line(j, tag=""):
        r = scalar_row(params(j))
        check(j, r)
        p = r["p"]
        drv = DRIVERS[G["drv"][j]] if G["mark"][j] else "-"
        flags = []
        if r["dq1"] < stock["dq1"] - 1:
            flags.append("(d)")
        if r["perm"]:
            flags.append("perm>4blk")
        flags.append("asis" if G["asis"][j] else f"relayout{int(G['addr'][j])}b")
        if (p["w"], p["l"], p["T"], p["k"], p["a"], p["h"], p["d"]) == (8, 43, 205, 13, 11, 18, 2):
            tag = "STOCK/v2 0.3"
        return (f"  h{p['h']:2d} d{p['d']} h'{p['h'] // p['d']:2d} a{p['a']:2d} k{p['k']:2d} w{p['w']:2d} l{p['l']:2d} "
                f"T{p['T']:3d} | {r['sig']:4d} B | pass {r['passA'] / 1e6:6.1f} cached {r['cycA'] / 1e6:6.1f} "
                f"({r['cycB'] / 1e6:6.1f}) M | gas {r['callee']:7.0f}+{r['calldata']:5d} | floor {r['fl']}/{r['flq']:.0f} "
                f"(d{r['fl'] - stock['fl']:+.0f}/{r['flq'] - stock['flq']:+.1f}) | EC x{r['ord'] / stock['ord']:.3g}/"
                f"x{r['wrap'] / stock['wrap']:.3g} worst term 2^{G['wterm'][j]:+.2f} | enc {r['enc'] - stock['enc']:+d} | "
                f"(c) {r['c']:.1f} ({r['c'] - c_stock:+.2f}+-{math.hypot(G['cse'][j], cstat[X0][1]):.2f} n{int(G['csamp'][j])}) | "
                f"(d) {r['dq1'] - stock['dq1']:+.1f} | {MARKS[G['mark'][j]]}"
                f" loss {G['loss'][j]:+.2f} [{drv}] {' '.join(flags)} {tag}")

    hdr = ("  params                                     | sig    | M cycles: pass, cached (share units) | gas callee+calldata |"
           " Lean floor cls/Grover (delta) | EC ord/wrap ratio, worst cov|fors log2 ratio | (c) b (delta) | (d) delta | mark")

    def show(front, title, limit):
        """One line per frontier shape (h, d, a, k, w, l): its cheapest-cycle member, plus the T values on the frontier."""
        order = front[np.argsort(G["cycA"][front], kind="stable")]
        shapes = {}
        for j in order.tolist():
            p = params(j)
            shapes.setdefault((p["h"], p["d"], p["a"], p["k"], p["w"], p["l"]), []).append(j)
        print(f"{title}: {len(front)} sets ({len(shapes)} shapes) on the frontier; first {min(limit, len(shapes))} "
              f"shapes by cached cycles (row = cheapest member; Ts = frontier T values)")
        print(hdr)
        for js in list(shapes.values())[:limit]:
            ts = sorted(params(j)["T"] for j in js)
            print(line(js[0]) + f" Ts {ts[0]}..{ts[-1]} ({len(ts)})")
        print()
        return order

    print("(2)/(3) Pareto frontiers over (cached-sign cycles [brief units], verify gas incl. calldata, signature bytes)\n")
    o_all = show(f_all, "ALL kept sets (any mark)", 15)
    o_pass = show(f_pass, "PASS-only sets", 40)
    o_pm = show(f_pm, "PASS + MINOR-LOSS sets", 15)
    o_asis = show(f_asis, "PASS sets that fit the v2 0.3 compact address as-is", 25)
    show(f_pm_asis, "PASS + MINOR-LOSS sets that fit the v2 0.3 compact address as-is", 15)
    print("TOTALS READING (mark_totals): rows below still print the every-term mark; their totals mark is PASS")
    show(f_passT, "PASS sets, totals reading", 25)
    show(f_passT_asis, "PASS sets that fit A7 as-is, totals reading", 15)
    show(f_small, f"PASS sets with sig <= {stock['sig']} B", 15)
    lmin_w = {4: 64, 8: 43, 16: 32}
    loff = sorted({(params(j)["w"], params(j)["l"] - lmin_w[params(j)["w"]]) for j in f_pass.tolist()})
    print(f"(w, l - lmin) on the PASS frontier: {loff}; a values: "
          f"{sorted({params(j)['a'] for j in f_pass.tolist()})} (search range 8..16)")
    sa, sb_ = set(f_pass.tolist()), set(f_passB.tolist())
    print(f"robustness: PASS frontier under share-implied unit costs has {len(sb_)} sets; {len(sa & sb_)} shared with the "
          f"brief-unit frontier ({len(sa - sb_)} drop out, {len(sb_ - sa)} enter)")
    stock_j = np.nonzero((G["hd"] == hds.index((18, 2))) & (G["xi"] == Xi[X0]) & (G["yi"] == kas.index(Y0)))[0]
    if len(stock_j):
        j0 = int(stock_j[0])
        dom = np.nonzero((G["cycA"] <= G["cycA"][j0]) & (G["gas"] <= G["gas"][j0]) & (G["bytes"] <= G["bytes"][j0])
                         & (G["mark"] == 0))[0]
        print(f"stock is {'ON' if j0 in sa else 'NOT on'} the PASS frontier; {len(dom) - 1} PASS sets weakly dominate it\n")

    # n = 24 exploration rows (flag (b)); not part of the sweep
    print("n=24 exploration (flag (b): 192-bit truncation of SHA-256; H = 3n+7 = 79 B needs 2 blocks; n!=16 lengths assumed):")
    ex = [full(18, 2, X0, Y0, 24)] + [dict(params(j), n=24) for j in o_pass[:3].tolist()]
    for p in ex:
        r = scalar_row(p)
        print(f"  h{p['h']} d{p['d']} a{p['a']} k{p['k']} w{p['w']} l{p['l']} T{p['T']} n24 | {r['sig']} B | cached "
              f"{r['cycA'] / 1e6:.1f} M | gas {r['callee']:.0f}+{r['calldata']} | floor {r['fl']}/{r['flq']:.0f} | "
              f"EC x{r['ord'] / stock['ord']:.2e}/x{r['wrap'] / stock['wrap']:.2e} | (c) {r['c']:.1f} | (b)")
    print()

    names, rows = _reproof_note(fb)
    print("re-proof cost (parameter-specific literals; word-boundary token counts, upper bounds on what must change):")
    for i, name in enumerate(names):
        print(f"  {name}:")
        for g, cells in rows:
            print(f"    {g:40s} {cells[i]}")
    print("  Every EasyCrypt cost lemma above is stated with literal budgets (155135, 364892, 771, 53386, ...), the coordinate\n"
          "  universes enumerate range 0 43 / 0 7 / 0 512 / 0 2048 / 0 12, RawWots digits are `digits 3 43`, and the shuffle\n"
          "  is 4 blocks: any set off (w=8, l=43, a=11, k=13, h'=9, d=2) re-states the cost, universe and encoding lemmas;\n"
          "  T alone moves only count_ds 43 8 T (WotsAcceptanceMass) and the T literals.\n")

    # TSV: PASS and MINOR-LOSS sets plus every frontier set
    keep = np.union1d(np.nonzero(G["mark"] <= 1)[0], np.concatenate([f_all, f_pass, f_pm, f_passB, f_small, f_asis, f_pm_asis, f_passT, f_passT_asis]))
    keep = np.union1d(keep, np.nonzero(G["markT"] <= 1)[0])
    fasis, fpma = set(f_asis.tolist()), set(f_pm_asis.tolist())
    fpT, fpTa = set(f_passT.tolist()), set(f_passT_asis.tolist())
    fa, fp, fpm = set(f_all.tolist()), set(f_pass.tolist()), set(f_pm.tolist())
    import os
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "family_search.tsv")
    cols = ["h", "d", "hp", "a", "k", "w", "l", "T", "n", "sig_bytes", "cached_Mcyc_brief", "cached_Mcyc_shares",
            "gas_total", "lean_floor_cls", "lean_floor_grover", "ec_ord_ratio", "ec_wrap_ratio",
            "worst_term_log2ratio", "enc_delta_bits", "c_margin_delta_bits", "c_samples", "c_median_se_bits", "c_delta_se_bits",
            "d_fors_multiuse_delta_bits",
            "floor_delta_cls_C1", "floor_delta_cls_C2", "floor_delta_cls_C16", "floor_delta_grover_C1",
            "floor_delta_grover_C2", "floor_delta_grover_C16", "addr_bits", "flags", "mark", "loss_bits",
            "driver", "front_all", "front_pass", "front_pass_minor", "front_pass_asis", "front_pass_minor_asis", "mark_totals", "loss_totals_bits", "driver_totals",
            "front_pass_totals", "front_pass_totals_asis"]
    with open(path, "w") as fh:
        fh.write("# family_search.tsv — format_options_numerics.py search (" + time.strftime("%Y-%m-%d") +
                 f"); SUBSET of {N} valid sets: PASS/MINOR-LOSS under either reading (mark, mark_totals) + every frontier set; stock cached {stock['cycA'] / 1e6:.3f} M, gas "
                 f"{stock['gas']:.0f}, c {c_stock:.3f} b, samples {samples} coarse / {refine_samples} refined (per-row c_samples)\n")
        fh.write("\t".join(cols) + "\n")
        for j in keep.tolist():
            p = params(j)
            ka = (p["k"], p["a"])
            fh.write("\t".join(str(v) for v in (
                p["h"], p["d"], p["h"] // p["d"], p["a"], p["k"], p["w"], p["l"], p["T"], 16, int(G["bytes"][j]),
                f"{G['cycA'][j] / 1e6:.3f}", f"{G['cycB'][j] / 1e6:.3f}", f"{G['gas'][j]:.0f}",
                fb.lean_floor_bits(128, 16, ka[1], ka[0]), fb.lean_floor_bits_grover(128, 16, ka[1], ka[0]),
                f"{G['ord'][j]:.5g}", f"{G['wrap'][j]:.5g}", f"{G['wterm'][j]:.3f}", p["l"] * fb.log2w(p["w"]) - 129, f"{G['cdel'][j]:.3f}", int(G["csamp"][j]),
                f"{G['cse'][j]:.3f}", f"{math.hypot(G['cse'][j], cstat[X0][1]):.3f}",
                f"{G['dq1'][j]:.2f}",
                *[fb.lean_floor_bits(128, 16 + math.log2(C), ka[1], ka[0]) - fb.lean_floor_bits(128, 16 + math.log2(C), 11, 13)
                  for C in CS],
                *[fb.lean_floor_bits_grover(128, 16 + math.log2(C), ka[1], ka[0])
                  - fb.lean_floor_bits_grover(128, 16 + math.log2(C), 11, 13) for C in CS],
                int(G["addr"][j]),
                ",".join(f for f in ("asis" if G["asis"][j] else ("relayout" if G["addr"][j] <= 56 else "addr>56"),
                                     "perm>4blk" if p["l"] > 65 else "", "(d)" if G["dq1"][j] < -1 else "") if f),
                MARKS[G["mark"][j]], f"{G['loss'][j]:.3f}",
                DRIVERS[G["drv"][j]] if G["mark"][j] else "-", int(j in fa), int(j in fp), int(j in fpm),
                int(j in fasis), int(j in fpma), MARKS[G["markT"][j]], f"{G['lossT'][j]:.3f}",
                DRIVERS_T[G["drvT"][j]] if G["markT"][j] else "-", int(j in fpT), int(j in fpTa))) + "\n")
    print(f"wrote family_search.tsv ({len(keep)} rows)")
    print(f"runtime: total {time.time() - t0:.1f} s (sweep {t_sweep:.1f} s incl. (c): {len(triples)} triples x "
          f"{samples} samples {t_c:.1f} s + {len(near) + len(closure)} x {refine_samples} {t_r:.1f} s)")


if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "search":
    search_main()
