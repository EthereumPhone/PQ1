#!/usr/bin/env python3
"""family_bound.py — the C10 SPHINCS+C cost and bound formulas generalised to a
parameter family (research, #1155 follow-up; 2026-11-14).

Family: h (hypertree height), d (layers; h' = h/d unless explicit per-layer heights
are given), a (FORS tree height), k (FORS trees; FORS+C forces the last tree's index
to 0), w (Winternitz base, power of 2), l (WOTS+C chains, no checksum), T (target
digit sum), n (hash output bytes, 16 = stock). Stock C10: h=18 d=2 a=11 k=13 w=8
l=43 T=205 n=16.

Stdlib only. Every formula takes a backend B (EXACT = fractions, FLOAT = Python
float from exact ints, or a numpy backend supplied by the caller) so the SAME code
is anchored exactly against bound_variants.py and then swept in floats.

CONSTANT -> FORMULA -> SOURCE (cdrafts-split/*.ec unless noted). "read" = the
parameter dependence is visible in the cited lemma; "ASSUMPTION" = it is not.

  303 leaf+merge   l(w-1)+2           DomainKeygenCost.domain_leaf_cost (302 = 43*7 chain
                                      steps + 1 T_l; PRF secrets are not node queries) + 1 H
                                      per leaf in DomainMerkleCost.domain_merkle_build_cost   read
  155135 build     (l(w-1)+2)2^h'-1   domain_merkle_build_cost (512 leaves, stack invariant)  read
  305 wots sign    perm + l(w-1)      DomainWotsCost.domain_wots_sign_cost (4 + 43*7)        read
  303 recover      l(w-1)+2           domain_wots_recover_cost (1 digest + 43*7 + 1 T_l)      read
  9 / 312          h'                 domain_merkle_recover_cost                             read
  155753 layer     build+1+305+303+h' DomainLayerCost.domain_layer_sign_cost                 read
  4 perm blocks    max(4, ceil(2(m-1)/32))  RawShuffle.permutation hard-codes 4 blocks of 32 B,
                                      2 B per Fisher-Yates swap: 4 is enough for m <= 65 items.
                                      ASSUMPTION above 65 (w=4 sets with l >= 66)
  53386 forest     1 + perm + (k-1)(2^(a+1)-1 + a+1) + (2^(a+1)-1) + 2
                                      DomainForestCost.domain_forest_sign_cost (the last tree
                                      is built as a full root, domain_fors_root_cost)         read
  146 / 771        (k-1)(a+1)+2 ;  1 + 146 + sum(l(w-1)+2+h')
                                      domain_forest_recover_cost; signer_verify_*_cost        read
  3*signing_budget (1+d)*GRIND_CAP    RawSignerCost.signer_sign_public_cost (role grind 1x +
                                      one count grind per layer, `layer*(signing_budget+...)`) read
  2*qs exceptional 2 (structural)     AddressedSignerExceptionCount: forest sign adds 2,
                                      layers 0; tied to the FORS+C last tree, not to k, a     read
  4qs+2 / 10qs+2   2d qs + d ; 5d qs + d   WotsSignerCount ("signer adds at most four ...
                                      both reconstructions; verification adds at most two",
                                      per-layer `c+2*layer`); WrapperWotsCount (2 signs x 2d +
                                      verify d)                                              read
  +86 / +88        d*l (+2)           ChainByteCandidates.wots_output_candidates_size
                                      (43 x 2 layers) ; +2 = the two fixed values in
                                      ChainCandidateMass.chain_candidate_cover                read
  +12 / +14        k-1 (+2)           ClientGuessCandidates (range 0 12 tree secrets)        read
  8 (chain vector) w                  ChainVectorInstall / DigestVectorSampling: d0..d7 =
                                      secret + 7 chain steps = the w chain values             read
  301 cuts         l(w-1)             WotsCoordinateUniverse.key_cuts                        read
  2^18 + 512 keys  sum_i 2^(h - h_0 - .. - h_{i-1})   WotsCoordinateUniverse.wots_keys (bottom
                                      2^18, top 512). Only d=2 is in the source: the d != 2
                                      key universe is an ASSUMPTION (one key per leaf of every
                                      layer, which is what the d=2 list enumerates)
  2^18*12*2^11     2^h (k-1) 2^a      ForsCoordinateUniverse.ordinary_fors_coordinates        read
  727934 wrapper   2*(forest + sum(build+1+perm)) + d*l(w-1)
                                      WrapperWotsCandidateCost (plan 363666 = 53386 +
                                      2*155140; release 602 = while layer<=2 of 301)          read
  coverage         sum_{j=1}^{k-1} n*falling(n-1,j)*S(k-1,j) / 2^((k-1)a + h j)
                                      StirlingCoverageBound + SelectedCoverageMass
                                      (target matches each witness on 18 hypertree bits and
                                      the assigned 11-bit indices of 12 trees)               read
  2^129 / 2^258    w^l, w^(2l)        WotsAcceptanceMass (count_ds 43 8 205 * 2^-129);
                                      AcceptedEncodingPool                                    read
  2^128            2^(8n)             node width (16-byte nodes)                             read
  2^256            2^256              SHA-256 output (prefix term)                           read
  GRIND_CAP 10M    10M (fixed)        C10Counter.signing_budget. ASSUMPTION that the cap stays
                                      10M: the search requires P[grind exhausts] <= 2^-40 so the
                                      cap is never the binding failure mode

SCOPE: the anchor (assert_anchor) proves only that the generalisation reproduces the
v1 numbers exactly, including T=200 (exercises A) and the (8, 10) split (exercises
the per-layer heights). At d=2, k-1=12, l=43 several readings coincide (2d = d+2,
5d = 3d+4, ...), so the anchor cannot distinguish them: the readings above are taken
from the lemmas, not from the anchor. Nothing here is a proof for another parameter
set: the EasyCrypt programs hard-code 43 chains, 512-leaf 9-level trees, 12+1 FORS
trees of 2048 leaves and digits of 3 bits.
"""
import math
from fractions import Fraction
from functools import lru_cache

import bound_variants as bv

GRIND_CAP = bv.GRIND_CAP
EXC_PER_SIGN = 2
STOCK = dict(h=18, d=2, a=11, k=13, w=8, l=43, T=205, n=16)


class _Backend:
    def __init__(self, name, R, mn, pow2):
        self.name, self.R, self.mn, self.pow2 = name, R, mn, pow2


EXACT = _Backend("exact", Fraction, min, lambda e: 2 ** e)
FLOAT = _Backend("float", lambda a, b: a / b, min, lambda e: 2 ** e)   # int/int: correctly rounded


# ── digit counts and Stirling numbers ────────────────────────────────────────
@lru_cache(None)
def digit_rows(l, w):
    """rows[r][s] = #{vectors in [0,w-1]^r with sum s}, r = 0..l (exact ints)."""
    rows = [[1]]
    for _ in range(l):
        prev = rows[-1]
        pref = [0]
        for x in prev:
            pref.append(pref[-1] + x)
        top = len(prev) - 1 + (w - 1)
        rows.append([pref[min(s, len(prev) - 1) + 1] - pref[max(0, s - w + 1)] for s in range(top + 1)])
    return rows


def digit_count(l, w, T):
    row = digit_rows(l, w)[l]
    return row[T] if 0 <= T < len(row) else 0


def stirling(m, j):
    return bv.stirling(m, j)


def log2w(w):
    b = w.bit_length() - 1
    assert 1 << b == w, "w must be a power of 2"
    return b


def perm_blocks(items):
    return max(4, -(-2 * (items - 1) // 32))


def heights(p):
    hs = p.get("layers") or (p["h"] // p["d"],) * p["d"]
    assert len(hs) == p["d"] and sum(hs) == p["h"], p
    return tuple(hs)


# ── EasyCrypt-shape constants (node-domain budgets, universes) ──────────────
def build(hp, l, w):
    return (l * (w - 1) + 2) * 2 ** hp - 1


def consts_g(p):
    h, d, a, k, w, l, T = (p[x] for x in ("h", "d", "a", "k", "w", "l", "T"))
    n = p.get("n", 16)
    hs = heights(p)
    chain = l * (w - 1)
    pw, pf = perm_blocks(l), perm_blocks(k - 1)
    tree = 2 ** (a + 1) - 1
    fors_sign = 1 + pf + (k - 1) * (tree + a + 1) + tree + 2
    layer_sign = [build(x, l, w) + 1 + (pw + chain) + (chain + 2 + x) for x in hs]
    nwots, below = 0, 0
    for x in hs:
        nwots += 2 ** (h - below)
        below += x
    wrapper_plan = fors_sign + sum(build(x, l, w) + 1 + pw for x in hs)
    return dict(
        p=dict(p), d=d, nbits=8 * n, digit_bits=l * log2w(w), A=digit_count(l, w, T),
        keygen=build(hs[-1], l, w), fors_sign=fors_sign, sign=fors_sign + sum(layer_sign),
        verify=1 + (k - 1) * (a + 1) + 2 + sum(chain + 2 + x for x in hs),
        wrapper_wots=2 * wrapper_plan + d * chain,
        wots_universe=w * chain * nwots, fors_universe=2 ** h * (k - 1) * 2 ** a,
        dl=d * l, km1=k - 1, perm_assumed=(pw > 4 or pf > 4),
    )


# ── coverage term ────────────────────────────────────────────────────────────
def coverage_g(nq, h, k, a, B=EXACT):
    total, fall = None, 1
    for j in range(1, k):
        fall *= max(0, nq - j)            # falling(nq-1, j) = prod_{i<j} max(0, nq-1-i)
        term = B.R(nq * fall * stirling(k - 1, j), B.pow2((k - 1) * a + h * j))
        total = term if total is None else total + term
    return total


# ── the two numerical bounds (shape of bound_variants.ordinary / wrapper) ────
def ordinary_terms(qr, qs, c, B=EXACT, coverage=None):
    K, S, V0, A, d = c["keygen"], c["sign"], c["verify"], c["A"], c["d"]
    N, D = B.pow2(c["nbits"]), B.pow2(c["digit_bits"])
    q = K + qr + qs * ((1 + d) * GRIND_CAP + S) + V0
    cand = K + qr + qs * S + V0
    exc = qr + EXC_PER_SIGN * qs + V0
    nW = qr + 2 * d * qs + d
    Uw, Uf, dl, km1 = c["wots_universe"], c["fors_universe"], c["dl"], c["km1"]
    if coverage is None:
        pp = c["p"]
        coverage = coverage_g(qr + qs + 1, pp["h"], pp["k"], pp["a"], B)
    t = {
        "node": B.mn(B.R(cand * (cand - 1), 2 * N), B.R(exc * (exc + 1), N)),
        "zero": B.R(q, N),
        "encoding": B.mn(B.R(q * (q - 1) * A, 2 * D * D), B.R(nW * (nW - 1), 2 * A)),
        "wots": B.mn(B.R(Uw * (q + dl), N), B.R(Uw * (cand + dl + 2), N)),
        "fors": B.mn(B.R(Uf * (q + km1), N), B.R(Uf * (cand + 2 + km1), N)),
        "coverage": coverage,
        "prefix": B.R(q, B.pow2(256)),
    }
    return q, t


def wrapper_terms(qr, qs, c, B=EXACT, coverage=None, pool=True):
    K, S, V0, A, d = c["keygen"], c["sign"], c["verify"], c["A"], c["d"]
    N, D = B.pow2(c["nbits"]), B.pow2(c["digit_bits"])
    q = K + qr + qs * (2 * ((1 + d) * GRIND_CAP + S) + V0) + V0
    wots = K + qr + qs * c["wrapper_wots"] + V0
    leaf = K + qr + qs * (2 * S + V0) + V0
    exc = qr + (2 * EXC_PER_SIGN + V0) * qs + V0
    Uw, Uf, dl, km1 = c["wots_universe"], c["fors_universe"], c["dl"], c["km1"]
    if coverage is None:
        pp = c["p"]
        coverage = coverage_g(qr + 3 * qs + 1, pp["h"], pp["k"], pp["a"], B)
    t = {
        "node": B.mn(B.R(q * (q - 1), 2 * N), B.R(exc * (exc + 1), N)),
        "zero": B.R(q, N),
        "encoding": B.R(q * (q - 1), 2 * D) * B.R(A, D),
        "wots": B.R(Uw * (wots + dl + 2), N),
        "fors": B.mn(B.R(Uf * (q + km1), N), B.R(Uf * (leaf + 2 + km1), N)),
        "coverage": coverage,
        "prefix": B.R(q, B.pow2(256)),
    }
    if pool:
        nw = qr + 5 * d * qs + d
        t["encoding"] = B.mn(t["encoding"], B.R(nw * (nw - 1), 2 * A))
    return q, t


# ── Quantitative.lean floor ──────────────────────────────────────────────────
def lean_floor_bits(nbits, qbits, a, k):
    """securityFloorBits = min(forsCBits = (k-1)a + a, n - qBits, n - 2 qBits). qbits may be
    fractional (16 + log2 C for the P14 cross-chain bootstrap budget)."""
    return min(k * a, nbits - qbits, nbits - 2 * qbits)


def lean_floor_bits_grover(nbits, qbits, a, k):
    """CONVENTION only (every term halved); not a QROM theorem."""
    return lean_floor_bits(nbits, qbits, a, k) / 2


# ── our own extra column (d): SPHINCS+-style FORS+C multi-use estimate ───────
def fors_multiuse_bits(h, k, a, qs):
    """-log2 of the per-H_MSG-try forgery probability against FORS+C after qs signatures:
    2^-a (forced-zero tree) * sum_r Pois(r; qs/2^h) * (1 - (1-2^-a)^r)^(k-1).
    Standard few-time estimate (classical), NOT a term of either proof; ours."""
    lam = qs / 2 ** h
    tot, pr, r = 0.0, math.exp(-lam), 0
    while True:
        r += 1
        pr *= lam / r
        cov = (1.0 - (1.0 - 2.0 ** -a) ** r) ** (k - 1)
        tot += pr * cov
        if r > lam + 60 and pr < 1e-30:
            break
    return a - math.log2(tot)


# ── signature size, verifier calls, gas ─────────────────────────────────────
def sig_bytes(p):
    n = p.get("n", 16)
    return n * (2 + (p["k"] - 1) * (p["a"] + 1)) + sum(4 + (p["l"] + x) * n for x in heights(p))


def verify_calls(p):
    """[(count, input bytes)] for the v2 one-block verifier. n=16: F 39, H 55, WOTS_DIGEST 43,
    H_MSG 87, T_l 16+8+l*n, T_k 16+8+k*n (Track B ledger). For n != 16 the lengths are an
    ASSUMPTION: F 2n+7, H 3n+7, WOTS_DIGEST 2n+11, H_MSG 3n+39, T_x n+8+x*n."""
    n, k, a, w, l, T = (p.get("n", 16), p["k"], p["a"], p["w"], p["l"], p["T"])
    F, H, WD, HM = 2 * n + 7, 3 * n + 7, 2 * n + 11, 3 * n + 39
    calls = [(1, HM), (k - 1, F), ((k - 1) * a, H), (1, F), (1, n + 8 + k * n)]
    for x in heights(p):
        calls += [(1, WD), (l * (w - 1) - T, F), (1, n + 8 + l * n), (x, H)]
    return calls


def n_calls(p):
    return sum(c for c, _ in verify_calls(p))


def gas_floor(p):
    return sum(c * (100 + 60 + 12 * (-(-ln // 32))) for c, ln in verify_calls(p))


GAS_STOCK_V2 = 100_600                      # Track B ledger, v2 0.3 head (callee-only)
GAS_OVERHEAD = Fraction(GAS_STOCK_V2 - gas_floor(STOCK), n_calls(STOCK))


def gas_callee(p):
    return gas_floor(p) + GAS_OVERHEAD * n_calls(p)


def gas_calldata(p):
    sb, d = sig_bytes(p), p["d"]
    return 16 * (sb - d) + 4 * d           # top byte of each 4-byte count is zero


def split_costs(p):
    """Separable parts used by the vectorised sweep: 'fors' depends on (k, a, n), 'layer' on
    (d, heights, w, l, T, n). The sweep re-checks the recombined totals against the scalar
    functions on every reported row."""
    calls = verify_calls(p)
    fl = lambda cs: sum(c * (160 + 12 * (-(-ln // 32))) for c, ln in cs)
    pc = pass_components(p, UNITS_BRIEF)
    pb = pass_components(p, UNITS_SHARES)
    n = p.get("n", 16)
    fk = ("fors", "rgrind")
    return dict(
        fors=dict(gas_floor=fl(calls[:5]), calls=sum(c for c, _ in calls[:5]),
                  bytes=n * (2 + (p["k"] - 1) * (p["a"] + 1)),
                  cycA=sum(pc[x] for x in fk), cycB=sum(pb[x] for x in fk)),
        layer=dict(gas_floor=fl(calls[5:]), calls=sum(c for c, _ in calls[5:]),
                   bytes=sum(4 + (p["l"] + x) * n for x in heights(p)),
                   cycA=sum(v for x, v in pc.items() if x not in fk + ("glue",)),
                   cycB=sum(v for x, v in pb.items() if x not in fk + ("glue",))),
    )


# ── device cycle model (v2 one-block driver, one signing pass, 160 MHz) ──────
MEASURED_V2_PASS = 50.35e6
MEASURED_SHARES = dict(keyloop=32.1e6, fors=7.85e6, search=7.32e6, tl=1.2e6, rgrind=0.95e6)
UNITS_BRIEF = dict(keyloop=91.7, fors=97.7, grind=103.0, tl12=862.0, block=62.0, hnode=169.0,
                   rgrind=465.0, glue=2.7e6)
VERIFY_CYC_STOCK = 0.2e6


def _blocks(nbytes):
    return -(-(nbytes + 9) // 64)


def _counts(p):
    """Hash-call counts behind the cycle model (one signing pass)."""
    hs, l, w, T, a, k, n = heights(p), p["l"], p["w"], p["T"], p["a"], p["k"], p.get("n", 16)
    A = digit_count(l, w, T)
    return dict(
        keyloop=sum(2 ** x for x in hs) * l * w,          # per leaf: l PRF + l(w-1) chain steps
        tl=sum(2 ** x for x in hs),                        # one T_l per leaf
        tl_blocks=_blocks(n + 8 + l * n),
        hnode=sum(2 ** x - 1 for x in hs),
        wsign=p["d"] * (l + T),                            # l PRF + T steps per WOTS signature
        search=p["d"] * (w ** l / A),                      # expected WOTS+C grind tries
        fors=k * (3 * 2 ** a - 1),                         # k full trees (c10v2_ref.sign builds K)
        fors_h=k * (2 ** a - 1),
        rgrind=2 ** a,                                     # expected R nonces (2^-a zero condition)
        extra_h_blocks=_blocks(3 * n + 7) - 1,             # 0 at n=16 (H fits one block)
    )


def units_shares():
    """Unit costs implied by the measured per-component shares of the stock v2 0.3 pass."""
    c = _counts(STOCK)
    u = dict(keyloop=MEASURED_SHARES["keyloop"] / c["keyloop"],
             fors=MEASURED_SHARES["fors"] / c["fors"],
             grind=MEASURED_SHARES["search"] / c["search"],
             tl12=MEASURED_SHARES["tl"] / c["tl"], block=62.0, hnode=169.0,
             rgrind=MEASURED_SHARES["rgrind"] / c["rgrind"])
    rest = (c["hnode"] * u["hnode"] + c["wsign"] * u["keyloop"])
    u["glue"] = MEASURED_V2_PASS - sum(MEASURED_SHARES.values()) - rest
    return u


UNITS_SHARES = units_shares()


def pass_components(p, u=UNITS_BRIEF):
    c = _counts(p)
    tl_cyc = u["tl12"] + u["block"] * (c["tl_blocks"] - 12)
    xb = c["extra_h_blocks"] * u["block"]
    return dict(keyloop=c["keyloop"] * u["keyloop"], tl=c["tl"] * tl_cyc,
                hnode=c["hnode"] * (u["hnode"] + xb), wsign=c["wsign"] * u["keyloop"],
                search=c["search"] * u["grind"], fors=c["fors"] * u["fors"] + c["fors_h"] * xb,
                rgrind=c["rgrind"] * u["rgrind"], glue=u["glue"])


def pass_cycles(p, u=UNITS_BRIEF):
    return sum(pass_components(p, u).values())


def verify_cycles(p):
    return VERIFY_CYC_STOCK * n_calls(p) / n_calls(STOCK)    # ASSUMPTION: per-call scaling


def cached_sign_cycles(p, u=UNITS_BRIEF):
    return 2 * pass_cycles(p, u) + verify_cycles(p)          # FI double compute + verify


def _cbits(x):
    return max(0, (x - 1).bit_length())          # bits to index x values


def addr_bits_needed(p):
    """Bits of the 7-byte compact address (c10v2_ref.a7: type 4, layer 1, tree 18, kp 9, ci 6, cp 4,
    ha 11 = 53 of 56) needed after a re-layout: tree carries the full h-bit hypertree index (FORS
    addresses), kp a leaf index (< 2^h') or FORS tree index (< k), ci a chain index (< l), cp a chain
    position (< w) or tree level (<= a, <= h'), ha a node index (< 2^a, < 2^h'). Above 56 bits the
    address grows, H (3n+7 = 55 B at n=16) needs two blocks and the cost model no longer applies."""
    hm = max(heights(p))
    return (4 + _cbits(p["d"]) + p["h"] + max(hm, _cbits(p["k"])) + _cbits(p["l"])
            + _cbits(max(p["w"] - 1, p["a"], hm) + 1) + max(p["a"], hm))


def addr_fits_asis(p):
    """True if the set fits the v2 0.3 A7 field widths unchanged."""
    hm = max(heights(p))
    return (p["d"] <= 2 and p["h"] <= 18 and hm <= 9 and p["k"] <= 512 and p["l"] <= 64
            and p["a"] <= 11 and p["w"] <= 16)


def grind_fail_log2(p):
    """log2 P[a grind exhausts GRIND_CAP] for the WOTS count grind and the R grind (worst)."""
    pw = digit_count(p["l"], p["w"], p["T"]) / p["w"] ** p["l"]
    return max(GRIND_CAP * math.log2(1 - pw) if pw < 1 else -math.inf,
               GRIND_CAP * math.log2(1 - 2.0 ** -p["a"]))


# ── anchors ──────────────────────────────────────────────────────────────────
def assert_anchor():
    """Exact (rational) reproduction of bound_variants.py, which itself is anchored to the
    project evaluators wots_pool_examples.py / wrapper_nonnode_examples.py."""
    n_caps = bv.anchor()
    caps = [(0, 0), (50000, 50000), (65536, 65536), (1000000, 1000), (2 ** 20, 2 ** 16), (2 ** 16, 2 ** 20)]
    checked = 0
    for name, v in bv.VARIANTS.items():
        ref = bv.consts(**v)
        p = dict(STOCK, T=v["T"], layers=tuple(v["layers"]))
        c = consts_g(p)
        for key in ("A", "keygen", "sign", "verify", "wrapper_wots", "wots_universe", "fors_universe"):
            assert c[key] == ref[key], (name, key, c[key], ref[key])
        for qr, qs in caps:
            for mine, theirs in ((ordinary_terms(qr, qs, c), bv.ordinary(qr, qs, ref)),
                                 (wrapper_terms(qr, qs, c), bv.wrapper(qr, qs, ref)),
                                 (wrapper_terms(qr, qs, c, pool=False), bv.wrapper(qr, qs, ref, pool=False))):
                assert mine[0] == theirs[0] and mine[1] == theirs[1], (name, qr, qs)
                checked += 1
    for T in (190, 200, 205, 210):
        assert digit_count(43, 8, T) == bv.digit_count(43, T)
    s = consts_g(STOCK)
    assert (s["fors_sign"], s["sign"], s["verify"], s["keygen"]) == (53386, 364892, 771, 155135)
    assert sig_bytes(STOCK) == 4008 and n_calls(STOCK) == 361
    assert addr_bits_needed(STOCK) == 53 and addr_fits_asis(STOCK)
    assert gas_floor(STOCK) == 67012                              # Track B ledger floor (v2)
    assert lean_floor_bits(128, 16, 11, 13) == 96 and lean_floor_bits(128, 18, 11, 13) == 92
    assert _counts(STOCK)["fors"] - 3 * 2 ** 11 + 1 == 73716      # brief's (k-1)-tree count + 1 tree
    assert round(STOCK_TRIES := 8 ** 43 / digit_count(43, 8, 205), 1) == 30698.4, STOCK_TRIES
    # float path agrees with the exact path at the stock caps
    for fn in (ordinary_terms, wrapper_terms):
        _, te = fn(65536, 65536, s)
        _, tf = fn(65536, 65536, s, B=FLOAT)
        for key in te:
            assert abs(float(te[key]) - tf[key]) <= 1e-12 * float(te[key]), (fn.__name__, key)
    return n_caps, checked


if __name__ == "__main__":
    print(assert_anchor())
