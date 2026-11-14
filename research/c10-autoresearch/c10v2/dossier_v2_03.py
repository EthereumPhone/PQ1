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
    print("     (corrected after Astra's review: tree 12, the recomputed revealed FORS leaves and the signing PRFs counted)")
    leaves, hp = 2**p["a"], p["h"] // p["d"]
    fors_v2 = p["k"] * leaves                       # the fused signer builds all k trees, siblings reused
    fors_v1 = p["k"] * leaves + (p["k"] - 1)        # v1 also recomputes each revealed leaf's secret
    wots_keygen_layer = 2**hp * p["l"]              # one subtree's WOTS keys per layer, rebuilt per pass
    wots_sign_layer = p["l"]                        # the signed key's chain starts
    wots_nocache = p["d"] * (wots_keygen_layer + wots_sign_layer)
    # warm top cache (#1148): layer 1 rebuilds only the 16-leaf subtree under its leaf (height-4 nodes stored)
    wots_cache = (wots_keygen_layer + wots_sign_layer) + (2**(hp - 5) * p["l"] + wots_sign_layer)
    v1_total = fors_v1
    for label, wots in (("no top cache", wots_nocache), ("warm top cache", wots_cache)):
        v2_total = fors_v2 + wots
        print(f"  {label:15s} v1 {v1_total:,} (FORS PRF; WOTS PRF 0: its sk_seed block is constant per layer)   "
              f"v2 0.3 {v2_total:,} (FORS {fors_v2:,} + WOTS {wots:,})   ratio x{v2_total/v1_total:.3f} ({lg(v2_total/v1_total):.2f} b)")
    print("  an exposure COUNT under one leakage criterion, not traces-to-key-recovery: the SCA comparison is UNKNOWN")
    print(f"  the fix (WOTS PRF with a per-layer-constant sk_seed block) adds {wots_nocache:,} compressions per pass"
          " without the top cache (estimate ~+4 M cycles; to be measured)")

    # round 17 (UPDATE 2026-11-14): gate (c) with the two-block WOTS PRF (`wprf2b`, c10v2_ref.py --variant wprf2b):
    # sk_seed sits in a first block constant per layer, so the WOTS PRF adds 0 to this counter (v1's shape).
    print("  with the two-block WOTS PRF (wprf2b): WOTS adds 0 sk_seed compressions with varying words")
    for label in ("no top cache", "warm top cache"):
        t = fors_v2
        print(f"  {label:15s} v2 0.3 + wprf2b {t:,} (FORS only)   x{t/v1_total:.5f} vs v1 ({lg(t/v1_total):+.4f} b)")
    # what the counter does not count, for v1 and v2 alike: the per-layer chaining value CV = Compress(IV,
    # sk_seed || const) is itself a secret that keys every WOTS secret of its layer, and it meets the varying A7 /
    # v1 address words in the PRF's second block
    cv_v1 = wots_nocache
    print(f"  NOT counted above (v1 and v2 + wprf2b alike): second-block compressions with the per-layer secret CV and"
          f" varying words: v1 {cv_v1:,}; v2 + wprf2b {wots_nocache:,} without the top cache, {wots_cache:,} with it")
    print(f"  cost: +1 compression per WOTS PRF = +{wots_nocache:,} per pass without the top cache (+{wots_cache:,} with it)")
    # round 20 (UPDATE 2026-11-14): the full stack — ts200 + prf2 + split810 + top cache + the merged two-block
    # paired WOTS PRF — and the bridge all3 + cache (prf2's one-block WOTS pairs). Heights (8, 10); prf2 pairs WOTS
    # chains (22 PRFs per key for l = 43) and FORS leaves (k * 2^a / 2); the warm cache (#1148, HC = 4) rebuilds only
    # the 16-leaf subtree under the top leaf. Cold = no cache (every pass rebuilds the 1,024-leaf top tree).
    # Corrected after Astra's round-20 review: whole-key generation pairs the chains (22 digests per key), but signing
    # calls the per-chain PRF once per chain (d * l = 86), and each revealed FORS secret repeats its pair's digest
    # (+ (k - 1), the same recomputation v1's 26,636 counts). Executed compressions, as for v1.
    def full_stack_counts(merged):
        pairs = (p["l"] + 1) // 2
        fors = p["k"] * 2**p["a"] // 2 + (p["k"] - 1)
        keys_cold, keys_warm = 2**8 + 2**10, 2**8 + 2**4
        sign_chains = p["d"] * p["l"]
        wots_cold, wots_warm = keys_cold * pairs + sign_chains, keys_warm * pairs + sign_chains
        if merged == "no-prf2":   # ablation: wprf2b unpaired, all asm (fused FORS subtree: no recomputed leaf)
            fors1 = p["k"] * 2**p["a"]
            return dict(sk_cold=fors1, sk_warm=fors1, cv_cold=keys_cold * p["l"] + sign_chains,
                        cv_warm=keys_warm * p["l"] + sign_chains)
        if merged:   # two-block: no sk_seed compression with varying words; the pairs are CV block-2 compressions
            return dict(sk_cold=fors, sk_warm=fors, cv_cold=wots_cold, cv_warm=wots_warm)
        return dict(sk_cold=fors + wots_cold, sk_warm=fors + wots_warm, cv_cold=0, cv_warm=0)
    for label, merged in (("full stack (merged WOTS PRF)", True), ("bridge all3 + cache (prf2 one-block)", False),
                          ("ablation no-prf2 (ts200 + split810 + cache + wprf2b)", "no-prf2")):
        c = full_stack_counts(merged)
        print(f"  {label}: sk_seed counter cold {c['sk_cold']:,} (x{c['sk_cold']/v1_total:.3f} vs v1), warm {c['sk_warm']:,}"
              f" (x{c['sk_warm']/v1_total:.3f}); CV residual cold {c['cv_cold']:,} (x{c['cv_cold']/cv_v1:.3f} of v1's"
              f" {cv_v1:,}), warm {c['cv_warm']:,} (x{c['cv_warm']/cv_v1:.3f})")
    # round 20, keygen (not in the per-pass counter, for v1 either): "cold" above = no top cache, i.e. a pass that
    # rebuilds the 1,024-leaf top tree. keygen_with_top_cache builds the top tree twice: once through the paired
    # key loop (22 PRF digests per key) and once, as the confirm build, with rotated chain order through the
    # per-chain PRF (43 per key). v1 keygen builds its 512-leaf top tree once (43 per key).
    pairs = (p["l"] + 1) // 2
    kg = 2**10 * pairs + 2**10 * p["l"]
    kg_v1 = 2**hp * p["l"]
    print(f"  keygen with the top cache: full stack sk_seed counter 0, CV {kg:,}; bridge sk_seed counter {kg:,}, CV 0"
          f" (v1 keygen: sk_seed 0, CV {kg_v1:,}); once per key derivation, not per signature")
    # round 18 (UPDATE 2026-11-14): w4l65 + wprf2b — the WOTS PRF adds no sk_seed compression with varying words;
    # FORS is w4l65's (same k, a); the per-layer CV residual scales with l
    w4_cv_nc = 2 * (2**hp * 65 + 65)
    w4_cv_c = (2**hp * 65 + 65) + (2**(hp - 5) * 65 + 65)
    print(f"  w4l65 + wprf2b: {fors_v2:,} sk_seed compressions (FORS only) x{fors_v2/v1_total:.5f} vs v1, with or without the"
          f" top cache; NOT counted: CV second-block compressions {w4_cv_nc:,} without the cache (x{w4_cv_nc/cv_v1:.3f} of v1's"
          f" {cv_v1:,}), {w4_cv_c:,} with it")
    # round 16 (UPDATE 2026-11-14): the same counter for the w4l65 frontier set (l = 65 WOTS PRF calls per key)
    q = dict(p, w=4, l=65, T=125)
    wk = 2**hp * q["l"]
    w_nc = q["d"] * (wk + q["l"])
    w_c = (wk + q["l"]) + (2**(hp - 5) * q["l"] + q["l"])
    print("  w4l65 (h18 d2 a11 k13 w4 l65 T125), same counter:")
    for label, wots, base in (("no top cache", w_nc, fors_v2 + wots_nocache), ("warm top cache", w_c, fors_v2 + wots_cache)):
        t = fors_v2 + wots
        print(f"  {label:15s} w4l65 {t:,} (FORS {fors_v2:,} + WOTS {wots:,})   x{t/v1_total:.3f} vs v1 ({lg(t/v1_total):.2f} b), "
              f"x{t/base:.3f} vs v2 0.3 ({lg(t/base):.2f} b)")
    per_key = lambda l_, w_, blocks: (l_ + l_ * (w_ - 1) + blocks, 2 * l_ + l_ * (w_ - 1) + blocks)
    tb = lambda l_: -(-(24 + 16 * l_ + 9) // 64)       # T_l: S || A7 || 0x00 || l values, padded blocks
    (a0, a1), (b0, b1) = per_key(43, 8, tb(43)), per_key(65, 4, tb(65))
    print(f"  the same fix adds {w_nc:,} compressions per pass for w4l65; per WOTS key (PRF + chain steps + T_l blocks):"
          f" v2 0.3 {a0} -> {a1} with the fix, w4l65 {b0} -> {b1}: the per-key gain narrows from x{b0/a0:.3f} to x{b1/a1:.3f}")


if __name__ == "__main__":
    main()
