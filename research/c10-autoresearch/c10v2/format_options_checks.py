#!/usr/bin/env python3
"""format_options_checks.py — structural security checks for the three candidate
v2 format changes (ts200, prf2, split810). Research (#1155), 2026-11-13.

  A. A7 field layout, draft 0.3 and split810: fields are disjoint bit ranges in
     56 bits; for every role the largest value each field takes under the
     parameter set fits its width; pack/unpack round-trips on every boundary
     combination. Disjoint fields + in-range values => the address map is
     injective, so no two (role, position) pairs share a tweak. That replaces an
     enumeration of every address (~10^10 FORS addresses alone).
  B. prf2 reveals whole 32-byte PRF outputs. Length extension then gives
     SHA-256(sk_seed || A7 || pad || x) for any x, so the set of sk_seed-keyed
     inputs must be block-prefix-free: no other sk_seed-prefixed message may
     start with a padded PRF block. Checked for the R-grind PRF (the only other
     one), byte by byte.
  C. prf2: how often both halves of one PRF output are actually revealed
     (WOTS pair both digit 0; FORS sibling leaves across signatures sharing an
     ht_idx), so B is load-bearing rather than hypothetical.
  D. The FORS few-time term (Fluhrer-Dang style) at the usage cap, to show it
     depends on (h, k, a, q) only: not on the layer split or the target sum.

Run: python3 format_options_checks.py
"""
import itertools
import math

H, D, A, K, W, L = 18, 2, 11, 13, 8, 43

LAYOUTS = {
    "draft03": (dict(type=4, layer=1, tree=18, kp=9, ci=6, cp=4, ha=11),
                dict(type=52, layer=51, tree=33, kp=24, ci=18, cp=12, ha=1)),
    "split810": (dict(type=4, layer=1, tree=18, kp=10, ci=6, cp=4, ha=11),
                 dict(type=52, layer=51, tree=33, kp=23, ci=17, cp=12, ha=1)),
}
FIELDS = ("type", "layer", "tree", "kp", "ci", "cp", "ha")


def pack(lay, **f):
    wid, sh = LAYOUTS[lay]
    v = 0
    for k in FIELDS:
        x = f.get(k, 0)
        assert 0 <= x < 1 << wid[k], (lay, k, x)
        v |= x << sh[k]
    return v


def unpack(lay, v):
    wid, sh = LAYOUTS[lay]
    return {k: v >> sh[k] & ((1 << wid[k]) - 1) for k in FIELDS}


def zero_mask(lay):
    wid, sh = LAYOUTS[lay]
    used = 0
    for k in FIELDS:
        m = ((1 << wid[k]) - 1) << sh[k]
        assert m >> 56 == 0, (lay, k, "overflows 56 bits")
        assert used & m == 0, (lay, k, "overlaps another field")
        used |= m
    return ((1 << 56) - 1) & ~used


def roles(heights):
    """Per role: (type, {field: (min, max)}) over every address the scheme uses."""
    h0, h1 = heights
    top_tree = 0
    r = {}
    # layer 0: tree = ht_idx >> h0 (< 2^(18-h0)), kp < 2^h0; layer 1: tree 0, kp < 2^h1
    kpmax = max((1 << h0) - 1, (1 << h1) - 1)
    treemax = (1 << (H - h0)) - 1
    hmax = max(h0, h1)
    r["WOTS_HASH"] = (0, dict(layer=(0, 1), tree=(0, treemax), kp=(0, kpmax), ci=(0, L - 1), cp=(0, W - 2)))
    r["WOTS_PK"] = (1, dict(layer=(0, 1), tree=(0, treemax), kp=(0, kpmax)))
    r["TREE"] = (2, dict(layer=(0, 1), tree=(0, treemax), cp=(1, hmax), ha=(0, (1 << (hmax - 1)) - 1)))
    r["FORS_TREE"] = (3, dict(tree=(0, (1 << H) - 1), kp=(0, K - 1), cp=(0, A), ha=(0, (1 << A) - 1)))
    r["FORS_ROOTS"] = (4, dict(tree=(0, (1 << H) - 1)))
    r["WOTS_PRF"] = (5, dict(layer=(0, 1), tree=(0, treemax), kp=(0, kpmax), ci=(0, L - 1)))
    r["FORS_PRF"] = (6, dict(tree=(0, (1 << H) - 1), kp=(0, K - 1), ha=(0, (1 << A) - 1)))
    r["WOTS_DIGEST"] = (7, dict(layer=(0, 1), tree=(0, treemax), kp=(0, kpmax)))
    r["H_MSG"] = (8, dict())
    r["FORS_LAST"] = (9, dict(tree=(0, (1 << H) - 1)))
    _ = top_tree
    return r


def check_layout(lay, heights):
    wid, _ = LAYOUTS[lay]
    zm = zero_mask(lay)
    types = set()
    n = 0
    for name, (ty, rng) in roles(heights).items():
        assert ty not in types, f"type {ty} reused"
        types.add(ty)
        for k, (lo, hi) in rng.items():
            assert hi < 1 << wid[k], f"{lay}: {name}.{k} max {hi} does not fit {wid[k]} bits"
        # every boundary combination round-trips, and touches no zero bit
        keys = list(rng)
        for combo in itertools.product(*[(rng[k][0], rng[k][1]) for k in keys]):
            f = dict(zip(keys, combo), type=ty)
            v = pack(lay, **f)
            assert v & zm == 0
            u = unpack(lay, v)
            assert all(u[k] == f.get(k, 0) for k in FIELDS), (lay, name, f, u)
            n += 1
    widths = {k: wid[k] for k in FIELDS}
    print(f"A. {lay} {heights}: fields disjoint in 56 bits (zero bits {bin(zm)}); every role's max value fits "
          f"its width {widths}; {n} boundary tuples round-trip; 10 roles, 10 distinct types")
    return zm


def check_prefix_free():
    tag = b"R_grind"
    v = int.from_bytes(tag, "big")
    print(f"B. 'R_grind' read as an A7 = 0x{v:014x}")
    for lay in LAYOUTS:
        zm = zero_mask(lay)
        f = unpack(lay, v)
        bad_zero = v & zm
        print(f"   {lay}: fields {f}; zero-bit violation 0x{bad_zero:x}; "
              f"PRF types need cp = 0 (WOTS_PRF also ha = 0): cp = {f['cp']}, ha = {f['ha']}")
        assert bad_zero != 0, "R_grind is a well-formed A7 in this layout"
        assert f["cp"] != 0, "R_grind could be a PRF A7"
    # The padded block of a 39-byte PRF message vs the R-grind's first block.
    pad = b"\x80" + b"\x00" * 16 + (39 * 8).to_bytes(8, "big")
    assert 39 + len(pad) == 64
    print(f"   a 39-byte PRF input pads to one block: sk_seed(32) || A7(7) || {pad.hex()}; the R-grind PRF's first "
          "block is sk_seed(32) || 'R_grind' || 25 bytes of opt_rand/message, and bytes 32..38 already differ "
          "for every A7 the scheme produces (shown above), so no sk_seed-keyed input extends a padded PRF block. "
          "All PRF inputs have one length (39 B), so none is a prefix of another.")


def count_table():
    cnt = [[0] * ((W - 1) * L + 1) for _ in range(L + 1)]
    cnt[0][0] = 1
    for k in range(1, L + 1):
        for s in range(len(cnt[0])):
            cnt[k][s] = sum(cnt[k - 1][s - v] for v in range(W) if s - v >= 0)
    return cnt


def check_pair_reveal():
    cnt = count_table()
    for T in (205, 200):
        p00 = cnt[L - 2][T] / cnt[L][T]           # both digits of a given pair are 0, given sum T
        p0 = cnt[L - 1][T] / cnt[L][T]            # one given digit is 0
        e = 21 * p00
        print(f"C. T={T}: P(digit = 0) = {p0:.4f}; P(both digits of a pair = 0) = {p00:.2e}; "
              f"expected fully revealed WOTS PRF outputs per WOTS signature = {e:.2e} (21 pairs)")
    # FORS: two signatures on the same ht_idx reveal leaves j and j^1 of one tree with prob 2^-11 per tree
    q = 1 << 16
    pairs = q * (q - 1) / 2 / (1 << H)            # expected ht_idx collisions among q signatures
    e = pairs * (K - 1) * 2 ** -A
    print(f"   FORS at q = 2^16 signatures per key: {pairs:.0f} expected same-ht_idx signature pairs; expected "
          f"fully revealed FORS PRF outputs ~ {e:.1f}. Both halves DO get revealed in normal use, so B is load-bearing.")


def fors_bits(q, h=H, k=K - 1, a=A, forced=True):
    lam = q / 2 ** h
    tot, pr = 0.0, math.exp(-lam)                # Poisson approximation of Bin(q, 2^-h)
    for r in range(0, 200):
        if r > 0:
            pr *= lam / r
        tot += pr * (1 - (1 - 2 ** -a) ** r) ** k
    if forced:
        tot *= 2 ** -a                            # the forger's H_MSG must also force the last index to 0
    return -math.log2(tot)


def check_fors():
    for q in (1 << 16, 1 << 18, 1 << 20):
        print(f"D. FORS+C few-time term (k-1 = 12 trees, a = 11, h = 18), q = 2^{int(math.log2(q))}: "
              f"2^-{fors_bits(q):.1f} per H_MSG query. Inputs: h, k, a, q only.")


def check_cross_layout():
    """E. Same seed under 0.3 and split810: A7 values (hence PRF secrets and chain tweaks) that coincide."""
    def wots(lay, kpmax):
        return {pack(lay, type=5, layer=l, tree=t, kp=k, ci=c) for l in (0, 1) for t in (0, 1) for k in range(kpmax) for c in range(L)}
    old, new = wots("draft03", 512), wots("split810", 1024)
    fo = {pack("draft03", type=6, tree=7, kp=t, ha=0): t for t in range(K)}
    fn = {pack("split810", type=6, tree=7, kp=t, ha=0): t for t in range(K)}
    shared_f = sorted((fo[v], fn[v]) for v in set(fo) & set(fn))
    print(f"E. 0.3 vs split810, same seed: {len(old & new)} of {len(new)} split810 WOTS_PRF A7s (trees 0,1) equal a 0.3 A7 "
          f"((kp, ci) -> (2kp + ci//32, 2ci mod 64)); identical FORS trees (0.3 t, split810 t): {shared_f}")


if __name__ == "__main__":
    check_layout("draft03", (9, 9))
    check_layout("split810", (8, 10))
    check_prefix_free()
    check_pair_reveal()
    check_fors()
    check_cross_layout()
