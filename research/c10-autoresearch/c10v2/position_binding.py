#!/usr/bin/env python3
"""Round 20 addendum (2026-11-14): FORS / WOTS secret POSITION-BINDING regression for every
secret PRF of the v2 variants (draft 0.3, prf2, wprf2b, the round-20 merged prf2 + wprf2b PRF,
all3, and the full stack), against c10v2_ref.py.

Why. A secret PRF that loses a hypertree-position field makes every position share one secret
table; revealed FORS secrets (and digit-0 WOTS chain values) then accumulate across signatures
until anyone can forge. The bug is signer-only: the verifier, the signer's self-verify and a
second implementation that shares the spec all still pass. (Class: PQ1's own `fcee705a` fix and
upstream SPHINCs- B-01. This file is written from scratch for c10v2_ref.py.)

Checks, per variant:
  F  two HONEST signatures at different hypertree positions that open the same FORS (tree t,
     leaf j) reveal DIFFERENT secrets; each revealed secret equals fors_prf at its own position;
     within each of those positions, distinct (tree, leaf) give distinct secrets (incl. j ^ 1).
  W  the WOTS analogue: the same chain index ci at a different (layer, tree, kp) gives a different
     secret (a grid, plus each single-field change), at the two honest signatures' own positions
     too; all L chain secrets are distinct within a position; and every revealed WOTS value is chain^digit(wots_prf(position, ci)), i.e. the signer
     uses this position-bound PRF.
  M  planted mutants that drop a position field from the PRF input (FORS ht_idx; WOTS layer,
     tree, kp; for the two-block PRFs, tree and kp out of the A7 tail) or the pair low bit (prf2
     hashes index & ~1 and only its half select restores the bit: the mutant hashes and selects with
     the bit cleared, so 2j and 2j + 1 share a secret) MUST make F or W fail, while the mutant's
     signatures still verify (the upstream observation: only this test sees it).

Usage: position_binding.py [variant-name ...]   (default: all six). Exit 0 iff every honest check
passes and every mutant is caught.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c10v2_ref as r  # noqa: E402

VARIANTS = {
    "draft03": (),
    "prf2": ("prf2",),
    "wprf2b": ("wprf2b",),
    "prf2+wprf2b": ("prf2", "wprf2b"),
    "all3": ("ts200", "prf2", "split810"),
    "full": ("ts200", "prf2", "split810", "wprf2b"),
    "noprf2": ("ts200", "split810", "wprf2b"),   # round 21: the no-prf2 candidate
}


class Fail(Exception):
    pass


def key():
    """kat_key(0): the same key the Rust test (proto_full/v2_position_binding.rs) derives."""
    return r.kat_key(0)


def msg(i):
    return r.sha256(b"c10v2-posbind-msg" + r.be(i, 4))


def digest_of(sk, ps, root, m):
    nonce = 0
    while True:
        R = r.r_candidate(sk, m, nonce)
        fidx, ht = r.indices(r.h_msg(ps, root, R, m))
        if fidx[r.K - 1] == 0:
            return fidx, ht
        nonce += 1


def find_pair(sk, ps, root):
    """The first message pair (in message order) whose digests open the same (t, j), t < K - 1,
    at different hypertree positions."""
    seen = {}
    i = 0
    while True:
        fidx, ht = digest_of(sk, ps, root, msg(i))
        for t in range(r.K - 1):
            prev = seen.get((t, fidx[t]))
            if prev is not None and prev[1] != ht:
                return dict(i1=prev[0], i2=i, t=t, j=fidx[t], ht1=prev[1], ht2=ht)
            seen.setdefault((t, fidx[t]), (i, ht))
        i += 1


def layer_positions(ht):
    out, tree = [], ht
    for layer in range(r.D):
        kp = tree & ((1 << r.HL[layer]) - 1)
        tree >>= r.HL[layer]
        out.append((layer, tree, kp))
    return out


def check_fors(sk, ps, root, pr, sigs):
    t, j = pr["t"], pr["j"]
    s = [sig[r.N + r.N * t:2 * r.N + r.N * t] for sig in sigs]
    for x, ht in zip(s, (pr["ht1"], pr["ht2"])):
        if x != r.fors_prf(sk, ht, t, j):
            raise Fail(f"F: revealed secret is not fors_prf at its position ht={ht:#x}")
    if pr["ht1"] == pr["ht2"]:
        raise Fail("F: the pair is at one position (search bug)")
    if s[0] == s[1]:
        raise Fail(f"F: FORS (t={t}, j={j}) secret SHARED across ht {pr['ht1']:#x} / {pr['ht2']:#x}")
    # within one position: distinct (tree, leaf) give distinct secrets, including the prf2 pair partner j ^ 1
    # (prf2 hashes leaf & ~1; only the half select restores the low bit)
    leaves = sorted({0, 1, 2, 3, r.FORS_LEAVES - 2, r.FORS_LEAVES - 1, j, j ^ 1})
    for ht in (pr["ht1"], pr["ht2"]):
        seen = {}
        for t2 in sorted({0, t, r.K - 2, r.K - 1}):
            for leaf in leaves:
                v = r.fors_prf(sk, ht, t2, leaf)
                if v in seen:
                    raise Fail(f"F: FORS secrets of {seen[v]} and {(t2, leaf)} COLLIDE within ht {ht:#x}")
                seen[v] = (t2, leaf)


def check_wots_signature(sk, ps, root, m, sig):
    """Every revealed WOTS value is chain^d(wots_prf(sk, position, ci)) for the signature's own
    positions (parsed with verify()'s arithmetic)."""
    S = ps
    R = sig[:r.N]
    fidx, ht = r.indices(r.h_msg(S, root, R, m))
    off = r.N
    secrets = [sig[off + t * r.N:off + (t + 1) * r.N] for t in range(r.K)]
    off += r.K * r.N
    roots = []
    for t in range(r.K - 1):
        ap = [sig[off + h * r.N:off + (h + 1) * r.N] for h in range(r.A)]
        off += r.A * r.N
        leaf = r.F(S, r.a7(r.FORS_TREE, tree=ht, kp=t, ha=fidx[t]), secrets[t])
        roots.append(r.climb(S, lambda c, i, t=t: r.a7(r.FORS_TREE, tree=ht, kp=t, cp=c, ha=i), leaf, fidx[t], ap))
    roots.append(r.F(S, r.a7(r.FORS_LAST, tree=ht), secrets[r.K - 1]))
    current = r.T(S, r.a7(r.FORS_ROOTS, tree=ht), roots)
    pos = []
    for layer, tree, kp in layer_positions(ht):
        sigma = [sig[off + i * r.N:off + (i + 1) * r.N] for i in range(r.L)]
        off += r.L * r.N
        count = int.from_bytes(sig[off:off + 4], "big")
        off += 4
        ap = [sig[off + h * r.N:off + (h + 1) * r.N] for h in range(r.HL[layer])]
        off += r.HL[layer] * r.N
        dg = r.digits(r.wots_digest(S, layer, tree, kp, current, count))
        for ci in range(r.L):
            want = r.chain(S, layer, tree, kp, ci, r.wots_prf(sk, layer, tree, kp, ci), 0, dg[ci])
            if sigma[ci] != want:
                raise Fail(f"W: revealed chain {ci} at (layer {layer}, tree {tree}, kp {kp}) is not from wots_prf there")
        wpk = r.wots_pk_from_sig(S, layer, tree, kp, current, sigma, count)
        current = r.climb(S, lambda c, i, l=layer, t=tree: r.a7(r.TREE, l, t, cp=c, ha=i), wpk, kp, ap)
        pos.append((layer, tree, kp))
    return pos


def check_wots_function(sk, honest_positions):
    cis = sorted({0, 1, 2, r.L - 2, r.L - 1})
    grid = []
    for layer in range(r.D):
        kmax = (1 << r.HL[layer]) - 1
        for tree in (0, 1, 0x2A5):
            for kp in (0, 1, kmax):
                grid.append((layer, tree, kp))
    for ci in cis:
        seen = {}
        for p in grid:
            v = r.wots_prf(sk, *p, ci)
            if v in seen:
                raise Fail(f"W: wots_prf ci={ci} SHARED by positions {seen[v]} and {p}")
            seen[v] = p
        base = (1, 0x2A5, 1)
        for field, alt in ((0, (0, 0x2A5, 1)), (1, (1, 0, 1)), (2, (1, 0x2A5, 0))):
            if r.wots_prf(sk, *base, ci) == r.wots_prf(sk, *alt, ci):
                raise Fail(f"W: wots_prf ci={ci} ignores field {('layer', 'tree', 'kp')[field]}")
    # within one position: all L chain secrets distinct (covers every prf2 pair 2j / 2j + 1)
    for p in ((0, 0, 0), (1, 0x2A5, 1)) + tuple(x for pp in honest_positions for x in pp):
        seen = {}
        for ci in range(r.L):
            v = r.wots_prf(sk, *p, ci)
            if v in seen:
                raise Fail(f"W: wots_prf chains {seen[v]} and {ci} COLLIDE within position {p}")
            seen[v] = ci
    # at the honest signatures' own positions (layer by layer)
    (pa, pb) = honest_positions
    for (la, ta, ka), (lb, tb, kb) in zip(pa, pb):
        if (ta, ka) == (tb, kb):
            continue
        for ci in range(r.L):
            if r.wots_prf(sk, la, ta, ka, ci) == r.wots_prf(sk, lb, tb, kb, ci):
                raise Fail(f"W: honest positions {(la, ta, ka)} / {(lb, tb, kb)} share chain {ci}'s secret")


def run_checks(sk, ps, root, pr, verify_too=True):
    m1, m2 = msg(pr["i1"]), msg(pr["i2"])
    sigs = [r.sign(sk, ps, root, m1), r.sign(sk, ps, root, m2)]
    ok = [r.verify(ps, root, m, s) for m, s in zip((m1, m2), sigs)] if verify_too else [None, None]
    errs = dict(F=[], W=[])
    try:
        check_fors(sk, ps, root, pr, sigs)
    except Fail as e:
        errs["F"].append(str(e))
    try:
        pos = [check_wots_signature(sk, ps, root, m, s) for m, s in zip((m1, m2), sigs)]
        check_wots_function(sk, pos)
    except Fail as e:
        errs["W"].append(str(e))
    return ok, errs


ORIG = {}


def mutants():
    """name -> (installer, applies-to predicate on the variant set)."""
    def drop_ht():
        r.fors_prf = lambda sk, ht, t, leaf: ORIG["fors_prf"](sk, 0, t, leaf)

    def drop(field):
        def inst():
            def w(sk, layer, tree, kp, ci):
                a = dict(layer=layer, tree=tree, kp=kp)
                a[field] = 0
                return ORIG["wots_prf"](sk, a["layer"], a["tree"], a["kp"], ci)
            r.wots_prf = w
        return inst

    def two_block_no_a7():
        # the two-block PRFs with the A7 tail squeezed out (block 1 = sk_seed || tag || layer kept):
        # what "a position field squeezed out of the PRF input" looks like for the merged PRF
        def w(sk, layer, tree, kp, ci):
            blk = r.WPRF2B_TAG + r.be(layer, 4) + b"\x00" * 12
            if "prf2" in r.VARIANT:
                d = r.sha256(sk + blk + r.a7(r.WOTS_PRF, layer, 0, 0, ci & ~1))
                return d[r.N * (ci & 1):r.N * (ci & 1) + r.N]
            return r.sha256(sk + blk + r.a7(r.WOTS_PRF, layer, 0, 0, ci))[:r.N]
        r.wots_prf = w

    def fors_pairbit():
        r.fors_prf = lambda sk, ht, t, leaf: ORIG["fors_prf"](sk, ht, t, leaf & ~1)

    def wots_pairbit():
        r.wots_prf = lambda sk, layer, tree, kp, ci: ORIG["wots_prf"](sk, layer, tree, kp, ci & ~1)

    return {
        "fors-drop-ht": (drop_ht, lambda v: True),
        "fors-drop-pair-bit": (fors_pairbit, lambda v: True),
        "wots-drop-pair-bit": (wots_pairbit, lambda v: True),
        "wots-drop-layer": (drop("layer"), lambda v: True),
        "wots-drop-tree": (drop("tree"), lambda v: True),
        "wots-drop-kp": (drop("kp"), lambda v: True),
        "wots2b-drop-a7-position": (two_block_no_a7, lambda v: "wprf2b" in v),
    }


def restore():
    r.fors_prf, r.wots_prf = ORIG["fors_prf"], ORIG["wots_prf"]


def main(names):
    ORIG.update(fors_prf=r.fors_prf, wots_prf=r.wots_prf)
    bad = 0
    for name in names:
        v = VARIANTS[name]
        r.configure(v)
        sk, ps = key()
        root = r.keygen(sk, ps)
        pr = find_pair(sk, ps, root)
        ok, errs = run_checks(sk, ps, root, pr)
        line = (f"{name:12s} pair msgs ({pr['i1']}, {pr['i2']}) open FORS (t={pr['t']}, j={pr['j']}) at ht "
                f"{pr['ht1']:#07x} / {pr['ht2']:#07x}; verify {ok}")
        if errs["F"] or errs["W"] or not all(ok):
            bad += 1
            print(f"FAIL {line}: {errs}")
        else:
            print(f"PASS {line}: F and W hold")
        for mname, (inst, applies) in mutants().items():
            if not applies(set(v)):
                continue
            inst()
            try:
                # a WOTS mutant changes the public key, so its own pair is re-found under its root
                mroot = r.keygen(sk, ps) if mname.startswith("wots") else root
                mpr = find_pair(sk, ps, mroot) if mname.startswith("wots") else pr
                mok, merrs = run_checks(sk, ps, mroot, mpr)
            finally:
                restore()
            want = "F" if mname.startswith("fors") else "W"
            # caught = the intended check fails, the other one still holds, and the verifier accepts
            caught = bool(merrs[want]) and not merrs["F" if want == "W" else "W"]
            if not caught:
                bad += 1
            print(f"  mutant {mname:24s} {'CAUGHT by ' + want if caught else 'NOT CAUGHT'}; mutant signatures"
                  f" verify {mok}; {merrs[want][0] if merrs[want] else merrs}")
    print(f"position_binding: {'OK' if not bad else f'{bad} FAILURE(S)'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or list(VARIANTS)))
