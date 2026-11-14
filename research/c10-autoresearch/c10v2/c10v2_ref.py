#!/usr/bin/env python3
"""
c10v2_ref.py — reference C10 v2 (one-block tweakable hash), written from
../c10v2-spec.md (DRAFT 0.3). Research only (#1155); nothing has landed.

Forked from contracts/verification/scripts/independent_c10_signer.py (the
clean-room v1 signer). Only the hash layer changes; the scheme around it
(FORS+C, WOTS+C, hypertree, signature layout) is the v1 one.

Run:
  python3 c10v2_ref.py selftest          # sign + verify + near-miss rejects
  python3 c10v2_ref.py kat OUT.json [N]  # N deterministic KATs (default 3)
"""

import hashlib
import json
import sys

# ── params (unchanged from v1) ─────────────────────────────────────────────
N = 16
H, D, A, K, W, L = 18, 2, 11, 13, 8, 43
LOG_W, W_MASK, TARGET_SUM, SUBTREE_H = 3, 0x7, 205, 9
FORS_LEAVES = 1 << A
SUBTREE_LEAVES = 1 << SUBTREE_H
SIG_LEN = 4008

# ── format-option variants (2026-11-13 security check; default = draft 0.3) ──
# ts200    : WOTS+C target sum 200 instead of 205 (verifier changes).
# prf2     : one PRF digest yields two secrets; index 2j takes bytes 0..15 and
#            2j+1 bytes 16..31 of PRF(A7 of index 2j). WOTS chain 42 is unpaired
#            (first half only). Keys change; the verifier does not.
# split810 : hypertree layer heights (8, 10) instead of (9, 9); A7 kp widens to
#            10 bits (bits 32..23) and ci moves to bits 22..17 (verifier changes).
# w4       : round 16 frontier set (research): WOTS+C with w = 4, l = 64, target sum
#            124 (digits from the low 128 bits of WOTS_DIGEST, 2 bits each); every
#            other parameter and the A7 layout unchanged (ci <= 63, cp <= 3 fit).
#            Keys, signature length (4,680 B) and the verifier change.
VARIANT = frozenset()
HL = (SUBTREE_H, SUBTREE_H)   # per-layer subtree heights, layer 0 first


def configure(variant):
    """Select a variant set (iterable of 'ts200', 'prf2', 'split810')."""
    global VARIANT, TARGET_SUM, HL, _WIDTH, _SHIFT, W, L, LOG_W, W_MASK, SIG_LEN
    v = frozenset(x for x in variant if x)
    unknown = v - {"ts200", "prf2", "split810", "w4"}
    assert not unknown, f"unknown variant {sorted(unknown)}"
    assert not ("w4" in v and "ts200" in v), "w4 sets its own target sum"
    VARIANT = v
    TARGET_SUM = 200 if "ts200" in v else 205
    if "w4" in v:
        W, L, LOG_W, W_MASK, TARGET_SUM = 4, 64, 2, 0x3, 124
    else:
        W, L, LOG_W, W_MASK = 8, 43, 3, 0x7
    SIG_LEN = N * (2 + (K - 1) * (A + 1)) + D * (4 + (L + H // D) * N)
    assert L * LOG_W <= 256 and W ** L >= 2**128
    HL = (8, 10) if "split810" in v else (SUBTREE_H, SUBTREE_H)
    assert sum(HL) == H
    if "split810" in v:
        _WIDTH = dict(type=4, layer=1, tree=18, kp=10, ci=6, cp=4, ha=11)
        _SHIFT = dict(type=52, layer=51, tree=33, kp=23, ci=17, cp=12, ha=1)
    else:
        _WIDTH = dict(type=4, layer=1, tree=18, kp=9, ci=6, cp=4, ha=11)
        _SHIFT = dict(type=52, layer=51, tree=33, kp=24, ci=18, cp=12, ha=1)
    _check_layout()


def variant_name():
    return "+".join(sorted(VARIANT)) or "draft03"

# A7 types (spec §1)
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS = 0, 1, 2, 3, 4
WOTS_PRF, FORS_PRF, WOTS_DIGEST, H_MSG, FORS_LAST = 5, 6, 7, 8, 9


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def be(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


# ── compact address (spec §1) ───────────────────────────────────────────────
_WIDTH = dict(type=4, layer=1, tree=18, kp=9, ci=6, cp=4, ha=11)
_SHIFT = dict(type=52, layer=51, tree=33, kp=24, ci=18, cp=12, ha=1)


def _check_layout():
    # fields are disjoint bit ranges inside 56 bits, so pack is injective on in-range tuples
    used = 0
    for f, w in _WIDTH.items():
        m = ((1 << w) - 1) << _SHIFT[f]
        assert m >> 56 == 0 and used & m == 0, f"A7 field {f} overlaps or overflows"
        used |= m


def a7(atype, layer=0, tree=0, kp=0, ci=0, cp=0, ha=0) -> bytes:
    v = 0
    for name, x in (("type", atype), ("layer", layer), ("tree", tree), ("kp", kp),
                    ("ci", ci), ("cp", cp), ("ha", ha)):
        assert 0 <= x < (1 << _WIDTH[name]), f"A7 field {name}={x} out of range"
        v |= x << _SHIFT[name]
    return v.to_bytes(7, "big")


# ── hash functions (spec §2); S = pk_seed (16 B) ─────────────────────────────
def F(S, adrs, v):
    assert len(S) == N and len(v) == N and len(adrs) == 7
    return sha256(S + v + adrs)[:N]                         # 39 B


def Hn(S, adrs, l, r):
    assert len(l) == N and len(r) == N
    return sha256(S + l + r + adrs)[:N]                     # 55 B


def T(S, adrs, vals):
    assert all(len(v) == N for v in vals)
    return sha256(S + adrs + b"\x00" + b"".join(vals))[:N]  # tweak-first: 24 + 16k


def wots_prf(sk_seed, layer, tree, kp, ci):
    assert len(sk_seed) == 32
    if "prf2" in VARIANT:
        d = sha256(sk_seed + a7(WOTS_PRF, layer, tree, kp, ci & ~1))
        return d[N * (ci & 1):N * (ci & 1) + N]
    return sha256(sk_seed + a7(WOTS_PRF, layer, tree, kp, ci))[:N]   # 39 B


def fors_prf(sk_seed, ht_idx, t, leaf):
    if "prf2" in VARIANT:
        d = sha256(sk_seed + a7(FORS_PRF, tree=ht_idx, kp=t, ha=leaf & ~1))
        return d[N * (leaf & 1):N * (leaf & 1) + N]
    return sha256(sk_seed + a7(FORS_PRF, tree=ht_idx, kp=t, ha=leaf))[:N]  # 39 B


def wots_digest(S, layer, tree, kp, m16, count):
    assert len(m16) == N
    return sha256(S + m16 + be(count, 4) + a7(WOTS_DIGEST, layer, tree, kp))  # 43 B, full


def h_msg(S, root16, R16, M32):
    assert len(root16) == N and len(R16) == N and len(M32) == 32
    return sha256(S + root16 + M32 + R16 + a7(H_MSG))      # 87 B, full


def r_candidate(sk_seed, msg32, nonce, opt_rand=None):
    # v1's R-grind PRF, unchanged (spec §6): 103 B, or 119 B with opt_rand.
    nb = b"\x00" * 28 + be(nonce, 4)
    if opt_rand is None:
        return sha256(sk_seed + b"R_grind" + msg32 + nb)[:N]
    return sha256(sk_seed + b"R_grind" + opt_rand + msg32 + nb)[:N]


# ── WOTS+C ───────────────────────────────────────────────────────────────────
def chain(S, layer, tree, kp, ci, v, start, steps):
    for p in range(start, start + steps):
        v = F(S, a7(WOTS_HASH, layer, tree, kp, ci, p), v)
    return v


def wots_pk(S, sk_seed, layer, tree, kp):
    pk = [chain(S, layer, tree, kp, i, wots_prf(sk_seed, layer, tree, kp, i), 0, W - 1)
          for i in range(L)]
    return T(S, a7(WOTS_PK, layer, tree, kp), pk)


def digits(d32):
    # Spec 0.3: v1's position, the LOW 129 bits, digit i = (D >> 3i) & 7.
    Di = int.from_bytes(d32, "big")
    return [(Di >> (i * LOG_W)) & W_MASK for i in range(L)]


def wots_sign(S, sk_seed, layer, tree, kp, node16, cheat=False):
    count = 0
    while True:
        dg = digits(wots_digest(S, layer, tree, kp, node16, count))
        if (sum(dg) == TARGET_SUM) != cheat:
            break
        count += 1
    sigma = [chain(S, layer, tree, kp, i, wots_prf(sk_seed, layer, tree, kp, i), 0, dg[i])
             for i in range(L)]
    return sigma, count


def wots_pk_from_sig(S, layer, tree, kp, node16, sigma, count):
    dg = digits(wots_digest(S, layer, tree, kp, node16, count))
    pk = [chain(S, layer, tree, kp, i, sigma[i], dg[i], (W - 1) - dg[i]) for i in range(L)]
    return T(S, a7(WOTS_PK, layer, tree, kp), pk)


# ── Merkle ─────────────────────────────────────────────────────────────────────
def build_subtree(S, sk_seed, layer, tree):
    nodes = [[wots_pk(S, sk_seed, layer, tree, kp) for kp in range(1 << HL[layer])]]
    for h in range(HL[layer]):
        prev = nodes[h]
        nodes.append([Hn(S, a7(TREE, layer, tree, cp=h + 1, ha=j // 2), prev[j], prev[j + 1])
                      for j in range(0, len(prev), 2)])
    return nodes


def auth(nodes, idx, height):
    out = []
    for h in range(height):
        out.append(nodes[h][idx ^ 1])
        idx >>= 1
    return out


def climb(S, mk_adrs, leaf, idx, ap):
    node = leaf
    for h, sib in enumerate(ap):
        adrs = mk_adrs(h + 1, idx >> 1)
        node = Hn(S, adrs, node, sib) if idx & 1 == 0 else Hn(S, adrs, sib, node)
        idx >>= 1
    return node


def keygen(sk_seed, pk_seed16):
    return build_subtree(pk_seed16, sk_seed, D - 1, 0)[HL[D - 1]][0]


# ── FORS+C ────────────────────────────────────────────────────────────────────
def fors_tree(S, sk_seed, ht_idx, t):
    leaves = [F(S, a7(FORS_TREE, tree=ht_idx, kp=t, ha=j), fors_prf(sk_seed, ht_idx, t, j))
              for j in range(FORS_LEAVES)]
    nodes = [leaves]
    for h in range(A):
        prev = nodes[h]
        nodes.append([Hn(S, a7(FORS_TREE, tree=ht_idx, kp=t, cp=h + 1, ha=j // 2), prev[j], prev[j + 1])
                      for j in range(0, len(prev), 2)])
    return nodes


def indices(digest):
    Di = int.from_bytes(digest, "big")
    a_mask = (1 << A) - 1
    return [(Di >> (i * A)) & a_mask for i in range(K)], (Di >> (K * A)) & ((1 << H) - 1)


def sign(sk_seed, pk_seed16, pk_root16, msg32, opt_rand=None, cheat=None):
    """cheat (near-miss generation only): 'fors' takes the first R whose last
    FORS index is NOT 0; ('wots', layer) signs that layer with the first count
    whose digit sum is NOT 205. Both still rebuild the correct root."""
    S = pk_seed16
    nonce = 0
    while True:
        R = r_candidate(sk_seed, msg32, nonce, opt_rand)
        digest = h_msg(S, pk_root16, R, msg32)
        fidx, ht_idx = indices(digest)
        if (fidx[K - 1] == 0) != (cheat == "fors"):
            break
        nonce += 1
    sig = bytearray(R)
    secrets, auths, roots = [], [], []
    for t in range(K - 1):
        nodes = fors_tree(S, sk_seed, ht_idx, t)
        secrets.append(fors_prf(sk_seed, ht_idx, t, fidx[t]))
        auths.append(auth(nodes, fidx[t], A))
        roots.append(nodes[A][0])
    last_root = fors_tree(S, sk_seed, ht_idx, K - 1)[A][0]
    secrets.append(last_root)
    roots.append(F(S, a7(FORS_LAST, tree=ht_idx), last_root))
    current = T(S, a7(FORS_ROOTS, tree=ht_idx), roots)
    for s in secrets:
        sig += s
    for ap in auths:
        for x in ap:
            sig += x
    idx_tree = ht_idx
    for layer in range(D):
        idx_leaf = idx_tree & ((1 << HL[layer]) - 1)
        idx_tree >>= HL[layer]
        nodes = build_subtree(S, sk_seed, layer, idx_tree)
        ap = auth(nodes, idx_leaf, HL[layer])
        sigma, count = wots_sign(S, sk_seed, layer, idx_tree, idx_leaf, current, cheat == ("wots", layer))
        for s in sigma:
            sig += s
        sig += be(count, 4)
        for x in ap:
            sig += x
        wpk = wots_pk_from_sig(S, layer, idx_tree, idx_leaf, current, sigma, count)
        current = climb(S, lambda c, i, l=layer, t=idx_tree: a7(TREE, l, t, cp=c, ha=i), wpk, idx_leaf, ap)
    assert current == pk_root16, "self-verify failed"
    assert len(sig) == SIG_LEN
    return bytes(sig)


def verify(pk_seed16, pk_root16, msg32, sig, plus_c=True) -> bool:
    if len(sig) != SIG_LEN:
        return False
    S = pk_seed16
    off = 0
    R = sig[off:off + N]; off += N
    fidx, ht_idx = indices(h_msg(S, pk_root16, R, msg32))
    if plus_c and fidx[K - 1] != 0:
        return False
    secrets = [sig[off + t * N: off + (t + 1) * N] for t in range(K)]; off += K * N
    roots = []
    for t in range(K - 1):
        ap = [sig[off + h * N: off + (h + 1) * N] for h in range(A)]; off += A * N
        leaf = F(S, a7(FORS_TREE, tree=ht_idx, kp=t, ha=fidx[t]), secrets[t])
        roots.append(climb(S, lambda c, i, t=t: a7(FORS_TREE, tree=ht_idx, kp=t, cp=c, ha=i), leaf, fidx[t], ap))
    roots.append(F(S, a7(FORS_LAST, tree=ht_idx), secrets[K - 1]))
    current = T(S, a7(FORS_ROOTS, tree=ht_idx), roots)
    idx_tree = ht_idx
    for layer in range(D):
        idx_leaf = idx_tree & ((1 << HL[layer]) - 1)
        idx_tree >>= HL[layer]
        sigma = [sig[off + i * N: off + (i + 1) * N] for i in range(L)]; off += L * N
        count = int.from_bytes(sig[off:off + 4], "big"); off += 4
        ap = [sig[off + h * N: off + (h + 1) * N] for h in range(HL[layer])]; off += HL[layer] * N
        dg = digits(wots_digest(S, layer, idx_tree, idx_leaf, current, count))
        if plus_c and sum(dg) != TARGET_SUM:
            return False
        wpk = wots_pk_from_sig(S, layer, idx_tree, idx_leaf, current, sigma, count)
        current = climb(S, lambda c, i, l=layer, t=idx_tree: a7(TREE, l, t, cp=c, ha=i), wpk, idx_leaf, ap)
    return current == pk_root16


# ── KATs ──────────────────────────────────────────────────────────────────────
def kat_key(i):
    sk = sha256(b"c10v2-kat-sk" + be(i, 4))
    pk_seed = sha256(b"c10v2-kat-pkseed" + be(i, 4))[:N]
    return sk, pk_seed


def kat_msg(i, j):
    return sha256(b"c10v2-kat-msg" + be(i, 4) + be(j, 4))


def selftest():
    sk, ps = kat_key(0)
    root = keygen(sk, ps)
    m = kat_msg(0, 0)
    sig = sign(sk, ps, root, m)
    assert verify(ps, root, m, sig), "valid signature rejected"
    bad = 0
    wsig = L * N + 4 + SUBTREE_H * N   # one WOTS layer section (836 B at l = 43)
    regions = [0, 16, 16 + 12 * 16, 2336, 2336 + L * 16 + 2, 2336 + L * N + 4 + 5, 2336 + wsig + 100, SIG_LEN - 1]
    for off in regions:
        s2 = bytearray(sig); s2[off] ^= 1
        bad += not verify(ps, root, m, bytes(s2))
    assert bad == len(regions), f"only {bad}/{len(regions)} near-misses rejected"
    assert not verify(ps, bytes([root[0] ^ 1]) + root[1:], m, sig)
    assert not verify(ps, root, kat_msg(0, 1), sig)
    for cheat in ("fors", ("wots", 0), ("wots", 1)):
        nm = sign(sk, ps, root, m, cheat=cheat)
        assert verify(ps, root, m, nm, plus_c=False), f"{cheat}: does not rebuild the root"
        assert not verify(ps, root, m, nm), f"{cheat}: +C-only near-miss ACCEPTED"
    print(f"selftest OK [{variant_name()}]: pk_root {root.hex()}, {len(regions)} bit-flips + wrong root + wrong msg "
          "rejected; 3 +C-only near-misses rebuild the root and are rejected only by the +C checks")
    return root, sig


def emit(path, n):
    out = []
    for i in range(n):
        sk, ps = kat_key(i)
        root = keygen(sk, ps)
        for j in range(2):
            m = kat_msg(i, j)
            sig = sign(sk, ps, root, m)
            assert verify(ps, root, m, sig)
            out.append(dict(sk_seed=sk.hex(), pk_seed=ps.hex(), pk_root=root.hex(), msg=m.hex(), sig=sig.hex()))
        print(f"key {i}: pk_root {root.hex()}", file=sys.stderr)
    sk, ps = kat_key(0)
    root = keygen(sk, ps)
    m = kat_msg(0, 0)
    near = []
    for cheat in ("fors", ("wots", 0), ("wots", 1)):
        nm = sign(sk, ps, root, m, cheat=cheat)
        assert verify(ps, root, m, nm, plus_c=False) and not verify(ps, root, m, nm)
        near.append(dict(kind=str(cheat), pk_seed=ps.hex(), pk_root=root.hex(), msg=m.hex(), sig=nm.hex()))
    with open(path, "w") as f:
        json.dump(dict(spec="c10v2-spec.md DRAFT 0.3" + ("" if not VARIANT else f" + variant {variant_name()}"),
                       variant=sorted(VARIANT), vectors=out, plus_c_near_misses=near), f, indent=1)


def digit_sums(sig, pk_seed16, pk_root16, msg32):
    """The two WOTS digit sums a verifier computes for `sig` (current variant)."""
    S, off = pk_seed16, 0
    R = sig[:N]
    fidx, ht_idx = indices(h_msg(S, pk_root16, R, msg32))
    off = N + K * N + (K - 1) * A * N
    roots = []
    for t in range(K - 1):
        ap = [sig[N + K * N + (t * A + h) * N: N + K * N + (t * A + h + 1) * N] for h in range(A)]
        leaf = F(S, a7(FORS_TREE, tree=ht_idx, kp=t, ha=fidx[t]), sig[N + t * N: N + (t + 1) * N])
        roots.append(climb(S, lambda c, i, t=t: a7(FORS_TREE, tree=ht_idx, kp=t, cp=c, ha=i), leaf, fidx[t], ap))
    roots.append(F(S, a7(FORS_LAST, tree=ht_idx), sig[N + (K - 1) * N: N + K * N]))
    current = T(S, a7(FORS_ROOTS, tree=ht_idx), roots)
    sums, idx_tree = [], ht_idx
    for layer in range(D):
        idx_leaf = idx_tree & ((1 << HL[layer]) - 1)
        idx_tree >>= HL[layer]
        sigma = [sig[off + i * N: off + (i + 1) * N] for i in range(L)]; off += L * N
        count = int.from_bytes(sig[off:off + 4], "big"); off += 4
        ap = [sig[off + h * N: off + (h + 1) * N] for h in range(HL[layer])]; off += HL[layer] * N
        dg = digits(wots_digest(S, layer, idx_tree, idx_leaf, current, count))
        sums.append(sum(dg))
        wpk = wots_pk_from_sig(S, layer, idx_tree, idx_leaf, current, sigma, count)
        current = climb(S, lambda c, i, l=layer, t=idx_tree: a7(TREE, l, t, cp=c, ha=i), wpk, idx_leaf, ap)
    return sums


def cross(variant):
    """Cross-format checks between draft 0.3 and `variant` (same sk, pk_seed, msg)."""
    sk, ps = kat_key(0)
    m = kat_msg(0, 0)
    configure(())
    root0 = keygen(sk, ps)
    sig0 = sign(sk, ps, root0, m)
    assert digit_sums(sig0, ps, root0, m) == [205, 205]
    configure(variant)
    root1 = keygen(sk, ps)
    sig1 = sign(sk, ps, root1, m)
    print(f"[{variant_name()}] pk_root {root1.hex()} (0.3: {root0.hex()})")
    if "prf2" in VARIANT or "split810" in VARIANT or "w4" in VARIANT:
        assert root1 != root0, "flag not live: pk_root unchanged"
    else:
        assert root1 == root0, "ts200 must not change keys"
    assert digit_sums(sig1, ps, root1, m) == [TARGET_SUM] * D, digit_sums(sig1, ps, root1, m)
    assert verify(ps, root1, m, sig1)
    # a 0.3 signature (sum 205, 9+9) under the variant verifier, against the variant's own root
    # when keys agree, else against the 0.3 root (the verifier only sees bytes)
    rej = not verify(ps, root0, m, sig0)
    if VARIANT <= {"prf2"}:
        assert not rej, "prf2 changes no verifier rule: a 0.3 signature must still verify"
    else:
        assert rej, "a draft-0.3 signature verified under a variant verifier"
    # the variant's signature under the 0.3 verifier
    vset = VARIANT
    configure(())
    acc = verify(ps, root1, m, sig1)
    if vset == {"prf2"}:
        assert acc, "the unchanged 0.3 verifier must accept a prf2 signature"
    else:
        assert not acc, "a variant signature verified under the draft-0.3 verifier"
    configure(variant)
    print(f"cross OK [{variant_name()}]: sums {digit_sums(sig1, ps, root1, m)}; 0.3 sig under variant verifier "
          f"{'rejected' if rej else 'accepted'}; variant sig under 0.3 verifier {'accepted' if acc else 'rejected'}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) >= 2 and args[0] == "--variant":
        configure(args[1].split(","))
        args = args[2:]
    else:
        configure(())
    if args and args[0] == "kat":
        emit(args[1], int(args[2]) if len(args) > 2 else 3)
    elif args and args[0] == "cross":
        cross(VARIANT)
    else:
        selftest()
