#!/usr/bin/env python3
"""verify_signer_side.py — round 20: prf2's and wprf2b's changes are signer-side only, so the UNCHANGED all3
verifier (ts200 + prf2 + split810, c10v2_ref.py) must accept the full stack's signatures (all3 + the merged
two-block paired WOTS PRF) under the full stack's own public key, and the full stack's verifier must accept all3
signatures. Also: a single-byte corruption is refused by both. KAT keys 0..2, messages 0..1."""
import c10v2_ref as r

ALL3 = ("ts200", "prf2", "split810")
FULL = ALL3 + ("wprf2b",)
n = 0
for k in range(3):
    sk, ps = r.kat_key(k)
    for i in range(2):
        m = r.kat_msg(k, i)
        for signer, verifier in ((FULL, ALL3), (ALL3, FULL)):
            r.configure(signer)
            root = r.keygen(sk, ps)
            sig = r.sign(sk, ps, root, m)
            r.configure(verifier)
            assert r.verify(ps, root, m, sig), (k, i, signer)
            bad = bytearray(sig); bad[2336 + 5] ^= 1
            assert not r.verify(ps, root, m, bytes(bad))
            n += 1
print(f"signer-side check OK: {n} signatures, the all3 verifier accepts the full stack's and vice versa; corruptions refused")

# round 21 (UPDATE 2026-11-14): the no-prf2 candidate (ts200 + split810 + wprf2b). Its verifier rules are ts200's and
# split810's; wprf2b is signer-side. So the all3 verifier (and the ts200 + split810 verifier, the same rules) must
# accept it, and the 0.3, ts200-only and split810-only verifiers must refuse it.
NP2 = ("ts200", "split810", "wprf2b")
acc_cfgs = (ALL3, ("ts200", "split810"))
rej_cfgs = ((), ("ts200",), ("split810",))
m2 = 0
for k in range(3):
    sk, ps = r.kat_key(k)
    for i in range(2):
        m = r.kat_msg(k, i)
        r.configure(NP2)
        root = r.keygen(sk, ps)
        sig = r.sign(sk, ps, root, m)
        bad = bytearray(sig); bad[2336 + 5] ^= 1
        for v in acc_cfgs:
            r.configure(v)
            assert r.verify(ps, root, m, sig), (k, i, v)
            assert not r.verify(ps, root, m, bytes(bad)), (k, i, v)
        for v in rej_cfgs:
            r.configure(v)
            assert not r.verify(ps, root, m, sig), (k, i, v)
        m2 += 1
print(f"no-prf2 candidate: {m2} signatures accepted by the all3 and ts200+split810 verifiers, refused by 0.3,"
      f" ts200-only and split810-only; corruptions refused")
