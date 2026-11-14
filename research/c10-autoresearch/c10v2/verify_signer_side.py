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
