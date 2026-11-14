#!/usr/bin/env python3
"""count_calls.py VARIANT... — round 19: exact SHA-256 call counts of c10v2_ref.py's keygen, sign and verify
(KAT key 0; messages 0..3), by wrapping its sha256. Draft 0.3's keygen (177,151) equals the Rust host count (round
16), which cross-checks the counter; the Python verifier makes one call more per layer than Rust's (363 against 361);
sign depends on the message through the grinds."""
import sys
import c10v2_ref as r

n = [0]
_sha = r.sha256
def counted(b):
    n[0] += 1
    return _sha(b)
r.sha256 = counted

def take():
    v, n[0] = n[0], 0
    return v

for name in sys.argv[1:] or ["draft03"]:
    r.configure(() if name == "draft03" else name.split(","))
    sk, ps = r.kat_key(0)
    take()
    root = r.keygen(sk, ps)
    kg = take()
    signs, verifies = [], []
    for i in range(4):
        m = r.kat_msg(0, i)
        take()                      # the message derivation is not part of sign (Astra r19)
        sig = r.sign(sk, ps, root, m)
        signs.append(take())
        assert r.verify(ps, root, m, sig)
        verifies.append(take())
    print(f"{r.variant_name():14s} keygen {kg:,}  sign {', '.join(f'{x:,}' for x in signs)} (mean {sum(signs) / 4:,.0f})"
          f"  verify {', '.join(str(x) for x in sorted(set(verifies)))}  sig {r.SIG_LEN} B")
