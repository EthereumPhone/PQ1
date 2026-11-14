#!/usr/bin/env python3
"""prefix_check.py — round 20: the merged PRF keeps every sk_seed-keyed SHA-256 input block-prefix-free (the prf2
PRF argument, format-options-security.md); round 21: optional variant argument. Records every sha256 input that starts with sk_seed during a full-stack
keygen and two signs (with and without opt_rand), pads each (SHA-256 Merkle-Damgard), and checks that no input's
block sequence is a proper prefix of, or equal to, a different input's. Also prints the classes (length, byte 32)."""
import collections
import sys
import c10v2_ref as r

def blocks(m):
    ml = len(m) * 8
    p = m + b"\x80" + b"\x00" * ((55 - len(m)) % 64) + ml.to_bytes(8, "big")
    return tuple(p[i:i + 64] for i in range(0, len(p), 64))

# round 21: an optional variant list (default: the full stack), e.g. ts200,split810,wprf2b for the no-prf2 candidate
r.configure(sys.argv[1].split(",") if len(sys.argv) > 1 else ("ts200", "prf2", "split810", "wprf2b"))
sk, ps = r.kat_key(0)
seen = set()
_sha = r.sha256
def rec(b):
    if b[:32] == sk:
        seen.add(bytes(b))
    return _sha(b)
r.sha256 = rec
root = r.keygen(sk, ps)
m = r.kat_msg(0, 0)
r.sign(sk, ps, root, m)
r.sign(sk, ps, root, m, opt_rand=bytes(range(16))) if "opt_rand" in r.sign.__code__.co_varnames else None
classes = collections.Counter((len(x), x[32]) for x in seen)
by_first = collections.defaultdict(list)
for x in seen:
    by_first[blocks(x)[0]].append(blocks(x))
bad = 0
for fb, seqs in by_first.items():
    seqs = sorted(set(seqs), key=len)
    for i, a in enumerate(seqs):
        for b in seqs[i + 1:]:
            if b[:len(a)] == a:
                bad += 1
print(f"{len(seen):,} distinct sk_seed-keyed inputs; classes (length, byte 32): "
      + ", ".join(f"({l} B, 0x{c:02x}) x{n:,}" for (l, c), n in sorted(classes.items())))
print(f"first blocks shared by several inputs: {sum(1 for v in by_first.values() if len(v) > 1)}; prefix relations: {bad}")
assert bad == 0
print("block-prefix-free: OK")
