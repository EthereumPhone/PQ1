#!/usr/bin/env python3
"""d3_insight.py — round 19: why the best d = 3 sets fail the every-term reading, and how much of it is accounting
slack. Every term of both games (family_bound, the EasyCrypt shape) at C = 1, 2, 16 against stock; then the binding
term — the wrapper `node` term's exceptional branch exc(exc+1)/N, exc = qr + (2*EXC_PER_SIGN + V0)*qs + V0 — re-run
with V0 (the per-signature verification charge, the EasyCrypt literal 771 for stock) replaced by the verifier's
actual hash-call count (n_calls: chains charged from the signature value, l(w-1) - T steps per layer, not the full
l(w-1)). Computed, not proved: a tightened cost lemma would have to justify the smaller charge."""
import math
import family_bound as fb

STOCK = dict(fb.STOCK)
SETS = {"h18 d3 a11 k13 w8 l46 T209": dict(STOCK, d=3, l=46, T=209),
        "h18 d3 a11 k13 w8 l43 T203": dict(STOCK, d=3, l=43, T=203)}
lg = lambda x: math.log2(x)


def terms(p, C, v0=None):
    c = fb.consts_g(p)
    if v0 is not None:
        c = dict(c, verify=v0)
    qs = C * 2 ** 16
    _, to = fb.ordinary_terms(2 ** 16, qs, c, fb.FLOAT)
    _, tw = fb.wrapper_terms(2 ** 16, qs, c, fb.FLOAT)
    return {("ord", k): float(v) for k, v in to.items()} | {("wrap", k): float(v) for k, v in tw.items()}


def main():
    print("every returned term, ratio set/stock (log2), worst five per set; and the game totals")
    for name, p in SETS.items():
        rs = []
        for C in (1, 2, 16):
            a, b = terms(p, C), terms(STOCK, C)
            for k in a:
                rs.append((lg(a[k] / b[k]), C, k, lg(a[k]), lg(sum(v for kk, v in a.items() if kk[0] == k[0]))))
        rs.sort(reverse=True)
        print(f"  {name}:")
        for r, C, k, sz, tot in rs[:5]:
            print(f"    {k[0]:4s} {k[1]:9s} C={C:2d}  {r:+.3f} b  (term 2^{sz:.1f}, that game's total 2^{tot:.1f})")
        for C in (1, 16):
            a, b = terms(p, C), terms(STOCK, C)
            for g in ("ord", "wrap"):
                ta, tb = sum(v for k, v in a.items() if k[0] == g), sum(v for k, v in b.items() if k[0] == g)
                print(f"    total {g:4s} C={C:2d}: x{ta / tb:.3f}")
    print("\nthe binding term with the verification charged at the verifier's actual call count (tight accounting)")
    v0s = fb.n_calls(STOCK)
    for name, p in SETS.items():
        c, cs = fb.consts_g(p), fb.consts_g(STOCK)
        v0 = fb.n_calls(p)
        for C in (1, 16):
            loose = lg(terms(p, C)[("wrap", "node")] / terms(STOCK, C)[("wrap", "node")])
            tight = lg(terms(p, C, v0)[("wrap", "node")] / terms(STOCK, C, v0s)[("wrap", "node")])
            print(f"  {name} C={C:2d}: V0 charged {c['verify']} vs stock {cs['verify']} -> wrapper node {loose:+.3f} b;"
                  f" actual calls {v0} vs {v0s} -> {tight:+.3f} b")
        worst_other = max(lg(terms(p, C)[k] / terms(STOCK, C)[k]) for C in (1, 2, 16) for k in terms(p, C)
                          if k != ("wrap", "node"))
        print(f"    every other term: worst {worst_other:+.3f} b")


if __name__ == "__main__":
    main()
