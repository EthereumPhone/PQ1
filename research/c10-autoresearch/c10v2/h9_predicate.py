# Transcription of pqsigner_v2_search43_target's accept predicate (H9) against
# the definition sum((D >> 3i) & 7, i < 43) == target, with D the big-endian digest.
import random, sys
M = 0xFFFFFFFF
def g24(v):
    s = (v & 0o07070707) + ((v >> 3) & 0o07070707)
    s = (s & 0o00770077) + ((s >> 6) & 0o00770077)
    return ((s & 0o7777) + (s >> 12)) & M
def words(D):  # HR3..HR7: big-endian words 3..7 of the 32-byte digest
    return [(D >> (32 * (7 - k))) & M for k in (3, 4, 5, 6, 7)]
def accept(D, target, slack):
    w3, w4, w5, w6, w7 = words(D)
    s4 = (g24(w7 & 0xFFFFFF) + g24((w7 >> 24) | ((w6 & 0xFFFF) << 8)) + g24((w6 >> 16) | ((w5 & 0xFF) << 16)) + g24(w5 >> 8)) & M
    if (s4 + slack) & M >= target:
        t = (w4 >> 24) | ((w3 & 1) << 8)
        return (s4 + g24(w4 & 0xFFFFFF) + (t & 7) + ((t >> 3) & 7) + (t >> 6)) & M == target
    return False
def truth(D, target):
    return sum((D >> (3 * i)) & 7 for i in range(43)) == target
def digest_from_digits(ds, rest):  # 43 digits low-first, plus arbitrary bits above bit 129
    D = rest << 129
    for i, d in enumerate(ds):
        D |= d << (3 * i)
    return D
def run(slack):
    rnd = random.Random(1); bad = 0; n = 0
    cases = []
    for _ in range(200000):
        cases.append(rnd.getrandbits(256))
    for k in range(256):
        cases.append(1 << k)
    # Boundary: digits 32..42 all 7 (77), digits 0..31 summing to exactly 128.
    for _ in range(2000):
        while True:
            lo = [rnd.randrange(8) for _ in range(32)]
            if sum(lo) == 128: break
        cases.append(digest_from_digits(lo + [7] * 11, rnd.getrandbits(127)))
    # Near-target random sums (hits and misses around 205).
    for _ in range(20000):
        ds = [rnd.randrange(8) for _ in range(43)]
        while sum(ds) < 200:
            i = rnd.randrange(43); ds[i] = min(7, ds[i] + 1)
        cases.append(digest_from_digits(ds, rnd.getrandbits(127)))
    for D in cases:
        for target in (205, 200, 150, 128, 301, 0):  # 200: the ts200 variant (format-options check)
            n += 1
            bad += accept(D, target, slack) != truth(D, target)
    return n, bad
n, bad = run(77); print(f"slack 77: {n} checks, {bad} mismatches")
n2, bad2 = run(76); print(f"slack 76 (control): {n2} checks, {bad2} mismatches")
sys.exit(0 if bad == 0 and bad2 > 0 else 1)
