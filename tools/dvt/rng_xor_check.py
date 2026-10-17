#!/usr/bin/env python3
"""Independently check an `rng-xor-probe` log (DVT row 4.9 / XOR check).

For every successful `rng_strong::fill` call the probe prints the platform
(STM32 TRNG) bytes `P`, each secure-element block in draw order (`O` OPTIGA,
`S` SE050, alternating per fold chunk) and the output. This recomputes
`OUT == P ^ OPTIGA ^ SE050` from those bytes, and checks that no source block
is zero, that the three contributions differ, and that no block repeats
across calls.

    tools/dvt/rng_xor_check.py run.log
"""
import re
import sys


def main(path):
    calls, cur = [], None
    for line in open(path, errors="replace"):
        m = re.search(r"\[xor\] CALL (\S+) n=(\d+) result=(\w+)", line)
        if m:
            cur = {"tag": m[1], "n": int(m[2]), "ok": m[3] == "Ok", "P": b"", "recs": [], "OUT": None}
            calls.append(cur)
            continue
        if cur is None:
            continue
        m = re.search(r"\[xor\] P ([0-9a-f]*)$", line.strip())
        if m:
            cur["P"] = bytes.fromhex(m[1])
            continue
        m = re.search(r"\[xor\] ([OS]) ok=(\d) len=(\d+) ([0-9a-f]*)$", line.strip())
        if m:
            cur["recs"].append((m[1], m[2] == "1", bytes.fromhex(m[4])))
            continue
        m = re.search(r"\[xor\] OUT ([0-9a-f]*)$", line.strip())
        if m:
            cur["OUT"] = bytes.fromhex(m[1])

    seen, bad, checked = set(), 0, 0
    for c in calls:
        if not c["ok"]:
            continue
        out, p = c["OUT"], c["P"]
        opt = b"".join(b for s, ok, b in c["recs"] if s == "O")
        se = b"".join(b for s, ok, b in c["recs"] if s == "S")
        order_ok = [s for s, _, _ in c["recs"]] == ["O", "S"] * (len(c["recs"]) // 2)
        problems = []
        if not order_ok or len(opt) != len(out) or len(se) != len(out) or len(p) != len(out):
            problems.append("shape")
        elif bytes(a ^ b ^ d for a, b, d in zip(p, opt, se)) != out:
            problems.append("XOR mismatch")
        for name, blob in (("P", p), ("O", opt), ("S", se)):
            if blob and not any(blob):
                problems.append(f"{name} all zero")
        if len({p, opt, se}) != 3:
            problems.append("two sources equal")
        for s, _, b in c["recs"]:
            if b in seen:
                problems.append(f"repeated {s} block")
            seen.add(b)
        checked += 1
        bad += bool(problems)
        print(f"{c['tag']:>18} n={c['n']:<3} {'OK' if not problems else ', '.join(problems)}")
    print(f"checked {checked} successful calls, {bad} with problems")
    return 1 if bad or not checked else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
