#!/usr/bin/env python3
"""gen_v2_chains.py — emit the unrolled WOTS chain block of SPHINCsC10v2Asm.sol (#1155 gas track).

The verifier carries the output between the markers `// BEGIN generated chains` and
`// END generated chains`; `--check FILE` fails if the file's block differs from this output,
`--write FILE` replaces it. Chain i (0..42): copy its 16-byte signature value to 0x10, run
positions digit_i = (d >> 3i) & 7 .. 6 in place, copy the end value to T_43 slot i.
"""
import sys

I = " " * 16


def block(indent=I, ci_shift=218):
    """ci_shift = 200 + the A7 bit of the chain-index field: 218 for draft 0.3, 217 for split810."""
    out = [f"{indent}// BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)"]
    for i in range(43):
        out.append(f"{indent}calldatacopy(0x10, add(wotsPtr, {16 * i}), 16) // chain {i}")
        out.append(f"{indent}for {{ let a := add(chainA, or(shl({ci_shift}, {i}), shl(212, and(shr({3 * i}, d), 7)))) }}"
                   f" lt(a, add(chainA, or(shl({ci_shift}, {i}), shl(212, 7)))) {{ a := add(a, shl(212, 1)) }} {{")
        out.append(f"{indent}    mstore(0x20, a)")
        out.append(f"{indent}    pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))")
        out.append(f"{indent}}}")
        out.append(f"{indent}mstore(add(TB, {24 + 16 * i}), mload(0x10))")
    out.append(f"{indent}// END generated chains")
    return "\n".join(out) + "\n"


def splice(src, new):
    b = src.index("// BEGIN generated chains")
    b = src.rindex("\n", 0, b) + 1
    e = src.index("// END generated chains")
    e = src.index("\n", e) + 1
    return src[:b] + new + src[e:]


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    ci = int(sys.argv[3]) if len(sys.argv) > 3 else 218
    src = open(path).read()
    new = splice(src, block(ci_shift=ci))
    if mode == "--check":
        sys.exit(0 if new == src else "generated chain block differs from gen_v2_chains.py output")
    open(path, "w").write(new)
