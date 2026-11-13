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
    step = lambda ind, off: [f"{ind}mstore(0x20, {'a' if off == 0 else f'add(a, shl(212, {off}))'})",
                             f"{ind}pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))"]
    for i in range(43):
        out.append(f"{indent}calldatacopy(0x10, add(wotsPtr, {16 * i}), 16) // chain {i}")
        out.append(f"{indent}{{")
        j = indent + "    "
        out.append(f"{j}let a := add(chainA, or(shl({ci_shift}, {i}), shl(212, and(shr({3 * i}, d), 7))))")
        for blk in (4, 2, 1):
            bit = 3 * i + {4: 2, 2: 1, 1: 0}[blk]
            out.append(f"{j}if and(nd, shl({bit}, 1)) {{")
            for k in range(blk):
                out += step(j + "    ", k)
            if blk > 1:
                out.append(f"{j}    a := add(a, shl(212, {blk}))")
            out.append(f"{j}}}")
        out.append(f"{indent}}}")
        out.append(f"{indent}mstore(add(TB, {24 + 16 * i}), mload(0x10))")
    out.append(f"{indent}// END generated chains")
    return "\n".join(out) + "\n"


def _digit16(i):
    """digit_i << 4 = ((d >> 3i) & 7) << 4, i.e. cp byte (A7 byte 5) of the chain's first position."""
    sh = 3 * i - 4
    if sh >= 0:
        return f"and(shr({sh}, d), 0x70)"
    return f"and(shl({-sh}, d), 0x70)"


def block_bytes(indent=I, split810=False):
    """Byte-wise A7 (batch 3): the per-layer `mstore(0x20, chainA)` leaves A7 bytes 0..3 and byte 6
    in place; per chain only byte 4 (ci) and per step only byte 5 (cp << 4) are written with
    mstore8. Position algebra (s = 7 - digit = 4 b2 + 2 b1 + b0, blocks run 4, 2, 1): the 4-block
    starts at digit, the 2-block at digit | 4, the 1-block is always position 6."""
    out = [f"{indent}// BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)"]
    call = "pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))"
    for i in range(43):
        out.append(f"{indent}calldatacopy(0x10, add(wotsPtr, {16 * i}), 16) // chain {i}")
        ci = f"or(kb, {2 * i})" if split810 else f"{4 * i}"
        out.append(f"{indent}mstore8(0x24, {ci}) // A7 byte 4: ci")
        out.append(f"{indent}{{")
        j = indent + "    "
        out.append(f"{j}let p := {_digit16(i)}")
        out.append(f"{j}if and(nd, shl({3 * i + 2}, 1)) {{")
        for k in range(4):
            v = "p" if k == 0 else f"add(p, {hex(16 * k)})"
            out += [f"{j}    mstore8(0x25, {v})", f"{j}    {call}"]
        out.append(f"{j}}}")
        out.append(f"{j}if and(nd, shl({3 * i + 1}, 1)) {{")
        out += [f"{j}    mstore8(0x25, or(p, 0x40))", f"{j}    {call}",
                f"{j}    mstore8(0x25, add(or(p, 0x40), 0x10))", f"{j}    {call}"]
        out.append(f"{j}}}")
        out.append(f"{j}if and(nd, shl({3 * i}, 1)) {{")
        out += [f"{j}    mstore8(0x25, 0x60)", f"{j}    {call}"]
        out.append(f"{j}}}")
        out.append(f"{indent}}}")
        out.append(f"{indent}mstore(add(TB, {24 + 16 * i}), mload(0x10))")
    out.append(f"{indent}// END generated chains")
    return "\n".join(out) + "\n"


def block_bytes_loop(indent=I, split810=False):
    """Size option "no B4": byte-wise A7, chains unrolled, steps as a loop over cp."""
    out = [f"{indent}// BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)"]
    for i in range(43):
        ci = f"or(kb, {2 * i})" if split810 else f"{4 * i}"
        out += [f"{indent}calldatacopy(0x10, add(wotsPtr, {16 * i}), 16) // chain {i}",
                f"{indent}mstore8(0x24, {ci}) // A7 byte 4: ci",
                f"{indent}for {{ let p := {_digit16(i)} }} lt(p, 0x70) {{ p := add(p, 0x10) }} {{",
                f"{indent}    mstore8(0x25, p)",
                f"{indent}    pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))",
                f"{indent}}}",
                f"{indent}mstore(add(TB, {24 + 16 * i}), mload(0x10))"]
    out.append(f"{indent}// END generated chains")
    return "\n".join(out) + "\n"


def block_bytes_rolled(indent=I, split810=False):
    """Size option "compact": byte-wise A7, one loop over the 43 chains, steps as a loop."""
    ci = "or(kb, shr(3, o))" if split810 else "shr(2, o)"
    out = [f"{indent}// BEGIN generated chains (research/c10-gas/gen_v2_chains.py; do not edit by hand)",
           f"{indent}let dd := d",
           f"{indent}for {{ let o := 0 }} lt(o, 688) {{ o := add(o, 16) }} {{ // o = 16 * chain index",
           f"{indent}    calldatacopy(0x10, add(wotsPtr, o), 16)",
           f"{indent}    mstore8(0x24, {ci}) // A7 byte 4: ci",
           f"{indent}    for {{ let p := shl(4, and(dd, 7)) }} lt(p, 0x70) {{ p := add(p, 0x10) }} {{",
           f"{indent}        mstore8(0x25, p)",
           f"{indent}        pop(staticcall(gas(), 0x02, 0x00, 39, 0x10, 16))",
           f"{indent}    }}",
           f"{indent}    mstore(add(add(TB, 24), o), mload(0x10))",
           f"{indent}    dd := shr(3, dd)",
           f"{indent}}}",
           f"{indent}// END generated chains"]
    return "\n".join(out) + "\n"


def block_v1(indent=I):
    """The same blocks for the v1 (32-byte) layout: value word at 0x40 (low half zero), ADRS word
    at 0x20 = wotsAdrs | i<<64 | p<<32, 96-byte preimage, endpoint to TB + 0x40 + 32 i."""
    out = [f"{indent}// BEGIN generated chains (research/c10-gas/gen_v2_chains.py v1; do not edit by hand)"]
    step = lambda ind, off: [f"{ind}mstore(0x20, {'a' if off == 0 else f'add(a, shl(32, {off}))'})",
                             f"{ind}pop(staticcall(gas(), 0x02, 0x00, 0x60, 0x40, 16))"]
    for i in range(43):
        out.append(f"{indent}mstore(0x40, and(calldataload(add(wotsPtr, {16 * i})), N_MASK)) // chain {i}")
        out.append(f"{indent}{{")
        j = indent + "    "
        out.append(f"{j}let a := add(wotsAdrs, or(shl(64, {i}), shl(32, and(shr({3 * i}, d), 7))))")
        for blk in (4, 2, 1):
            bit = 3 * i + {4: 2, 2: 1, 1: 0}[blk]
            out.append(f"{j}if and(nd, shl({bit}, 1)) {{")
            for k in range(blk):
                out += step(j + "    ", k)
            if blk > 1:
                out.append(f"{j}    a := add(a, shl(32, {blk}))")
            out.append(f"{j}}}")
        out.append(f"{indent}}}")
        out.append(f"{indent}mstore(add(TB, {0x40 + 32 * i}), mload(0x40))")
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
    arg = sys.argv[3] if len(sys.argv) > 3 else "218"
    src = open(path).read()
    if arg == "v1":
        new = splice(src, block_v1())
    elif arg == "split810":
        new = splice(src, block_bytes(split810=True))
    else:
        new = splice(src, block_bytes())
    if mode == "--check":
        sys.exit(0 if new == src else "generated chain block differs from gen_v2_chains.py output")
    open(path, "w").write(new)
