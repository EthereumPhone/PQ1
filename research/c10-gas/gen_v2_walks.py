#!/usr/bin/env python3
"""gen_v2_walks.py — emit the unrolled FORS and hypertree auth walks of the v2 verifiers
(#1155 gas track), between `// BEGIN generated FORS walk` / `// END generated FORS walk` and
`// BEGIN generated Merkle walk` / `// END generated Merkle walk`.

Each level hashes S || L16 || R16 || A7 in place:
  * the node at height h-1 sits at slot s_{h-1} in {0x10, 0x20} (0x10 iff bit h-1 of its leaf
    index t is 0); its sibling is copied to the other half, 0x30 - s_{h-1};
  * A7 bytes 0..4 (type, layer, tree, kp, ci) are constant for the whole walk and stored once at
    0x30; per level only bytes 5..6 (cp = h, ha = t >> h) are rewritten by mstore(0x35, ...);
  * the parent lands at s_h (or, at the top, at its T_13 slot / at 0x10).
The per-level slots and (cp, ha) pairs come from two words (cpha, slots) computed once per walk with one MUL
each (lines tagged C10-LANES; exhaustive unit gate test/gas/C10Lanes.t.sol):
  cpha  = (t * K2 & M2) | C2: 16-bit lane h-1 (from the top) = h<<12 | (t>>h)<<1, h = 1..11;
  slots = (t * K1 & M1) + M1: byte 2k+1 = 0x10 + 16 * bit k of t, k = 0..10.
Valid for t < 2^11 (FORS tree index, hypertree leaf index of height <= 11).

  --check FILE [split810]   fail if the file's blocks differ from this output
  --write FILE [split810]   replace them
"""
import sys

I = " " * 16
LANES = [
    "let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), "
    "0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), "
    "0x100020003000400050006000700080009000a000b00000000000000000000000) // C10-LANES",
    "let slots := add(and(mul(t, 0x10000800040002000100008000400020001000080004000000000000000000), "
    "0x10001000100010001000100010001000100010001000000000000000000000), "
    "0x10001000100010001000100010001000100010001000000000000000000000) // C10-LANES",
]


def level(ind, h, ptr, out):
    return [f"{ind}calldatacopy(sub(0x30, byte({2 * h - 1}, slots)), add({ptr}, {16 * (h - 1)}), 16)",
            f"{ind}mstore(0x35, shl({16 * (h - 1)}, cpha))",
            f"{ind}pop(staticcall(gas(), 0x02, 0x00, 55, {out}, 16))"]


def gen_slot(h):
    return f"byte({2 * h + 1}, slots)"


def fors():
    o = [f"{I}// BEGIN generated FORS walk (research/c10-gas/gen_v2_walks.py; do not edit by hand)",
         f"{I}let t := treeIdx"] + [I + l for l in LANES] + [
        f"{I}pop(staticcall(gas(), 0x02, 0x00, 39, {gen_slot(0)}, 16)) // the leaf, at its slot",
        f"{I}mstore(0x30, shl(200, base)) // A7 bytes 0..4 for all 11 levels",
        f"{I}let authPtr := add(sigBase, add(224, mul(i, 176)))"]
    for h in range(1, 11):
        o += level(I, h, "authPtr", gen_slot(h))
    o += level(I, 11, "authPtr", "add(TB, add(24, shl(4, i)))")  # the root, into T_13 slot i
    o.append(f"{I}// END generated FORS walk")
    return "\n".join(o) + "\n"


def merkle(split810=False):
    o = [f"{I}// BEGIN generated Merkle walk (research/c10-gas/gen_v2_walks.py; do not edit by hand)",
         f"{I}let t := idxLeaf"] + [I + l for l in LANES] + [
        f"{I}mstore(0x30, shl(200, treeBase)) // A7 bytes 0..4 for every level (the chains overwrote 0x30)",
        f"{I}pop(staticcall(gas(), 0x02, TB, 712, {gen_slot(0)}, 16)) // T_43: the WOTS pk, at its slot",
        f"{I}let merklePtr := add(sigBase, add(countOff, 4))"]
    if not split810:
        for h in range(1, 9):
            o += level(I, h, "merklePtr", gen_slot(h))
        o += level(I, 9, "merklePtr", "0x10")  # the root (index 0): the next layer's m16
    else:
        # heights 1..8 for both layers (layer 0's root, index 0 at height 8, lands at 0x10 by
        # the slot rule); heights 9..10 for layer 1 only, its root at 0x10
        for h in range(1, 9):
            o += level(I, h, "merklePtr", gen_slot(h))
        o.append(f"{I}if layer {{")
        o += level(I + "    ", 9, "merklePtr", gen_slot(9))
        o += level(I + "    ", 10, "merklePtr", "0x10")
        o.append(f"{I}}}")
    o.append(f"{I}// END generated Merkle walk")
    return "\n".join(o) + "\n"


def splice(src, tag, new):
    b = src.index(f"// BEGIN generated {tag}")
    b = src.rindex("\n", 0, b) + 1
    e = src.index(f"// END generated {tag}")
    e = src.index("\n", e) + 1
    return src[:b] + new + src[e:]


def apply(src, split810=False):
    return splice(splice(src, "FORS walk", fors()), "Merkle walk", merkle(split810))


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    split = len(sys.argv) > 3 and sys.argv[3] == "split810"
    src = open(path).read()
    new = apply(src, split)
    if mode == "--check":
        sys.exit(0 if new == src else "generated walk blocks differ from gen_v2_walks.py output")
    open(path, "w").write(new)
