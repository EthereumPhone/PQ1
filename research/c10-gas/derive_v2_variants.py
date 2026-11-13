#!/usr/bin/env python3
"""derive_v2_variants.py — derive the three research-variant verifiers from the optimized draft-0.3
verifier (#1155 gas track), so the variants carry exactly the same optimizations.

  ts200    : WOTS+C target digit sum 200 instead of 205;
  split810 : hypertree layer heights (8, 10) and the matching A7 layout (kp 10 bits at 32..23,
             ci at 22..17, FORS addresses included);
  all3     : ts200 + split810 (prf2 is signer-side only).

Every edit is an exact, asserted text substitution on src/verifiers/SPHINCsC10v2Asm.sol; the doc
header of each variant is kept from its current file. Equivalence of each derived variant with
its frozen reference (test/ref/RefSPHINCsC10v2{Ts200,Split810,All3}Asm.sol) is checked by
test/gas/C10VariantEquivalence.t.sol, not by this script.

Usage (from the worktree root):
  python3 research/c10-gas/derive_v2_variants.py --write   # regenerate the three variant files
  python3 research/c10-gas/derive_v2_variants.py --check   # fail if they differ from a fresh derivation
"""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VER = os.path.join(ROOT, "contracts", "smart-wallet", "src", "verifiers")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_v2_chains  # noqa: E402
import gen_v2_walks  # noqa: E402

BASE = os.path.join(VER, "SPHINCsC10v2Asm.sol")
I = " " * 16


def sub(s, old, new):
    assert s.count(old) == 1, f"expected exactly one occurrence of:\n{old}"
    return s.replace(old, new)


OLD_MEMORY = """/// Memory: 0x00.. scratch for one-block preimages (S at 0x00..0x10, never overwritten);
/// 0x800.. the T_k buffer `S || A7 || 0x00 || v_0 ..`; 0x780 the precompile output.
"""


def header(path):
    """The variant's own doc header (everything before its `contract` line), with its memory note
    replaced by the optimized base's (the reference variants carry the old 0x800/0x780 layout)."""
    src = open(path).read()
    h = src[: src.index("\ncontract ") + 1]
    b = open(BASE).read()
    mem = b[b.index("/// Memory:"): b.index("/// Packed 16-byte stores")]
    if OLD_MEMORY in h:
        h = h.replace(OLD_MEMORY, mem)
    assert mem in h, f"memory note missing in {path}"
    return h


def body(src):
    return src[src.index("\ncontract ") + 1:]


def ts200(b):
    return sub(b, "if iszero(eq(digitSum, 205)) { revert(0, 0) } // WOTS+C target sum",
               "if iszero(eq(digitSum, 200)) { revert(0, 0) } // WOTS+C target sum (variant ts200: 200)")


def split810(b):
    b = sub(b, "            // A7 = type<<52 | layer<<51 | tree<<33 | kp<<24 | ci<<18 | cp<<12 | ha<<1 (spec §1).",
            "            // A7 (variant split810) = type<<52 | layer<<51 | tree<<33 | kp<<23 | ci<<17 | cp<<12 | ha<<1:\n"
            "            // kp widens to 10 bits (32..23), ci moves to 22..17; every other field as spec §1.")
    b = sub(b, "let base := or(or(shl(52, 3), shl(33, htIdx)), shl(24, i))",
            "let base := or(or(shl(52, 3), shl(33, htIdx)), shl(23, i))")
    b = sub(b, """                let idxLeaf := and(idxTree, 0x1FF)
                idxTree := shr(9, idxTree)
                let kpBase := or(or(shl(51, layer), shl(33, idxTree)), shl(24, idxLeaf))""",
            """                let hl := add(8, shl(1, layer)) // subtree height: 8 at layer 0, 10 at layer 1
                let idxLeaf := and(idxTree, sub(shl(hl, 1), 1))
                idxTree := shr(hl, idxTree)
                let kpBase := or(or(shl(51, layer), shl(33, idxTree)), shl(23, idxLeaf))""")
    b = sub(b, "// overwrites it. A7 = chainA | i<<18 | p<<12 (type 0, WOTS_HASH): bytes 0..3 and 6\n"
               "                // are those of chainA, written once per layer; byte 4 = ci<<2 is written per chain and",
            "// overwrites it. A7 = chainA | i<<17 | p<<12 (type 0, WOTS_HASH): bytes 0..3 and 6\n"
            "                // are those of chainA, written once per layer; byte 4 = kb | ci<<1 (split810: kp's\n"
            "                // lowest bit, A7 bit 23, is byte 4's top bit, kept in kb) is written per chain and")
    b = sub(b, "                mstore(0x20, shl(200, kpBase)) // A7 of chain 0 at position 0\n",
            "                mstore(0x20, shl(200, kpBase)) // A7 of chain 0 at position 0\n"
            "                let kb := byte(4, shl(200, kpBase)) // A7 byte 4 without ci: kp bit 0 at bit 7\n")
    b = gen_v2_chains.splice(b, gen_v2_chains.block_bytes(split810=True))
    # Merkle: heights 1..8 for both layers, 9..10 for layer 1 only (gen_v2_walks.merkle(split810))
    b = sub(b, "// the FORS one (generated); the root (index 0 at height 9) lands at 0x10, the next\n"
               "                // layer's m16.",
            "// the FORS one (generated); heights 1..8 for both layers, 9..10 for layer 1 only;\n"
            "                // the root (index 0, height 8 or 10) lands at 0x10, the next layer's m16.")
    b = gen_v2_walks.splice(b, "Merkle walk", gen_v2_walks.merkle(split810=True))
    b = sub(b, "                sigOff := add(countOff, 148) // 4 + 9*16",
            "                sigOff := add(countOff, add(4, shl(4, hl))) // 4 + hl*16: 132 (layer 0), 164 (layer 1)")
    return b


VARIANTS = {
    "SPHINCsC10v2Ts200Asm": lambda b: ts200(b),
    "SPHINCsC10v2Split810Asm": lambda b: split810(b),
    "SPHINCsC10v2All3Asm": lambda b: ts200(split810(b)),
}


def derive():
    base = body(open(BASE).read())
    assert base.startswith("contract SPHINCsC10v2Asm {")
    out = {}
    for name, f in VARIANTS.items():
        path = os.path.join(VER, name + ".sol")
        b = f(base).replace("contract SPHINCsC10v2Asm {", f"contract {name} {{", 1)
        out[path] = header(path) + b
    return out


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    bad = 0
    for path, text in derive().items():
        if mode == "--write":
            open(path, "w").write(text)
        elif open(path).read() != text:
            print(f"differs from derivation: {path}")
            bad += 1
    sys.exit(1 if bad else 0)
