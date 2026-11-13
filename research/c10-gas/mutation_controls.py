#!/usr/bin/env python3
"""
mutation_controls.py — show the equivalence gate can fail (#1155 gas track).

Plants one small semantic bug at a time into a CANDIDATE verifier (src/verifiers/), runs the
equivalence + per-primitive gates, and requires them to FAIL. The file is restored after every
mutant (also on error / Ctrl-C). A mutant whose `old` text is not found exactly once is
reported STALE: the candidate changed, so the mutant list must be updated before the result
counts. Exit status 0 only if every listed mutant applied and was caught.

Usage (from the worktree root):
  python3 research/c10-gas/mutation_controls.py [v1|v2|all] [--runs N]
"""
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SW = os.path.join(ROOT, "contracts", "smart-wallet")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
V2 = "src/verifiers/SPHINCsC10v2Asm.sol"
V1 = "src/verifiers/SPHINCsC10Asm.sol"
VTS = "src/verifiers/SPHINCsC10v2Ts200Asm.sol"
VSP = "src/verifiers/SPHINCsC10v2Split810Asm.sol"
VA3 = "src/verifiers/SPHINCsC10v2All3Asm.sol"
# forge --match-contract regex per mutated file: the semantic gates for that verifier only (the
# gas benches are excluded; a mutant that only a gas bench notices counts as MISSED)
SUITES = {
    V1: "^(C10EquivalenceTest|C10PrimitiveTraceTest|C10DigitSumTest)$",
    V2: "^(C10EquivalenceTest|C10PrimitiveTraceTest|C10DigitSumTest|C10LanesTest)$",
    VTS: "^C10VariantEquivalenceTs200Test$",
    VSP: "^C10VariantEquivalenceSplit810Test$",
    VA3: "^C10VariantEquivalenceAll3Test$",
}

# (id, file, old, new, what it breaks). Keep `old` unique in the CURRENT candidate.
MUTANTS = [
    # ── v2 ──
    ("v2-len-reason", V2, '"Invalid sig length"', '"Invalid sig lengtH"',
     "revert data of the length check (returndata compare)"),
    ("v2-len-ge", V2, "eq(sig.length, 4008)", "gt(sig.length, 4007)",
     "longer signatures pass the length check"),
    ("v2-seedmask-drop", V2, "if iszero(eq(and(pkSeed, N_MASK), pkSeed)) {",
     "if iszero(eq(and(pkSeed, not(0)), pkSeed)) {", "I-2 key-shape false path for pkSeed"),
    ("v2-forsc-drop", V2, "if and(shr(132, digest), 0x7FF) { revert(0, 0) }", "",
     "FORS+C last-index rule removed"),
    ("v2-wotsc-false", V2, "if iszero(eq(digitSum, 205)) { revert(0, 0) }",
     "if iszero(eq(digitSum, 205)) { mstore(0, 0) return(0, 0x20) }",
     "WOTS+C failure returns false instead of reverting"),
    ("v2-count-31bit", V2, "let count := shr(224, calldataload(add(sigBase, countOff)))",
     "let count := and(shr(224, calldataload(add(sigBase, countOff))), 0x7FFFFFFF)",
     "count >= 2^31 hashed with the top bit cleared (only rejected inputs differ: trace-only)"),
    ("v2-root-cmp", V2, "valid := eq(and(mload(0x10), N_MASK), pkRoot)", "valid := eq(and(mload(0x10), N_MASK), and(mload(0x10), N_MASK))",
     "final root comparison"),
    ("v2-e2-sib15", V2, "calldatacopy(byte(8, slots), add(merklePtr, 64), 16)",
     "calldatacopy(byte(8, slots), add(merklePtr, 64), 15)",
     "E2: hypertree sibling copy one byte short (stale last byte)"),
    ("v2-e2-forsroot-slot", V2, "pop(staticcall(gas(), 0x02, 0x00, 55, add(TB, add(24, shl(4, i))), 16))",
     "pop(staticcall(gas(), 0x02, 0x00, 55, add(TB, add(23, shl(4, i))), 16))",
     "E2: FORS root written one byte early into the T_13 buffer"),
    ("v2-swar-lane14", V2, "and(shr(3, d), 0xe070381c0e070381c0e070381c0e07)",
     "and(shr(3, d), 0x1c0e070381c0e070381c0e070381c0e07)",
     "SWAR digit sum counts would-be digit 43 (verifier copy only; text pin)"),
    ("v2-e3-chain-short", V2, "if and(nd, shl(60, 1)) {", "if and(nd, shl(60, 0)) {",
     "B4: WOTS chain 20 skips its single-step block (stops one step early when 7 - digit is odd)"),
    ("v2-b4-block2", V2, "if and(nd, shl(91, 1)) {", "if and(nd, shl(92, 1)) {",
     "B4: chain 30's two-step block keyed on the wrong bit"),
    ("v2-e3-digit7", V2, "calldatacopy(0x10, add(wotsPtr, 672), 16) // chain 42",
     "calldatacopy(0x10, add(wotsPtr, 672), 16) if eq(and(shr(126, d), 7), 7) { mstore(0x10, 0) }",
     "E3: zero-step (digit 7) chains lose their signature value"),
    ("v2-e4-fors-h8-sibslot", V2, "calldatacopy(byte(14, slots), add(authPtr, 112), 16)",
     "calldatacopy(byte(16, slots), add(authPtr, 112), 16)",
     "E4: FORS height-8 sibling slot from the wrong index bit"),
    ("v2-e4-merkle-h5-ha", V2, "calldatacopy(byte(10, slots), add(merklePtr, 80), 16)",
     "calldatacopy(byte(12, slots), add(merklePtr, 80), 16)",
     "E4/B5: hypertree height-6 sibling slot from the wrong index bit"),
    ("v2-b5-fors-h11-cpha", V2, "mstore(0x35, shl(160, cpha))", "mstore(0x35, shl(144, cpha))",
     "B5: FORS root level hashed with height 10's (cp, ha)"),
    ("v2-b5-merkle-a7base", V2, "mstore(0x30, shl(200, treeBase)) // A7 bytes 0..4 for every level (the chains overwrote 0x30)",
     "pop(0)", "B5: hypertree A7 bytes 0..4 left as the last chain step's"),
    ("v2-c3-sibling-lanes", V2, "let slots := sub(add(sbit, 0x2010201020102010201020102010201020102010201000000000000000000000), shl(8, sbit)) // C10-LANES\n" + " " * 16 + "pop(staticcall(gas(), 0x02, 0x00, 39, byte(1, slots), 16))",
     "let slots := sub(add(sbit, 0x2010201020102010201020102010201020102010201000000000000000000000), shl(7, sbit)) // C10-LANES\n" + " " * 16 + "pop(staticcall(gas(), 0x02, 0x00, 39, byte(1, slots), 16))",
     "C3: sibling-slot bytes computed with the wrong shift (FORS walk)"),
    ("v2-b5-lanes-pin", V2, "let t := treeIdx\n" + " " * 16 + "let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), 0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), 0x100020003000400050006000700080009000a000b00000000000000000000000) // C10-LANES",
     "let t := treeIdx\n" + " " * 16 + "let cpha := or(and(mul(t, 0x1000080004000200010000800040002000100008000400000000000000000), 0x7fe03fe01fe00fe007e003e001e000e00060002000000000000000000000000), 0x100020003000400050006000700080009000a000b00000000000000000000001) // C10-LANES",
     "B5: unused low bits of the cp/ha constant changed (semantically equivalent; text pin only)"),
    ("v2-e5-ci-step", V2, "mstore8(0x24, 28) // A7 byte 4: ci", "mstore8(0x24, 32) // A7 byte 4: ci",
     "C1: chain 7 hashed under ci = 8"),
    ("v2-c1-ci-bit16", V2, "mstore8(0x24, 40) // A7 byte 4: ci", "mstore8(0x24, 41) // A7 byte 4: ci",
     "C1: chain 10's A7 byte 4 sets the reserved bit 16"),
    ("v2-c1-digit", V2, "let p := and(shr(11, d), 0x70)", "let p := and(shr(12, d), 0x70)",
     "C1: chain 5's first position from the wrong digest bits"),
    ("v2-b2-slot", V2, "mstore(add(TB, 40), mload(0x10))", "mstore(add(TB, 41), mload(0x10))",
     "B2: chain 1 end value stored one byte off in T_43"),
    ("v2-a7-last", V2, "shl(200, or(shl(52, 9), shl(33, htIdx)))", "shl(200, or(shl(52, 3), shl(33, htIdx)))",
     "FORS_LAST tweak type"),
    # ── v1 ──
    # ── research variants (derived files; mutated directly) ──
    ("vts-target", VTS, "if iszero(eq(digitSum, 200))", "if iszero(eq(digitSum, 205))",
     "ts200: target sum back to 205"),
    ("vsp-layer1-levels", VSP, "                if layer {\n", "                if 0 {\n",
     "split810: layer 1's heights 9..10 skipped"),
    ("vsp-sigoff", VSP, "sigOff := add(countOff, add(4, shl(4, hl)))", "sigOff := add(countOff, add(4, shl(4, 9)))",
     "split810: layer-0 section length as in (9, 9)"),
    ("va3-ci", VA3, "mstore8(0x24, or(kb, 10)) // A7 byte 4: ci", "mstore8(0x24, or(kb, 20)) // A7 byte 4: ci",
     "all3: chain 5 hashed with the draft-0.3 ci position"),
    ("vsp-kb", VSP, "let kb := byte(4, shl(200, kpBase))", "let kb := 0",
     "split810: kp bit 0 dropped from A7 byte 4 of the chain steps"),
    # ── v1 ──
    ("v1-len-reason", V1, '"Invalid sig length"', '"Invalid sig lengtH"',
     "revert data of the length check (returndata compare)"),
    ("v1-rootmask-drop", V1, "if iszero(eq(and(pkRoot, N_MASK), pkRoot)) {",
     "if iszero(eq(and(pkRoot, not(0)), pkRoot)) {", "I-2 key-shape false path for pkRoot"),
    ("v1-forsc-drop", V1, "if and(shr(132, dVal), 0x7FF) { revert(0, 0) }", "",
     "FORS+C last-index rule removed"),
    ("v1-wotsc-drop", V1, "if iszero(eq(digitSum, 205)) { revert(0, 0) }", "",
     "WOTS+C digit-sum rule removed"),
    ("v1-count-31bit", V1, "let count := shr(224, calldataload(add(sigBase, countOff)))",
     "let count := and(shr(224, calldataload(add(sigBase, countOff))), 0x7FFFFFFF)",
     "count >= 2^31 hashed with the top bit cleared (trace-only)"),
    ("v1-l1h8-sibling-32", V1, "calldatacopy(sub(0x60, and(shr(8, x), 0x20)), add(merklePtr, 128), 16)",
     "calldatacopy(sub(0x60, and(shr(8, x), 0x20)), add(merklePtr, 128), add(16, mul(layer, 16)))",
     "last sibling (offset 3992) copied as 32 bytes: ABI padding leaks into its low half (trailing-junk only, GAP-1 site)"),
    ("v1-e7-zero-after-hmsg", V1, "            mstore(0x60, 0)\n", "",
     "E7: low half of the R word not cleared after H_msg (message bytes leak into FORS H)"),
    ("v1-e7-zero-after-digest", V1, "mstore(0x60, 0) // restore the zero low half", "pop(0) // restore the zero low half",
     "E7: count bytes leak into the first Merkle H preimage"),
    ("v1-e8-fors-h3-ha", V1, "shr(3, treeIdx)))", "shr(2, treeIdx)))",
     "E8: FORS height-3 ha from the wrong shift"),
    ("v1-b7-block1", V1, "if and(nd, shl(30, 1)) {", "if and(nd, shl(31, 1)) {",
     "B7: v1 chain 10's single-step block keyed on the wrong bit"),
    ("v1-root-cmp", V1, "valid := eq(and(mload(0x40), N_MASK), root)", "valid := eq(and(mload(0x40), N_MASK), and(mload(0x40), N_MASK))",
     "final root comparison"),
]


def lanes_pin_ok():
    tag = "// C10-LANES"
    def lines(rel):
        return sorted({l.strip() for l in open(os.path.join(SW, rel)) if l.rstrip().endswith(tag)})
    want = lines("test/gas/C10Lanes.t.sol")
    return bool(want) and lines(V2) == want


def pin_ok():
    """The gate.sh text pin, in Python: every `// C10-SWAR-DIGITSUM` line of the unit test must be
    the exact set of such lines in each verifier that carries the tag."""
    tag = "// C10-SWAR-DIGITSUM"
    def lines(rel):
        return [l.strip() for l in open(os.path.join(SW, rel)) if l.rstrip().endswith(tag)]
    want = lines("test/gas/C10DigitSum.t.sol")
    return bool(want) and all(lines(rel) == want for rel in (V1, V2))


def run_gates(runs, regex):
    env = dict(os.environ, FOUNDRY_FUZZ_RUNS=str(runs))
    p = subprocess.run([FORGE, "test", "--match-path", "test/gas/C10*.t.sol", "--match-contract", regex],
                       cwd=SW, env=env, capture_output=True, text=True)
    out = p.stdout + p.stderr
    fails = re.findall(r"^\[FAIL.*\] (test\w+)\(", out, re.M)
    first = re.search(r"EQUIVALENCE FAIL[^\n\"]*|SHA-256 call #[^\n\"]*", out)
    compiled = "Compiler run successful" in out or "No files changed" in out or "Compiling" in out
    return p.returncode, sorted(set(fails)), (first.group(0) if first else ""), compiled, out


def main():
    which = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "all"
    if which not in ("v1", "v2", "vts", "vsp", "va3", "all"):
        sys.exit(f"unknown selection {which!r}: use v1, v2, vts, vsp, va3 or all")
    runs = int(sys.argv[sys.argv.index("--runs") + 1]) if "--runs" in sys.argv else 64
    sel = [m for m in MUTANTS if which == "all" or m[0].startswith(which + "-")]
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
        sel = [m for m in sel if m[0] == only]
    if not sel:
        sys.exit("no mutants selected")
    regexes = sorted({SUITES[m[1]] for m in sel})
    for rx in regexes:
        rc, fails, _, _, out = run_gates(runs, rx)
        if rc != 0:
            print(f"BASELINE NOT GREEN ({rx}) — fix the candidate first:\n", "\n".join(fails), out[-3000:])
            sys.exit(2)
    print(f"baseline green; {len(sel)} mutants, fuzz runs {runs}")
    ok = True
    for mid, rel, old, new, what in sel:
        path = os.path.join(SW, rel)
        src = open(path).read()
        n = src.count(old)
        if n != 1:
            print(f"STALE   {mid:26s} `old` found {n}x in {rel}")
            ok = False
            continue
        try:
            open(path, "w").write(src.replace(old, new))
            pin = pin_ok() and lanes_pin_ok()
            rc, fails, first, _, out = run_gates(runs, SUITES[rel])
        finally:
            open(path, "w").write(src)
        semantic = [f for f in fails if not f.startswith("test_gas")]
        if not pin:
            print(f"CAUGHT  {mid:26s} by the text pin" + (f" and {len(semantic)} tests" if semantic else ""))
            continue
        if rc == 0:
            print(f"MISSED  {mid:26s} {what}")
            ok = False
        elif fails and not semantic:
            print(f"BENCH   {mid:26s} only the gas bench failed: {what}")
            ok = False
        elif not fails:
            # nonzero exit with no failing test: compile error or infrastructure failure
            print(f"INFRA   {mid:26s} gates exited {rc} without a failing test (compile error?)")
            ok = False
        else:
            print(f"CAUGHT  {mid:26s} by {len(semantic)} tests: {', '.join(semantic)[:200]}")
            if first:
                print(f"          first: {first[:150]}")
    post = [run_gates(runs, rx) for rx in regexes]
    red = [f for r in post if r[0] != 0 for f in r[1]]
    print("post-run baseline", "RED: " + ", ".join(red) if red else "green")
    sys.exit(0 if ok and not red else 1)


if __name__ == "__main__":
    main()
