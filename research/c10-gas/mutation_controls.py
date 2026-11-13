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
    ("v2-e2-sib15", V2, "calldatacopy(sub(0x20, shl(4, and(mIdx, 1))), add(merklePtr, shl(4, h)), 16)",
     "calldatacopy(sub(0x20, shl(4, and(mIdx, 1))), add(merklePtr, shl(4, h)), 15)",
     "E2: hypertree sibling copy one byte short (stale last byte)"),
    ("v2-e2-forsroot-slot", V2, "pop(staticcall(gas(), 0x02, 0x00, 55, add(TB, add(24, shl(4, i))), 16))",
     "pop(staticcall(gas(), 0x02, 0x00, 55, add(TB, add(23, shl(4, i))), 16))",
     "E2: FORS root written one byte early into the T_13 buffer"),
    ("v2-swar-lane14", V2, "and(shr(3, d), 0xe070381c0e070381c0e070381c0e07)",
     "and(shr(3, d), 0x1c0e070381c0e070381c0e070381c0e07)",
     "SWAR digit sum counts would-be digit 43 (verifier copy only; text pin)"),
    ("v2-a7-last", V2, "shl(200, or(shl(52, 9), shl(33, htIdx)))", "shl(200, or(shl(52, 3), shl(33, htIdx)))",
     "FORS_LAST tweak type"),
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
    ("v1-l1h8-sibling-unmasked", V1, "let sibling := and(calldataload(add(merklePtr, shl(4, h))), N_MASK)",
     "let sibling := and(calldataload(add(merklePtr, shl(4, h))), or(N_MASK, mul(and(eq(layer, 1), eq(h, 8)), not(N_MASK))))",
     "last sibling (offset 3992) read unmasked: ABI padding leaks in (trailing-junk only, GAP-1 site)"),
    ("v1-root-cmp", V1, "valid := eq(currentNode, root)", "valid := eq(currentNode, currentNode)",
     "final root comparison"),
]


def pin_ok():
    """The gate.sh text pin, in Python: every `// C10-SWAR-DIGITSUM` line of the unit test must be
    the exact set of such lines in each verifier that carries the tag."""
    tag = "// C10-SWAR-DIGITSUM"
    def lines(rel):
        return sorted({l.strip() for l in open(os.path.join(SW, rel)) if l.rstrip().endswith(tag)})
    want = lines("test/gas/C10DigitSum.t.sol")
    for rel in (V1, V2):
        got = lines(rel)
        if got and got != want:
            return False
    return True


def run_gates(runs):
    env = dict(os.environ, FOUNDRY_FUZZ_RUNS=str(runs))
    p = subprocess.run([FORGE, "test", "--match-path", "test/gas/C10*.t.sol"], cwd=SW, env=env,
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    fails = re.findall(r"^\[FAIL.*\] (test\w+)\(", out, re.M)
    first = re.search(r"EQUIVALENCE FAIL[^\n\"]*|SHA-256 call #[^\n\"]*", out)
    compiled = "Compiler run successful" in out or "No files changed" in out or "Compiling" in out
    return p.returncode, sorted(set(fails)), (first.group(0) if first else ""), compiled, out


def main():
    which = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "all"
    runs = int(sys.argv[sys.argv.index("--runs") + 1]) if "--runs" in sys.argv else 64
    sel = [m for m in MUTANTS if which == "all" or m[0].startswith(which + "-")]
    rc, fails, _, _, out = run_gates(runs)
    if rc != 0:
        print("BASELINE NOT GREEN — fix the candidate first:\n", "\n".join(fails), out[-3000:])
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
            pin = pin_ok()
            rc, fails, first, _, out = run_gates(runs)
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
        elif "Compiler run failed" in out or "Error (" in out and not fails:
            print(f"NOCOMP  {mid:26s} mutant did not compile")
            ok = False
        else:
            print(f"CAUGHT  {mid:26s} by {len(semantic)} tests: {', '.join(semantic)[:200]}")
            if first:
                print(f"          first: {first[:150]}")
    rc, fails, _, _, _ = run_gates(runs)
    print("post-run baseline", "green" if rc == 0 else "RED: " + ", ".join(fails))
    sys.exit(0 if ok and rc == 0 else 1)


if __name__ == "__main__":
    main()
