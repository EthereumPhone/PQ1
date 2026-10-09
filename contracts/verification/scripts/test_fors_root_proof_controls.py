#!/usr/bin/env python3
"""Typed tree construction and final-slot changes must break unchanged proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    "actual-root": ("ForsRootSpec.lean", [
        ("leaf-count", "1#usize <<< params.A", "3#usize <<< params.A"),
        ("first-leaf", "{ start := 0#usize, «end» := n_leaves }", "{ start := 1#usize, «end» := n_leaves }"),
        ("secret-seed", "hash.fors_secret sk_seed ht_idx tree_idx i", "hash.fors_secret seed ht_idx tree_idx i"),
        ("secret-leaf", "hash.fors_secret sk_seed ht_idx tree_idx i", "hash.fors_secret sk_seed ht_idx tree_idx 0#u32"),
        ("leaf-hypertree", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 0#u64 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2"),
        ("leaf-tree", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE 0#u32 0#u32 0#u32 i2"),
        ("leaf-domain", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 i1 2#u32 tree_idx 0#u32 0#u32 i2"),
        ("merge-condition", "if i1 = node_h", "if i1 ≠ node_h"),
        ("parent-height", "node_h + 1#u32", "node_h + 2#u32"),
        ("parent-index", "j >>> i2", "j >>> node_h"),
        ("child-order", "hash.th_pair seed adrs a a1", "hash.th_pair seed adrs a1 a"),
        ("stack-position", "Array.update stack sp1 node1", "Array.update stack 0#usize node1"),
        ("stored-height", "Array.update stack_heights sp1 node_h", "Array.update stack_heights sp1 0#u32"),
        ("returned-root", "Array.index_usize stack1 0#usize", "Array.index_usize stack1 1#usize"),
    ]),
    "spec-root": ("ForsRootBridge.lean", [
        ("leaf-index", "ByteVec.pad16 (lf idx)", "ByteVec.pad16 (lf 0)"),
        ("parent-domain", "Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx", "Spec.thPair seed (Spec.Adrs.forsNode 0 treeIdx"),
        ("right-child", "lf ℓ (2 * idx + 1)", "lf ℓ (2 * idx)"),
    ]),
    "spec-slot": ("ForsRootBridge.lean", [
        ("wrong-slot", "if treeIdx = K - 1", "if treeIdx = K - 2"),
        ("old-leaf-rule", "forsMtNode seed (UInt64.ofNat htIdx) (UInt32.ofNat treeIdx)\n      (fun j => forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx)\n        (UInt32.ofNat j)) A 0", "forsSecret skSeed (UInt32.ofNat htIdx) (UInt32.ofNat treeIdx) 0"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "actual-root":
        source = (ROOT / "Extracted/ForsRoot/Funs.lean").read_text()
        declaration = source.split("namespace sphincs_c10\n", 1)[1].rsplit("end sphincs_c10", 1)[0]
        renames = ["fors.compute_fors_root_loop0_loop0", "fors.compute_fors_root_loop0",
                   "fors.compute_fors_root", "params.FORS_LEAVES"]
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
    else:
        source = (ROOT / "Extracted/ForsRootVendored.lean").read_text()
        name = "forsMtNode" if family == "spec-root" else "forsSigningValue"
        start = source.index("def " + name + " ")
        declaration = source[start:source.index("\n\n", start)]
        renames = [name if family == "spec-root" else "Signer.forsSigningValue"]
        if family == "spec-slot":
            declaration = declaration.replace("def forsSigningValue ", "def Signer.forsSigningValue ", 1)
        ns = "SphincsCVerify.Spec"
        opens = "open SphincsCVerify.Spec ByteVec"
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    for name in renames:
        pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
        declaration = re.sub(pattern, name + "_probe", declaration)
        proof = re.sub(pattern, name + "_probe", proof)
    declaration = f"namespace {ns}\n{opens}\n" + declaration + f"\nend {ns}\n"
    source = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="fors-root-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, (_, mutations) in FAMILIES.items()
                for name, before, after in mutations]
        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            # The terminal helper is in the proof namespace: split at the LAST
            # opening, after the injected replacement's closing namespace.
            typed = run(family + "-" + name + "-definition", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            result = run(family + "-" + name, source)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and any(x in output for x in
                ("unsolved goals", "Type mismatch", "Application type mismatch", "Tactic `rewrite` failed",
                 "'show' tactic failed", "`simp` made no progress", "Tactic `rfl` failed",
                 "Tactic `apply` failed", "Could not unify", "Tactic `assumption` failed",
                 "omega could not prove", "scalar_tac failed")), (name, output)
            assert not any(x in output for x in ("unknown module", "Unknown constant", "unexpected token",
                "Unknown identifier", "maximum recursion", "maximum number of heartbeats", "timeout", "declaration uses")), (name, output)
        def checked(job):
            try:
                negative(job)
                return None
            except (AssertionError, subprocess.TimeoutExpired) as exc:
                return f"{job[0]}/{job[1]}: {exc}"
        with ThreadPoolExecutor(max_workers=3) as pool:
            failures = [result for result in pool.map(checked, jobs) if result is not None]
        assert not failures, "\n".join(failures)
    print(f"OK: FORS root construction proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")

if __name__ == "__main__":
    main()
