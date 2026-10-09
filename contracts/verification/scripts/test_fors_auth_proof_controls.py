#!/usr/bin/env python3
"""Typed authentication-path and sibling-selection changes must break unchanged proofs."""
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
    "actual-auth": ("ForsAuthSpec.lean", [
        ("leaf-count", "1#usize <<< params.A", "3#usize <<< params.A"),
        ("first-leaf", "{ start := 0#usize, «end» := n_leaves }", "{ start := 1#usize, «end» := n_leaves }"),
        ("returned-secret-input", "hash.fors_secret sk_seed ht_idx tree_idx leaf_idx", "hash.fors_secret sk_seed ht_idx tree_idx 0#u32"),
        ("leaf-secret-seed", "hash.fors_secret sk_seed ht_idx tree_idx i", "hash.fors_secret seed ht_idx tree_idx i"),
        ("leaf-hypertree", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 0#u64 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2"),
        ("leaf-tree", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE 0#u32 0#u32 0#u32 i2"),
        ("leaf-domain", "address.make_adrs 0#u32 i1 params.ADRS_FORS_TREE tree_idx 0#u32 0#u32 i2", "address.make_adrs 0#u32 i1 2#u32 tree_idx 0#u32 0#u32 i2"),
        ("merge-condition", "if i1 = node_h", "if i1 ≠ node_h"),
        ("parent-height", "tree_idx 0#u32 i2\n          parent_idx", "tree_idx 0#u32 node_h\n          parent_idx"),
        ("parent-index", "let i3 ← j >>> i2", "let i3 ← j >>> node_h"),
        ("child-order", "hash.th_pair seed adrs a a1", "hash.th_pair seed adrs a1 a"),
        ("target-height", "leaf_idx >>> node_h", "leaf_idx >>> i2"),
        ("sibling-index", "target_at_h ^^^ 1#u32", "target_at_h ^^^ 0#u32"),
        ("capture-side", "if i7 = 0#u32", "if i7 ≠ 0#u32"),
        ("left-capture-value", "Array.update auth_path i10 sibling", "Array.update auth_path i10 node"),
        ("right-capture-value", "Array.update auth_path i10 node", "Array.update auth_path i10 sibling"),
        ("stack-position", "Array.update stack sp1 node1", "Array.update stack 0#usize node1"),
        ("stored-height", "Array.update stack_heights sp1 node_h", "Array.update stack_heights sp1 0#u32"),
        ("discarded-capture", "cont (auth_path1, i, node1, i2)", "cont (auth_path, i, node1, i2)"),
        ("returned-path", "ok (secret, auth_path1)", "ok (secret, auth_path)"),
    ]),
    "spec-auth": ("ForsAuthBridge.lean", [
        ("sibling-even", "then p + 1", "then p + 2"),
        ("sibling-odd", "else p - 1", "else p"),
        ("path-leaf", "(sibIdx leafIdx h.val)", "(sibIdx 0 h.val)"),
        ("path-length", "(n := Spec.A)", "(n := Spec.A - 1)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "actual-auth":
        source = (ROOT / "Extracted/ForsAuth/Funs.lean").read_text()
        declaration = source.split("namespace sphincs_c10\n", 1)[1].rsplit("end sphincs_c10", 1)[0]
        # The new extraction deduplicates this unchanged constant from ForsRoot.
        declaration = "def params.FORS_LEAVES : Result Std.Usize := 1#usize <<< params.A\n" + declaration
        renames = ["fors.sign_fors_tree_loop0_loop0", "fors.sign_fors_tree_loop0",
                   "fors.sign_fors_tree", "params.FORS_LEAVES"]
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
    else:
        source = (ROOT / "Extracted/ForsAuthVendored.lean").read_text()
        declaration = source.split("namespace SphincsCVerify.Spec\n", 1)[1].rsplit("end SphincsCVerify.Spec", 1)[0]
        renames = ["sibIdx", "forsMtAuthPath"]
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
    with tempfile.TemporaryDirectory(prefix="fors-auth-controls-") as td:
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
    print(f"OK: FORS authentication-path proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")

if __name__ == "__main__":
    main()
