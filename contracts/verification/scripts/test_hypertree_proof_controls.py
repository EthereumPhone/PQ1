#!/usr/bin/env python3
"""Compiling semantic replacements must break unchanged continuation proofs."""
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
    "chains": ("HypertreeParseSpec.lean", "hypertree.verify_loop3_loop0", [
        ("destination", "Array.index_mut_usize wots_sigma i", "Array.index_mut_usize wots_sigma 0#usize"),
        ("source", "{ start := offset, «end» := i1 }", "{ start := 0#usize, «end» := params.N }"),
        ("offset", "cont (iter1, i1, a2)", "cont (iter1, offset, a2)"),
    ]),
    "auth": ("HypertreeParseSpec.lean", "hypertree.verify_loop3_loop1", [
        ("destination", "Array.index_mut_usize auth_path h", "Array.index_mut_usize auth_path 0#usize"),
        ("source", "{ start := offset, «end» := i }", "{ start := 0#usize, «end» := params.N }"),
        ("offset", "cont (iter1, i, a2)", "cont (iter1, offset, a2)"),
    ]),
    "layer": ("HypertreeLayerSpec.lean", "hypertree.verify_loop3", [
        ("leaf-mask", "idx_tree &&& i2", "idx_tree &&& 255#u32"),
        ("tree-shift", "idx_tree >>> i", "idx_tree >>> 8#usize"),
        ("chains", "«end» := params.L", "«end» := 42#usize"),
        ("counter-high", "[ i3, i5, i7, i9 ]", "[ 0#u8, i5, i7, i9 ]"),
        ("counter-order", "[ i3, i5, i7, i9 ]", "[ i9, i7, i5, i3 ]"),
        ("counter-offset", "offset1 + 4#usize", "offset1 + 3#usize"),
        ("siblings", "«end» := i } sig", "«end» := 8#usize } sig"),
        ("layer-address", "wots.pk_from_sig seed layer i10", "wots.pk_from_sig seed 0#u32 i10"),
        ("tree-address", "wots.pk_from_sig seed layer i10", "wots.pk_from_sig seed layer 0#u64"),
        ("leaf-address", "i10 idx_leaf current_node", "i10 0#u32 current_node"),
        ("node-handoff", "i11 wots_pk idx_leaf", "i11 current_node idx_leaf"),
        ("tree-handoff", "current_node1, idx_tree1))", "current_node1, idx_tree))"),
    ]),
    "loop": ("HypertreeContinuationSpec.lean", "hypertree.verify_loop3", [
        ("initial-layer", "(iter, offset, current_node, idx_tree)", "({start := 1#u32, «end» := iter.«end»}, offset, current_node, idx_tree)"),
        ("initial-offset", "(iter, offset, current_node, idx_tree)", "(iter, 0#usize, current_node, idx_tree)"),
        ("initial-node", "(iter, offset, current_node, idx_tree)", "(iter, offset, Array.repeat 16#usize 0#u8, idx_tree)"),
        ("initial-tree", "(iter, offset, current_node, idx_tree)", "(iter, offset, current_node, 0#u32)"),
    ]),
    "terminal": ("HypertreeContinuationSpec.lean", "verifierHypertreeContinuation", [
        ("layer-count", "«end» := i5", "«end» := 1#u32"),
        ("offset", "sig seed 2336#usize", "sig seed 0#usize"),
        ("root", "\n    pk_root", "\n    current_node"),
    ]),
    "strict": ("HypertreeStrictSpec.lean", "verifyHypertree", [
        ("layer-count", "[:D]", "[:1]"),
        ("layer-order", "layers.getD layer", "layers.getD (1 - layer)"),
        ("tree-shift", "idxTree >>> SubtreeH", "idxTree >>> 8"),
        ("return-node", "pure (some currentNode)", "pure (some forsPk)"),
    ]),
}

def fixture(family, before=None, after=None):
    proof_file, name, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "strict":
        source = (ROOT / "Extracted/HypertreeContinuationVendored.lean").read_text()
        start = source.index("def verifyHypertree\n")
        end = source.index("\nend Hypertree", start)
        ns = "SphincsCVerify.Spec.Hypertree"
        opens = "open SphincsCVerify.Spec Wots Fors SphincsCVerify.Util ByteVec"
        attr = ""
    elif family == "terminal":
        source = (ROOT / "Extracted/ForsVerifierPrefix.lean").read_text()
        start = source.index("def verifierHypertreeContinuation ")
        end = source.index("\n\ntheorem", start)
        ns = "Extracted.Equiv"
        opens = "open Aeneas Aeneas.Std Result ControlFlow sphincs_c10"
        attr = ""
    else:
        source = (ROOT / "Extracted/Verify/Funs.lean").read_text()
        if family == "loop":
            start = source.index("def " + name + "\n")
            end = source.index("\n/--", start)
            attr = "@[rust_loop]\n"
        else:
            start = source.index("def " + name + ".body\n")
            end = source.index("\n/--", source.index("def " + name + "\n", start))
            attr = "@[rust_loop_body]\n"
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
    if family == "loop":
        proof = proof[:proof.index("private theorem all_zip_eq")] + "\nend Extracted.Equiv\n"
    declaration = source[start:end]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    # Renaming the loop alone must continue to call the ORIGINAL proved body.
    pattern = re.escape(name) + (r"(?![A-Za-z0-9_.])" if family == "loop" else r"(?![A-Za-z0-9_])")
    declaration = re.sub(pattern, name + "_probe", declaration)
    proof = re.sub(pattern, name + "_probe", proof)
    declaration = f"namespace {ns}\n{opens}\n{attr}" + declaration + f"\nend {ns}\n"
    marker = "namespace Extracted.Equiv"
    source = proof.replace(marker, declaration + "\n" + marker, 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="hypertree-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, (_, _, mutations) in FAMILIES.items()
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
    print("OK: hypertree proof controls: 6 positive baselines; 29 typed semantic mutations rejected")

if __name__ == "__main__":
    main()
