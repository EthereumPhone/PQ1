#!/usr/bin/env python3
"""Typed positional, final-slot and actual-caller changes break consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "loop": ("SignForestSpec.lean", [
        ("constant-order", "Array.index_usize fors_order step", "Array.index_usize fors_order 0#usize"),
        ("wrong-index", "Array.index_usize fors_indices t", "Array.index_usize fors_indices 0#usize"),
        ("wrong-secret-seed", "fors.sign_fors_tree seed sk_seed ht_idx i1 i2", "fors.sign_fors_tree seed seed ht_idx i1 i2"),
        ("secret-position", "Array.update fors_secrets t secret", "Array.update fors_secrets step secret"),
        ("path-position", "Array.update fors_auth_paths t auth_path", "Array.update fors_auth_paths step auth_path"),
        ("root-position", "Array.update fors_roots t a2", "Array.update fors_roots step a2"),
        ("discard-paths", "ok (cont (iter1, a3, a, a1))", "ok (cont (iter1, a3, a, fors_auth_paths))"),
    ]),
    "phase": ("SignForestPhaseSpec.lean", [
        ("skip-first", "{ start := 0#usize, «end» := i1 }", "{ start := 1#usize, «end» := i1 }"),
        ("short-loop", "{ start := 0#usize, «end» := i1 }", "{ start := 0#usize, «end» := 11#usize }"),
        ("last-tree", "fors.compute_fors_root seed sk_seed ht_idx i2", "fors.compute_fors_root seed sk_seed ht_idx 11#u32"),
        ("transmitted-final", "hypertree.set_row fors_secrets1 i1 last_root", "hypertree.set_row fors_secrets1 i1 (Array.repeat 16#usize 0#u8)"),
        ("final-domain", "address.make_adrs 0#u32 i3 params.ADRS_FORS_TREE i4 0#u32 0#u32 0#u32", "address.make_adrs 0#u32 i3 4#u32 i4 0#u32 0#u32 0#u32"),
        ("final-height", "address.make_adrs 0#u32 i3 params.ADRS_FORS_TREE i4 0#u32 0#u32 0#u32", "address.make_adrs 0#u32 i3 params.ADRS_FORS_TREE i4 0#u32 1#u32 0#u32"),
        ("omit-final-hash", "hypertree.set_row fors_roots1 i1 a5", "hypertree.set_row fors_roots1 i1 last_root"),
    ]),
    "caller": ("SignForestFactor.lean", [
        ("caller-transmitted-final", "hypertree.set_row fors_secrets1 i1 last_root", "hypertree.set_row fors_secrets1 i1 (Array.repeat 16#usize 0#u8)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof = (ROOT / "Extracted" / FAMILIES[family][0]).read_text()
    source = (ROOT / "Extracted/SignForest/Funs.lean").read_text()
    if family == "loop":
        start = source.index("/-- [sphincs_c10::hypertree::sign_inner]: loop body 0:")
        end = source.index("/-- [sphincs_c10::hypertree::sign_inner]: loop body 1:")
        declaration, ns, renames = source[start:end], "sphincs_c10", ["hypertree.sign_inner_loop0"]
    elif family == "caller":
        start = source.index("/-- [sphincs_c10::hypertree::sign_inner]:\n")
        declaration = source[start:].rsplit("end sphincs_c10", 1)[0]
        ns, renames = "sphincs_c10", ["hypertree.sign_inner"]
    else:
        source = (ROOT / "Extracted/SignForestFactor.lean").read_text()
        declaration = source[source.index("def signerForsPhase "):source.index("def signerAfterForest ")]
        ns, renames = "Extracted.Equiv", ["signerForsPhase"]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    for name in renames:
        pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
        declaration = re.sub(pattern, name + "_probe", declaration)
        proof = re.sub(pattern, name + "_probe", proof)
    declaration = (f"namespace {ns}\nopen Aeneas Aeneas.Std Result ControlFlow Error sphincs_c10\n"
                   "noncomputable section\n" + declaration + f"\nend\nend {ns}\n")
    result = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in result and "axiom " not in result
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="sign-forest-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, (_, changes) in FAMILIES.items()
                for name, before, after in changes]
        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definitions", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, source), family + "/" + name)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: forest proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic changes rejected")

if __name__ == "__main__":
    main()
