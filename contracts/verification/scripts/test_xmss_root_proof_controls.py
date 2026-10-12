#!/usr/bin/env python3
"""Typed XMSS construction changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "actual-root": ("XmssRootSpec.lean", [
        ("leaf-count", "1#usize <<< i", "3#usize <<< i"),
        ("first-leaf", "{ start := 0#usize, «end» := n_leaves }", "{ start := 1#usize, «end» := n_leaves }"),
        ("secret-seed", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed seed layer tree i"),
        ("leaf-layer", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed 0#u32 tree i"),
        ("leaf-tree", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed layer 0#u64 i"),
        ("leaf-index", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed layer tree 0#u32"),
        ("merge-condition", "if i1 = node_h", "if i1 ≠ node_h"),
        ("parent-height", "node_h + 1#u32", "node_h + 2#u32"),
        ("parent-index", "kp >>> i2", "kp >>> node_h"),
        ("parent-domain", "address.make_adrs layer tree params.ADRS_TREE", "address.make_adrs layer tree 3#u32"),
        ("parent-layer", "address.make_adrs layer tree params.ADRS_TREE", "address.make_adrs 0#u32 tree params.ADRS_TREE"),
        ("parent-tree", "address.make_adrs layer tree params.ADRS_TREE", "address.make_adrs layer 0#u64 params.ADRS_TREE"),
        ("child-order", "hash.th_pair seed adrs a a1", "hash.th_pair seed adrs a1 a"),
        ("stack-position", "Array.index_mut_usize stack sp1", "Array.index_mut_usize stack 0#usize"),
        ("height-position", "Array.index_mut_usize stack_heights sp1", "Array.index_mut_usize stack_heights 0#usize"),
        ("initial-height", "stack_heights sp kp node 0#u32", "stack_heights sp kp node 1#u32"),
        ("returned-root", "Array.index_usize stack1 0#usize", "Array.index_usize stack1 1#usize"),
        ("public-seed", "let seed ← hash.pad16 pk_seed", "let seed ← hash.pad16 (Array.repeat 16#usize 0#u8)"),
        ("public-layer", "merkle.compute_subtree_root seed sk_seed 1#u32 0#u64", "merkle.compute_subtree_root seed sk_seed 0#u32 0#u64"),
        ("public-tree", "merkle.compute_subtree_root seed sk_seed 1#u32 0#u64", "merkle.compute_subtree_root seed sk_seed 1#u32 1#u64"),
    ]),
    "spec-root": ("XmssRootBridge.lean", [
        ("leaf-index", "| 0, idx => lf idx", "| 0, idx => lf 0"),
        ("parent-layer", "Spec.Adrs.treeNode layer tree", "Spec.Adrs.treeNode 0 tree"),
        ("right-child", "lf ℓ (2 * idx + 1)", "lf ℓ (2 * idx)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "actual-root":
        source = (ROOT / "Extracted/XmssRoot/Funs.lean").read_text()
        declaration = source.split("namespace sphincs_c10\n", 1)[1].rsplit("end sphincs_c10", 1)[0]
        renames = ["merkle.compute_subtree_root_loop0_loop0", "merkle.compute_subtree_root_loop0",
                   "merkle.compute_subtree_root", "params.SUBTREE_LEAVES", "merkle.REPORT_EVERY",
                   "hypertree.compute_pk_root_inner", "hypertree.compute_pk_root", "hypertree.progress_none"]
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
    else:
        source = (ROOT / "Extracted/XmssRootVendored.lean").read_text()
        start = source.index("def mtNode ")
        declaration = source[start:source.index("\n\n", start)]
        renames = ["mtNode"]
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
    with tempfile.TemporaryDirectory(prefix="xmss-root-controls-") as td:
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
            typed = run(family + "-" + name + "-definition", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, source), family + "/" + name)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: XMSS root proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
