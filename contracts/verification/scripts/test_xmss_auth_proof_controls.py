#!/usr/bin/env python3
"""Typed XMSS path/copy/fold changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "actual-auth": ("XmssAuthSpec.lean", [
        ("first-leaf", "{ start := 0#usize, «end» := n_leaves }", "{ start := 1#usize, «end» := n_leaves }"),
        ("secret-seed", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed seed layer tree i"),
        ("leaf-layer", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed 0#u32 tree i"),
        ("leaf-tree", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed layer 0#u64 i"),
        ("leaf-index", "wots.keygen_pk seed sk_seed layer tree i", "wots.keygen_pk seed sk_seed layer tree 0#u32"),
        ("merge-condition", "if i1 = node_h", "if i1 ≠ node_h"),
        ("capture-flag", "let b ← Array.index_usize keep_set h\n      let (keep1", "let b ← Array.index_usize keep_set 0#usize\n      let (keep1"),
        ("capture-skip", "if b\n        then ok (keep, keep_set)", "if !b\n        then ok (keep, keep_set)"),
        ("target-height", "target_leaf >>> node_h", "target_leaf >>> 0#u32"),
        ("sibling-index", "target_at_h ^^^ 1#u32", "target_at_h ^^^ 0#u32"),
        ("left-index", "pair_start >>> node_h", "pair_start >>> 0#u32"),
        ("right-index", "left_idx + 1#u32", "left_idx + 2#u32"),
        ("left-capture", "Array.update keep h left", "Array.update keep h node"),
        ("right-capture", "Array.update keep h node", "Array.update keep h left"),
        ("discard-flags", "cont (i, keep1, keep_set1, node1, i2)", "cont (i, keep1, keep_set, node1, i2)"),
        ("discard-capture", "cont (i, keep1, keep_set1, node1, i2)", "cont (i, keep, keep_set1, node1, i2)"),
        ("parent-domain", "address.make_adrs layer tree params.ADRS_TREE", "address.make_adrs layer tree 3#u32"),
        ("parent-index", "0#u32 0#u32 i2 parent_idx", "0#u32 0#u32 i2 0#u32"),
        ("child-order", "hash.th_pair seed adrs a a1", "hash.th_pair seed adrs a1 a"),
        ("stack-position", "Array.index_mut_usize stack sp1", "Array.index_mut_usize stack 0#usize"),
        ("initial-flags", "let keep_set := Array.repeat 9#usize false", "let keep_set := Array.repeat 9#usize true"),
        ("returned-root", "Array.index_usize stack1 0#usize", "Array.index_usize stack1 1#usize"),
        ("copy-read", "let a ← Array.index_usize keep h", "let a ← Array.index_usize keep 0#usize"),
        ("copy-write", "Array.update auth_path h a", "Array.update auth_path 0#usize a"),
        ("copy-assertion", "if b\n    then\n      let a ← Array.index_usize keep h", "if !b\n    then\n      let a ← Array.index_usize keep h"),
        ("copy-length", "{ start := 0#usize, «end» := i }", "{ start := 0#usize, «end» := 8#usize }"),
        ("returned-path", "ok (auth_path1, root)", "ok (auth_path, root)"),
    ]),
    "spec-auth": ("XmssAuthBridge.lean", [
        ("path-leaf", "(sibIdx leafIdx h.val)", "(sibIdx 0 h.val)"),
        ("path-height", "lf h.val (sibIdx", "lf 0 (sibIdx"),
        ("path-length", "(n := Spec.SubtreeH)", "(n := Spec.SubtreeH - 1)"),
    ]),
    "recovery": ("XmssAuthRecovery.lean", [
        ("parity", "if idx % 2 = 0 then", "if idx % 2 != 0 then"),
        ("child-order", "(pad16p node) (pad16p sib)", "(pad16p sib) (pad16p node)"),
        ("missing-sibling", "(pad16p node) (pad16p sib)", "(pad16p node) (pad16p node)"),
        ("parent-height", "treeAdrs layer tree h (idx / 2)", "treeAdrs layer tree (h + 1) (idx / 2)"),
        ("parent-index", "treeAdrs layer tree h (idx / 2)", "treeAdrs layer tree h idx"),
        ("next-index", "rest next (idx / 2) (h + 1)", "rest next idx (h + 1)"),
        ("discard-merge", "rest next (idx / 2) (h + 1)", "rest node (idx / 2) (h + 1)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "actual-auth":
        original = (ROOT / "Extracted/XmssAuth/Funs.lean").read_text()
        declaration = original.split("namespace sphincs_c10\n", 1)[1].rsplit("end sphincs_c10", 1)[0]
        renames = ["merkle.build_subtree_with_auth_loop0_loop0", "merkle.build_subtree_with_auth_loop0",
                   "merkle.build_subtree_with_auth_loop1", "merkle.build_subtree_with_auth",
                   "Usize.Insts.CoreFmtDisplay"]
        ns, opens = "sphincs_c10", "open Aeneas Aeneas.Std Result ControlFlow Error"
    elif family == "spec-auth":
        original = (ROOT / "Extracted/XmssAuthVendored.lean").read_text()
        declaration = original.split("namespace SphincsCVerify.Spec\n", 1)[1].rsplit("end SphincsCVerify.Spec", 1)[0]
        renames = ["mtAuthPath"]
        ns, opens = "SphincsCVerify.Spec", "open SphincsCVerify.Spec ByteVec"
    else:
        original = (ROOT / "Extracted/MerkleVerifySpec.lean").read_text()
        start = original.index("noncomputable def authFold ")
        declaration = original[start:original.index("\n\n", start)]
        proof = proof.split("/-- The actual path builder", 1)[0] + "end Extracted.Equiv\n"
        renames = ["authFold"]
        ns, opens = "Extracted.Equiv", "open Aeneas Aeneas.Std Result"
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
    with tempfile.TemporaryDirectory(prefix="xmss-auth-controls-") as td:
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
            typed = run(family + "-" + name + "-definitions", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, source), family + "/" + name)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: XMSS authentication proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
