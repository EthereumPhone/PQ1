#!/usr/bin/env python3
"""Typed semantic changes must break the unchanged universal recovery proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import subprocess
import tempfile

from test_fors_auth_proof_controls import require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"

FAMILIES = {
    "pair": ("SphincsCVerify.Spec", "thPair", [
        ("reverse", "ByteSeg.ofByteVec left,\n    ByteSeg.ofByteVec right", "ByteSeg.ofByteVec right,\n    ByteSeg.ofByteVec left"),
        ("seed", "ByteSeg.ofByteVec seed,", "ByteSeg.ofByteVec a,"),
        ("omit-right", ",\n    ByteSeg.ofByteVec right", ""),
    ]),
    "address": ("SphincsCVerify.Spec.Adrs", "treeNode", [
        ("domain", "UInt32.ofNat ADRS_TREE", "UInt32.ofNat ADRS_WOTS"),
        ("layer", "make layer tree", "make 0 tree"),
        ("tree", "make layer tree", "make layer 0"),
        ("height", "0 0 height parentIdx", "0 0 (height + 1) parentIdx"),
        ("parent", "0 0 height parentIdx", "0 0 height (parentIdx + 1)"),
    ]),
    "recovery": ("SphincsCVerify.Spec.Hypertree", "verifyAuthPath", [
        ("parity", "idx % 2 == 0", "idx % 2 == 1"),
        ("parent", "parentIdx := idx / 2", "parentIdx := idx / 4"),
        ("height", "UInt32.ofNat (h + 1)", "UInt32.ofNat h"),
        ("sibling", "authPath.getD h", "authPath.getD (SubtreeH - 1 - h)"),
        ("levels", "for h in [:SubtreeH]", "for h in [:SubtreeH - 1]"),
        ("leaf", "node := leafNode", "node := zero 16"),
        ("advance", "idx := parentIdx", "idx := idx"),
    ]),
}


def main():
    specification = (ROOT / "Extracted/MerkleRecoveryVendored.lean").read_text()
    proof = (ROOT / "Extracted/MerkleRecoveryBridge.lean").read_text()
    with tempfile.TemporaryDirectory(prefix="merkle-recovery-controls-") as td:
        def fixture(family, before=None, after=None):
            namespace, name, _ = FAMILIES[family]
            start = specification.index("def " + name)
            declaration = specification[start:specification.index("\n\n", start)]
            if before is not None:
                assert declaration.count(before) == 1, (name, "ambiguous mutation")
                declaration = declaration.replace(before, after)
            declaration = (f"namespace {namespace}\n"
                "open SphincsCVerify.Spec SphincsCVerify.Spec.ByteVec SphincsCVerify.Util\n"
                + declaration + f"\nend {namespace}\n").replace(name, name + "_probe")
            source = proof
            if family == "pair":
                source = source[:source.index("theorem merkle_tree_adrs (")] + "\nend Extracted.Equiv\n"
            elif family == "address":
                source = source[:source.index("attribute [local irreducible] thPair Adrs.treeNode")] + "\nend Extracted.Equiv\n"
            source = source.replace(name, name + "_probe")
            marker = "namespace Extracted.Equiv"
            source = source.replace(marker, declaration + "\n" + marker, 1)
            assert "sorry" not in source and "axiom " not in source
            return source

        def run(name, source):
            p = Path(td) / (name + ".lean")
            p.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(p)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)

        jobs = [(family, name, before, after) for family, (_, _, mutations) in FAMILIES.items()
                for name, before, after in mutations]

        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definition", source.split("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            result = run(family + "-" + name, source)
            require_semantic_rejection(result, name)

        def checked(job):
            try:
                negative(job)
                return None
            except (AssertionError, subprocess.TimeoutExpired) as exc:
                return f"{job[0]}/{job[1]}: {exc}"

        with ThreadPoolExecutor(max_workers=3) as pool:
            failures = [result for result in pool.map(checked, jobs) if result is not None]
        assert not failures, "\n".join(failures)
    print("OK: Merkle recovery proof controls: 3 positive baselines; 15 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
