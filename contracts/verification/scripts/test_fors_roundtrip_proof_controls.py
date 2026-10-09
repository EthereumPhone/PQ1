#!/usr/bin/env python3
"""Typed recovery-fold changes must break the unchanged membership proof."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

MUTATIONS = [
    ("parity", "if idx % 2 = 0 then", "if idx % 2 != 0 then"),
    ("left-right", "(pad16p node) (pad16p sibling)", "(pad16p sibling) (pad16p node)"),
    ("missing-sibling", "(pad16p node) (pad16p sibling)", "(pad16p node) (pad16p node)"),
    ("parent-height", "(h+1) (idx/2)", "h (idx/2)"),
    ("parent-index", "(h+1) (idx/2)", "(h+1) idx"),
    ("next-index", "rest next (idx/2) (h+1)", "rest next idx (h+1)"),
    ("discard-merge", "rest next (idx/2) (h+1)", "rest node (idx/2) (h+1)"),
]


def fixture(before=None, after=None):
    original = (ROOT / "Extracted/ForsRecoverySpec.lean").read_text()
    declaration = original[original.index("noncomputable def forsRecoveryFold "):
                           original.index("theorem forsRecoveryAdrs_eq_of_map_val")]
    if before is not None:
        assert declaration.count(before) == 1, (before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    proof = (ROOT / "Extracted/ForsRoundtripSpec.lean").read_text()
    proof = proof.split("/-- All three actual helpers", 1)[0] + "end Extracted.Equiv\n"
    source = proof.replace("namespace Extracted.Equiv\n",
                           "namespace Extracted.Equiv\n" + declaration + "\n", 1)
    source = re.sub(r"\bforsRecoveryFold\b", "forsRecoveryFold_probe", source)
    header = source.split("/-- Folding canonical siblings", 1)[0]
    assert "sorry" not in source and "axiom " not in source
    return source, header + "end Extracted.Equiv\n"


def main():
    with tempfile.TemporaryDirectory(prefix="fors-roundtrip-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        positive = run("positive", fixture()[0])
        assert positive.returncode == 0, positive.stdout + positive.stderr

        def negative(mutation):
            name, before, after = mutation
            source, definitions = fixture(before, after)
            typed = run(name + "-definitions", definitions)
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(name, source), name)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, MUTATIONS))
    print(f"OK: FORS round-trip proof control baseline; {len(MUTATIONS)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
