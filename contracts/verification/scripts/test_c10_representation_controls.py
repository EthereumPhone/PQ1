#!/usr/bin/env python3
"""Typed changes to shared C10 forms must break the unchanged Lean endpoint proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

sys.path.insert(0, str(ROOT.parent / "easycrypt/c10-port/tools"))
from c10_representation import source
from c10_representation_controls import CHANGES, changed


def fixture(definitions):
    proof = (ROOT / "Extracted/C10RepresentationBridge.lean").read_text()
    imported = "import Extracted.C10Representation\n"
    namespace = "namespace Extracted.C10RepresentationBridge"
    if proof.count(imported) != 1 or proof.count(namespace) != 1:
        raise ValueError("representation proof anchors changed")
    proof = proof.replace(imported, "")
    return proof.replace(namespace, definitions.replace("import Init\n", "") + "\n" + namespace)


def main():
    with tempfile.TemporaryDirectory(prefix="c10-representation-controls-") as tmp:
        def run(name, text):
            path = Path(tmp) / (name + ".lean")
            path.write_text(text)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        baseline = run("positive", fixture(original))
        if baseline.returncode:
            raise RuntimeError("positive representation proof failed:\n" + baseline.stdout + baseline.stderr)
        print("PASS C10 representation: unchanged endpoint proofs", flush=True)

        def negative(row):
            name, func, before, after, _, _ = row
            definitions = changed(original, func, before, after, True)
            typed = run(name + "_definitions", definitions)
            if typed.returncode:
                raise RuntimeError(name + ": changed definition failed typing:\n" + typed.stdout + typed.stderr)
            require_semantic_rejection(run(name, fixture(definitions)), name)
            print("PASS C10 representation typed rejection: " + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, CHANGES))
    print(f"OK C10 representation: positive baseline and {len(CHANGES)} typed semantic rejections")


if __name__ == "__main__":
    main()
