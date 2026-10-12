#!/usr/bin/env python3
"""Typed byte-layout mutations must break the actual consuming Lean proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "write": ("SignWriteSpec.lean", "hypertree.write16", [
        ("wrong-start", "{ start := offset, «end» := i }", "{ start := 0#usize, «end» := i }"),
        ("wrong-bytes", "Array.to_slice block", "Array.to_slice (Array.repeat 16#usize 0#u8)"),
    ]),
    "secrets": ("SignWriteSpec.lean", "hypertree.sign_inner_loop1", [
        ("short-secret-block", "if t < params.K", "if t < 12#usize"),
        ("wrong-secret", "Array.index_usize fors_secrets t", "Array.index_usize fors_secrets 0#usize"),
    ]),
    "path": ("SignWriteSpec.lean", "hypertree.sign_inner_loop2_loop0", [
        ("wrong-height", "Array.index_usize a h", "Array.index_usize a 0#usize"),
    ]),
    "forest": ("SignForestSerialize.lean", "hypertree.sign_inner_loop2", [
        ("short-forest", "if t < i", "if t < 11#usize"),
    ]),
    "chains": ("SignWriteSpec.lean", "hypertree.sign_inner_loop3_loop0", [
        ("wrong-chain", "Array.index_usize wots_sigma i", "Array.index_usize wots_sigma 0#usize"),
    ]),
    "xmss": ("SignWriteSpec.lean", "hypertree.sign_inner_loop3_loop1", [
        ("short-auth", "if h < i", "if h < 8#usize"),
    ]),
    "count": ("SignLayerSerialize.lean", "signerWriteCount", [
        ("little-endian", "core.num.U32.to_be_bytes count", "core.num.U32.to_le_bytes count"),
        ("short-counter", "offset + 4#usize", "offset + 3#usize"),
    ]),
    "forest-caller": ("SignForestSerializeCaller.lean", "signerAfterForest", [
        ("skip-first-secret", "sig1 i fors_secrets2 0#usize", "sig1 i fors_secrets2 1#usize"),
    ]),
    "layer-caller": ("SignLayerSerializeCaller.lean", "hypertree.sign_inner_loop3.body", [
        ("caller-little-endian", "core.num.U32.to_be_bytes count", "core.num.U32.to_le_bytes count"),
    ]),
}


def fixture(family, before=None, after=None):
    filename, name, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / filename).read_text()
    if family == "count":
        start = proof.index("def signerWriteCount ")
        end = proof.index("@[step] theorem firmware_write_count")
        declaration = proof[start:end]
        if before is not None:
            assert declaration.count(before) == 1
            declaration = declaration.replace(before, after)
        proof = proof[:start] + declaration + proof[end:]
        return proof, proof[:start] + declaration + "\nend Extracted.Equiv\n"
    if family == "forest-caller":
        source = (ROOT / "Extracted/SignForestFactor.lean").read_text()
        declaration = source[source.index("def signerAfterForest "):source.index("def signerHead ")]
        ns = "Extracted.Equiv"
    else:
        source = (ROOT / "Extracted/SignForest/Funs.lean").read_text()
        # Include .body and the enclosing loop, stopping at the next source marker.
        start = source.index("def " + name + ("\n" if family in {"write", "layer-caller"} else ".body\n"))
        if family in {"write", "layer-caller"}:
            end = source.index("/--", start)
        else:
            loop = source.index("def " + name + "\n", start)
            end = source.index("/--", loop)
        declaration = source[start:end]
        ns = "sphincs_c10"
    if family == "write":
        proof = proof[:proof.index("theorem signatureWrites_congr")] + "\nend Extracted.Equiv\n"
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
    declaration = re.sub(pattern, name + "_probe", declaration)
    proof = re.sub(pattern, name + "_probe", proof)
    declaration = (f"namespace {ns}\nopen Aeneas Aeneas.Std Result ControlFlow Error sphincs_c10\n"
                   "noncomputable section\n" + declaration + f"\nend\nend {ns}\n")
    imports = proof.split("namespace Extracted.Equiv", 1)[0]
    result = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in result and "axiom " not in result
    return result, imports + declaration


def main():
    with tempfile.TemporaryDirectory(prefix="sign-serialization-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family)[0])
            assert result.returncode == 0, (family, result.stdout, result.stderr)
            print("PASS baseline: " + family, flush=True)
        jobs = [(family, name, before, after) for family, (_, _, changes) in FAMILIES.items()
                for name, before, after in changes]
        def negative(job):
            family, name, before, after = job
            proof, definitions = fixture(family, before, after)
            typed = run(family + "-" + name + "-definitions", definitions)
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, proof), family + "/" + name)
            print("PASS typed rejection: " + family + "/" + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: serialization proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic changes rejected")


if __name__ == "__main__":
    main()
