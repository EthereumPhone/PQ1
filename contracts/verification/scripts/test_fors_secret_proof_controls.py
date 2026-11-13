#!/usr/bin/env python3
"""Typed FORS secret generation changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    "secret": ("ForsSecretSpec.lean", "hash.fors_secret", [
        ("seed", "Array.to_slice sk_seed", "Array.to_slice (Array.repeat 32#usize 0#u8)"),
        ("tag", "102#u8, 111#u8", "103#u8, 111#u8"),
        ("hypertree", "core.num.U32.to_be_bytes ht_idx", "core.num.U32.to_be_bytes 0#u32"),
        ("tree", "core.num.U32.to_be_bytes tree_idx", "core.num.U32.to_be_bytes 0#u32"),
        ("leaf", "core.num.U32.to_be_bytes leaf_idx", "core.num.U32.to_be_bytes 0#u32"),
        # Research refactor: one contiguous 48-byte preimage buffer, then
        # `hash.sha256_bytes16`. Field order = the hypertree/tree writes swapped.
        ("field-order", "core.num.U32.to_be_bytes ht_idx)\n  let s7 ← lift (Array.to_slice a)\n"
         "  let s8 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s6 s7\n"
         "  let buf3 := index_mut_back2 s8\n  let (s9, index_mut_back3) ←\n"
         "    core.array.Array.index_mut (core.ops.index.IndexMutSlice\n"
         "      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) buf3\n"
         "      { start := 40#usize, «end» := 44#usize }\n"
         "  let a1 ← lift (core.num.U32.to_be_bytes tree_idx)",
         "core.num.U32.to_be_bytes tree_idx)\n  let s7 ← lift (Array.to_slice a)\n"
         "  let s8 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s6 s7\n"
         "  let buf3 := index_mut_back2 s8\n  let (s9, index_mut_back3) ←\n"
         "    core.array.Array.index_mut (core.ops.index.IndexMutSlice\n"
         "      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) buf3\n"
         "      { start := 40#usize, «end» := 44#usize }\n"
         "  let a1 ← lift (core.num.U32.to_be_bytes ht_idx)"),
        ("position", "{ start := 44#usize, «end» := 48#usize }", "{ start := 40#usize, «end» := 44#usize }"),
        ("digest", "hash.sha256_bytes16 s15", "hash.truncate (Array.repeat 32#usize 0#u8)"),
    ]),
    "spec-secret": ("ForsSecretBridge.lean", "forsSecret", [
        ("seed", "ByteSeg.ofByteVec skSeed", "ByteSeg.ofByteVec (zero 32)"),
        ("tag", "ByteSeg.ofByteVec forsTag", "ByteSeg.ofByteVec (zero 4)"),
        ("hypertree", "ofU32BE htIdx", "ofU32BE 0"),
        ("tree", "ofU32BE treeIdx", "ofU32BE 0"),
        ("leaf", "ofU32BE leafIdx", "ofU32BE 0"),
        ("field-order", "ByteSeg.ofByteVec (ofU32BE htIdx),\n    ByteSeg.ofByteVec (ofU32BE treeIdx)",
         "ByteSeg.ofByteVec (ofU32BE treeIdx),\n    ByteSeg.ofByteVec (ofU32BE htIdx)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, name, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "spec-secret":
        source = (ROOT / "Extracted/ForsSecretVendored.lean").read_text()
        start = source.index("def " + name + "\n")
        end = source.index("\n\n", start)
        ns = "SphincsCVerify.Spec"
        opens = "open SphincsCVerify.Spec ByteVec"
    else:
        source = (ROOT / "Extracted/ForsSecret/Funs.lean").read_text()
        start = source.index("def " + name + "\n")
        end = source.index("\nend sphincs_c10", start)
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
    declaration = source[start:end]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
    declaration = re.sub(pattern, name + "_probe", declaration)
    proof = re.sub(pattern, name + "_probe", proof)
    declaration = f"namespace {ns}\n{opens}\n" + declaration + f"\nend {ns}\n"
    source = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="fors-secret-controls-") as td:
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
    print(f"OK: FORS secret generation proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")

if __name__ == "__main__":
    main()
