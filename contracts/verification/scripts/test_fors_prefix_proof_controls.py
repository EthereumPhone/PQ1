#!/usr/bin/env python3
"""Typed parser, actual-caller and verifier-FORS changes must break the proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
# Each family rechecks an unchanged proof against a typechecked replacement.
FAMILIES = {
    "secrets": ("ForsParseSpec.lean", "hypertree.verify_loop0", [
        ("destination", "Array.index_mut_usize fors_secrets t", "Array.index_mut_usize fors_secrets 0#usize"),
        ("source", "{ start := offset, «end» := i }", "{ start := 0#usize, «end» := params.N }"),
        ("offset", "cont (iter1, i, a2)", "cont (iter1, offset, a2)"),
    ]),
    "path": ("ForsParseSpec.lean", "hypertree.verify_loop1_loop0", [
        ("tree", "Array.index_mut_usize auth_paths t", "Array.index_mut_usize auth_paths 0#usize"),
        ("height", "Array.index_mut_usize a h", "Array.index_mut_usize a 0#usize"),
        ("source", "{ start := offset, «end» := i }", "{ start := 0#usize, «end» := params.N }"),
        ("offset", "cont (iter1, i, a4)", "cont (iter1, offset, a4)"),
    ]),
    "paths": ("ForsParseSpec.lean", "hypertree.verify_loop1", [
        ("height-count", "«end» := params.A", "«end» := 10#usize"),
        ("tree", "sig offset auth_paths t", "sig offset auth_paths 0#usize"),
    ]),
    "caller": ("ForsVerifierPrefix.lean", "hypertree.verify", [
        ("randomizer", "{ start := 0#usize, «end» := i }", "{ start := 16#usize, «end» := 32#usize }"),
        ("secret-count", "«end» := params.K", "«end» := 12#usize"),
        ("path-count", "«end» := i1 } sig offset", "«end» := 11#usize } sig offset"),
        ("last-tree", "params.ADRS_FORS_TREE i4", "params.ADRS_FORS_TREE 0#u32"),
        ("last-height", "i4 0#u32 0#u32 0#u32", "i4 0#u32 1#u32 0#u32"),
        ("last-secret", "Array.index_usize fors_secrets1 i1", "Array.index_usize fors_secrets1 0#usize"),
        ("last-slot", "Array.update fors_roots1 i1 a6", "Array.update fors_roots1 0#usize a6"),
        ("compression", "compute_fors_pk seed ht_idx fors_roots2", "compute_fors_pk seed ht_idx fors_roots1"),
        ("handoff-node", "fors_pk ht_idx", "(Array.repeat 16#usize 0#u8) ht_idx"),
        ("handoff-offset", "sig seed offset1", "sig seed 0#usize"),
    ]),
    "verifier": ("ForsPrefixSpec.lean", "reconstructForsPk", [
        ("index", "indices.getD t.val 0", "indices.getD 0 0"),
        ("last-tree", "(UInt32.ofNat (K - 1)) 0 0", "(UInt32.ofNat (K - 2)) 0 0"),
        ("last-slot", "normalRoots.push lastRoot", "normalRoots.push (zero 16)"),
        ("order", "computeForsPk seed htIdx allRoots", "computeForsPk seed htIdx allRoots.reverse"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, name, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family == "verifier":
        source = (ROOT / "Extracted/ForsPrefixVendored.lean").read_text()
        start = source.index("def reconstructForsPk\n")
        end = source.index("\nend SphincsCVerify", start)
    else:
        source = (ROOT / "Extracted/Verify/Funs.lean").read_text()
        if family == "caller":
            start = source.index('/-- [sphincs_c10::hypertree::verify]:\n')
            end = source.index('\nend sphincs_c10', start)
        else:
            start = source.index('def ' + name + '.body\n')
            end_start = source.index('def ' + name + '\n', start)
            end = source.index('\n/--', end_start)
    declaration = source[start:end]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    if family == "caller":
        declaration = declaration.replace("def hypertree.verify\n", "def hypertree.verify_probe\n")
        proof = proof.replace("hypertree.verify ", "hypertree.verify_probe ").replace("hypertree.verify,", "hypertree.verify_probe,")
    else:
        declaration = re.sub(re.escape(name) + r"(?![A-Za-z0-9_])", name + "_probe", declaration)
        proof = re.sub(re.escape(name) + r"(?![A-Za-z0-9_])", name + "_probe", proof)
    if family == "path":
        # Outer-loop callers are separate proof families; stop after the
        # unchanged inner-loop theorem that directly consumes this replacement.
        proof = proof[:proof.rfind("/--", 0, proof.index("theorem firmware_parse_fors_auth"))]
        proof += "\nend Extracted.Equiv\n"
    ns = "SphincsCVerify.Spec.Fors" if family == "verifier" else "sphincs_c10"
    opens = "open SphincsCVerify.Spec SphincsCVerify.Util ByteVec" if family == "verifier" else "open Aeneas Aeneas.Std Result ControlFlow Error"
    # Loop attributes precede the first definition in the original file.
    if family in ("secrets", "path", "paths"):
        declaration = "@[rust_loop_body]\n" + declaration
    declaration = f"namespace {ns}\n{opens}\n" + declaration + f"\nend {ns}\n"
    marker = "namespace Extracted.Equiv"
    source = proof.replace(marker, declaration + "\n" + marker, 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="fors-prefix-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            r = run(family + "-positive", fixture(family))
            assert r.returncode == 0, (family, r.stdout, r.stderr)
        jobs = [(family, name, before, after) for family, (_, _, mutations) in FAMILIES.items()
                for name, before, after in mutations]
        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definition", source.split("namespace Extracted.Equiv", 1)[0])
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
    print("OK: FORS prefix proof controls: 5 positive baselines; 23 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
