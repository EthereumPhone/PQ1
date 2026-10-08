#!/usr/bin/env python3
"""Typed Rust-derived and verifier semantic changes must break unchanged proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    "address": ("SphincsCVerify.Spec.Adrs", "forsNode", [
        ("domain", "UInt32.ofNat ADRS_FORS_TREE", "UInt32.ofNat ADRS_TREE"),
        ("position", "make 0 htIdx", "make 0 0"),
        ("tree", "treeIdx 0 height", "0 0 height"),
        ("height", "0 height parentIdx", "0 (height + 1) parentIdx"),
        ("parent", "treeIdx 0 height parentIdx", "treeIdx 0 height (parentIdx + 1)"),
    ]),
    "recovery": ("SphincsCVerify.Spec.Fors", "reconstructRoot", [
        ("parity", "pathIdx % 2 == 0", "pathIdx % 2 == 1"),
        ("parent", "parentIdx := pathIdx / 2", "parentIdx := pathIdx / 4"),
        ("height", "UInt32.ofNat (h + 1)", "UInt32.ofNat h"),
        ("sibling", "authPath.getD h", "authPath.getD (A - 1 - h)"),
        ("levels", "for h in [:A]", "for h in [:A - 1]"),
        ("secret", "th seed leafAdrs (pad16 secret)", "th seed leafAdrs (pad16 (zero 16))"),
        ("leaf-index", "forsNode htIdx treeIdx 0 leafIdx", "forsNode htIdx treeIdx 0 0"),
        ("leaf-hash", "node := th seed leafAdrs (pad16 secret)", "node := secret"),
        ("advance", "pathIdx := parentIdx", "pathIdx := pathIdx"),
    ]),
    "rust": ("", "", [
        ("parity", "if i3 = 0#u32", "if i3 = 1#u32"),
        ("parent", "path_idx >>> 1#i32", "path_idx >>> 2#i32"),
        ("height", "h + 1#usize", "h + 2#usize"),
        ("sibling", "Array.index_usize auth_path h", "Array.index_usize auth_path 0#usize"),
        ("secret", "hash.pad16 secret", "hash.pad16 (Array.repeat 16#usize 0#u8)"),
        ("leaf-hash", "let node ← hash.th seed leaf_adrs a", "let node := secret"),
        ("levels", "«end» := params.A", "«end» := 10#usize"),
        ("advance", "cont (iter1, node1, parent_idx)", "cont (iter1, node1, path_idx)"),
        ("initial-index", "node leaf_idx", "node 0#u32"),
    ]),
}


def main():
    specification = (ROOT / "Extracted/ForsRecoveryVendored.lean").read_text()
    proof = (ROOT / "Extracted/ForsRecoveryBridge.lean").read_text()
    functional = (ROOT / "Extracted/ForsRecoverySpec.lean").read_text()
    generated = (ROOT / "Extracted/ForsRecovery/Funs.lean").read_text()
    with tempfile.TemporaryDirectory(prefix="fors-recovery-controls-") as td:
        def fixture(family, before=None, after=None):
            namespace, name, _ = FAMILIES[family]
            if family == "rust":
                start = generated.index("/-- [sphincs_c10::hypertree::reconstruct_fors_root]")
                declaration = "open Aeneas Aeneas.Std Result ControlFlow Error\nnamespace sphincs_c10\n" + generated[start:]
                if before is not None:
                    assert declaration.count(before) == 1, (before, "ambiguous mutation")
                    declaration = declaration.replace(before, after)
                declaration = declaration.replace("hypertree.reconstruct_fors_root", "hypertree.reconstruct_fors_root_probe")
                source = functional.replace("hypertree.reconstruct_fors_root", "hypertree.reconstruct_fors_root_probe")
            else:
                start = specification.index("def " + name)
                declaration = specification[start:specification.index("\n\n", start)]
                if before is not None:
                    assert declaration.count(before) == 1, (before, "ambiguous mutation")
                    declaration = declaration.replace(before, after)
                declaration = (f"namespace {namespace}\n"
                    "open SphincsCVerify.Spec SphincsCVerify.Spec.ByteVec\n"
                    + declaration + f"\nend {namespace}\n").replace(name, name + "_probe")
                source = proof
                if family == "address":
                    source = source[:source.index("-- Keep wrong-input controls")] + "\nend Extracted.Equiv\n"
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
            output = result.stdout + result.stderr
            assert result.returncode != 0 and any(x in output for x in
                ("unsolved goals", "Type mismatch", "Application type mismatch", "Tactic `rewrite` failed",
                 "'show' tactic failed", "`simp` made no progress", "Tactic `rfl` failed",
                 "Tactic `apply` failed", "Could not unify", "Tactic `assumption` failed")), (name, output)
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
    print("OK: FORS recovery proof controls: 3 positive baselines; 23 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
