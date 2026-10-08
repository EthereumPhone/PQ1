#!/usr/bin/env python3
"""Typed changes to forest inputs/order/refusal must break the unchanged proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    "compression": ("ForsPkSpec.lean", "ForsPk/Funs.lean", "fors.compute_fors_pk", [
        ("position", "FromU64U32.from ht_idx", "FromU64U32.from 0#u32"),
        ("domain", "params.ADRS_FORS_ROOTS", "3#u32"),
        ("roots", "Array.to_slice roots", "Array.to_slice (Array.repeat 13#usize (Array.repeat 16#usize 0#u8))"),
    ]),
    "loop": ("ForsForestSpec.lean", "Verify/Funs.lean", "hypertree.verify_loop2", [
        ("tree", "UScalar.cast .U32 t", "UScalar.cast .U32 0#usize"),
        ("index", "Array.index_usize fors_indices t", "Array.index_usize fors_indices 0#usize"),
        ("secret", "Array.index_usize fors_secrets t", "Array.index_usize fors_secrets 0#usize"),
        ("path", "Array.index_usize auth_paths t", "Array.index_usize auth_paths 0#usize"),
        ("position", "reconstruct_fors_root seed ht_idx i", "reconstruct_fors_root seed 0#u32 i"),
        ("destination", "Array.update fors_roots t a2", "Array.update fors_roots 0#usize a2"),
        ("discard", "cont (iter1, a3)", "cont (iter1, fors_roots)"),
    ]),
    "reject": ("ForsRejectSpec.lean", "Verify/Funs.lean", "hypertree.verify", [
        ("guard", "i2 != 0#u32", "i2 == 0#u32"),
        ("verdict", "then ok false", "then ok true"),
        ("field", "params.K - 1#usize", "params.K - 2#usize"),
        ("message", "hash.h_msg seed root r_b32 msg_hash", "hash.h_msg seed root r_b32 (Array.repeat 32#usize 0#u8)"),
    ]),
    "address": ("ForsPkSpec.lean", "ForsForestVendored.lean", "forsRoots", [
        ("position", "make 0 htIdx", "make 0 0"),
        ("domain", "UInt32.ofNat ADRS_FORS_ROOTS", "3"),
    ]),
    "verifier-compression": ("ForsPkSpec.lean", "ForsForestVendored.lean", "computeForsPk", [
        ("order", "roots.toList", "roots.toList.reverse"),
        ("last-root", "roots.toList", "(roots.toList.take 12)"),
    ]),
}


def main():
    with tempfile.TemporaryDirectory(prefix="fors-forest-controls-") as td:
        def fixture(family, before=None, after=None):
            proof_file, generated_file, name, _ = FAMILIES[family]
            proof = (ROOT / "Extracted" / proof_file).read_text()
            generated = (ROOT / "Extracted" / generated_file).read_text()
            if family == "loop":
                start = generated.index('/-- [sphincs_c10::hypertree::verify]: loop body 3:')
                end = generated.index('/-- [sphincs_c10::hypertree::verify]: loop body 5:', start)
            elif family == "reject":
                start = generated.index('/-- [sphincs_c10::hypertree::verify]:\n')
                end = generated.index('\nend sphincs_c10', start)
            else:
                start = generated.index('def ' + name)
                end = generated.index('\n\n', start)
            declaration = generated[start:end]
            if before is not None:
                assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
                declaration = declaration.replace(before, after)
            if family in ("address", "verifier-compression"):
                ns = "SphincsCVerify.Spec." + ("Adrs" if family == "address" else "Fors")
                declaration = f"namespace {ns}\nopen SphincsCVerify.Spec\n" + declaration + f"\nend {ns}\n"
            else:
                declaration = "open Aeneas Aeneas.Std Result ControlFlow Error\nnamespace sphincs_c10\n" + declaration + "\nend sphincs_c10\n"
            # Rename exact procedure paths: rejection must leave verify_loop* intact.
            if family == "reject":
                declaration = declaration.replace("def hypertree.verify\n", "def hypertree.verify_probe\n")
                proof = proof.replace("hypertree.verify ", "hypertree.verify_probe ").replace("unfold hypertree.verify\n", "unfold hypertree.verify_probe\n")
            else:
                declaration = declaration.replace(name, name + "_probe")
                proof = proof.replace(name, name + "_probe")
            if family == "address":
                # Only the address bridge lemma is under this mutation; its
                # callers still import the original compression definition.
                proof = proof[:proof.index("attribute [local irreducible] thMulti")] + "\nend Extracted.Equiv\n"
            marker = "namespace Extracted.Equiv"
            source = proof.replace(marker, declaration + "\n" + marker, 1)
            assert "sorry" not in source and "axiom " not in source
            return source

        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        for family in FAMILIES:
            r = run(family + "-positive", fixture(family))
            assert r.returncode == 0, (family, r.stdout, r.stderr)

        jobs = [(family, name, before, after) for family, (_, _, _, mutations) in FAMILIES.items()
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
    print("OK: FORS forest proof controls: 5 positive baselines; 18 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
