#!/usr/bin/env python3
"""Typed shuffle/signing changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

FAMILIES = {
    "shuffle": ("ShuffleSpec.lean", [
        ("identity-value", "Array.update buf t i", "Array.update buf t 0#u8"),
        ("identity-tail", "Array.repeat 64#usize 0#u8", "Array.repeat 64#usize 1#u8"),
        ("lost-first-swap", "Array.update buf i i10", "Array.update buf i tmp"),
        ("lost-second-swap", "Array.update buf1 j tmp", "Array.update buf1 j i10"),
        ("oversized-bound", "let i1 ← i + 1#usize", "let i1 ← i + 2#usize"),
        ("stream-overrun", "let pos1 ← pos + 2#usize", "let pos1 ← pos + 3#usize"),
        ("stream-copy-index", "let a ← Array.update stream w i", "let a ← Array.update stream 128#usize i"),
        ("negative-start", "let i ← n - 1#usize", "let i ← n - 2#usize"),
    ]),
    "sign": ("WotsSignSpec.lean", [
        ("skip-first", "{ start := 0#usize, «end» := params.L }", "{ start := 1#usize, «end» := params.L }"),
        ("short-loop", "{ start := 0#usize, «end» := params.L }", "{ start := 0#usize, «end» := 42#usize }"),
        ("constant-order-index", "Array.index_usize chain_order step", "Array.index_usize chain_order 0#usize"),
        ("wrong-secret-seed", "hash.wots_secret sk_seed layer tree kp i2", "hash.wots_secret seed layer tree kp i2"),
        ("wrong-secret-layer", "hash.wots_secret sk_seed layer tree kp i2", "hash.wots_secret sk_seed 0#u32 tree kp i2"),
        ("wrong-chain-address", "address.set_chain_index base_adrs i3", "address.set_chain_index base_adrs 0#u32"),
        ("wrong-digit", "Array.index_usize digits i1", "Array.index_usize digits 0#usize"),
        ("wrong-chain-start", "hash.chain_hash seed chain_adrs sk_i 0#u32 i5", "hash.chain_hash seed chain_adrs sk_i 1#u32 i5"),
        ("wrong-chain-steps", "hash.chain_hash seed chain_adrs sk_i 0#u32 i5", "hash.chain_hash seed chain_adrs sk_i 0#u32 7#u32"),
        ("wrong-write-slot", "Array.update sigma i1 a", "Array.update sigma step a"),
        ("discard-signature", "ok (sigma1, count)", "ok (sigma, count)"),
        ("discard-count", "ok (sigma1, count)", "ok (sigma1, 0#u32)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    module = "Shuffle" if family == "shuffle" else "WotsSign"
    original = (ROOT / "Extracted" / module / "Funs.lean").read_text()
    if family == "shuffle":
        # Only the actual generated loops; the shared trait implementations
        # and explicit hash/zeroize boundaries remain imported unchanged.
        start = original.index("/-- [sphincs_c10::shuffle::fisher_yates]: loop body 0:")
        declaration = original[start:].rsplit("end sphincs_c10", 1)[0]
        renames = ["shuffle.fisher_yates_loop2_loop0", "shuffle.fisher_yates_loop0",
                   "shuffle.fisher_yates_loop1", "shuffle.fisher_yates_loop2",
                   "shuffle.fisher_yates_loop3", "shuffle.fisher_yates"]
    else:
        declaration = original.split("namespace sphincs_c10\n", 1)[1].rsplit("end sphincs_c10", 1)[0]
        renames = ["wots.sign_with_shuffle_loop", "wots.sign_with_shuffle"]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    for name in renames:
        pattern = re.escape(name) + r"(?![A-Za-z0-9_])"
        declaration = re.sub(pattern, name + "_probe", declaration)
        proof = re.sub(pattern, name + "_probe", proof)
    declaration = "namespace sphincs_c10\nopen Aeneas Aeneas.Std Result ControlFlow Error\n" + declaration + "\nend sphincs_c10\n"
    source = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="wots-sign-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, (_, changes) in FAMILIES.items()
                for name, before, after in changes]

        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definitions", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(family + "-" + name, source), family + "/" + name)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print(f"OK: shuffle/signing proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic changes rejected")


if __name__ == "__main__":
    main()
