#!/usr/bin/env python3
"""Typecheck altered extracted functions, then require the unchanged proof to fail.

The positive control compiles a fresh renamed copy of the actual extracted
search and its proofs. Mutations change only executable definitions. Each
negative must fail on a proof obligation, not parsing, imports, or a timeout.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"


def main():
    generated = (ROOT / "Extracted/GrindR/Funs.lean").read_text()
    marker = "/-- [sphincs_c10::fors::grind_r]: loop body 0:"
    body = generated[generated.index(marker):].replace("fors.grind_r", "fors.probe_grind_r")
    proof = (ROOT / "Extracted/GrindRSpec.lean").read_text()
    header, rest = proof.split("namespace Extracted.Equiv", 1)
    rest = ("namespace Extracted.Equiv" + rest).replace("fors.grind_r", "fors.probe_grind_r")
    definitions = header + "\nnamespace sphincs_c10\n" + body
    mutations = [
        ("start", "last_shift 0#u32", "last_shift 1#u32", 1),
        ("short-bound", "nonce < 10000000#u32", "nonce < 9999999#u32", 1),
        ("long-bound", "nonce < 10000000#u32", "nonce < 10000001#u32", 1),
        ("skip", "nonce + 1#u32", "nonce + 2#u32", 1),
        ("predicate", "if i = 0#u64", "if i = 1#u64", 1),
        ("window", "read_bits_le digest last_shift params.A", "read_bits_le digest 131#usize params.A", 1),
        ("tag", "82#u8, 95#u8", "83#u8, 95#u8", 2),
        ("randomness", "[ s3, s4, s5, s6, s7 ]", "[ s3, s4, s3, s6, s7 ]", 1),
        ("message", "Array.to_slice message", "Array.to_slice sk_seed", 2),
        ("nonce-order", "core.num.U32.to_be_bytes nonce", "core.num.U32.to_le_bytes nonce", 1),
        ("returned-digest", "done (r, digest)", "done (r, r_b32)", 1),
        ("randomizer", "hash.truncate r_full", "hash.truncate message", 1),
    ]
    with tempfile.TemporaryDirectory(prefix="grind-r-proof-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        baseline = run("positive", definitions + rest)
        assert baseline.returncode == 0, baseline.stdout + baseline.stderr

        def negative(job):
            name, before, after, occurrences = job
            assert definitions.count(before) == occurrences, (name, "ambiguous mutation")
            altered = definitions.replace(before, after)
            typed = run(name + "-definition", altered)
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            result = run(name, altered + rest)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and any(s in output for s in (
                "unsolved goals", "Type mismatch", "Application type mismatch",
                "Tactic `rewrite` failed", "Tactic `rfl` failed", "Tactic `assumption` failed",
                "Could not unify the theorem with the target",
            )), (name, output)
            assert not any(s in output for s in (
                "unknown module", "Unknown constant", "unexpected token", "maximum recursion",
                "maximum number of heartbeats", "timeout", "declaration uses",
            )), (name, output)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, mutations))
    print("OK: FORS grinder proof controls: fresh positive; 12 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
