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
    generated = (ROOT / "Extracted/FindCount/Funs.lean").read_text()
    marker = "/-- [sphincs_c10::wots::find_count]: loop body 1:"
    body = generated[generated.index(marker):].replace("wots.find_count", "wots.probe_find_count")
    proof = (ROOT / "Extracted/FindCountSpec.lean").read_text()
    header, rest = proof.split("namespace Extracted.Equiv", 1)
    rest = ("namespace Extracted.Equiv" + rest).replace("wots.find_count", "wots.probe_find_count")
    definitions = header + "\nnamespace sphincs_c10\n" + body
    mutations = [
        ("start", "adrs 0#u32", "adrs 1#u32"),
        ("short-bound", "count < 10000000#u32", "count < 9999999#u32"),
        ("long-bound", "count < 10000000#u32", "count < 10000001#u32"),
        ("threshold", "sum = params.TARGET_SUM", "sum >= params.TARGET_SUM"),
        ("skip", "count + 1#u32", "count + 2#u32"),
        ("returned-count", "done (count, d, digits)", "done (0#u32, d, digits)"),
        ("wrong-message", "wots_digest seed wots_adrs msg_hash count",
         "wots_digest seed wots_adrs seed count"),
        ("sum-omits-last", "«end» := params.L", "«end» := 42#usize"),
    ]
    with tempfile.TemporaryDirectory(prefix="find-count-proof-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        baseline = run("positive", definitions + rest)
        assert baseline.returncode == 0, baseline.stdout + baseline.stderr

        def negative(job):
            name, before, after = job
            assert definitions.count(before) == 1, (name, "ambiguous mutation")
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
    print("OK: bounded grinder proof controls: fresh positive; 8 typed semantic mutations rejected")


if __name__ == "__main__":
    main()
