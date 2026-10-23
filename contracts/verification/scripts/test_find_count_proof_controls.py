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

from test_fors_auth_proof_controls import require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"


def main():
    generated = (ROOT / "Extracted/FindCount/Funs.lean").read_text()
    marker = "/-- [sphincs_c10::wots::digit_sum]: loop body 0:"

    def probe(text):
        # `digit_sum` and `find_count` (and their loops) are the executable
        # definitions under test; everything else keeps its real name.
        return (text.replace("wots.find_count", "wots.probe_find_count")
                    .replace("wots.digit_sum", "wots.probe_digit_sum"))

    body = probe(generated[generated.index(marker):])
    proof = (ROOT / "Extracted/FindCountSpec.lean").read_text()
    header, rest = proof.split("namespace Extracted.Equiv", 1)
    rest = probe("namespace Extracted.Equiv" + rest)
    definitions = header + "\nnamespace sphincs_c10\n" + body
    mutations = [
        ("start", "adrs 0#u32", "adrs 1#u32"),
        ("short-bound", "count < 10000000#u32", "count < 9999999#u32"),
        ("long-bound", "count < 10000000#u32", "count < 10000001#u32"),
        ("threshold", "i = params.TARGET_SUM", "i >= params.TARGET_SUM"),
        ("skip", "count + 1#u32", "count + 2#u32"),
        ("returned-count", "done (count, d, a)", "done (0#u32, d, a)"),
        ("wrong-message", "wots_digest seed wots_adrs msg_hash count",
         "wots_digest seed wots_adrs seed count"),
        # `digit_sum` must equal the verifier's digit sum: every mask, shift,
        # byte index and group count below is load-bearing for that lemma.
        ("sum-omits-group", "«end» := 5#usize", "«end» := 4#usize"),
        ("group-byte", "31#usize - i", "30#usize - i"),
        ("even-mask", "v &&& 1864135#u32", "v &&& 1864134#u32"),
        ("odd-shift", "let i13 ← v >>> 3#i32", "let i13 ← v >>> 4#i32"),
        ("fold-shift", "s1 >>> 12#i32", "s1 >>> 13#i32"),
        ("field-mask", "s2 &&& 63#u32", "s2 &&& 31#u32"),
        ("top-byte", "digest 16#usize", "digest 17#usize"),
        ("top-bit", "i2 &&& 1#u8", "i2 &&& 3#u8"),
        ("top-digit-mask", "v &&& 7#u32", "v &&& 15#u32"),
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
            require_semantic_rejection(result, name)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, mutations))
    print(f"OK: bounded grinder proof controls: fresh positive; {len(mutations)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
