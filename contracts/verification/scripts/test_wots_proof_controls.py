#!/usr/bin/env python3
"""Require the universal bridges to reject changed WOTS digest/digit specs.

Fresh external fixtures retain the real extracted functions and proof scripts.
Both unchanged specification controls must compile before semantic mutations.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pwd
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"


def main():
    spec = (ROOT / "Extracted/WotsSpecVendored.lean").read_text()
    proof = (ROOT / "Extracted/WotsSpecBridge.lean").read_text()
    families = {
        "hash": ("SphincsCVerify.Spec", "wotsDigest", [
            ("seed", "ByteSeg.ofByteVec seed,", "ByteSeg.ofByteVec wotsAdrs,"),
            ("adrs", "ByteSeg.ofByteVec wotsAdrs,", "ByteSeg.ofByteVec seed,"),
            ("message", "ByteSeg.ofByteVec msgHash,", "ByteSeg.ofByteVec seed,"),
            ("low-byte-only", "u32ToB32 count", "u32ToB32 (count % 256)"),
            ("high-bit-lost", "u32ToB32 count", "u32ToB32 (count &&& 0x7fffffff)"),
            ("counter-replaced", "u32ToB32 count", "ByteVec.ones 32"),
        ]),
        "digits": ("SphincsCVerify.Util", "extractDigits", [
            ("offset", "(i * LogW) LogW", "(i * LogW + 1) LogW"),
            ("width", "(i * LogW) LogW", "(i * LogW) 2"),
            ("order", "(i * LogW) LogW", "((42 - i) * LogW) LogW"),
            ("missing-last", "(n := L)", "(n := 42)"),
        ]),
    }
    with tempfile.TemporaryDirectory(prefix="wots-proof-controls-") as td:
        def fixture(family, before=None, after=None):
            namespace, name, _ = families[family]
            start = spec.index("def " + name + "\n") if family == "hash" else spec.index("def " + name + " ")
            body = spec[start:spec.index("\n\n", start)]
            if before is not None:
                assert body.count(before) == 1, (family, before, "ambiguous mutation")
                body = body.replace(before, after)
            declaration = (f"namespace {namespace}\nopen SphincsCVerify.Spec SphincsCVerify.Spec.ByteVec\n"
                           + body + f"\nend {namespace}\n").replace(name, name + "_probe")
            marker = "namespace Extracted.Equiv"
            source = proof.replace(name, name + "_probe").replace(marker, declaration + "\n" + marker, 1)
            assert "sorry" not in source and "axiom " not in source
            return source

        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)

        for family in families:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, result.stdout + result.stderr

        jobs = [(family, name, before, after) for family, (_, _, mutations) in families.items()
                for name, before, after in mutations]

        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definition", source.split("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            result = run(family + "-" + name, source)
            output = result.stdout + result.stderr
            # Require a proof/type obligation, never parser/import/tool failure.
            assert result.returncode != 0 and any(x in output for x in
                ("unsolved goals", "Type mismatch", "Application type mismatch", "Tactic `rewrite` failed", "Insufficient number of fields")), (name, output)
            assert not any(x in output for x in ("unknown module", "Unknown constant", "unexpected token",
                "maximum recursion", "maximum number of heartbeats", "timeout", "declaration uses")), (name, output)

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, jobs))
    print("OK: WOTS universal proof controls: 2 positive baselines; 6 hash + 4 digit mutations rejected")


if __name__ == "__main__":
    main()
