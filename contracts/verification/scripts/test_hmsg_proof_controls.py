#!/usr/bin/env python3
"""Check that the universal H_msg input-layout proof rejects changed call arguments.

Fixtures are fresh external files. Positive control runs first; negative results
must be unproved equality goals, not import/tool failures, sorry, or timeout.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pwd
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(__import__('os').getuid()).pw_dir) / ".elan/bin/lake"

def main():
    generated = (ROOT / "Extracted/Hash/Funs.lean").read_text()
    body = generated[generated.index("def hash.h_msg\n"):generated.index("\n\n", generated.index("def hash.h_msg\n"))]
    spec = (ROOT / "Extracted/HashSpecs/HMsg.lean").read_text()
    proof = spec[spec.index("theorem hash.h_msg_spec"):spec.index("\nend sphincs_c10")]
    prefix = "import Extracted.Hash.Funs\nimport Extracted.HashPure\nopen Aeneas Aeneas.Std Result\nnamespace sphincs_c10\n"
    mutations = [("domain", "255#u8", "254#u8"),
        ("seed", "Array.to_slice seed", "Array.to_slice root"),
        ("root", "Array.to_slice root", "Array.to_slice seed"),
        ("randomizer", "Array.to_slice r)", "Array.to_slice message)"),
        ("message", "Array.to_slice message", "Array.to_slice r"),
        ("order", "[ s, s1, s2, s3, s4 ]", "[ s4, s3, s2, s1, s ]")]
    with tempfile.TemporaryDirectory(prefix="hmsg-proof-controls-") as td:
        def run(name, changed):
            path = Path(td) / (name + ".lean")
            source = (prefix + changed + "\n" + proof + "\nend sphincs_c10\n").replace("hash.h_msg", "hash.h_msg_probe")
            assert "sorry" not in source and "axiom " not in source
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  text=True, capture_output=True, timeout=60)
        result = run("positive", body)
        assert result.returncode == 0, result.stdout + result.stderr
        def negative(mutation):
            name, before, after = mutation
            assert body.count(before) == 1, (name, "ambiguous mutation")
            result = run(name, body.replace(before, after))
            assert result.returncode != 0 and "unsolved goals" in result.stdout and "timeout" not in result.stdout, (name, result.stdout, result.stderr)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, mutations))
    print("OK: H_msg proof positive baseline + 6 semantic input mutations rejected")

if __name__ == "__main__":
    main()
