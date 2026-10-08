#!/usr/bin/env python3
"""Every copied recovery declaration must participate in the fidelity gate."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT

MUTATIONS = [
    ("def SubtreeH :", ":= 9", ":= 8"),
    ("def ADRS_TREE :", ":= 2", ":= 3"),
    ("def treeNode ", "0 0 height parentIdx", "0 0 parentIdx height"),
    ("def thPair ", "ByteSeg.ofByteVec right", "ByteSeg.ofByteVec left"),
    ("def verifyAuthPath\n", "parentIdx := idx / 2", "parentIdx := idx / 4"),
]


def main():
    with tempfile.TemporaryDirectory(prefix="merkle-recovery-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        p = root / "extracted/Extracted/MerkleRecoveryVendored.lean"
        original = p.read_text()

        def check():
            return subprocess.run([sys.executable, str(root / COPY[0])],
                                  capture_output=True, text=True, timeout=20)

        result = check()
        assert result.returncode == 0, result.stdout + result.stderr
        for marker, before, after in MUTATIONS:
            start = original.index(marker)
            end = start + len(original[start:].split("\n\n", 1)[0])
            body = original[start:end]
            assert body.count(before) == 1, (marker, "ambiguous mutation")
            p.write_text(original[:start] + body.replace(before, after) + original[end:])
            result = check()
            assert result.returncode != 0 and f"DRIFT in {marker!r}" in result.stdout, (marker, result.stdout, result.stderr)
            renamed = re.sub(r"^(def |structure )(\w+)", r"\1deleted_\2", body, count=1)
            assert renamed != body
            p.write_text(original[:start] + renamed + original[end:])
            result = check()
            assert result.returncode != 0 and f"MISSING in vendored: {marker!r}" in result.stdout, (marker, result.stdout, result.stderr)
    print("OK: Merkle recovery fidelity baseline, 5 semantic mutations, 5 declaration deletions")


if __name__ == "__main__":
    main()
