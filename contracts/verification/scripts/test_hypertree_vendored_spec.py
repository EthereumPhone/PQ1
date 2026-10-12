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
    ("def D :", "Nat := 2", "Nat := 1"),
    ("structure LayerSig", "authPath.size = SubtreeH", "authPath.size = SubtreeH + 1"),
    ("def defaultLayerSig :", "count := 0", "count := 1"),
    ("def verifyHypertree\n", "bad := true", "bad := false"),
]


def main():
    with tempfile.TemporaryDirectory(prefix="hypertree-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        p = root / "extracted/Extracted/HypertreeContinuationVendored.lean"
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
    print("OK: hypertree fidelity baseline, 4 semantic mutations, 4 declaration deletions")


if __name__ == "__main__":
    main()
