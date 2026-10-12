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
    ("def take ", "extract 0 k", "extract 1 (k + 1)"),
    ("def pad16 ", "v.append (zero 16)", "(zero 16).append v"),
    ("def truncate16 ", "d.take 16", "(zero 32).take 16"),
    ("def W :", ":= 8", ":= 4"),
    ("def TargetSum :", ":= 205", ":= 204"),
    ("def ADRS_WOTS :", ":= 0", ":= 3"),
    ("def ADRS_WOTS_PK :", ":= 1", ":= 0"),
    ("def setChainPos ", "prefix6.append (ofU32BE pos)", "prefix6.append (ofU32BE (pos + 1))"),
    ("def wots ", "UInt32.ofNat ADRS_WOTS", "UInt32.ofNat ADRS_WOTS_PK"),
    ("def wotsPk ", "UInt32.ofNat ADRS_WOTS_PK", "UInt32.ofNat ADRS_WOTS"),
    ("def th (", "ByteSeg.ofByteVec val", "ByteSeg.ofByteVec seed"),
    ("def thMulti ", "vals.map", "vals.reverse.map"),
    ("def chainHash\n", "startPos + (steps - 1 - i)", "startPos + i"),
    ("structure Sigma", "count : UInt32", "count : UInt64"),
    ("def pkFromSig\n", "digitSum digits ≠ TargetSum", "digitSum digits < TargetSum"),
]


def main():
    with tempfile.TemporaryDirectory(prefix="wots-recovery-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        p = root / "extracted/Extracted/WotsRecoveryVendored.lean"
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
    print("OK: WOTS recovery fidelity baseline, 15 semantic mutations, 15 declaration deletions")


if __name__ == "__main__":
    main()
