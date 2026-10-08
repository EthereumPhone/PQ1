#!/usr/bin/env python3
"""WOTS copied hash/digit declarations must all participate in fidelity checks."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT

MUTATIONS = [
    ("def zero ", "(0 : UInt8)", "(1 : UInt8)"),
    ("def u32ToB32 ", "(zero 28).append (ofU32BE x)", "(ofU32BE x).append (zero 28)"),
    ("def LogW :", "def LogW : Nat := 3", "def LogW : Nat := 2"),
    ("def L :", "def L : Nat := 43", "def L : Nat := 42"),
    ("def wotsDigest", "ByteSeg.ofByteVec msgHash,", "ByteSeg.ofByteVec seed,"),
    ("def extractDigits ", "readBitsLe digest (i * LogW) LogW", "readBitsLe digest (i * LogW + 1) LogW"),
    ("def digitSum ", "(init := 0)", "(init := 1)"),
]

def main():
    with tempfile.TemporaryDirectory(prefix="wots-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        p = root / "extracted/Extracted/WotsSpecVendored.lean"
        original = p.read_text()
        def check():
            return subprocess.run([sys.executable, str(root / COPY[0])],
                                  capture_output=True, text=True, timeout=20)
        result = check()
        assert result.returncode == 0, result.stdout + result.stderr
        for marker, before, after in MUTATIONS:
            assert original.count(before) == 1, (marker, "ambiguous mutation")
            p.write_text(original.replace(before, after))
            result = check()
            assert result.returncode != 0 and "DRIFT in" in result.stdout, (marker, result.stdout, result.stderr)
            p.write_text(original.replace(marker, marker.replace("def ", "def deleted_", 1)
                                        if "def " in marker else "structure DeletedByteSeg"))
            result = check()
            assert result.returncode != 0 and "MISSING in vendored:" in result.stdout, (marker, result.stdout, result.stderr)
    print("OK: WOTS fidelity baseline, 7 semantic mutations, 7 declaration deletions")

if __name__ == "__main__":
    main()
