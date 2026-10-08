#!/usr/bin/env python3
"""H_msg's copied hash/input declarations must all participate in fidelity checks."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT

MUTATIONS = [
    ("def ones ", "(0xFF : UInt8)", "(0 : UInt8)"),
    ("structure ByteSeg", "bytes : ByteVec size", "bytes : ByteVec 0"),
    ("def ofByteVec ", "⟨n, v⟩", "⟨0, v⟩"),
    ("def ByteSeg.flatten ", "acc ++ seg.bytes.data", "seg.bytes.data ++ acc"),
    ("def sha256_impl ", "Sha256Impl.sha256Bytes bytes", "Sha256Impl.sha256Bytes #[]"),
    ("@[irreducible] def sha256 :", ":= sha256_impl", ":= fun _ => ones 32"),
    ("def hMsg", "ByteSeg.ofByteVec message,", "ByteSeg.ofByteVec r,"),
]

def main():
    with tempfile.TemporaryDirectory(prefix="hmsg-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        p = root / "extracted/Extracted/HMsgSpecVendored.lean"
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
    print("OK: H_msg fidelity baseline, 7 semantic mutations, 7 declaration deletions")

if __name__ == "__main__":
    main()
