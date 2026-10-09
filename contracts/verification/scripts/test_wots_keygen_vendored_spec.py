#!/usr/bin/env python3
"""Every copied recovery declaration must participate in the fidelity gate."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT

MUTATIONS = {
    "WotsKeygenVendored.lean": [
        ("def u64ToB32 ", "zero 24", "zero 23"),
        ("def wotsTag :", "0x77", "0x76"),
        ("def wotsSecret\n", "ofU32BE kp", "ofU32BE chainIdx"),
        ("def keygenPk\n", "(List.range L).map", "(List.range L).reverse.map"),
    ],
}


def main():
    with tempfile.TemporaryDirectory(prefix="wots-keygen-fidelity-") as td:
        root = Path(td)
        for name in COPY:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)

        def check():
            return subprocess.run([sys.executable, str(root / COPY[0])],
                                  capture_output=True, text=True, timeout=20)

        result = check()
        assert result.returncode == 0, result.stdout + result.stderr
        for filename, mutations in MUTATIONS.items():
            p = root / "extracted/Extracted" / filename
            original = p.read_text()
            for marker, before, after in mutations:
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
                p.write_text(original)
    print("OK: WOTS generation fidelity baseline, 4 semantic mutations, 4 declaration deletions")


if __name__ == "__main__":
    main()
