#!/usr/bin/env python3
"""Every copied XMSS root declaration must participate in the fidelity gate."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT
from test_fors_auth_vendored_spec import require_fidelity_rejection

MUTATIONS = {
    "XmssRootVendored.lean": [
        ("def mtNode ", "lf ℓ (2 * idx + 1)", "lf ℓ (2 * idx)"),
    ],
}


def main():
    with tempfile.TemporaryDirectory(prefix="xmss-root-fidelity-") as td:
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
                require_fidelity_rejection(result, filename, marker, "DRIFT in")
                renamed = re.sub(r"^(def |structure )(\w+)", r"\1deleted_\2", body, count=1)
                assert renamed != body
                p.write_text(original[:start] + renamed + original[end:])
                result = check()
                require_fidelity_rejection(result, filename, marker, "MISSING in vendored:")
                p.write_text(original)
    print("OK: XMSS root fidelity baseline, 1 semantic mutation, 1 declaration deletion")


if __name__ == "__main__":
    main()
