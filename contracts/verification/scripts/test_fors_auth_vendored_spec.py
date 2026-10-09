#!/usr/bin/env python3
"""Every copied authentication-path declaration must participate in the fidelity gate."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from test_fors_vendored_spec import COPY, ROOT

MUTATIONS = {
    "ForsAuthVendored.lean": [
        ("def sibIdx ", "p + 1", "p + 2"),
        ("def forsMtAuthPath ", "(sibIdx leafIdx h.val)", "(sibIdx 0 h.val)"),
    ],
}


def require_fidelity_rejection(result, filename, marker, kind):
    """Accept only a complete, normal checker rejection for this declaration."""
    assert result.returncode == 1, ("abnormal or successful exit", result.returncode,
                                    result.stdout, result.stderr)
    assert not result.stderr, ("checker error stream", result.stderr)
    lines = result.stdout.splitlines()
    prefix = f"[{filename}] {kind} {marker!r}"
    if kind == "DRIFT in":
        assert len(lines) == 3 and lines[0] == prefix + ":", result.stdout
        assert lines[1].startswith("  src: ") and lines[2].startswith("  ven: "), result.stdout
    else:
        assert kind == "MISSING in vendored:", kind
        assert lines == [prefix], result.stdout


def test_result_classifier():
    """A drift marker followed by an interrupted checker is not valid evidence."""
    filename, marker = "ForsAuthVendored.lean", "def sibIdx "
    invalid_count = 0
    for kind, stdout in [
        ("DRIFT in", f"[{filename}] DRIFT in {marker!r}:\n  src: original\n  ven: changed\n"),
        ("MISSING in vendored:", f"[{filename}] MISSING in vendored: {marker!r}\n"),
    ]:
        require_fidelity_rejection(subprocess.CompletedProcess([], 1, stdout, ""), filename, marker, kind)
        invalid = [subprocess.CompletedProcess([], code, stdout, "")
                   for code in [0, -9, -15, 2, 124, 130, 134, 137, 139]]
        for diagnostic in ["Traceback (most recent call last):\nMemoryError\n",
                           "MemoryError\n", "Killed\n", "KeyboardInterrupt\n", "OSError\n"]:
            invalid += [subprocess.CompletedProcess([], 1, stdout, diagnostic),
                        subprocess.CompletedProcess([], 1, stdout + diagnostic, "")]
        invalid += [subprocess.CompletedProcess([], 1, "", ""),
                    subprocess.CompletedProcess([], 1, stdout + stdout, ""),
                    subprocess.CompletedProcess([], 1, stdout.replace(filename, "Other.lean"), "")]
        for result in invalid:
            try:
                require_fidelity_rejection(result, filename, marker, kind)
            except AssertionError:
                invalid_count += 1
                continue
            raise AssertionError(("invalid fidelity result accepted", result))
    print(f"OK: fidelity-result classifier: 2 complete rejections accepted; {invalid_count} invalid outcomes rejected")


def main():
    test_result_classifier()
    with tempfile.TemporaryDirectory(prefix="fors-auth-fidelity-") as td:
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
    print("OK: FORS auth fidelity baseline, 2 semantic mutations, 2 declaration deletions")


if __name__ == "__main__":
    main()
