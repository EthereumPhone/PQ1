#!/usr/bin/env python3
"""Per-file proof-hole ratchet for the Verity research scaffold (#673)."""
from pathlib import Path
import os
import sys

from lean_source import keyword_count

VERITY = Path(__file__).resolve().parents[2] / "verity"
BASELINE = {"PQSigner/Theorems.lean": 11, "PQSigner/Verifier/Merkle.lean": 1}


def check(directory: Path) -> int:
    source = directory / "PQSigner"
    if source.is_symlink():
        raise ValueError("symlinked Verity source root")
    files = []
    for parent, dirs, names in os.walk(source):
        for name in dirs + names:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError(f"symlink in Verity source tree: {path}")
        files.extend(Path(parent) / name for name in names if name.endswith(".lean"))
    if not files:
        raise ValueError("empty Verity source tree")
    total = 0
    for path in sorted(files):
        data = path.read_bytes()
        count = keyword_count(data.decode("utf-8"), "(?:sorry|admit|sorryAx|proof_wanted)")
        name = path.relative_to(directory).as_posix()
        baseline = BASELINE.get(name, 0)
        if count > baseline:
            raise ValueError(f"{name}: {count} raw proof-hole mentions exceed baseline {baseline}")
        total += count
    return total


if __name__ == "__main__":
    try:
        total = check(VERITY)
        print(f"PASS: Verity sorry/admit ratchet ({total} accounted holes, baseline 12)")
    except (OSError, ValueError) as exc:
        print(f"VERITY HOLE FAILURE: {exc}", file=sys.stderr)
        sys.exit(1)
