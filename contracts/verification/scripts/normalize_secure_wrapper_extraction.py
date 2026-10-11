#!/usr/bin/env python3
"""Localize imports and map materialized source spans to their pinned repo files.

The emitted production module is committed verbatim and checked against a fresh
source-adapter build. No Lean declaration or function body is rewritten here.
"""
from pathlib import Path
import sys

TOOL = "contracts/verification/tools/secure-wrapper-model/"


def normalize(text: str) -> str:
    return (text.replace("import Securewrapper.", "import Extracted.SecureWrapper.")
            .replace("Source: 'src/lib.rs'", f"Source: '{TOOL}src/lib.rs'")
            .replace("Source: 'src/production.rs'", f"Source: '{TOOL}generated/production.rs'"))


if __name__ == "__main__":
    source, destination = map(Path, sys.argv[1:])
    destination.write_text(normalize(source.read_text()))
