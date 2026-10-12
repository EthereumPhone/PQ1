#!/usr/bin/env python3
"""Drop only the verifier's identical U32 range trait already defined by Hash."""
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
text = source.read_text()
canonical = (Path(__file__).resolve().parents[1] /
             "extracted/Extracted/Hash/Funs.lean").read_text()
marker = '/-- Trait implementation: [core::iter::range::{impl core::iter::range::Step for u32}]'
body = '@[reducible, rust_trait_impl "core::iter::range::Step<u32>"]'
assert text.count(marker) == 1 and text.count(body) == 1
start = text.index(marker)
end = text.index('/-- [', start)
a = text.index(body, start)
b = canonical.index(body)
canonical_end = canonical.index('\n}\n', b) + 3
assert text[a:end].strip() == canonical[b:canonical_end].strip(), "range trait drift"
destination.write_text(text[:start] + text[end:])
