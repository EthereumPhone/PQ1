#!/usr/bin/env python3
"""Share only byte-identical declarations; rename the three release caller bodies.

The input is fresh Aeneas output with debug assertions disabled, after the same
parameter/range-trait deduplication used by SignForest. No expression, guard or
return value is rewritten. Opaque dependencies keep their existing models.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

source, destination = map(Path, sys.argv[1:])
root = Path(__file__).resolve().parents[1]
canonical = (root / "extracted/Extracted/SignForest/Funs.lean").read_text()
text = source.read_text()
for name, count in (("ShuffleSeed.derive", 2), ("fisher_yates", 1)):
    old = f"← shuffle.{name} "
    assert text.count(old) == count, f"release shuffle call drift: {name}"
    text = text.replace(old, f"← sphincs_c10.shuffle.{name} ")

def chunks(value):
    assert value.endswith("end sphincs_c10\n")
    parts = re.split(r"(?m)^(?=/--)", value.removesuffix("end sphincs_c10\n"))
    declarations = {}
    for part in parts[1:]:
        match = re.search(r"(?m)^def ([\w.]+)", part)
        assert match, "unrecognized generated declaration"
        name = match[1]
        assert name not in declarations, f"duplicate declaration: {name}"
        declarations[name] = part
    return parts[0], declarations

header, actual = chunks(text)
_, previous = chunks(canonical)
changed = {"hypertree.sign_inner", "hypertree.sign_inner_loop3",
           "hypertree.sign_inner_loop3.body"}
assert set(actual) == set(previous), "release declaration inventory drift"
for name in actual.keys() - changed:
    assert actual[name].strip() == previous[name].strip(), f"shared body drift: {name}"
header = header.replace("import Extracted.Verify.Funs",
                        "import Extracted.SignForest.Funs")
output = header + "".join(body for name, body in actual.items() if name in changed)
# Lexical identifier renaming only; calls to shared loop helpers remain intact.
output = re.sub(r"\bhypertree\.sign_inner_loop3(?=\b)(?!_)",
                "hypertree.release_sign_inner_loop3", output)
output = re.sub(r"\bhypertree\.sign_inner\b", "hypertree.release_sign_inner", output)
destination.write_text(output + "end sphincs_c10\n")

registry = json.loads((root / "extraction_registry.json").read_text())
checked = next(e for e in registry["entries"] if e["target"] == "extract-sign-forest")
assert hashlib.sha256((source.parent / "Types.lean").read_bytes()).hexdigest() == \
    checked["raw_generated_sha256"]["Types.lean"], "shared Types drift"
(source.parent / "Types.fixed.lean").write_text(
    "/- Byte-identical generated types are shared with the checked signer. -/\n"
    "import Extracted.SignForest.Types\n")
