#!/usr/bin/env python3
"""Normalize signer name shadowing and kernel-check panic-string size witnesses."""
from pathlib import Path
import re
import sys

source, destination = map(Path, sys.argv[1:])
text = source.read_text()
for name, count in (("ShuffleSeed.derive", 2), ("fisher_yates", 1)):
    old = f"← shuffle.{name} "
    assert text.count(old) == count, f"signer shuffle call drift: {name}"
    text = text.replace(old, f"← sphincs_c10.shuffle.{name} ")
# Aeneas toStr's omitted size witness defaults to a native proof. Supply
# the same finite bound with an explicit kernel proof, preserving both strings.
pattern = r'(toStr\s+"([^"\\]*(?:\\.[^"\\]*)*)")\)'
expected = {"Signing self-verification failed: root mismatch",
            "Last FORS index must be 0 after R-grinding"}
found = re.findall(pattern, text)
assert len(found) == 2 and {x[1] for x in found} == expected, "signer panic string drift"
def kernel_witness(match):
    literal = '"' + match[2] + '"'
    proof = (f"by (conv_lhs => rw [← String.ofList_toList (s := {literal}), "
             "String.toByteArray_ofList]); "
             "simp only [List.utf8Encode, List.size_toByteArray]; "
             "simp [String.utf8EncodeChar]; scalar_tac")
    return match[1] + " (" + proof + "))"

text = re.sub(pattern, kernel_witness, text)
destination.write_text(text)
