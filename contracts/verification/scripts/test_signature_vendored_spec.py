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
    "VerifierTopVendored.lean": [
        ("def N :", "Nat := 16", "Nat := 15"),
        ("def SigR :", "Nat := N", "Nat := N + 1"),
        ("def SigForsSecrets :", "K * N", "K * N + 1"),
        ("def SigForsAuth :", "(K - 1) * A * N", "(K - 2) * A * N"),
        ("def SigForsTotal :", "SigR + SigForsSecrets + SigForsAuth", "SigR + SigForsSecrets + SigForsAuth + 1"),
        ("def SigHtLayer :", "L * N + 4 + SubtreeH * N", "L * N + 3 + SubtreeH * N"),
        ("def SignatureLen :", "SigForsTotal + D * SigHtLayer", "SigForsTotal + (D - 1) * SigHtLayer"),
        ("def loadWord32 ", "Array.replicate 32 0", "Array.replicate 32 1"),
        ("def loadValue16 ", "loadWord32 sig offset", "loadWord32 sig (offset + 1)"),
        ("def loadU32BE ", "b0.toNat <<< 24", "b0.toNat <<< 16"),
        ("structure Signature", "layers.size = D", "layers.size = D + 1"),
        ("def verifyWithDigest\n", "indices.getD (K - 1) 0", "indices.getD (K - 2) 0"),
        ("def verify\n", "pad16 sig.r", "pad16 pkRoot"),
    ],
    "SignatureDecodeVendored.lean": [
        ("structure VerifyingKey", "pkSeed : ByteVec 16", "pkSeed : ByteVec 32"),
        ("def deserialise ", "(N + i.val * N)", "(N + i.val * N + 1)"),
        ("def verify\n", "vk.pkSeed vk.pkRoot", "vk.pkRoot vk.pkSeed"),
    ],
}


def main():
    with tempfile.TemporaryDirectory(prefix="signature-fidelity-") as td:
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
    print("OK: signature/top-verifier fidelity baseline, 16 semantic mutations, 16 declaration deletions")


if __name__ == "__main__":
    main()
