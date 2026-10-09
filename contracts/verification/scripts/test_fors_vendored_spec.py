#!/usr/bin/env python3
"""The eight digest-decoder definitions must all participate in fidelity checks."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COPY = [
    "scripts/check_vendored_spec.py",
    "extracted/Extracted/XmssAuthVendored.lean",
    "extracted/Extracted/XmssRootVendored.lean",
    "extracted/Extracted/ForsRootVendored.lean",
    "extracted/Extracted/ForsAuthVendored.lean",
    "lean/SphincsCVerify/Spec/Treehash.lean",
    "lean/SphincsCVerify/Spec/Signer.lean",
    "extracted/Extracted/ForsSecretVendored.lean",
    "extracted/Extracted/WotsKeygenVendored.lean",
    "extracted/Extracted/VerifierTopVendored.lean",
    "extracted/Extracted/SignatureDecodeVendored.lean",
    "lean/SphincsCVerify/Spec/Signature.lean",
    "extracted/Extracted/HypertreeContinuationVendored.lean",
    "extracted/Extracted/ForsPrefixVendored.lean",
    "extracted/Extracted/ForsForestVendored.lean",
    "lean/SphincsCVerify/Spec/Fors.lean",
    "extracted/Extracted/ForsRecoveryVendored.lean",
    "lean/SphincsCVerify/Spec/Hypertree.lean",
    "extracted/Extracted/MerkleRecoveryVendored.lean",
    "lean/SphincsCVerify/Spec/Bytes.lean",
    "lean/SphincsCVerify/Spec/Adrs.lean",
    "lean/SphincsCVerify/Spec/Hash.lean",
    "lean/SphincsCVerify/Spec/Wots.lean",
    "lean/SphincsCVerify/Spec/Params.lean",
    "lean/SphincsCVerify/Spec/Sha256Impl.lean",
    "lean/SphincsCVerify/Util/Bits.lean",
    "extracted/Extracted/SpecVendored.lean",
    "extracted/Extracted/Sha256Vendored.lean",
    "extracted/Extracted/ForsSpecVendored.lean",
    "extracted/Extracted/HMsgSpecVendored.lean",
    "extracted/Extracted/WotsSpecVendored.lean",
    "extracted/Extracted/WotsRecoveryVendored.lean",
]
MUTATIONS = [
    ("def get ", "v.data[i']", "0"),
    ("def H :", "def H : Nat := 18", "def H : Nat := 17"),
    ("def K :", "def K : Nat := 13", "def K : Nat := 12"),
    ("def A :", "def A : Nat := 11", "def A : Nat := 10"),
    ("@[inline] def readBitsLe.stepValue", "31 - bitIdx / 8", "bitIdx / 8"),
    ("def readBitsLe ", "loop 0 0", "loop 1 0"),
    ("def extractForsIndices ", "readBitsLe digest (i * A) A", "readBitsLe digest (i * A + 1) A"),
    ("def extractHtIndex ", "readBitsLe digest (K * A) H", "readBitsLe digest (K * A + 1) H"),
]


def main():
    with tempfile.TemporaryDirectory(prefix="fors-vendored-control-") as td:
        root = Path(td)
        for name in COPY:
            dst = root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dst)
        vendor = root / "extracted/Extracted/ForsSpecVendored.lean"
        original = vendor.read_text()

        def check():
            return subprocess.run([sys.executable, str(root / COPY[0])], text=True,
                                  capture_output=True, timeout=20)

        result = check()
        assert result.returncode == 0, result.stdout + result.stderr
        for marker, before, after in MUTATIONS:
            assert original.count(before) == 1, (marker, "ambiguous mutation")
            vendor.write_text(original.replace(before, after))
            result = check()
            assert result.returncode != 0 and f"DRIFT in {marker!r}" in result.stdout, (
                marker, result.returncode, result.stdout, result.stderr)
        vendor.write_text(original.replace("def extractHtIndex ", "def deletedExtractHtIndex "))
        result = check()
        assert result.returncode != 0 and "MISSING in vendored: 'def extractHtIndex '" in result.stdout
    print("OK: FORS vendored fidelity: positive baseline + 8 semantic drifts + deleted decoder rejected")


if __name__ == "__main__":
    main()
