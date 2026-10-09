#!/usr/bin/env python3
"""Compiling semantic replacements must break unchanged whole-verifier proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
# file, declaration start/end, namespace, names to rename, proof, mutations
FAMILIES = {
    "load16": ("VerifierTopVendored", "def loadWord32 ", "def loadU32BE ",
        "SphincsCVerify.Spec.ByteVec", ["loadWord32", "loadValue16"], "SignatureDecodeSpec", [
            ("source-offset", "sig.data.extract offset (offset + 32)", "sig.data.extract (offset+1) (offset+33)"),
            ("byte-order", "sig.data.extract offset (offset + 32)", "(sig.data.extract offset (offset+32)).reverse"),
        ]),
    "counter": ("VerifierTopVendored", "def loadU32BE ", "/-! ###",
        "SphincsCVerify.Spec.ByteVec", ["loadU32BE"], "SignatureDecodeSpec", [
            ("high-byte", "UInt32.ofNat b0.toNat", "UInt32.ofNat 0"),
            ("high-shift", "b0.toNat <<< 24", "b0.toNat <<< 16"),
            ("low-byte", "UInt32.ofNat b3.toNat", "UInt32.ofNat b2.toNat"),
        ]),
    "decoder": ("SignatureDecodeVendored", "def deserialise ", "def verify\n",
        "SphincsCVerify.Spec.Signature", ["deserialise"], "SignatureDecodeSpec", [
            ("randomizer", "ByteVec.loadValue16 bytes 0", "ByteVec.loadValue16 bytes 16"),
            ("fors-secrets", "(N + i.val * N)", "(i.val * N)"),
            ("fors-auth", "SigR + SigForsSecrets + t.val", "SigForsSecrets + t.val"),
            ("layer-offset", "SigForsTotal + ℓ.val * SigHtLayer", "SigForsTotal + (1-ℓ.val) * SigHtLayer"),
            ("chain-index", "layerOff + i.val * N", "layerOff + (i.val+1) * N"),
            ("count-offset", "ByteVec.loadU32BE bytes (layerOff + L * N)", "ByteVec.loadU32BE bytes (layerOff + L * N + 1)"),
            ("auth-offset", "layerOff + L * N + 4 + h.val * N", "layerOff + L * N + h.val * N"),
        ]),
    "byte-entry": ("SignatureDecodeVendored", "def verify\n", "end SphincsCVerify.Spec.Signature",
        "SphincsCVerify.Spec.Signature", ["verify"], "WholeVerifierSpec", [
            ("seed-binding", "Hypertree.verify vk.pkSeed vk.pkRoot", "Hypertree.verify vk.pkRoot vk.pkRoot"),
            ("root-binding", "Hypertree.verify vk.pkSeed vk.pkRoot", "Hypertree.verify vk.pkSeed vk.pkSeed"),
            ("decision", "Hypertree.verify vk.pkSeed vk.pkRoot msgHash (deserialise sig)", "!(Hypertree.verify vk.pkSeed vk.pkRoot msgHash (deserialise sig))"),
        ]),
    "header": ("VerifierTopVendored", "def verify\n", "end Hypertree",
        "SphincsCVerify.Spec.Hypertree", ["verify"], "WholeVerifierSpec", [
            ("randomizer-binding", "hMsg seed root rB32 msgHash", "hMsg seed root root msgHash"),
            ("message-binding", "hMsg seed root rB32 msgHash", "hMsg seed root rB32 rB32"),
            ("root-binding", "hMsg seed root rB32 msgHash", "hMsg seed seed rB32 msgHash"),
        ]),
    "decision": ("VerifierTopVendored", "def verifyWithDigest\n", "def verify\n",
        "SphincsCVerify.Spec.Hypertree", ["verifyWithDigest"], "WholeVerifierSpec", [
            ("forced-field", "indices.getD (K - 1) 0", "indices.getD 0 0"),
            ("root-comparison", "decide (finalRoot = pkRoot)", "!decide (finalRoot = pkRoot)"),
            ("forced-refusal", "≠ 0 then\n    false", "≠ 0 then\n    true"),
        ]),
}


def fixture(family, before=None, after=None):
    file, start, end, namespace, names, proof_file, _ = FAMILIES[family]
    source = (ROOT / "Extracted" / (file + ".lean")).read_text()
    start = source.index(start)
    declaration = source[start:source.index(end, start)].strip()
    if before is not None:
        assert declaration.count(before) == 1, (family, before)
        declaration = declaration.replace(before, after)
    proof = (ROOT / "Extracted" / (proof_file + ".lean")).read_text()
    if family == "load16":
        proof = proof[:proof.index("def parsedSignature")] + "\nend Extracted.Equiv\n"
    if family == "counter":
        proof = proof[:proof.index("attribute [local irreducible] ByteVec.loadU32BE")] + "\nend Extracted.Equiv\n"
    if family in ("byte-entry", "header"):
        # The byte-entry theorem is the first consumer of these replacements.
        # Later callers only repeat its failed obligation after Lean inserts an
        # error placeholder; they add no independent mutation evidence.
        proof = proof[:proof.index("theorem strict_accepts_implies_raw")] + "\nend Extracted.Equiv\n"
    for name in names:
        # Replace the unqualified declaration/self references, and only the
        # namespace-qualified uses in the unchanged proof. Never rename verify
        # in a different namespace (e.g. the actual Rust verifier).
        declaration = re.sub(r"(?<![A-Za-z0-9_.])" + name + r"(?![A-Za-z0-9_])",
                             name + "_probe", declaration)
        short_ns = namespace.removeprefix("SphincsCVerify.Spec.")
        proof = re.sub(re.escape(short_ns + "." + name) + r"(?![A-Za-z0-9_])",
                       short_ns + "." + name + "_probe", proof)
    injected = (f"namespace {namespace}\n"
                "open SphincsCVerify.Spec SphincsCVerify.Spec.Hypertree SphincsCVerify.Util ByteVec\n"
                + declaration + f"\nend {namespace}\n")
    # Clone the callers as well: their names must actually refer to the
    # replacement, rather than silently testing the original imported body.
    if family in ("header", "decision"):
        if family == "decision":
            top = (ROOT / "Extracted/VerifierTopVendored.lean").read_text()
            top = top[top.index("def verify\n"):top.index("end Hypertree")]
            top = top.replace("def verify\n", "def verify_probe\n").replace(
                "verifyWithDigest seed", "verifyWithDigest_probe seed")
            injected += "namespace SphincsCVerify.Spec.Hypertree\nopen SphincsCVerify.Spec SphincsCVerify.Util ByteVec\n" + top + "\nend SphincsCVerify.Spec.Hypertree\n"
            proof = re.sub(r"Hypertree\.verify(?![A-Za-z0-9_])", "Hypertree.verify_probe", proof)
        entry = (ROOT / "Extracted/SignatureDecodeVendored.lean").read_text()
        entry = entry[entry.index("def verify\n"):entry.index("end SphincsCVerify.Spec.Signature")]
        entry = entry.replace("def verify\n", "def verify_probe\n").replace(
            "Hypertree.verify ", "Hypertree.verify_probe ")
        injected += "namespace SphincsCVerify.Spec.Signature\nopen SphincsCVerify.Spec\n" + entry + "\nend SphincsCVerify.Spec.Signature\n"
        proof = re.sub(r"Signature\.verify(?![A-Za-z0-9_])", "Signature.verify_probe", proof)
    marker = "namespace Extracted.Equiv"
    # These proofs rewrite H_msg explicitly. Keep the hash construction opaque
    # to definitional equality so a wrong header binding fails immediately,
    # instead of expanding SHA internals while reporting a semantic mismatch.
    proof = proof.replace(marker, injected + "\n" + marker +
                          "\nattribute [local irreducible] SphincsCVerify.Spec.hMsg "
                          "SphincsCVerify.Spec.Hypertree.verifyWithDigest "
                          "Extracted.Equiv.verifierDigest", 1)
    assert "sorry" not in proof and "axiom " not in proof
    return proof


def main():
    with tempfile.TemporaryDirectory(prefix="whole-verifier-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, values in FAMILIES.items()
                for name, before, after in values[-1]]
        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            typed = run(family + "-" + name + "-definition",
                        source.split("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (family, name, typed.stdout, typed.stderr)
            result = run(family + "-" + name, source)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and any(x in output for x in
                ("unsolved goals", "Type mismatch", "Application type mismatch", "Tactic `rewrite` failed",
                 "'show' tactic failed", "'change' tactic failed", "`simp` made no progress", "Tactic `rfl` failed",
                 "Tactic `apply` failed", "Could not unify", "Tactic `assumption` failed",
                 "omega could not prove", "scalar_tac failed")), (family, name, output)
            assert not any(x in output for x in ("unknown module", "Unknown constant", "unexpected token",
                "Unknown identifier", "maximum recursion", "maximum number of heartbeats", "timeout",
                "declaration uses")), (family, name, output)
        def checked(job):
            try:
                negative(job)
                return None
            except (AssertionError, subprocess.TimeoutExpired) as exc:
                return f"{job[0]}/{job[1]}: {exc}"
        with ThreadPoolExecutor(max_workers=3) as pool:
            failures = [result for result in pool.map(checked, jobs) if result is not None]
        assert not failures, "\n".join(failures)
    print(f"OK: whole verifier proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
