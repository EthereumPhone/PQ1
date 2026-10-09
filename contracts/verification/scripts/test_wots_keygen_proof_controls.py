#!/usr/bin/env python3
"""Typed WOTS generation changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    "tree": ("WotsSecretSpec.lean", "hash.u64_to_b32", [
        ("padding", "Array.repeat 32#usize 0#u8", "Array.repeat 32#usize 1#u8"),
        ("position", "start := 24#usize, «end» := 32#usize", "start := 0#usize, «end» := 8#usize"),
        ("value", "core.num.U64.to_be_bytes v", "core.num.U64.to_be_bytes 0#u64"),
    ]),
    "secret": ("WotsSecretSpec.lean", "hash.wots_secret", [
        ("seed", "Array.to_slice sk_seed", "Array.to_slice (Array.repeat 32#usize 0#u8)"),
        ("tag", "119#u8, 111#u8", "118#u8, 111#u8"),
        ("layer", "core.num.U32.to_be_bytes layer", "core.num.U32.to_be_bytes 0#u32"),
        ("tree", "hash.u64_to_b32 tree", "hash.u64_to_b32 0#u64"),
        ("keypair", "core.num.U32.to_be_bytes kp", "core.num.U32.to_be_bytes 0#u32"),
        ("chain", "core.num.U32.to_be_bytes chain_idx", "core.num.U32.to_be_bytes 0#u32"),
        ("field-order", "[ s, s1, s2, s3, s4, s5 ]", "[ s, s1, s2, s3, s5, s4 ]"),
    ]),
    "body": ("WotsKeygenSpec.lean", "wots.keygen_pk_loop", [
        ("secret-seed", "hash.wots_secret sk_seed", "hash.wots_secret seed"),
        ("secret-index", "tree kp i1", "tree kp 0#u32"),
        ("chain-index", "address.set_chain_index base_adrs i2", "address.set_chain_index base_adrs 0#u32"),
        ("chain-start", "sk_i 0#u32 i4", "sk_i 1#u32 i4"),
        ("chain-steps", "sk_i 0#u32 i4", "sk_i 0#u32 6#u32"),
        ("destination", "Array.update pk_elements i a", "Array.update pk_elements 0#usize a"),
    ]),
    "loop": ("WotsKeygenSpec.lean", "wots.keygen_pk_loop", [
        ("initial-index", "(iter, pk_elements)", "({start := 1#usize, «end» := iter.«end»}, pk_elements)"),
    ]),
    "keygen": ("WotsKeygenSpec.lean", "wots.keygen_pk", [
        ("base-domain", "tree params.ADRS_WOTS kp", "tree params.ADRS_WOTS_PK kp"),
        ("compression-domain", "tree params.ADRS_WOTS_PK kp", "tree params.ADRS_WOTS kp"),
        ("chain-count", "«end» := params.L", "«end» := 42#usize"),
        ("layer-binding", "layer tree kp base_adrs pk_elements", "0#u32 tree kp base_adrs pk_elements"),
        ("tree-binding", "layer tree kp base_adrs pk_elements", "layer 0#u64 kp base_adrs pk_elements"),
        ("keypair-binding", "layer tree kp base_adrs pk_elements", "layer tree 0#u32 base_adrs pk_elements"),
        ("compression-seed", "hash.th_multi seed pk_adrs s", "hash.th_multi sk_seed pk_adrs s"),
    ]),
    "spec-secret": ("WotsSecretBridge.lean", "wotsSecret", [
        ("secret-seed", "ByteSeg.ofByteVec skSeed", "ByteSeg.ofByteVec (zero 32)"),
        ("field-order", "ofU32BE kp", "ofU32BE chainIdx"),
    ]),
    "spec-keygen": ("WotsKeygenBridge.lean", "keygenPk", [
        ("chain-order", "(List.range L).map", "(List.range L).reverse.map"),
        ("steps", "skI 0 (W - 1)", "skI 0 (W - 2)"),
    ]),
}


def fixture(family, before=None, after=None):
    proof_file, name, _ = FAMILIES[family]
    proof = (ROOT / "Extracted" / proof_file).read_text()
    if family.startswith("spec-"):
        source = (ROOT / "Extracted/WotsKeygenVendored.lean").read_text()
        start = source.index("def " + name + "\n")
        end = source.index("\n\n", start)
        ns = "SphincsCVerify.Spec" + (".Wots" if family == "spec-keygen" else "")
        opens = "open SphincsCVerify.Spec ByteVec"
        attr = ""
    else:
        folder = "WotsSecret" if family in ("tree", "secret") else "WotsKeygen"
        source = (ROOT / "Extracted" / folder / "Funs.lean").read_text()
        start = source.index("def " + name + (".body\n" if family == "body" else "\n" if family != "tree" else " "))
        if family == "body":
            end = source.index("\n/--", source.index("def " + name + "\n", start))
        else:
            candidates = [source.find(mark, start) for mark in ("\n/--", "\nend sphincs_c10")]
            end = min(x for x in candidates if x >= 0)
        ns = "sphincs_c10"
        opens = "open Aeneas Aeneas.Std Result ControlFlow Error"
        attr = "@[rust_loop_body]\n" if family == "body" else "@[rust_loop]\n" if family == "loop" else ""
    if family == "spec-keygen":
        proof = proof.replace("attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes",
                              "attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes SphincsCVerify.Spec.chainHash")
    if family == "tree":
        proof = proof[:proof.index("@[step] theorem wots_secret_spec")] + "\nend Extracted.Equiv\n"
    if family in ("body", "loop"):
        proof = proof[:proof.index("/-- Every input completes")] + "\nend Extracted.Equiv\n"
    declaration = source[start:end]
    if before is not None:
        assert declaration.count(before) == 1, (family, before, "ambiguous mutation")
        declaration = declaration.replace(before, after)
    pattern = re.escape(name) + (r"(?![A-Za-z0-9_.])" if family == "loop" else r"(?![A-Za-z0-9_])")
    declaration = re.sub(pattern, name + "_probe", declaration)
    proof = re.sub(pattern, name + "_probe", proof)
    declaration = f"namespace {ns}\n{opens}\n{attr}" + declaration + f"\nend {ns}\n"
    source = proof.replace("namespace Extracted.Equiv", declaration + "\nnamespace Extracted.Equiv", 1)
    assert "sorry" not in source and "axiom " not in source
    return source


def main():
    with tempfile.TemporaryDirectory(prefix="wots-keygen-controls-") as td:
        def run(name, source):
            path = Path(td) / (name + ".lean")
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        for family in FAMILIES:
            result = run(family + "-positive", fixture(family))
            assert result.returncode == 0, (family, result.stdout, result.stderr)
        jobs = [(family, name, before, after) for family, (_, _, mutations) in FAMILIES.items()
                for name, before, after in mutations]
        def negative(job):
            family, name, before, after = job
            source = fixture(family, before, after)
            # The terminal helper is in the proof namespace: split at the LAST
            # opening, after the injected replacement's closing namespace.
            typed = run(family + "-" + name + "-definition", source.rsplit("namespace Extracted.Equiv", 1)[0])
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            result = run(family + "-" + name, source)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and any(x in output for x in
                ("unsolved goals", "Type mismatch", "Application type mismatch", "Tactic `rewrite` failed",
                 "'show' tactic failed", "`simp` made no progress", "Tactic `rfl` failed",
                 "Tactic `apply` failed", "Could not unify", "Tactic `assumption` failed",
                 "omega could not prove", "scalar_tac failed")), (name, output)
            assert not any(x in output for x in ("unknown module", "Unknown constant", "unexpected token",
                "Unknown identifier", "maximum recursion", "maximum number of heartbeats", "timeout", "declaration uses")), (name, output)
        def checked(job):
            try:
                negative(job)
                return None
            except (AssertionError, subprocess.TimeoutExpired) as exc:
                return f"{job[0]}/{job[1]}: {exc}"
        with ThreadPoolExecutor(max_workers=3) as pool:
            failures = [result for result in pool.map(checked, jobs) if result is not None]
        assert not failures, "\n".join(failures)
    print(f"OK: WOTS generation proof controls: {len(FAMILIES)} positive baselines; {len(jobs)} typed semantic mutations rejected")

if __name__ == "__main__":
    main()
