#!/usr/bin/env python3
"""Typed WOTS generation changes must break the unchanged consuming proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import pwd
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".elan/bin/lake"
FAMILIES = {
    # Research refactor: `wots_secret` builds one contiguous 80-byte buffer
    # (`hash.u64_to_b32` is gone; the tree's 8 BE bytes go to [64..72) over a
    # zero gap) and hashes it with `hash.sha256_bytes16`. The former "tree"
    # family's padding/position/value mutations are the tree-* rows here.
    "secret": ("WotsSecretSpec.lean", "hash.wots_secret", [
        ("seed", "Array.to_slice sk_seed", "Array.to_slice (Array.repeat 32#usize 0#u8)"),
        ("tag", "119#u8, 111#u8", "118#u8, 111#u8"),
        ("layer", "core.num.U32.to_be_bytes layer", "core.num.U32.to_be_bytes 0#u32"),
        ("tree", "core.num.U64.to_be_bytes tree", "core.num.U64.to_be_bytes 0#u64"),
        ("tree-padding", "Array.repeat 80#usize 0#u8", "Array.repeat 80#usize 1#u8"),
        ("tree-position", "{ start := 64#usize, «end» := 72#usize }", "{ start := 40#usize, «end» := 48#usize }"),
        ("keypair", "core.num.U32.to_be_bytes kp", "core.num.U32.to_be_bytes 0#u32"),
        ("chain", "core.num.U32.to_be_bytes chain_idx", "core.num.U32.to_be_bytes 0#u32"),
        ("field-order", "core.num.U32.to_be_bytes kp)\n  let s13 ← lift (Array.to_slice a2)\n"
         "  let s14 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s12 s13\n"
         "  let buf5 := index_mut_back4 s14\n  let (s15, index_mut_back5) ←\n"
         "    core.array.Array.index_mut (core.ops.index.IndexMutSlice\n"
         "      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) buf5\n"
         "      { start := 76#usize, «end» := 80#usize }\n"
         "  let a3 ← lift (core.num.U32.to_be_bytes chain_idx)",
         "core.num.U32.to_be_bytes chain_idx)\n  let s13 ← lift (Array.to_slice a2)\n"
         "  let s14 ← core.slice.Slice.copy_from_slice core.marker.CopyU8 s12 s13\n"
         "  let buf5 := index_mut_back4 s14\n  let (s15, index_mut_back5) ←\n"
         "    core.array.Array.index_mut (core.ops.index.IndexMutSlice\n"
         "      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) buf5\n"
         "      { start := 76#usize, «end» := 80#usize }\n"
         "  let a3 ← lift (core.num.U32.to_be_bytes kp)"),
        ("digest", "hash.sha256_bytes16 s18", "hash.truncate (Array.repeat 32#usize 0#u8)"),
    ]),
    # `hash.wots_secret_chain` (wots_secret -> set_chain_index -> chain_hash),
    # probed against `wots_secret_chain_spec` alone.
    "chain": ("WotsKeygenSpec.lean", "hash.wots_secret_chain", [
        ("secret-seed", "hash.wots_secret sk_seed", "hash.wots_secret seed"),
        ("secret-index", "layer tree kp ci", "layer tree kp 0#u32"),
        ("chain-index", "address.set_chain_index base_adrs ci", "address.set_chain_index base_adrs 0#u32"),
        ("chain-start", "sk_i 0#u32 steps", "sk_i 1#u32 steps"),
        ("chain-steps", "sk_i 0#u32 steps", "sk_i 0#u32 6#u32"),
    ]),
    "body": ("WotsKeygenSpec.lean", "wots.keygen_pk_loop", [
        ("secret-seed", "hash.wots_secret_chain seed sk_seed", "hash.wots_secret_chain seed seed"),
        ("secret-index", "tree kp i1 i3", "tree kp 0#u32 i3"),
        ("chain-steps", "params.W - 1#usize", "params.W - 2#usize"),
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
        folder = "WotsSecret" if family == "secret" else "WotsKeygen"
        source = (ROOT / "Extracted" / folder / "Funs.lean").read_text()
        start = source.index("def " + name + (".body\n" if family == "body" else "\n"))
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
    if family == "chain":
        proof = proof[:proof.index("theorem wots_keygen_loop_spec")] + "\nend Extracted.Equiv\n"
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
            require_semantic_rejection(result, name)
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
