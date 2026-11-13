#!/usr/bin/env python3
"""Check that the hoisted chain_hash proof rejects changed loop bodies.

`hash.chain_hash_spec` (HashSpecs/ChainHash.lean) proves the extracted loop
over the 96-byte buffer equals `chain_hash_pure`. Renamed copies of the
extracted loop body, loop and `chain_hash` are re-checked with the committed
proofs: the unmodified copy must prove, and every typed semantic mutation of
the body must leave an unproved goal — not an import/tool failure, sorry, or
timeout. Fixtures are fresh external files; positive control runs first.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pwd
import re
import subprocess
import tempfile

from test_fors_auth_proof_controls import require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
LAKE = Path(pwd.getpwuid(__import__('os').getuid()).pw_dir) / ".elan/bin/lake"


def block(text, start, end_marker="\n\n"):
    i = text.index(start)
    return text[i:text.index(end_marker, i)]


def rename(source):
    for before, after in [
        ("hash.chain_hash_loop.body", "hash.chain_hash_loopP.body"),
        ("hash.chain_hash_loop ", "hash.chain_hash_loopP "),
        ("hash.chain_hash_loop\n", "hash.chain_hash_loopP\n"),
        ("hash.chain_hash seed", "hash.chain_hashP seed"),
        ("def hash.chain_hash\n", "def hash.chain_hashP\n"),
        ("unfold hash.chain_hash\n", "unfold hash.chain_hashP\n"),
        ("chain_hash_loop_value", "chain_hash_loop_valueP"),
        ("hash.chain_hash_spec", "hash.chain_hash_specP"),
        ("@[step] theorem", "theorem"),
    ]:
        source = source.replace(before, after)
    return source


def main():
    generated = (ROOT / "Extracted/Hash/Funs.lean").read_text()
    spec = (ROOT / "Extracted/HashSpecs/ChainHash.lean").read_text()
    body = block(generated, "@[rust_loop_body]\ndef hash.chain_hash_loop.body")
    loop = block(generated, "@[rust_loop]\ndef hash.chain_hash_loop\n")
    top = block(generated, "def hash.chain_hash\n")
    loop_proof = block(spec, "theorem chain_hash_loop_value",
                       "\n\nset_option maxRecDepth 16384 in\n/-- `chain_buf`")
    spec_proof = spec[spec.index("@[step] theorem hash.chain_hash_spec"):spec.index("\nend sphincs_c10")]
    definitions = rename(body) + "\n\n" + rename(loop) + "\n\n" + rename(top)
    proofs = rename(loop_proof) + "\n\n" + rename(spec_proof)
    prefix = ("import Extracted.HashSpecs.ChainHash\nset_option maxHeartbeats 8000000\n"
              "set_option maxRecDepth 16384\nopen Aeneas Aeneas.Std Result ControlFlow Error\n"
              "open Extracted.SetSlice\nnamespace sphincs_c10\n")
    # Each mutation is a plausible implementation slip in the hoisted loop.
    mutations = [
        ("position-offset", "{ start := 56#usize, «end» := 60#usize }",
         "{ start := 52#usize, «end» := 56#usize }"),
        ("value-offset", "{ start := 64#usize, «end» := i1 }",
         "{ start := 48#usize, «end» := 64#usize }"),
        # Research refactor: the loop hashes with `hash.sha256_bytes16` (the
        # first N digest bytes, a shared helper) and writes the 16-byte result
        # back; the digest-half selection moved into that helper and is
        # controlled by the separate `truncate` fixture below.
        ("digest-stale-buffer", "let s3 ← lift (Array.to_slice buf1)", "let s3 ← lift (Array.to_slice buf)"),
        ("position-ignores-start", "let i ← start_pos + step", "let i ← 0#u32 + step"),
        ("no-value-writeback", "ok (cont (iter1, buf2))", "ok (cont (iter1, buf1))"),
    ]
    with tempfile.TemporaryDirectory(prefix="chain-hash-proof-controls-") as td:
        def run(name, changed, with_proof=True):
            path = Path(td) / (name + ".lean")
            source = prefix + changed + "\n\n" + (proofs if with_proof else "") + "\nend sphincs_c10\n"
            assert "sorry" not in source and "axiom " not in source
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  text=True, capture_output=True, timeout=600)
        result = run("positive", definitions)
        assert result.returncode == 0, result.stdout + result.stderr

        def negative(mutation):
            name, before, after = mutation
            assert definitions.count(before) == 1, (name, "ambiguous mutation")
            changed = definitions.replace(before, after)
            typed = run(name + "-definition", changed, with_proof=False)
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(run(name, changed), name)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, mutations))

        # Digest-half selection: renamed copies of `hash.truncate` and
        # `hash.sha256_bytes16` re-checked with the committed `truncate_spec` /
        # `sha256_bytes16_spec` (HashSpecs/Truncate.lean).
        def trename(source):
            source = source.replace("hash.truncate_spec", "hash.truncateP_spec")
            source = source.replace("hash.sha256_bytes16_spec", "hash.sha256_bytes16P_spec")
            source = re.sub(r"hash\.truncate(?![A-Za-z0-9_])", "hash.truncateP", source)
            return re.sub(r"hash\.sha256_bytes16(?![A-Za-z0-9_])", "hash.sha256_bytes16P", source)
        tspec = (ROOT / "Extracted/HashSpecs/Truncate.lean").read_text()
        tdefs = trename(block(generated, "def hash.truncate\n") + "\n\n"
                        + block(generated, "def hash.sha256_bytes16\n"))
        tproofs = trename(tspec[tspec.index("@[step] theorem hash.truncate_spec"):tspec.index("\nend sphincs_c10")])
        tprefix = ("import Extracted.HashSpecs.Truncate\nset_option linter.unusedSimpArgs false\n"
                   "open Aeneas Aeneas.Std Result ControlFlow Error\nopen Extracted.SetSlice\nnamespace sphincs_c10\n")
        def trun(name, changed, with_proof=True):
            path = Path(td) / ("truncate-" + name + ".lean")
            source = tprefix + changed + "\n\n" + (tproofs if with_proof else "") + "\nend sphincs_c10\n"
            assert "sorry" not in source and "axiom " not in source
            path.write_text(source)
            return subprocess.run([str(LAKE), "env", "lean", str(path)], cwd=ROOT,
                                  text=True, capture_output=True, timeout=600)
        result = trun("positive", tdefs)
        assert result.returncode == 0, result.stdout + result.stderr
        tmutations = [
            ("digest-wrong-half",
             "(core.slice.index.SliceIndexRangeToUsizeSlice Std.U8)) digest\n      { «end» := params.N }",
             "(core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) digest\n      { start := params.N, «end» := 32#usize }"),
            ("digest-not-hashed", "let a ← hash.sha256_bytes data", "let a ← ok (Array.repeat 32#usize 0#u8)"),
        ]
        for name, before, after in tmutations:
            assert tdefs.count(before) == 1, (name, "ambiguous mutation")
            changed = tdefs.replace(before, after)
            typed = trun(name + "-definition", changed, with_proof=False)
            assert typed.returncode == 0, (name, typed.stdout, typed.stderr)
            require_semantic_rejection(trun(name, changed), "truncate/" + name)
    print(f"OK: chain_hash proof positive baseline + {len(mutations)} typed semantic loop mutations rejected; "
          f"truncate/sha256_bytes16 positive baseline + {len(tmutations)} typed semantic mutations rejected")


if __name__ == "__main__":
    main()
