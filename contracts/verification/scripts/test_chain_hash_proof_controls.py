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
        ("digest-wrong-half",
         "(core.slice.index.SliceIndexRangeToUsizeSlice Std.U8)) d\n        { «end» := params.N }",
         "(core.slice.index.SliceIndexRangeUsizeSlice Std.U8)) d\n        { start := params.N, «end» := 32#usize }"),
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
    print(f"OK: chain_hash proof positive baseline + {len(mutations)} typed semantic loop mutations rejected")


if __name__ == "__main__":
    main()
