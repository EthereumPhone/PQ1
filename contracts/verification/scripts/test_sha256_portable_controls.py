#!/usr/bin/env python3
"""Require typed changes to the actual word kernel to break unchanged proofs.

Default controls mutate extracted definitions and run in CI without Charon.
--source-controls also mutates original Rust, re-extracts with Charon/Aeneas,
typechecks the generated definitions, and requires the same proof rejection or
kernel-checked counterexample.
Every fixture uses fresh namespaces; no theorem about the original function can
prove the changed one. Resource failures and setup errors are not rejections.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile

from check_sha256_portable_source import ROOT, MODEL, VENDOR, check
from check_axiom_closure import KERNEL, parse_dump_records
from test_c10_functional_signer_controls import run_lean, require_intended

PROOFS = ROOT / "contracts/verification/extracted/Extracted/Sha256Portable"
# name, extracted before/after/count, Rust file/before/after, first rejecting lemma
CHANGES = [
    ("round-rotation", " 6#u32)", " 7#u32)", 2, "src/sha256/soft.rs",
     "$a.rotate_right(6)", "$a.rotate_right(7)", "round2_impl"),
    ("schedule-rotation", " 17#u32)", " 18#u32)", 4, "src/sha256/soft.rs",
     "$a.rotate_right(17)", "$a.rotate_right(18)", "msg2_eq"),
    ("constant", "1116352408#u32", "1116352409#u32", 1, "src/consts.rs",
     "0x428a2f98,", "0x428a2f99,", "constants_eq"),
    ("word-order", "let i8 ← Array.index_usize block 3#usize",
     "let i8 ← Array.index_usize block 2#usize", 1, "src/sha256/soft.rs",
     "[block[3], block[2], block[1], block[0]]",
     "[block[2], block[2], block[1], block[0]]", "compression_packed"),
    ("omitted-rounds", "let abef15 ← soft.sha256_digest_round_x2 abef14 cdgh15 t215",
     "let abef15 := abef14", 1, "src/sha256/soft.rs",
     "    schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);",
     "    // Negative control: final four rounds omitted.", "compression_packed"),
    ("feed-forward", "core.num.U32.wrapping_add i37 h)",
     "core.num.U32.wrapping_add i37 g)", 1, "src/sha256/soft.rs",
     "state[7].wrapping_add(h)", "state[7].wrapping_add(g)", "compression_packed"),
]


def replace_exact(text: str, before: str, after: str, count: int = 1) -> str:
    if text.count(before) != count:
        raise RuntimeError(f"mutation target count changed: {before!r}")
    return text.replace(before, after)


def fixture(funs: str, theorem: str | None = None, typed: bool = False) -> str:
    parts = [funs]
    if not typed:
        parts += [(PROOFS / (name + ".lean")).read_text()
                  for name in ["Core", "Schedule", "Model", "Compression"]]
    body = "\n".join(re.sub(r"(?m)^import .*\n", "", part) for part in parts)
    body = body.replace("sha256_portable", "sha256_portable_control")
    body = body.replace("Sha256Portable", "Sha256PortableControl")
    if theorem:
        start = body.index("theorem " + theorem + " ")
        # Stop at the next declaration so errors in dependent proofs cannot mask
        # the intended first failure or introduce admitted downstream evidence.
        next_decl = re.search(r"\n(?:theorem|def|end) ", body[start + 1:])
        if next_decl is None:
            raise RuntimeError("cannot delimit control theorem")
        body = body[:start + 1 + next_decl.start()]
        # A documentation comment immediately preceding the next declaration
        # must leave with that declaration, not attach to the closing `end`.
        body = re.sub(r"\n/--(?:(?!/--).)*?-/\s*$", "", body, flags=re.S)
        body += "\nend Sha256PortableControl\n"
    return "import Extracted.Sha256Vendored\nimport Aeneas\n" + body


def case_fixture(funs: str, expected: bool = True) -> str:
    # A concrete instance of compression_spec. Kernel reduction (+kernel),
    # never native_decide, checks both the positive and inequivalence witnesses.
    body = fixture(funs, typed=True)
    return body + """
open Aeneas Aeneas.Std Result
set_option maxRecDepth 65536
set_option maxHeartbeats 4000000
def compression_case_result : Bool :=
  match sha256_portable_control.soft.sha256_digest_block_u32
    (Std.Array.make 8#usize [0#u32,1#u32,2#u32,3#u32,4#u32,5#u32,6#u32,7#u32])
    (Std.Array.make 16#usize [8#u32,9#u32,10#u32,11#u32,12#u32,13#u32,14#u32,15#u32,
      16#u32,17#u32,18#u32,19#u32,20#u32,21#u32,22#u32,23#u32]) with
  | .ok out => (out.val.map (fun x => x.bv)).toArray ==
      SphincsCVerify.Spec.Sha256Impl.compress #[0,1,2,3,4,5,6,7]
        #[8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]
  | _ => false
theorem compression_case : compression_case_result = """ + str(expected).lower() + """ := by
  decide +kernel
#print axioms compression_case
"""


def require_case_proof(result, label: str) -> None:
    if result.returncode:
        raise RuntimeError(label + ": kernel witness failed\n" + result.stdout + result.stderr)
    records = parse_dump_records(result.stdout + result.stderr)
    if set(records) != {"compression_case"} or not records["compression_case"] <= KERNEL:
        raise RuntimeError(label + ": unexpected witness axiom closure")


def check_one(run, label: str, funs: str, theorem: str) -> None:
    typed = run(label + "_typed", fixture(funs, typed=True))
    if typed.returncode:
        raise RuntimeError(label + ": changed definition did not typecheck\n" + typed.stdout + typed.stderr)
    concrete = label.removeprefix("source_") in {"word-order", "omitted-rounds", "feed-forward"}
    # Bad word/feed-forward bindings make elaboration of the universal proof
    # expand huge round terms. Use a kernel-checked counterexample instead of
    # counting those resource failures as semantic rejection.
    if concrete:
        require_case_proof(run(label + "_counterexample", case_fixture(funs, False)), label)
        print("PASS portable word compression kernel counterexample: " + label, flush=True)
        return
    text = fixture(funs, theorem)
    result = run(label + "_reject", text)
    require_intended(result, text, theorem, label)
    print("PASS portable word compression typed rejection: " + label + " at " + theorem, flush=True)


def check_controls(run) -> None:
    funs = (PROOFS / "Funs.lean").read_text()
    for label, body in [("positive", funs), ("preserving", funs.replace(" 6#u32)", " (6#u32))"))]:
        result = run(label, fixture(body))
        if result.returncode:
            raise RuntimeError(label + " failed\n" + result.stdout + result.stderr)
        print("PASS portable word compression: " + label, flush=True)
    require_case_proof(run("positive_case", case_fixture(funs)), "positive_case")

    def negative(row):
        label, before, after, count, *_, theorem = row
        check_one(run, label, replace_exact(funs, before, after, count), theorem)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative, CHANGES))


def source_controls(run, directory: Path) -> None:
    errors = check()
    if errors:
        raise RuntimeError("; ".join(errors))
    tools = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/pqsigner-lean"
    for label, _, _, _, source, before, after, theorem in CHANGES:
        work = directory / ("source-" + label)
        model = work / MODEL
        shutil.copytree(ROOT / MODEL, model)
        path = work / VENDOR / source
        path.write_text(replace_exact(path.read_text(), before, after))
        llbc = work / "sha256portable.llbc"
        generated = work / "generated"
        generated.mkdir()
        commands = [
            [str(tools / "charon"), "rustc", "--preset=aeneas", "--abort-on-error",
             "--rustc-arg=-Cdebug-assertions=off", "--rustc-arg=-Coverflow-checks=on",
             "--start-from", "sha256_portable::soft::sha256_digest_block_u32",
             "--dest-file", str(llbc), "--", "--edition=2021", "--crate-type=lib",
             "--crate-name=sha256_portable", str(MODEL / "lib.rs"), "--out-dir", str(work)],
            [str(tools / "aeneas"), "-backend", "lean", "-split-files", "-abort-on-error",
             "-dest", str(generated), str(llbc)],
        ]
        for stage, command in zip(["charon", "aeneas"], commands, strict=True):
            result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
            (work / (stage + ".log")).write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(label + ": " + stage + " failed")
            if stage == "charon" and json.loads(llbc.read_text()).get("has_errors") is not False:
                raise RuntimeError(label + ": Charon reported extraction errors")
        if sorted(p.name for p in generated.iterdir()) != ["Funs.lean", "Types.lean"]:
            raise RuntimeError(label + ": unexpected generated inventory")
        # Types is an empty namespace; check it explicitly before using Funs.
        typed = run("source_" + label + "_types", fixture((generated / "Types.lean").read_text(), typed=True))
        if typed.returncode:
            raise RuntimeError(label + ": generated types failed")
        check_one(run, "source_" + label, (generated / "Funs.lean").read_text(), theorem)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-controls", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pq-sha256-controls-") as tmp:
        directory = Path(tmp)

        def run(name, text):
            path = directory / (name + ".lean")
            path.write_text(text)
            return run_lean(path)

        check_controls(run)
        if args.source_controls:
            source_controls(run, directory)
    print("OK: portable compression positive/preserving and six typed semantic controls"
          + ("; six Rust source re-extractions rejected or kernel-refuted" if args.source_controls else ""))


if __name__ == "__main__":
    main()
