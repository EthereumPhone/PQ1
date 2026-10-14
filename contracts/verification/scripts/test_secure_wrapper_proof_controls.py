#!/usr/bin/env python3
"""Type-correct wrapper mutations must break unchanged release/refusal proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import signal
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, require_semantic_rejection

ROOT = Path(__file__).resolve().parents[1] / "extracted"
MODEL = ROOT / "Extracted/SecureWrapper"
FAMILIES = {
    "release": ("SecureWrapperSpec.lean", [
        ("second-message", "msg_hash (some opt_rand_buf1) shuffle_seed_b1 ()",
         "sk.sk_seed (some opt_rand_buf1) shuffle_seed_b1 ()"),
        ("second-randomizer", "msg_hash (some opt_rand_buf1) shuffle_seed_b1 ()",
         "msg_hash none shuffle_seed_b1 ()"),
        ("compare-gate", "if b4\n", "if true\n"),
        ("verify-message", "sphincs_c10.verify effects19 a a1 msg_hash sig_a",
         "sphincs_c10.verify effects19 a a1 sk.sk_seed sig_a"),
        ("verify-result", "effects20 v", "effects20 true"),
        ("cfi-gate", "if i3 != fi.OK_SENTINEL", "if false"),
        ("released-bytes", "ok (core.result.Result.Ok sig_a, effects26)",
         "ok (core.result.Result.Ok (Array.repeat 4008#usize 0#u8), effects26)"),
        ("success-barrier", "let effects26 ← fi.zeroize_barrier effects25\n                        ok (core.result.Result.Ok",
         "let effects26 ← ok effects25\n                        ok (core.result.Result.Ok"),
        ("delay-gate", "if b5\n", "if false\n"),
        ("delay-observation", "let (b5, effects24) ← fi.delay_source_failed effects23",
         "let (b5, effects24) ← ok (false, effects23)"),
    ]),
    "refusal": ("SecureWrapperRefusal.lean", [
        ("mismatch-relock", "let effects18 ← nsc.zeroize_sensitive_state effects17",
         "let effects18 ← ok effects17"),
        ("verify-relock", "let effects22 ← nsc.zeroize_sensitive_state effects21",
         "let effects22 ← ok effects21"),
        ("cfi-relock", "let effects24 ← nsc.zeroize_sensitive_state effects23",
         "let effects24 ← ok effects23"),
        ("entropy-barrier", "let effects6 ← fi.zeroize_barrier effects5",
         "let effects6 ← ok effects5"),
        ("delay-refusal-barrier", "let effects26 ← fi.zeroize_barrier effects25\n                        ok (core.result.Result.Err",
         "let effects26 ← ok effects25\n                        ok (core.result.Result.Err"),
        ("delay-refusal-relock", "if b5\n                      then\n",
         "if b5\n                      then\n                        let effects24 ← nsc.zeroize_sensitive_state effects24\n"),
    ]),
}


def declaration(before=None, after=None):
    types = (MODEL / "Types.lean").read_text()
    types = types[types.index('/-- [secure_wrapper_model::production::VerifiedRateCharge]'):]
    types = types.rsplit("end secure_wrapper_model", 1)[0]
    body = (MODEL / "Funs.lean").read_text()
    body = body[body.index('/-- [secure_wrapper_model::production::CFI_STEP_RATE_LIMIT]'):]
    body = body.rsplit("end secure_wrapper_model", 1)[0]
    if before is not None:
        assert body.count(before) >= 1, (before, "missing mutation anchor")
        # The two OptRand entropy refusals deliberately share the same barrier
        # expression. Mutate both; every other anchor is unique.
        assert body.count(before) == (2 if before == "let effects6 ← fi.zeroize_barrier effects5" else 1)
        body = body.replace(before, after)
    return ("namespace secure_wrapper_model\nopen Aeneas Aeneas.Std Result ControlFlow Error\n" + types + body + "\nend secure_wrapper_model\n").replace(
        "production.", "production_probe.")


def fixture(family, before=None, after=None, proof=True):
    name, _ = FAMILIES[family]
    source = (ROOT / "Extracted" / name).read_text()
    if not proof:
        return "import Extracted.SecureWrapper.Funs\nopen Aeneas Aeneas.Std Result\nnoncomputable section\n" + declaration(before, after)
    source = source.replace("production.", "production_probe.")
    where = source.index("namespace secure_wrapper_model")
    source = source[:where] + "noncomputable section\n" + declaration(before, after) + source[where:]
    assert "sorry" not in source and "axiom " not in source
    return source


def run(source):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".lean", prefix="secure-wrapper-control-") as f:
        f.write(source)
        f.flush()
        command = [str(LAKE), "env", "lean", f.name]
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def check(job):
    family, name, before, after = job
    typed = run(fixture(family, before, after, proof=False))
    assert typed.returncode == 0, (name, "mutation failed to typecheck", typed.stdout, typed.stderr)
    result = run(fixture(family, before, after))
    require_semantic_rejection(result, name)
    print(f"PASS {family}/{name}: typed mutation rejected by unchanged proof", flush=True)


def main():
    for family in FAMILIES:
        baseline = run(fixture(family))
        assert baseline.returncode == 0, (family, "clean fixture failed", baseline.stdout, baseline.stderr)
        print(f"PASS {family}: unchanged fixture", flush=True)
    jobs = [(family, *mutation) for family, (_, mutations) in FAMILIES.items() for mutation in mutations]
    with ThreadPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as pool:
        list(pool.map(check, jobs))
    print(f"OK: {len(jobs)} typed wrapper controls; no resource exit accepted as proof evidence")


if __name__ == "__main__":
    main()
