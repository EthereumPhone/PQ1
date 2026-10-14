#!/usr/bin/env python3
"""Execute literal-source/lifted-source comparisons and non-vacuity controls.

These are finite host corpora with scripted dependency responses, not a proof
of the lifting pass or of the physical backends. cfg(test) is forbidden by the
native executable so the production rate and sentinel guards are exercised.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
REL = Path("contracts/verification/tools/secure-wrapper-model")
MARKER = "PASS: 16384 guard combinations, 4008 mismatch positions, 32 sparse-entropy cases; production cfg; native/lifted result and effect equality"
MUTATIONS = [
    ("rate-readback", "secure/src/crypto.rs", "!= signs_before.wrapping_add(1)", "== signs_before.wrapping_add(1)", 2),
    ("comparison", "secure/src/crypto.rs", "if !bool::from(sig_a[..].ct_eq(&sig_b[..]))", "if bool::from(sig_a[..].ct_eq(&sig_b[..]))", 1),
    ("verification", "secure/src/crypto.rs", "check_true_into_sentinel(|| core::hint::black_box(v)) !=", "check_true_into_sentinel(|| core::hint::black_box(v)) ==", 1),
    ("cfi", "secure/src/crypto.rs", "check_into_sentinel(CFI_EXPECTED) !=", "check_into_sentinel(CFI_EXPECTED) ==", 1),
    ("delay-source", "secure/src/crypto.rs", "if crate::fi::delay_source_failed() {", "if !crate::fi::delay_source_failed() {", 1),
    ("relock", str(REL / "src/lib.rs"), "super::event(e,14);", "let _ = e;", 1),
]


def compile_and_run(root, target, features=(), release=True):
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), RUSTFLAGS="",
               CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS="false",
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS="true")
    command = ["cargo", "build", "--locked", "--package", "secure-wrapper-check"]
    if release:
        command += ["--release"]
    if features:
        command += ["--features", ",".join(features)]
    build = subprocess.run(command, cwd=root / REL, env=env, capture_output=True, text=True, timeout=90)
    assert build.returncode == 0, ("source must compile before execution", build.stdout, build.stderr)
    binary = target / ("release" if release else "debug") / "secure-wrapper-check"
    return subprocess.run([str(binary)], cwd=root, env=env, capture_output=True, text=True, timeout=30)


def main():
    with tempfile.TemporaryDirectory(prefix="secure-wrapper-source-") as name:
        scratch = Path(name)
        materialized = subprocess.run(
            [sys.executable, str(ROOT / "contracts/verification/scripts/materialize_secure_wrapper.py"), str(scratch / "materialized")],
            cwd=ROOT, capture_output=True, text=True, timeout=90)
        assert materialized.returncode == 0, (materialized.stdout, materialized.stderr)
        assert materialized.stdout.count("MATERIALIZED: literal and lifted production-cfg wrapper;") == 1
        # Both profiles preserve not(test); enabling the forced feature here is
        # compile coverage only, not proof of its receipt-validation semantics.
        for release, features in [(False, ()), (True, ()), (True, ("erc7730-forced-blind",))]:
            result = compile_and_run(ROOT, scratch / "positive-target", features, release)
            assert result.returncode == 0 and result.stdout.splitlines() == [MARKER], (result.stdout, result.stderr)
            print(f"PASS native/lifted corpus: release={release}, features={features}", flush=True)
        for label, relative, before, after, count in MUTATIONS:
            tree = scratch / label
            (tree / "secure/src").mkdir(parents=True)
            shutil.copyfile(ROOT / "secure/src/crypto.rs", tree / "secure/src/crypto.rs")
            shutil.copytree(ROOT / REL, tree / REL, ignore=shutil.ignore_patterns("target"))
            source = tree / relative
            text = source.read_text()
            assert text.count(before) == count, (label, "mutation anchor drift")
            source.write_text(text.replace(before, after))
            result = compile_and_run(tree, tree / "target")
            assert result.returncode == 101, (label, "missing ordinary Rust assertion failure", result.returncode, result.stderr)
            assert "assertion `left == right` failed" in result.stderr
            assert any(reason in result.stderr for reason in ["wrong independent release outcome", "wrong relock classification"]), (label, result.stderr)
            print(f"PASS source control: {label} compiled and failed the independent outcome oracle", flush=True)
    print("OK: 3 production-cfg corpus builds and 6 compiled semantic source controls")


if __name__ == "__main__":
    main()
