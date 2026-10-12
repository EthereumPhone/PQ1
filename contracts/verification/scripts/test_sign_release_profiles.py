#!/usr/bin/env python3
"""Execute the real software signer in both assertion and callback cfg shapes."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[3]

def main():
    profile = tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]["release"]
    assert not profile.get("debug-assertions", False)
    assert profile["overflow-checks"] is True
    for override in profile.get("package", {}).values():
        assert "debug-assertions" not in override and "overflow-checks" not in override
    receipts = {}
    with tempfile.TemporaryDirectory(prefix="sign-release-profiles-") as td:
        for checked in (True, False):
            for extracted in (False, True):
                label = f"assertions-{checked}-extraction-{extracted}"
                env = os.environ.copy()
                env.update(CARGO_TARGET_DIR=td,
                           CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=str(checked).lower(),
                           CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS="true",
                           RUSTFLAGS="--cfg lean_extract" if extracted else "")
                result = subprocess.run(
                    ["cargo", "test", "-p", "sphincs-c10", "--release", "--test",
                     "release_sign_assertions", "--", "--nocapture"],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=240)
                assert result.returncode == 0, (label, result.stdout, result.stderr)
                rows = re.findall(r"^(VALID|WRONG_ROOT) (true|false) ([0-9a-f]+)$",
                                  result.stdout, re.M)
                expected = {(kind, mode) for kind in (["VALID"] if checked else ["VALID", "WRONG_ROOT"])
                            for mode in ("true", "false")}
                actual = {(kind, mode): sig for kind, mode, sig in rows}
                assert len(rows) == len(actual) and set(actual) == expected, (label, rows)
                assert all(len(sig) == 8016 for sig in actual.values()), label
                receipts[checked, extracted] = actual
                print(f"PASS {label}: both OptRand modes; valid, changed-message and wrong-root outcomes", flush=True)
        reference = receipts[True, False]
        for actual in receipts.values():
            assert {key: actual[key] for key in reference} == reference
        assert receipts[False, False] == receipts[False, True]
    print("OK: all 4008 bytes agree across four signer build configurations; release wrong-root results fail verification")

if __name__ == "__main__":
    main()
