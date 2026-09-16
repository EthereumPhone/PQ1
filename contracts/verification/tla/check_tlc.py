#!/usr/bin/env python3
"""Shared TLC acceptance gate: exact config inventory and completed outcomes.

The validated TLC build returns 0 for success and 12 for invariant violations.
Other statuses are tool errors, even if an expected banner was already printed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SUITES = {
    "page123": ("Page123Compaction", [
        ("sigsfirst_skip", None),
        ("sigslast_skip", "INV_SIGS_COMPACTION_LOCAL"),
        ("sigsfirst_mayvalid", "INV_SIGS_COMPACTION_LOCAL"),
        ("endtoend_sigsfirst_skip", "INV_SIGS_NO_ROLLBACK"),
        ("partial_erase_sigsfirst", "INV_SIGS_COMPACTION_LOCAL"),
        ("cnt_sigsfirst_skip", "INV_CNT_NO_ROLLBACK"),
    ]),
    "combined": ("CombinedBudget", [
        ("cb_onchain_cap", None), ("cb_margin_noreset", None),
        ("cb_margin_reset", "INV_MARGIN_BOUNDED"),
    ]),
    "pin": ("PinReconcileDirectional", [
        ("pin_benign_leads", None), ("pin_alive", "INV_ALIVE_NONVACUOUS"),
        ("pin_rollback_caught", None), ("pin_leg_bypass", "INV_NO_LEG_BYPASS"),
        ("pin_dir_nofalsewipe", None), ("pin_sym_falsewipe", "INV_NO_FALSE_WIPE"),
        ("pin_dir_residual", "INV_CATCHES_RESET"), ("pin_sym_catches", None),
    ]),
}
EXPECTED_CONFIGS = {f"{cfg}.cfg" for _, cases in SUITES.values() for cfg, _ in cases}


def check_pins(directory: Path) -> None:
    pins: dict[str, str] = {}
    for line in (directory / "cfg_pins.sha256").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_]+\.cfg)", line)
        if match is None:
            raise ValueError(f"malformed or noncanonical config pin: {line!r}")
        digest, name = match.groups()
        if name in pins:
            raise ValueError(f"duplicate config pin: {name}")
        pins[name] = digest
    actual = {p.name for p in directory.glob("*.cfg")}
    if pins.keys() != EXPECTED_CONFIGS or actual != EXPECTED_CONFIGS:
        raise ValueError("config paths must match the exact 17-config suite inventory")
    for name, digest in pins.items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"config hash drift or symlink: {name}")


def check_result(status: int, output: str, invariant: str | None) -> None:
    lines = output.splitlines()
    success = [line for line in lines if "No error has been found" in line]
    violations = [line for line in lines if "is violated" in line]
    errors = [line for line in lines if line.startswith("Error:")]
    finished = [line for line in lines if re.fullmatch(r"Finished in .+ at .+", line)]
    if len(finished) != 1 or not lines or lines[-1] != finished[0]:
        raise ValueError("TLC did not report exactly one final completion")
    if invariant is None:
        if status != 0 or len(success) != 1 or violations or errors:
            raise ValueError(f"expected completed success; process status {status}")
    else:
        expected = f"Error: Invariant {invariant} is violated."
        if (status != 12 or success or violations != [expected]
                or errors != [expected, "Error: The behavior up to this point is:"]):
            raise ValueError(f"expected only {invariant} violation with status 12; got {status}")


class GateTests(unittest.TestCase):
    def test_results(self):
        done = "Finished in 00s at 2026-09-14 00:00:00\n"
        good = "Model checking completed. No error has been found.\n" + done
        bad = ("Error: Invariant INV_TEST is violated.\n"
               "Error: The behavior up to this point is:\n" + done)
        check_result(0, good, None)
        check_result(12, bad, "INV_TEST")
        for status, output, inv in [
            (42, good, None), (42, bad, "INV_TEST"), (0, bad, "INV_TEST"),
            (12, bad, "INV_OTHER"), (0, good + bad, None),
            (12, good + bad, "INV_TEST"), (0, good + "Error: crash\n", None),
            (0, good.replace(done, ""), None), (12, bad + bad, "INV_TEST"),
        ]:
            with self.subTest(status=status, output=output, invariant=inv):
                with self.assertRaises(ValueError):
                    check_result(status, output, inv)

    def test_pins(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in EXPECTED_CONFIGS:
                (directory / name).write_bytes((HERE / name).read_bytes())
            manifest = (HERE / "cfg_pins.sha256").read_text()
            pinfile = directory / "cfg_pins.sha256"
            pinfile.write_text(manifest)
            check_pins(directory)
            rows = manifest.splitlines()
            for corrupt in [
                "\n".join([rows[0]] + rows[:-1]) + "\n",  # duplicate + omission, same count
                "\n".join(rows[:-1]) + "\n", manifest + rows[0] + "\n",
                manifest.replace("  ", "  ./", 1), manifest.replace("  ", "  ../", 1),
            ]:
                pinfile.write_text(corrupt)
                with self.assertRaises(ValueError):
                    check_pins(directory)
            pinfile.write_text(manifest)
            target = directory / "cb_onchain_cap.cfg"
            target.write_text(target.read_text().replace("INVARIANT INV_ONCHAIN_CAP", ""))
            with self.assertRaises(ValueError):
                check_pins(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=SUITES, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(GateTests))
        return int(not result.wasSuccessful())
    if args.suite is None:
        parser.error("suite is required")
    try:
        check_pins(HERE)
        jar = Path(os.environ.get("TLA2TOOLS", str(Path.home() / "tla2tools.jar")))
        if not jar.is_file():
            raise ValueError(f"tla2tools.jar missing: {jar}; set TLA2TOOLS")
        model, cases = SUITES[args.suite]
        failed = False
        # Keep TLC state/trace artifacts out of the source tree.
        with tempfile.TemporaryDirectory(prefix="pq-tlc-") as temp:
            for cfg, invariant in cases:
                run = subprocess.run([
                    "java", "-cp", str(jar.resolve()), "tlc2.TLC", "-config",
                    str(HERE / f"{cfg}.cfg"), "-deadlock", "-noGenerateSpecTE",
                    str(HERE / f"{model}.tla"),
                ], cwd=temp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, timeout=300)
                output = run.stdout
                try:
                    check_result(run.returncode, output, invariant)
                except ValueError as exc:
                    failed = True
                    print(f"  [FAIL] {cfg}: {exc}\n{output}", file=sys.stderr)
                else:
                    print(f"  [ok] {cfg}: {invariant or 'HOLD'} (exit {run.returncode})")
        print("=== MISMATCH ===" if failed else f"=== all {len(cases)} expected outcomes matched ===")
        return int(failed)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"TLC GATE FAILURE: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
