#!/usr/bin/env python3
"""Every `#[test]` in the repo must actually execute in some CI suite.

WHY (#708): `secure/src/nsc/prodtest.rs` ends in a `#[cfg(test)] mod tests`
that sits inside a file-level `#![cfg(feature = "prodtest")]`. `prodtest`
pulls in `stm32u585`, which does not build for the host, so the whole module
is silently skipped by the host test run. Eight tests had never executed. One
of them asserted `PRODTEST_FW_VERSION == 3` while the constant had already
moved to 5 — it would have failed on sight, for two releases running.

Nothing caught it, because the signal everyone reads is an aggregate pass
count: `2624 passed; 0 failed` looks identical whether a test ran and passed
or was never compiled in. A test that cannot run is worse than no test — it
is an assertion the reader believes is enforced.

WHAT THIS CHECKS. Declared-vs-executed, by name:

  declared  = every `#[test]` fn in the tracked sources
  runnable  = every test `cargo test ... -- --list` reports for the suites
              CI actually runs
  violation = declared and not runnable and not allowlisted

The static alternative — grepping for `#[cfg(test)]` nested inside a
file-level `#![cfg(...)]` — catches only the shape that happened to bite us.
This oracle also catches `#[ignore]`, `cfg(target_arch)`, a module that was
never `mod`-declared, a `#[test]` inside a `#[cfg(feature)]` block mid-file,
and whatever the next variant turns out to be. It is the same check that
found #708 by hand: extract the names, grep the run output for each.

SUITES ARE DERIVED FROM `.github/workflows/ci.yml`, not restated here. A
hardcoded list is a second source of truth that drifts the first time someone
edits CI — and it would drift *silently*, in the safe-looking direction, by
claiming coverage that CI no longer provides. Deriving them means adding a CI
test step extends this gate for free, and deleting one surfaces immediately
as a pile of newly-unreachable tests.

FAILS IN BOTH DIRECTIONS. A declared test that never runs is a violation; so
is an allowlist entry whose test no longer exists, or which now runs after
all. A one-way inventory guard lets a deleted item hide (see the repo's
`inventory_guards_count_unique` lesson), and a stale exemption is how a real
regression gets pre-approved.

Usage:  scripts/check_tests_actually_run.py [--list-only] [--json OUT]
Exit:   0 clean, 1 violations, 2 could not run the oracle.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"
ALLOWLIST = REPO / "scripts" / "tests_never_run_allowlist.json"

# Below this, assume the extraction broke rather than that the repo shrank.
# A regex that matches nothing otherwise passes this gate green.
MIN_DECLARED = 3000
MIN_RUNNABLE = 3000

TEST_ATTR = re.compile(r"^\s*#\[test\]\s*$")
FN_NAME = re.compile(r"\bfn\s+([A-Za-z0-9_]+)")
# `#[cfg(...)]`/`#[should_panic]`/doc comments may sit between the attribute
# and the fn, so scan a few lines forward rather than requiring adjacency.
FN_LOOKAHEAD = 6


def ci_test_commands() -> list[tuple[str, list[str]]]:
    """Every `cargo test ...` CI runs, as (cwd, argv) with continuations joined."""
    text = CI.read_text()
    # Join shell line-continuations so a multi-line `-p a \ -p b` is one command.
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    out: list[tuple[str, list[str]]] = []
    for line in joined.splitlines():
        if "cargo test" not in line:
            continue
        stripped = line.strip()
        # Skip YAML keys and comments that merely mention the phrase.
        if stripped.startswith("#") or stripped.startswith("- name:"):
            continue
        cwd = "."
        cd_match = re.match(r"^(?:run:\s*)?cd\s+([^\s&]+)\s*&&\s*(.*)$", stripped)
        if cd_match:
            cwd, stripped = cd_match.group(1), cd_match.group(2)
        idx = stripped.find("cargo test")
        if idx < 0:
            continue
        argv = stripped[idx:].split()
        # `--locked` fights a lockfile another worktree may be editing, and
        # says nothing about which tests exist.
        argv = [a for a in argv if a != "--locked"]
        out.append((cwd, argv))
    return out


def list_tests(cwd: str, argv: list[str]) -> tuple[set[str], str]:
    """Names `cargo test -- --list` reports. Returns (bare fn names, error)."""
    env = {k: v for k, v in os.environ.items() if k != "RUSTFLAGS"}
    # Firmware linker flags in RUSTFLAGS break host build scripts; that run
    # would be void rather than merely failing.
    cmd = list(argv) + (["--"] if "--" not in argv else []) + ["--list"]
    proc = subprocess.run(
        cmd, cwd=REPO / cwd, env=env, capture_output=True, text=True, check=False
    )
    names = {
        line[: -len(": test")].split("::")[-1]
        for line in proc.stdout.splitlines()
        if line.endswith(": test")
    }
    if proc.returncode != 0 and not names:
        return names, (proc.stderr.strip().splitlines() or ["(no stderr)"])[-1]
    return names, ""


def declared_tests() -> list[tuple[str, str]]:
    """Every `#[test]` fn in tracked sources, as (path, fn name)."""
    files = subprocess.run(
        ["git", "ls-files", "*.rs"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.split()
    found: list[tuple[str, str]] = []
    for rel in files:
        try:
            lines = (REPO / rel).read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines):
            if not TEST_ATTR.match(line):
                continue
            for j in range(i + 1, min(i + 1 + FN_LOOKAHEAD, len(lines))):
                m = FN_NAME.search(lines[j])
                if m:
                    found.append((rel, m.group(1)))
                    break
    return found


def load_allowlist() -> dict[str, dict]:
    if not ALLOWLIST.exists():
        return {}
    raw = json.loads(ALLOWLIST.read_text())
    entries = {}
    for e in raw.get("exempt", []):
        entries[f"{e['file']}::{e['test']}"] = e
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list-only", action="store_true", help="print findings, exit 0")
    ap.add_argument("--json", help="write the full result to this path")
    args = ap.parse_args()

    commands = ci_test_commands()
    if not commands:
        print("!! parsed no `cargo test` commands out of ci.yml — refusing to pass "
              "vacuously", file=sys.stderr)
        return 2
    print(f"== {len(commands)} cargo-test suite(s) derived from ci.yml")

    runnable: set[str] = set()
    for cwd, argv in commands:
        names, err = list_tests(cwd, argv)
        label = " ".join(argv[:6]) + (" ..." if len(argv) > 6 else "")
        if err:
            print(f"!! could not list tests for `{label}` (cwd={cwd}): {err}",
                  file=sys.stderr)
            return 2
        print(f"   {len(names):>5} tests  {label}")
        runnable |= names

    declared = declared_tests()
    print(f"\n== declared #[test] fns: {len(declared)}")
    print(f"== distinct runnable names: {len(runnable)}")

    if len(declared) < MIN_DECLARED or len(runnable) < MIN_RUNNABLE:
        print(f"!! extraction looks broken (declared={len(declared)} "
              f"runnable={len(runnable)}, floors {MIN_DECLARED}/{MIN_RUNNABLE}) — "
              "refusing to pass vacuously", file=sys.stderr)
        return 2

    allow = load_allowlist()
    violations, exempted_hits = [], set()
    for rel, name in declared:
        if name in runnable:
            continue
        key = f"{rel}::{name}"
        if key in allow:
            exempted_hits.add(key)
            continue
        violations.append((rel, name))

    # Direction two: exemptions that no longer describe reality.
    declared_keys = {f"{rel}::{name}" for rel, name in declared}
    stale = []
    for key, entry in allow.items():
        if key not in declared_keys:
            stale.append((key, "test no longer exists — drop the exemption"))
        elif key not in exempted_hits:
            stale.append((key, "test RUNS now — drop the exemption so it is gated"))

    if args.json:
        Path(args.json).write_text(json.dumps({
            "suites": len(commands), "declared": len(declared),
            "runnable": len(runnable),
            "violations": [{"file": f, "test": t} for f, t in violations],
            "stale_allowlist": [{"key": k, "why": w} for k, w in stale],
        }, indent=2) + "\n")

    if violations:
        by_file: dict[str, list[str]] = {}
        for rel, name in violations:
            by_file.setdefault(rel, []).append(name)
        print(f"\n!! {len(violations)} declared test(s) in {len(by_file)} file(s) "
              "never execute in any CI suite:\n")
        for rel in sorted(by_file):
            print(f"  {rel}  ({len(by_file[rel])})")
            for name in sorted(by_file[rel])[:10]:
                print(f"      {name}")
            if len(by_file[rel]) > 10:
                print(f"      ... and {len(by_file[rel]) - 10} more")
        print("\nEach is an assertion a reader believes is enforced and which is not.")
        print("Fix by moving the logic somewhere the host build reaches (see the")
        print("`*_under_test` modules for the established idiom), or add an entry to")
        print(f"{ALLOWLIST.relative_to(REPO)} with a reason that says why it cannot run.")

    if stale:
        print(f"\n!! {len(stale)} stale allowlist entr(ies):\n")
        for key, why in stale:
            print(f"  {key}\n      {why}")

    if args.list_only:
        return 0
    return 1 if (violations or stale) else 0


if __name__ == "__main__":
    sys.exit(main())
