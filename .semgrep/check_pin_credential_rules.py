#!/usr/bin/env python3
"""Fixture test for the #855 semgrep rules (run by `make invariant-gates`).

The four rules in pqsigner-invariants.yml that police "no secure element is
shown a PIN" are path-scoped regexes. A regex that has quietly stopped
matching looks exactly like a clean tree, so each rule is fed the shapes it
exists to catch and must fire on every one of them.

Fixtures live in `.semgrep/fixtures/pin-credential/*.fixture`. Each starts
with a line `// VIRTUAL-PATH: <repo-relative path>`, because the rules are
scoped by path: the fixture is copied to that path inside a scratch tree and
semgrep is run there. A line that must be reported carries a trailing
`// MUST-FIRE: <rule-id>` (for a multi-line match, on the line the match
starts on). Every other line must NOT be reported: the `ok-*.fixture` files
hold the post-#855 shapes and must come back clean.

Exit 0 only when, for every fixture, the set of (rule, start line) reported
equals the set annotated. A rule that fires nowhere in the fixtures is also
an error: it would be untested.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CONFIG = HERE / "pqsigner-invariants.yml"
FIXTURES = HERE / "fixtures" / "pin-credential"
RULES = {
    "no-pin-named-value-to-secure-element-sink",
    "no-unkeyed-pin-derivation-in-se-path",
    "pin-credential-bytes-confined",
    "post-wipe-counter-reset-is-gated",
}
VPATH = re.compile(r"^// VIRTUAL-PATH: (\S+)\s*$")
MUST = re.compile(r"// MUST-FIRE: ([a-z0-9-]+)\s*$")


def main() -> int:
    semgrep = os.environ.get("SEMGREP", "semgrep")
    fixtures = sorted(FIXTURES.glob("*.fixture"))
    if not fixtures:
        print(f"FAIL: no fixtures in {FIXTURES}", file=sys.stderr)
        return 1

    expected: set[tuple[str, str, int]] = set()   # (virtual path, rule, line)
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        seen_paths: dict[str, str] = {}
        for fx in fixtures:
            lines = fx.read_text().splitlines()
            m = VPATH.match(lines[0]) if lines else None
            if not m:
                print(f"FAIL: {fx.name}: first line must be `// VIRTUAL-PATH: <path>`", file=sys.stderr)
                return 1
            vpath = m.group(1)
            if vpath in seen_paths:
                print(f"FAIL: {fx.name} and {seen_paths[vpath]} share the virtual path {vpath}", file=sys.stderr)
                return 1
            seen_paths[vpath] = fx.name
            dest = root / vpath
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fx, dest)
            for n, line in enumerate(lines, 1):
                mm = MUST.search(line)
                if mm:
                    if mm.group(1) not in RULES:
                        print(f"FAIL: {fx.name}:{n}: unknown rule `{mm.group(1)}`", file=sys.stderr)
                        return 1
                    expected.add((vpath, mm.group(1), n))

        proc = subprocess.run(
            [semgrep, "--config", str(CONFIG), "--severity", "ERROR", "--metrics", "off",
             "--quiet", "--json", "--no-git-ignore", "."],
            cwd=root, capture_output=True, text=True,
        )
        if proc.returncode not in (0, 1):
            print(f"FAIL: semgrep exited {proc.returncode}\n{proc.stderr[-2000:]}", file=sys.stderr)
            return 1
        try:
            results = json.loads(proc.stdout)["results"]
        except (json.JSONDecodeError, KeyError) as e:
            print(f"FAIL: could not parse semgrep output: {e}", file=sys.stderr)
            return 1

    actual: set[tuple[str, str, int]] = set()
    for r in results:
        rule = r["check_id"].rsplit(".", 1)[-1]
        if rule in RULES:
            actual.add((r["path"].lstrip("./"), rule, r["start"]["line"]))

    ok = True
    for miss in sorted(expected - actual):
        print(f"FAIL: rule did not fire: {miss[1]} at {seen_paths[miss[0]]}:{miss[2]} ({miss[0]})", file=sys.stderr)
        ok = False
    for extra in sorted(actual - expected):
        print(f"FAIL: unexpected finding: {extra[1]} at {seen_paths.get(extra[0], extra[0])}:{extra[2]}", file=sys.stderr)
        ok = False
    untested = RULES - {rule for (_, rule, _) in expected}
    for rule in sorted(untested):
        print(f"FAIL: rule `{rule}` has no MUST-FIRE fixture line", file=sys.stderr)
        ok = False
    if not ok:
        return 1
    print(f"check-pin-credential-rules: OK — {len(expected)} must-fire lines across "
          f"{len(fixtures)} fixtures, {len(RULES)} rules, no stray findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
