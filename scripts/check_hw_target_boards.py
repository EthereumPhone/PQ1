#!/usr/bin/env python3
"""Every Makefile recipe that builds an stm32u585 image must name a board.

WHY (#706): `secure/src/board/mod.rs` hard-errors when an `stm32u585` build
names neither `board-iota2` nor `board-pq1`. Recipes that derive their feature
list from `$(FEATURES)` get `$(BOARD_FEATURE)` for free; recipes with a
HARDCODED `--features` list must append it themselves, and six did not. They
therefore compiled for *neither* board — `saes-self-test-hw` among them, which
is how the dead SHSI/DHUK path went unnoticed for months. A target that does
not build is a subsystem nobody is testing, and nothing failed loudly enough to
say so.

The board-implying feature set is DERIVED from `secure/Cargo.toml`, not
hardcoded here: any feature whose transitive closure reaches `stm32u585`
requires a board. So a new feature that implies `stm32u585` is covered the day
it is added, without anyone remembering to update this script.

Usage:  scripts/check_hw_target_boards.py [--makefile PATH] [--manifest PATH]
Exit:   0 clean, 1 violations found, 2 could not parse.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# A recipe line that builds the secure crate with an explicit feature list.
FEATURES_RE = re.compile(r"--features\s+(?P<quote>[\"']?)(?P<list>[^\"'\\\n]+)(?P=quote)")
BOARD_TOKENS = ("$(BOARD_FEATURE)", "board-iota2", "board-pq1")


def parse_feature_graph(manifest: Path) -> dict[str, list[str]]:
    """`[features]` as {feature: [implied, ...]}, ignoring `dep/feature` entries."""
    text = manifest.read_text()
    section = re.search(r"^\[features\]\s*$(.*?)(?=^\[)", text, re.S | re.M)
    if not section:
        raise SystemExit("could not find [features] in " + str(manifest))
    graph: dict[str, list[str]] = {}
    # Entries may span lines: `name = ["a", "b",\n  "c"]`
    for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=\s*\[(.*?)\]", section.group(1), re.S | re.M):
        name, body = m.group(1), m.group(2)
        implied = [
            v for v in re.findall(r"\"([^\"]+)\"", body)
            if "/" not in v  # `dep/feature` cannot imply one of OUR features
        ]
        graph[name] = implied
    return graph


def features_requiring_board(graph: dict[str, list[str]], root: str = "stm32u585") -> set[str]:
    """Features whose transitive closure reaches `root`."""
    required = set()
    for feature in graph:
        seen, stack = set(), [feature]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur == root:
                required.add(feature)
                break
            stack.extend(graph.get(cur, ()))
    return required


def current_target(lines: list[str], idx: int) -> str:
    """Nearest preceding `target:` line — for naming the offender usefully."""
    for i in range(idx, -1, -1):
        m = re.match(r"^([A-Za-z0-9._%-]+):", lines[i])
        if m:
            return m.group(1)
    return "<unknown target>"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--makefile", default=str(REPO / "Makefile"))
    ap.add_argument("--manifest", default=str(REPO / "secure" / "Cargo.toml"))
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    graph = parse_feature_graph(Path(args.manifest))
    need_board = features_requiring_board(graph)
    if "stm32u585" not in need_board:
        print("!! stm32u585 not found in the feature graph — refusing to pass vacuously",
              file=sys.stderr)
        return 2
    if args.verbose:
        print(f"features implying stm32u585: {len(need_board)}")

    lines = Path(args.makefile).read_text().splitlines()
    violations = []
    for idx, line in enumerate(lines):
        for m in FEATURES_RE.finditer(line):
            flist = m.group("list")
            # `$(FEATURES)`-derived recipes get the board appended for them.
            if "$(FEATURES)" in flist or "_FEATURES)" in flist:
                continue
            if any(tok in flist for tok in BOARD_TOKENS):
                continue
            named = {f.strip() for f in flist.split(",") if f.strip()}
            hits = sorted(named & need_board)
            if hits:
                violations.append((current_target(lines, idx), idx + 1, hits, flist.strip()))

    if not violations:
        print("OK — every hardcoded stm32u585 feature list names a board")
        return 0

    print(f"!! {len(violations)} recipe(s) build an stm32u585 image without naming a board:\n")
    for target, lineno, hits, flist in violations:
        print(f"  {target}  (Makefile:{lineno})")
        print(f"    implies stm32u585 via: {', '.join(hits)}")
        print(f"    features: {flist}")
        print("    fix: append $(BOARD_FEATURE) to the --features list\n")
    print("These do not compile for EITHER board, so whatever they test is untested.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
