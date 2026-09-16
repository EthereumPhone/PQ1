#!/usr/bin/env python3
"""Exact source and elaborated axiom inventory (F1/#676, F4/#675).

Source pins deliberately bind whole axiom-bearing modules, including namespace,
modifiers, type context and multiplicity. This is stricter and simpler than a
home-grown declaration parser. The census counts every raw substring "axiom",
including prose, strings and #print axioms; all matching modules are pinned.
All source paths, including the root and unbuilt heavy modules, are scanned.
An intentional edit to a pinned module requires a
reviewed re-pin. There is no automatic update mode.

The elaborated inventory pins every axiom present in the default root environment
(including dependency declarations), not merely those used by headline proofs.
Presence of a dependency's sorryAx here is NOT permission to use it: existing
per-theorem closure gates remain mandatory. This is not an independent kernel.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

from lean_source import keyword_count

SCRIPTS = Path(__file__).resolve().parent
PROJECTS = {"lean": "SphincsCVerify", "extracted": "Extracted"}
QUARANTINE = "Extracted/AxiomCheckNegativeControl.lean"


def source_inventory(project: Path, root: str) -> dict:
    rootfile = project / f"{root}.lean"
    if not rootfile.is_file() or not (project / root).is_dir() or (project / root).is_symlink():
        raise ValueError(f"missing Lean project root: {root}")
    paths = [rootfile]
    for directory, dirs, files in os.walk(project / root):
        for name in dirs + files:
            if (Path(directory) / name).is_symlink():
                raise ValueError(f"symlink in Lean source tree: {directory}/{name}")
        paths.extend(Path(directory) / name for name in files if name.endswith(".lean"))
    inventory = {}
    for path in sorted(paths):
        if path.is_symlink():
            raise ValueError(f"symlink in Lean source tree: {path}")
        data = path.read_bytes()
        source = data.decode("utf-8")
        rel = path.relative_to(project).as_posix()
        # The component must occur literally even in quoted/multi-module imports.
        # Reject prose references too rather than interpreting extensible syntax.
        if rel != QUARANTINE and "AxiomCheckNegativeControl" in source:
            raise ValueError(f"quarantine reference in {rel}")
        count = keyword_count(source, "axiom")
        if count:
            inventory[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "axiom_mentions": count}
    return inventory


def elaborated_inventory(rows: list) -> list:
    seen = set()
    out = []
    for row in rows:
        if set(row) != {"name", "module", "type", "levels", "unsafe"} or row["name"] in seen:
            raise ValueError("malformed/duplicate elaborated axiom row")
        seen.add(row["name"])
        entry = {k: v for k, v in row.items() if k != "type"}
        entry["type_sha256"] = hashlib.sha256(row["type"].encode()).hexdigest()
        out.append(entry)
    if not out:
        raise ValueError("empty elaborated inventory")
    return sorted(out, key=lambda row: row["name"])


def compare(expected, actual, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label} inventory drift\nexpected: {json.dumps(expected, sort_keys=True)}"
                         f"\nactual: {json.dumps(actual, sort_keys=True)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=PROJECTS)
    args = parser.parse_args()
    try:
        root = PROJECTS[args.project]
        project = SCRIPTS.parent / args.project
        expected = json.loads((SCRIPTS / f"axiom_inventory_{args.project}.json").read_text())
        if set(expected) != {"source", "elaborated"}:
            raise ValueError("invalid inventory manifest schema")
        compare(expected["source"], source_inventory(project, root), "source")
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        lake = home / ".elan/bin/lake"
        env = dict(os.environ, HOME=str(home), ELAN_HOME=str(home / ".elan"))
        for name in ("ELAN_TOOLCHAIN", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
            env.pop(name, None)
        # Rebuild before reading oleans, including standalone invocations.
        subprocess.run([str(lake), "build"], cwd=project, env=env, check=True, timeout=1800)
        run = subprocess.run([
            str(lake), "env", "lean", "--run", str(SCRIPTS / "dump_axiom_inventory.lean"), root,
        ], cwd=project, env=env, check=True, capture_output=True, text=True, timeout=120)
        compare(expected["elaborated"], elaborated_inventory(json.loads(run.stdout)), "elaborated")
        print(f"PASS: {root} exact axiom inventory ({len(expected['source'])} source modules, "
              f"{len(expected['elaborated'])} environment axioms including dependencies)")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"AXIOM INVENTORY FAILURE: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
