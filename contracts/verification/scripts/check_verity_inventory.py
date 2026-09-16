#!/usr/bin/env python3
"""Fresh Part B elaboration and exact Part A quarantine for Verity (#673).

The installed, pinned Lean compiler/stdlib and this gate are trusted. No Lake,
project cache, caller-selected toolchain, or imported Verity package is used.
The semantic boundary is exported declarations, including private/generated
ones; discarded anonymous examples are not claims exported by a module.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import resource
import subprocess
import tempfile

from check_verity_holes import VERITY, check

SCRIPTS = Path(__file__).resolve().parent
TOOLCHAIN = "leanprover/lean4:v4.22.0"
GITHASH = "ba2cbbf09d4978f416e0ebd1fceeebc2c4138c05"
MODULES = [f"PQSigner/Verifier/{name}.lean" for name in
           ("Params", "Address", "Hash", "Wots", "Merkle", "Fors", "Hypertree", "Top")]
QUARANTINE = [f"PQSigner/{name}.lean" for name in
              ("Common", "PQMultiOwnable", "PQSmartWalletFactory", "PQSmartWallet", "Theorems")]
ALLOWED = {"propext", "Classical.choice", "Quot.sound",
           "PQSigner.Verifier.Hash.sha256_size", "PQSigner.Verifier.Hash.sha256_deterministic"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(data):
    return json.loads(data, object_pairs_hook=unique)


def source_snapshot(directory: Path) -> dict[str, bytes]:
    """Account for every project Lean source; reject links and unlisted roots."""
    found = {}
    if directory.is_symlink():
        raise ValueError("symlinked Verity directory")
    def error(exc):
        raise exc
    for parent, dirs, names in os.walk(directory, onerror=error):
        # Lake outputs/packages are deliberately outside the compilation boundary.
        if Path(parent) == directory:
            dirs[:] = [d for d in dirs if d != ".lake"]
        for name in dirs + names:
            path = Path(parent) / name
            if path.is_symlink():
                raise ValueError(f"symlink in Verity source: {path}")
        for name in names:
            path = Path(parent) / name
            if path.suffix == ".lean":
                found[path.relative_to(directory).as_posix()] = path.read_bytes()
    expected = set(MODULES + QUARANTINE + ["lakefile.lean"])
    if set(found) != expected:
        raise ValueError(f"source coverage mismatch: missing {sorted(expected - found.keys())}; "
                         f"unlisted {sorted(found.keys() - expected)}")
    for name in ("lean-toolchain", "assurance_inventory.json"):
        path = directory / name
        if path.is_symlink():
            raise ValueError(f"symlinked census input: {name}")
        found[name] = path.read_bytes()
    return found


def run(command: list[str], directory: Path, env: dict[str, str]) -> bytes:
    # Bound execution and output independently. File-backed output avoids an
    # unbounded capture_output allocation for compiler diagnostics/expressions.
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU, (110, 110))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, cwd=directory, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=120, check=False, preexec_fn=limits)
        size = output.tell()
        if size > 8 * 1024 * 1024:
            raise ValueError("Lean census output exceeds 8 MiB")
        output.seek(0)
        data = output.read()
    if result.returncode:
        raise ValueError(f"Lean command {command[1:]} failed ({result.returncode}): {data.decode(errors='replace')[:4000]}")
    return data


def fresh_inventory(snapshot: dict[str, bytes]) -> dict:
    if snapshot["lean-toolchain"].decode().strip() != TOOLCHAIN:
        raise ValueError("Verity toolchain changed; review the census pin")
    # Do not resolve `lean` from PATH or honor ELAN_TOOLCHAIN/LEAN_PATH/LD_*.
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    lean = home / ".elan/toolchains/leanprover--lean4---v4.22.0/bin/lean"
    collector = (SCRIPTS / "dump_verity_inventory.lean").read_bytes()
    replay_path = SCRIPTS / "verity_census_vendor/VerityCensusReplay.lean"
    replay = replay_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="verity-census-") as temp:
        root = Path(temp)
        env = {"PATH": f"{lean.parent}:/usr/bin:/bin", "HOME": str(root),
               "LEAN_PATH": str(root), "LANG": "C.UTF-8"}
        if run([str(lean), "-j1", "--githash"], root, env).decode().strip() != GITHASH:
            raise ValueError("installed Lean revision differs from the pinned census compiler")
        for name in MODULES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(snapshot[name])
        for name in MODULES:
            run([str(lean), "-j1", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false",
                 "-o", str((root / name).with_suffix(".olean")), name], root, env)
        (root / "VerityCensusReplay.lean").write_bytes(replay)
        run([str(lean), "-j1", "-o", "VerityCensusReplay.olean", "VerityCensusReplay.lean"], root, env)
        dump = root / "Census.lean"
        dump.write_bytes(collector)
        modules = [name[:-5].replace("/", ".") for name in MODULES]
        result = load_json(run([str(lean), "-j1", "--run", str(dump), *modules], root, env))
    if collector != (SCRIPTS / "dump_verity_inventory.lean").read_bytes() or replay != replay_path.read_bytes():
        raise ValueError("census collector changed during execution")
    return result


def signature(declaration: dict, *, body: bool = False) -> dict:
    result = {key: declaration[key] for key in ("name", "module", "levels", "unsafe", "partial")}
    result["type_sha256"] = digest(declaration["type"].encode())
    if body:
        result["value_sha256"] = digest(declaration["value"].encode())
    return result


def by_name(items: list[dict]) -> dict[str, dict]:
    result = {}
    for item in items:
        if item["name"] in result:
            raise ValueError(f"duplicate declaration: {item['name']}")
        result[item["name"]] = item
    return result


def validate(snapshot: dict[str, bytes], inventory: dict) -> dict:
    baseline = load_json(snapshot["assurance_inventory.json"])
    if set(baseline) != {"schema_version", "toolchain", "lean_githash", "quarantine_sha256",
                         "environment_axioms", "admitted_declarations", "partial_declarations"}:
        raise ValueError("invalid census baseline fields")
    if (baseline["schema_version"], baseline["toolchain"], baseline["lean_githash"]) != (1, TOOLCHAIN, GITHASH):
        raise ValueError("invalid census baseline version/toolchain")
    if baseline["quarantine_sha256"] != {name: digest(snapshot[name]) for name in QUARANTINE}:
        raise ValueError("unverified Part A source quarantine changed; explicit review required")
    expected_modules = [name[:-5].replace("/", ".") for name in MODULES]
    if inventory["schema_version"] != 1 or inventory["modules"] != expected_modules:
        raise ValueError("elaborated module coverage mismatch")
    axioms = by_name([signature(d) for d in inventory["axioms"]])
    if axioms != by_name(baseline["environment_axioms"]):
        raise ValueError("elaborated axiom identity/type census changed")
    declarations = by_name(inventory["declarations"])
    if {d["module"] for d in declarations.values()} != set(expected_modules):
        raise ValueError("missing project declarations in elaborated census")
    admitted = by_name(baseline["admitted_declarations"])
    partials = sorted(d["name"] for d in declarations.values() if d["partial"])
    if partials != baseline["partial_declarations"] or any(d["unsafe"] for d in declarations.values()):
        raise ValueError("unsafe/partial declaration census changed")
    checked = len(declarations) - len(partials)
    if inventory["kernel_rechecked_declarations"] != checked:
        raise ValueError("kernel replay coverage mismatch")
    for name, d in declarations.items():
        dependencies = set(d["axioms"])
        extra = dependencies - ALLOWED - {"sorryAx"}
        if extra:
            raise ValueError(f"{name}: unapproved transitive axioms {sorted(extra)}")
        if "sorryAx" in dependencies and (name not in admitted or signature(d, body=True) != admitted[name]):
            raise ValueError(f"{name}: unapproved or changed admitted declaration")
    for name, allowed in admitted.items():
        if name not in declarations or signature(declarations[name]) != {k: v for k, v in allowed.items() if k != "value_sha256"}:
            raise ValueError(f"admitted obligation removed or its statement changed: {name}")
    return {"compiled_modules": len(MODULES), "exported_declarations": len(declarations),
            "environment_axioms": len(axioms), "project_axioms": len(ALLOWED) - 3,
            "kernel_rechecked_declarations": checked,
            "admitted_declarations": sum("sorryAx" in d["axioms"] for d in declarations.values()),
            "unverified_part_a_files": len(QUARANTINE)}


def census(directory: Path = VERITY) -> dict:
    before = source_snapshot(directory)
    raw_mentions = check(directory)
    inventory = fresh_inventory(before)
    result = validate(before, inventory)
    if source_snapshot(directory) != before:
        raise ValueError("Verity sources or census baseline changed during execution")
    return {**result, "raw_hole_mentions": raw_mentions}


if __name__ == "__main__":
    try:
        print("PASS: Verity assurance census " + json.dumps(census(), sort_keys=True))
        print("Part A is source-pinned, uncompiled and unverified (11 holes, one CREATE2 axiom).")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"VERITY CENSUS FAILURE: {exc}")
