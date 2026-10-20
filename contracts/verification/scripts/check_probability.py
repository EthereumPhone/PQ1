#!/usr/bin/env python3
"""Fresh standalone PMF build, exact claim inventory and typed controls.

Source pins are drift checks, not proofs of model correspondence. The Lean
kernel checks the proofs; standard logical axioms are the only allowed closure.
Dependency/toolchain source and compiled libraries remain part of the tool TCB.
"""
from __future__ import annotations

import concurrent.futures
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from check_axiom_closure import KERNEL, parse_dump_records
from check_ledger_consistency import _pinned_lake, _pinned_tool_env, extract_statement
from probability_controls import cases
from probability_execution import (
    CONTROL_FLAGS, CONTROL_TIMEOUT, STAGES, authenticate_shards, input_identity,
    judge_control, producer_context, resource_limits, shard_cases, worker_count,
)

ROOT = Path(__file__).resolve().parents[3]
PROJECT = ROOT / "contracts/verification/probability"
MANIFEST = PROJECT / "claims.json"
FORBIDDEN = re.compile(
    r"\b(?:axiom|sorry|admit|native_decide|unsafe|partial|opaque|elab|macro|syntax|"
    r"run_elab|addDecl|addDeclCore|addAndCompile|addInductive|inductDecl|mkProj|"
    r"ofReduceBool|reduceBool|implemented_by|extern|csimp)\b|"
    r"decide\s+\+native|Expr\.proj|#(?:eval|run|print|check)"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def static_checks() -> dict:
    manifest = json.loads(MANIFEST.read_text())
    sources = {}
    for directory, dirs, files in os.walk(PROJECT):
        dirs[:] = [d for d in dirs if d != ".lake"]
        for name in dirs + files:
            require(not (Path(directory) / name).is_symlink(), f"source symlink: {name}")
        for name in files:
            if name.endswith(".lean"):
                path = Path(directory) / name
                sources[path.relative_to(PROJECT).as_posix()] = path.read_bytes()
    require(set(sources) == set(manifest["sources"]), "Lean source census differs")
    seen = {}
    for name, data in sources.items():
        require(digest(data) == manifest["sources"][name], f"source pin differs: {name}")
        if name == "Audit.lean":
            continue
        text = data.decode()
        require(not FORBIDDEN.search(text), f"forbidden proof construct: {name}")
        imports = re.findall(r"^import (\S+)\s*$", text, re.M)
        require(all(s.startswith(("Mathlib.", "C10Probability.")) or s == "C10Probability"
                    for s in imports), f"unexpected import: {name}")
        for short in re.findall(r"^theorem (\w+)\b", text, re.M):
            full = "C10Probability." + short
            require(full not in seen, f"duplicate declaration {full}")
            statement = extract_statement(text, short)
            require(statement is not None, f"unsupported statement layout: {full}")
            seen[full] = {"file": name, "statement_sha256": digest(statement.encode())}
    require(seen == manifest["theorems"], "theorem census/statement pins differ")
    expected_audit = "import C10Probability\n\n" + "".join(
        f"#print axioms {name}\n" for name in sorted(seen))
    require(sources["Audit.lean"].decode() == expected_audit, "audit query inventory differs")
    for relative, sha in manifest["bindings"].items():
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"missing binding {relative}")
        require(digest(path.read_bytes()) == sha, f"binding drift: {relative}")
    return manifest


def command(args: list[str], out: Path, label: str, env: dict, timeout=900) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run(args, cwd=PROJECT, env=env, capture_output=True,
                              text=True, timeout=timeout)
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        code, output = 124, str(exc)
    path = out / (label + ".log")
    path.write_text(output)
    return {"command": args, "exit": code, "seconds": time.monotonic() - start,
            "log": str(path), "log_sha256": digest(output.encode())}


def check_closures(output: str, names: set[str]) -> dict:
    records = parse_dump_records(output)
    require(set(records) == names, "missing/extra axiom-closure record")
    require(all(axioms <= KERNEL for axioms in records.values()), "non-kernel axiom in closure")
    return {name: sorted(axioms) for name, axioms in records.items()}


def run_controls(out: Path, lean: str, env: dict, workers: int = 4,
                 shard_index: int = 0, shard_count: int = 1) -> list[dict]:
    fixtures = out / "controls"
    fixtures.mkdir()
    selected = cases(PROJECT)
    require(len(selected) == 1655 and sum(not c["expected"] for c in selected) == 1451,
            "control census differs")
    selected = shard_cases(selected, shard_index, shard_count)
    jobs = []
    for case in selected:
        for stage in STAGES:
            path = fixtures / (case["name"] + "-" + stage + ".lean")
            path.write_text(case[stage])
            jobs.append((case, stage, path))

    def run(job):
        case, stage, path = job
        row = command([lean, *CONTROL_FLAGS, str(path)], fixtures, path.stem, env, CONTROL_TIMEOUT)
        row.update(name=case["name"], stage=stage, source_sha256=digest(path.read_bytes()),
                   expected_pass=stage != "checked" or case["expected"])
        row["errors"] = judge_control(row, Path(row["log"]).read_text(), path.read_text(),
                                      str(path), row["expected_pass"])
        return row

    rows = []
    # Each process has its own source/output. Imported build artifacts are read-only.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run, job) for job in jobs]
        failures = []
        for future in futures:
            try:
                rows.append(future.result())
            except Exception as exc:
                failures.append(str(exc))
    (out / "controls.json").write_text(json.dumps(rows, indent=2) + "\n")
    require(not failures, "control failures: " + "; ".join(failures))
    return rows


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", default=os.environ.get("PROBABILITY_WORKERS", "auto"))
    parser.add_argument("--shard-count", type=int, default=os.environ.get("PROBABILITY_SHARD_COUNT", "1"))
    parser.add_argument("--shard-index", type=int, default=os.environ.get("PROBABILITY_SHARD_INDEX"))
    parser.add_argument("--aggregate", type=Path, default=os.environ.get("PROBABILITY_AGGREGATE"))
    parser.add_argument("--output", type=Path, default=os.environ.get("PROBABILITY_OUTPUT"))
    parser.add_argument("--batch-id", help="Fresh local shard group ID; forbidden in CI")
    args = parser.parse_args(argv)
    require(1 <= args.shard_count <= 8, "shard count outside 1..8")
    require(not (args.aggregate and args.shard_index is not None), "aggregate cannot be a shard")
    require(args.shard_index is None or 0 <= args.shard_index < args.shard_count,
            "shard index outside range")
    require(args.shard_count == 1 or args.aggregate or args.shard_index is not None,
            "partial control count requires explicit shard or aggregate")
    return args


def main(args=None) -> None:
    args = arguments() if args is None else args
    started = time.monotonic()
    limits = resource_limits()
    workers = worker_count(args.workers, limits)
    mode = "aggregate" if args.aggregate else "shard" if args.shard_index is not None else "full"
    context = producer_context(ROOT, args.batch_id) if mode != "full" else None
    manifest = static_checks()
    lake = _pinned_lake()
    env = _pinned_tool_env()
    for name in ("LEAN_PATH", "LEAN_SRC_PATH", "LAKE_HOME", "LAKE_PACKAGES_DIR"):
        env.pop(name, None)
    require(not (PROJECT / ".lake").is_symlink(), "symlinked build root")
    (PROJECT / ".lake").mkdir(exist_ok=True)
    if args.output:
        out = args.output.resolve()
        require(not out.exists(), "output must be a new directory")
        require(not any(parent.is_symlink() for parent in args.output.absolute().parents),
                "symlinked output parent")
        out.mkdir(parents=True)
    else:
        out = Path(tempfile.mkdtemp(prefix="probability-evidence-", dir=PROJECT / ".lake"))
    print(f"Evidence: {out}", flush=True)
    # Rebuild every project module; retain only third-party dependency artifacts.
    build = PROJECT / ".lake/build"
    require(not build.is_symlink(), "symlinked project build")
    if build.exists():
        shutil.rmtree(build)
    result = {"passed": False, "manifest_sha256": digest(MANIFEST.read_bytes()),
              "mode": mode, "workers": workers, "resources": limits, "context": context,
              "shard": [args.shard_index, args.shard_count] if mode == "shard" else None}
    try:
        result["build"] = command([lake, "build"], out, "build", env)
        require(result["build"]["exit"] == 0, "fresh kernel build failed")
        require("warning:" not in Path(result["build"]["log"]).read_text(), "kernel build warning")
        result["audit"] = command([lake, "env", "lean", "Audit.lean"], out, "axioms", env)
        require(result["audit"]["exit"] == 0, "axiom audit compiler failed")
        result["closures"] = check_closures(Path(result["audit"]["log"]).read_text(),
                                            set(manifest["theorems"]))
        # Ask Lake for its selected binary and search path; never inherit caller LEAN_PATH.
        elan = str(Path(lake).with_name("elan"))
        lean = subprocess.check_output([elan, "which", "lean"], cwd=PROJECT,
                                       env=env, text=True).strip()
        lean_path = subprocess.check_output([lake, "env", "/usr/bin/printenv", "LEAN_PATH"],
                                           cwd=PROJECT, env=env, text=True).strip()
        require(Path(lean).is_absolute() and Path(lean).is_file(), "missing selected Lean binary")
        result["lean"] = {"path": lean, "sha256": digest(Path(lean).read_bytes())}
        control_env = dict(env, LEAN_PATH=lean_path)
        selected = cases(PROJECT)
        require(len(selected) == 1655 and sum(not c["expected"] for c in selected) == 1451,
                "control census differs")
        result["identity"] = input_identity(ROOT, PROJECT, manifest, lean, selected, lake)
        # An actual compiler-produced closure with a new assumption must reject.
        canary = out / "ClosureCanary.lean"
        canary.write_text("import C10Probability\nnamespace ProbabilityGateCanary\n"
                          "axiom addedAssumption : False\n"
                          "theorem checked : False := addedAssumption\nend ProbabilityGateCanary\n"
                          "#print axioms ProbabilityGateCanary.checked\n")
        result["closure_canary"] = command([lean, str(canary)], out, "closure-canary", control_env, 90)
        require(result["closure_canary"]["exit"] == 0, "closure canary did not compile")
        try:
            check_closures(Path(result["closure_canary"]["log"]).read_text(),
                           {"ProbabilityGateCanary.checked"})
        except RuntimeError as exc:
            require(str(exc) == "non-kernel axiom in closure", "wrong canary rejection")
            result["closure_canary"]["rejected_as_expected"] = True
        else:
            raise RuntimeError("closure gate accepted the added-assumption canary")
        try:
            check_closures("", set(manifest["theorems"]))
        except RuntimeError:
            result["missing_closure_control"] = True
        else:
            raise RuntimeError("closure gate accepted missing proof records")
        if mode == "aggregate":
            result["aggregate"] = authenticate_shards(
                args.aggregate, args.shard_count, result["identity"], context, selected, manifest,
                check_closures, os.environ.get("PROBABILITY_PRODUCER_RESULT", ""))
        else:
            result["controls"] = run_controls(out, lean, control_env, workers,
                                             args.shard_index or 0, args.shard_count)
        require(manifest == static_checks(), "inputs changed during proof gate")
        require(result["identity"] == input_identity(ROOT, PROJECT, manifest, lean, cases(PROJECT), lake),
                "toolchain/dependencies/policy changed during proof gate")
        if context is not None:
            require(context == producer_context(ROOT, args.batch_id), "producer context changed")
        result["passed"] = True
    finally:
        result["seconds"] = time.monotonic() - started
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    if mode == "shard":
        print(f"PASS shard {args.shard_index}/{args.shard_count}: {len(result['closures'])} theorem "
              f"closures; {len(result['controls'])} compiler jobs (partial control coverage)")
    else:
        print(f"PASS: {len(result['closures'])} theorem closures; 1655 typed cases / 4965 compiler jobs")


if __name__ == "__main__":
    main()
