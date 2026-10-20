"""Execution/receipt helpers for the PMF gate; no mathematical evidence reuse.

Shards are independent fresh runs. Their receipts are accepted only by an
aggregate in the same CI run/attempt, with a fresh local proof build and an
exact input/toolchain identity. Raw control output is judged again.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

STAGES = ("definition", "baseline", "checked")
CONTROL_TIMEOUT = 90
CONTROL_FLAGS = ["--json"]
SCHEMA = 1
MAX_WORKERS = 32
MAX_SHARDS = 8
RESERVE_BYTES = 2 * 1024**3
WORKER_BYTES = 2 * 1024**3
EXCLUDED = (r"unknown|unexpected token|timeout|heartbeats|recursion depth|stack|memory|"
            r"failed to synthesize|typeclass instance problem is stuck|did not reduce to")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def decode_json(text: str):
    """Reject ambiguous JSON in both receipt documents and compiler diagnostics."""
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def constant(value):
        raise RuntimeError(f"non-finite JSON constant: {value}")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def read_json(path: Path):
    require(path.is_file() and not path.is_symlink(), f"missing or symlinked JSON: {path}")
    return decode_json(path.read_text())


def resource_limits() -> dict:
    """Linux admission budget, including cgroup ceilings, not a Lean flag change."""
    cpus = len(os.sched_getaffinity(0))
    available = next(int(line.split()[1]) * 1024
                     for line in Path("/proc/meminfo").read_text().splitlines()
                     if line.startswith("MemAvailable:"))
    # Resolve the process's unified cgroup; inspect all ancestors for ceilings.
    unified = next((line.split(":", 2)[2] for line in
                    Path("/proc/self/cgroup").read_text().splitlines()
                    if line.startswith("0::")), "/")
    base = Path("/sys/fs/cgroup")
    current = base / unified.lstrip("/")
    while current == base or base in current.parents:
        cpu = current / "cpu.max"
        if cpu.is_file():
            quota, period = cpu.read_text().split()
            if quota != "max":
                cpus = min(cpus, max(1, int(quota) // int(period)))
        maximum, used = current / "memory.max", current / "memory.current"
        if maximum.is_file() and used.is_file() and maximum.read_text().strip() != "max":
            available = min(available, max(0, int(maximum.read_text()) - int(used.read_text())))
        if current == base:
            break
        current = current.parent
    capacity = min(MAX_WORKERS, cpus, max(0, (available - RESERVE_BYTES) // WORKER_BYTES))
    return {"cpus": cpus, "available_bytes": available, "reserve_bytes": RESERVE_BYTES,
            "bytes_per_worker": WORKER_BYTES, "capacity": capacity}


def worker_count(value: str, limits: dict) -> int:
    require(value == "auto" or re.fullmatch(r"[1-9][0-9]*", value) is not None,
            "workers must be auto or a positive decimal integer")
    requested = min(12, limits["capacity"]) if value == "auto" else int(value)
    require(1 <= requested <= MAX_WORKERS, "workers outside 1..32 or no memory headroom")
    require(requested <= limits["capacity"], "workers exceed CPU/memory admission budget")
    return requested


def validate_cases(selected: list[dict]) -> None:
    names = [case["name"] for case in selected]
    require(len(names) == len(set(names)), "duplicate control name")
    for case in selected:
        require(re.fullmatch(r"[a-zA-Z0-9_-]+", case["name"]) is not None, "unsafe control name")
        require(type(case["expected"]) is bool, "control expectation must be Boolean")
        require(all(isinstance(case[stage], str) for stage in STAGES), "missing control stage")


def shard_cases(selected: list[dict], index: int, count: int) -> list[dict]:
    validate_cases(selected)
    require(type(count) is int and 1 <= count <= MAX_SHARDS, "shard count outside 1..8")
    require(type(index) is int and 0 <= index < count, "shard index outside range")
    # Preserve the original full-run order for comparable local benchmarks.
    if count == 1:
        return selected
    # A case's three stages always travel together; sorted stride is deterministic.
    return [case for i, case in enumerate(sorted(selected, key=lambda c: c["name"]))
            if i % count == index]


def judge_control(row: dict, text: str, source: str, source_path: str, expected: bool) -> list:
    """Validate fields used to classify a consuming-theorem rejection."""
    require(type(row["exit"]) is int, "non-integer compiler exit")
    messages = [decode_json(line) for line in text.splitlines() if line.strip()]
    require(all(isinstance(message, dict) for message in messages), "malformed compiler message")
    require(all(message.get("severity") in ("information", "warning", "error")
                and isinstance(message.get("data"), str) for message in messages),
            "missing or invalid compiler diagnostic severity/text")
    errors = [message for message in messages if message.get("severity") == "error"]
    require(all(message["data"].strip() for message in errors), "empty compiler failure reason")
    if expected:
        require(row["exit"] == 0 and not errors, f"positive control failed: {source_path}")
    else:
        first = next(i for i, line in enumerate(source.splitlines(), 1)
                     if line.startswith("theorem checked"))
        require(row["exit"] == 1 and bool(errors), f"mutant did not reject: {source_path}")
        require(all(type(m.get("pos", {}).get("line")) is int
                    and first <= m["pos"]["line"] <= source.count("\n") + 1
                    and m.get("fileName") == source_path for m in errors),
                f"mutant failure outside consuming theorem: {source_path}")
        require(all(not re.search(EXCLUDED, m["data"], re.I) for m in errors),
                f"non-semantic mutant failure: {source_path}")
    return errors


def producer_context(root: Path) -> dict:
    # Local callers use the cold full gate with configurable workers. Accepting
    # caller-chosen local group IDs would create an unauthenticated reuse path.
    require(os.environ.get("GITHUB_ACTIONS") == "true",
            "shard production/aggregation requires the current GitHub workflow run")
    git = lambda *args: subprocess.check_output(["git", *args], cwd=root, text=True).strip()
    context = {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}")}
    keys = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA",
            "GITHUB_EVENT_NAME", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA")
    require(all(os.environ.get(key) for key in keys), "incomplete CI producer context")
    require(context["commit"] == os.environ["GITHUB_SHA"], "checkout differs from CI SHA")
    require(not git("status", "--porcelain", "--untracked-files=normal"),
            "CI checkout is not clean")
    context.update(kind="github", **{key: os.environ[key] for key in keys})
    return context


def tree_hash(root: Path, accept) -> str:
    """Hash file contents under canonical relative names, rejecting symlink inputs."""
    require(root.is_dir() and not root.is_symlink(), f"invalid identity tree: {root}")
    entries = {}
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), f"symlinked identity input: {name}")
        for name in sorted(files):
            path = Path(directory) / name
            if accept(path):
                require(path.is_file(), f"missing identity file: {path}")
                if path.is_symlink():
                    require(root.resolve() in path.resolve().parents,
                            f"identity symlink escapes tree: {path}")
                entries[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    require(bool(entries), f"empty identity tree: {root}")
    return digest(canonical(entries))


def input_identity(root: Path, project: Path, manifest: dict, lean: str,
                   selected: list[dict], lake: str, *, include_project: bool = True) -> dict:
    """Bind actual proof/policy/dependency bytes, not merely the checkout commit.

    Dependency caches and the Lean distribution remain the existing tool TCB.
    Hash source and compiler-loadable library bytes so altered caches cannot
    silently compose with a different shard's evidence.
    """
    files = ["contracts/verification/Makefile", ".github/workflows/lean-probability.yml",
             "scripts/gate_enforcement.json"]
    files += [p.relative_to(root).as_posix()
              for p in sorted((root / "contracts/verification/scripts").glob("*.py"))]
    files += [f"contracts/verification/probability/{name}"
              for name in ("claims.json", "lakefile.toml", "lake-manifest.json", "lean-toolchain")]
    files += [f"contracts/verification/probability/{name}" for name in manifest["sources"]]
    files += list(manifest["bindings"])
    pins = {}
    for name in sorted(set(files)):
        path = root / name
        require(path.is_file() and not path.is_symlink(), f"missing identity input: {name}")
        pins[name] = digest(path.read_bytes())
    library = lambda p: (p.suffix in {".lean", ".ir", ".a", ".dll", ".dylib"}
                         or ".olean" in p.name or ".so" in p.name)
    packages = project / ".lake/packages"
    # Include dependency configuration/support sources as well as actual
    # compiler-loadable artifacts. Exclude only generated non-library state.
    dependency = lambda p: library(p) or ".lake" not in p.relative_to(packages).parts
    identity = {"schema": SCHEMA, "inputs_sha256": digest(canonical(pins)),
            "manifest_sha256": digest(canonical(manifest)),
            "manifest_file_sha256": digest((project / "claims.json").read_bytes()),
            "cases_sha256": digest(canonical(selected)),
            "lean_sha256": digest(Path(lean).read_bytes()),
            "lake_sha256": digest((Path(lean).parent / "lake").read_bytes()),
            "elan_sha256": digest(Path(lake).read_bytes()),
            "python_sha256": digest(Path(sys.executable).read_bytes()),
            "python_version": sys.version,
            "python_flags": {"ignore_environment": sys.flags.ignore_environment,
                             "no_site": sys.flags.no_site},
            "toolchain_sha256": tree_hash(Path(lean).parent.parent / "lib", library),
            "dependencies_sha256": tree_hash(packages, dependency),
            "policy": {"control_flags": CONTROL_FLAGS, "timeout": CONTROL_TIMEOUT,
                       "stages": list(STAGES), "excluded": EXCLUDED}}
    if include_project:
        identity["project_libraries_sha256"] = tree_hash(project / ".lake/build/lib/lean", library)
    return identity


def check_file(bundle: Path, name: str, expected: str) -> str:
    path = bundle / name
    require(path.is_file() and not path.is_symlink(), f"missing receipt file: {name}")
    require(all(not parent.is_symlink() for parent in path.parents), "symlinked receipt directory")
    data = path.read_bytes()
    require(digest(data) == expected, f"receipt file digest differs: {name}")
    return data.decode()


def authenticate_shards(directory: Path, count: int, identity: dict, context: dict,
                        selected: list[dict], manifest: dict, check_closures,
                        producer_result: str) -> dict:
    """Only a complete same-run matrix can satisfy the aggregate gate."""
    require(type(count) is int and 1 <= count <= MAX_SHARDS, "shard count outside 1..8")
    require(producer_result == "success", "producer matrix failed/cancelled/incomplete")
    require(directory.is_dir() and not directory.is_symlink(), "missing shard directory")
    expected_names = {f"shard-{i}" for i in range(count)}
    require({p.name for p in directory.iterdir()} == expected_names, "missing/extra shard bundle")
    seen, receipts = set(), []
    for index in range(count):
        bundle = directory / f"shard-{index}"
        require(bundle.is_dir() and not bundle.is_symlink(), "invalid shard bundle")
        result = read_json(bundle / "result.json")
        require(result.get("passed") is True, "shard did not pass")
        require(result.get("mode") == "shard" and result.get("shard") == [index, count],
                "wrong shard assignment")
        require(all(type(value) is int for value in result["shard"]), "non-integer shard identity")
        require(result.get("identity") == identity, "shard input/toolchain/policy mismatch")
        require(result.get("manifest_sha256") == identity["manifest_file_sha256"],
                "shard manifest receipt differs")
        require(result.get("context") == context, "stale or foreign producer context")
        require(result.get("lean", {}).get("sha256") == identity["lean_sha256"],
                "selected compiler differs")
        require(type(result.get("workers")) is int and 1 <= result["workers"] <= MAX_WORKERS,
                "invalid shard worker count")
        for key, filename in (("build", "build.log"), ("audit", "axioms.log"),
                              ("closure_canary", "closure-canary.log")):
            row = result[key]
            require(type(row.get("exit")) is int and row["exit"] == 0, f"failed shard {key}")
            text = check_file(bundle, filename, row["log_sha256"])
            if key == "build":
                require("warning:" not in text, "shard build warning")
            if key == "audit":
                closures = check_closures(text, set(manifest["theorems"]))
                require(result["closures"] == closures, "shard closure records differ")
            if key == "closure_canary":
                try:
                    check_closures(text, {"ProbabilityGateCanary.checked"})
                except RuntimeError as exc:
                    require(str(exc) == "non-kernel axiom in closure", "wrong canary rejection")
                else:
                    raise RuntimeError("shard accepted added-assumption canary")
                require(row.get("rejected_as_expected") is True, "missing canary rejection")
        require(result.get("missing_closure_control") is True, "missing closure canary not checked")
        expected = {(case["name"], stage): (case, stage)
                    for case in shard_cases(selected, index, count) for stage in STAGES}
        rows = result["controls"]
        require(isinstance(rows, list) and len(rows) == len(expected), "incomplete shard controls")
        local_seen = set()
        for row in rows:
            key = (row["name"], row["stage"])
            require(key in expected and key not in local_seen and key not in seen,
                    "unexpected/duplicate control stage")
            local_seen.add(key)
            seen.add(key)
            case, stage = expected[key]
            stem = case["name"] + "-" + stage
            source = check_file(bundle, "controls/" + stem + ".lean", digest(case[stage].encode()))
            require(row.get("source_sha256") == digest(source.encode()), "control source pin differs")
            passed = stage != "checked" or case["expected"]
            require(type(row.get("expected_pass")) is bool and row["expected_pass"] == passed,
                    "control expectation differs")
            command = row["command"]
            require(isinstance(command, list) and len(command) == 3
                    and command[0] == result["lean"]["path"] and command[1:-1] == CONTROL_FLAGS
                    and Path(command[-1]).name == stem + ".lean",
                    "control compiler invocation differs")
            text = check_file(bundle, "controls/" + stem + ".log", row["log_sha256"])
            errors = judge_control(row, text, source, command[-1], passed)
            require(row.get("errors") == errors, "compiler errors differ from raw output")
        receipts.append({"shard": index, "result_sha256": digest((bundle / "result.json").read_bytes()),
                         "jobs": len(rows)})
    require(seen == {(case["name"], stage) for case in selected for stage in STAGES},
            "aggregate coverage incomplete")
    return {"passed": True, "jobs": len(seen), "cases": len(selected), "shards": receipts}
