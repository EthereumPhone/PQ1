#!/usr/bin/env python3
"""Fail closed if the host-only ERC-8176 ECDSA verifier escapes its boundary.

Invariant #5 forbids classical *signing authority* in firmware, firmware-update,
and wallet-contract paths. ERC-8176 nevertheless mandates verification of an
external Ethereum EAS ECDSA signature while compiling the descriptor catalogue.
This gate makes that exception exact instead of weakening the invariant:

* only pinned k256/ecdsa packages and resolved features are accepted;
* the only dependency edges into them are dbgen -> k256 -> ecdsa;
* no workspace member other than dbgen/xtask may reach them through a normal or
  build dependency (secure reaches dbgen only as a host-test dev dependency);
* only dbgen/src/erc8176.rs may import k256; its production regions may recover
  and verify signatures but may not use a signing or secret-key API.

The synthetic fixture code is cfg(test) and may sign deterministic test records.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ALLOWED_HOST_ROOTS = {"dbgen", "pqsigner-xtask"}
EXPECTED_PACKAGES = {
    "k256": (
        "0.14.0",
        {"arithmetic", "digest", "ecdsa", "ecdsa-core", "sha2", "sha256"},
    ),
    "ecdsa": (
        "0.17.0",
        {"algorithm", "der", "digest"},
    ),
}
EXPECTED_EDGES = {
    ("dbgen", "k256", "normal", None),
    ("k256", "ecdsa", "normal", None),
}
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def metadata() -> dict:
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr, end="")
        raise SystemExit("ERROR: cargo metadata --locked failed")
    return json.loads(completed.stdout)


def dependency_path(
    root: str, nodes: dict[str, dict], packages: dict[str, dict]
) -> list[str] | None:
    """Return a normal/build path from root to a classical package, if any."""
    queue: list[tuple[str, list[str]]] = [(root, [root])]
    seen = {root}
    while queue:
        package_id, path = queue.pop(0)
        for dep in nodes.get(package_id, {}).get("deps", []):
            kinds = {entry.get("kind") or "normal" for entry in dep["dep_kinds"]}
            if not kinds.intersection({"normal", "build"}):
                continue
            child = dep["pkg"]
            if child in seen:
                continue
            child_path = path + [child]
            if packages[child]["name"] in EXPECTED_PACKAGES:
                return child_path
            seen.add(child)
            queue.append((child, child_path))
    return None


def check_source(failures: list[str]) -> None:
    allowed = ROOT / "dbgen/src/erc8176.rs"
    imports = []
    for source in ROOT.rglob("*.rs"):
        try:
            text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"(?m)^\s*(?:use|extern\s+crate)\s+k256\b", text):
            imports.append(source.relative_to(ROOT).as_posix())
    if imports != ["dbgen/src/erc8176.rs"]:
        failures.append(f"k256 imports must be exactly dbgen/src/erc8176.rs; got {imports}")

    source = allowed.read_text(encoding="utf-8")
    verifier_import = "use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};"
    if source.count(verifier_import) != 1:
        failures.append("ERC-8176 production import must contain only recovery/verifier types")

    fixture_start = source.find("#[cfg(test)]\npub(crate) struct SyntheticSnapshotFixture")
    production_restart = source.find("struct RejectDuplicateJsonKeys;")
    test_module = source.find("#[cfg(test)]\nmod tests {")
    if min(fixture_start, production_restart, test_module) < 0 or not (
        fixture_start < production_restart < test_module
    ):
        failures.append("ERC-8176 cfg(test)/production boundary markers drifted")
        return

    production = source[:fixture_start] + source[production_restart:test_module]
    forbidden_signing = (
        "SigningKey",
        "SecretKey",
        "sign_prehash",
        "sign_digest",
        "sign_recoverable",
        "try_sign",
    )
    present = [token for token in forbidden_signing if token in production]
    if present:
        failures.append(f"ERC-8176 production source uses signing/secret APIs: {present}")


def main() -> int:
    graph = metadata()
    packages = {package["id"]: package for package in graph["packages"]}
    nodes = {node["id"]: node for node in graph["resolve"]["nodes"]}
    workspace = set(graph["workspace_members"])
    failures: list[str] = []

    classical_ids: dict[str, str] = {}
    for name, (version, expected_features) in EXPECTED_PACKAGES.items():
        matches = [
            package_id
            for package_id, package in packages.items()
            if package["name"] == name
        ]
        if len(matches) != 1:
            failures.append(f"expected exactly one {name} package, got {len(matches)}")
            continue
        package_id = matches[0]
        package = packages[package_id]
        classical_ids[name] = package_id
        if package["version"] != version or package.get("source") != CRATES_IO:
            failures.append(
                f"{name} must be crates.io {version}; got {package['version']} "
                f"from {package.get('source')}"
            )
        resolved_features = set(nodes[package_id].get("features", []))
        if resolved_features != expected_features:
            failures.append(
                f"{name} resolved features drifted: expected {sorted(expected_features)}, "
                f"got {sorted(resolved_features)}"
            )

    actual_edges = set()
    classical_id_set = set(classical_ids.values())
    for parent_id, node in nodes.items():
        for dep in node.get("deps", []):
            if dep["pkg"] not in classical_id_set:
                continue
            for dep_kind in dep["dep_kinds"]:
                actual_edges.add(
                    (
                        packages[parent_id]["name"],
                        packages[dep["pkg"]]["name"],
                        dep_kind.get("kind") or "normal",
                        dep_kind.get("target"),
                    )
                )
    if actual_edges != EXPECTED_EDGES:
        failures.append(
            f"classical verifier dependency edges drifted: expected {sorted(EXPECTED_EDGES)}, "
            f"got {sorted(actual_edges)}"
        )

    for root_id in sorted(workspace):
        root_name = packages[root_id]["name"]
        if root_name in ALLOWED_HOST_ROOTS:
            continue
        path = dependency_path(root_id, nodes, packages)
        if path:
            failures.append(
                f"{root_name} reaches classical crypto through normal/build deps: "
                + " -> ".join(packages[package_id]["name"] for package_id in path)
            )

    check_source(failures)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("classical-crypto-boundary: PASS (host-only ERC-8176 verifier; no signing authority)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
