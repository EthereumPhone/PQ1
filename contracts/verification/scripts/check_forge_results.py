#!/usr/bin/env python3
"""Validate machine-readable Forge evidence for verify-three-claims.

The shell runner deliberately invokes Forge with a clean environment and fixed
fuzz/invariant parameters.  This checker supplies the second half of that
boundary: a zero exit status is insufficient.  Every emitted test must succeed,
the result set must be non-empty, and every fuzz/invariant record must carry the
exact advertised execution counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ALLOWED_SKIPS = frozenset({
    (
        "test/DeployedBytecodeReproCheck.t.sol:"
        "DeployedBytecodeReproCheckTest::"
        "test_deployed_base_mainnet_bytecode_is_reproducible()"
    ),
    (
        "test/EntryPointCodehashReceipt.t.sol:"
        "EntryPointCodehashReceiptTest::"
        "test_entrypoint_v06_codehash_pinned()"
    ),
})
EXPECTED_FUZZ_TESTS = frozenset({
    (
        "test/SPHINCsC10Asm.t.sol:SPHINCsC10AsmTest::"
        "testFuzz_verifyLengthBoundaries(uint16)"
    ),
    (
        "test/SPHINCsC10Asm.t.sol:SPHINCsC10AsmTest::"
        "testFuzz_verifyRandomSigsRejected(uint256)"
    ),
})
EXPECTED_INVARIANT_TESTS = frozenset({
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_bootstrapUses_capped()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_bootstrapUses_monotonic()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_bootstrap_owner_present()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_combined_cap_all_slots()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_impl_slot_unchanged()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_nextOwnerIndex_at_least_2()"
    ),
    (
        "test/PQSmartWalletInvariants.t.sol:PQSmartWalletInvariantsTest::"
        "invariant_owner_set_append_only()"
    ),
})
# RE-PINNED 2026-10-20 (Trail of Bits audit freeze). The previous pins (120
# tests / 6 invariants, invariant mode 6 tests) were already stale on master:
# before the freeze the suite emitted 130 rows and the invariant contract
# carried a unit test. The freeze adds LegacyERC1271 (11) and TokenReceiver
# (8), replaces the cross-slot-removal test with two tests, and adds
# invariant_owner_set_append_only plus test_handler_reinstall_path_is_live.
# Counts and manifests were taken from a Forge run that reports one row per
# invariant (forge 1.2.3, `~/.foundry/bin`), with every row inspected:
# Success apart from the two allowed skips, invariants at 256 x 500 with 0
# reverts. Known gap, tracked separately: forge 1.2.3 omits
# failed_corpus_replays, which this checker requires, and Foundry >= 1.8 (the
# CI pin) runs a contract's invariants as one campaign and emits a single row.
EXPECTED_MODE_COUNTS = {
    "full": {"tests": 157, "fuzz": 2, "invariants": 7, "skips": 2},
    "invariants": {"tests": 9, "fuzz": 0, "invariants": 7, "skips": 0},
}
# Checker-owned pin over every emitted [suite::test, status, kind] row:
# compact JSON per row, bytewise sorted, each terminated by "\n", then SHA-256.
# Update only after inspecting an intentional test identity/status/kind change.
EXPECTED_RESULT_MANIFEST_SHA256 = {
    "full": "7d6416b7f90ea0b7838be4b232c8019dc50a48fc8072d40a98b9f43a416946b8",
    "invariants": "2cd3436542c683d2505fc2fa29bd6cafcb007fdbb581cbfb82be6b76d5c96f59",
}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def result_manifest_digest(rows: list[list[object]]) -> str:
    """Hash the exact label/status/kind rows without delimiter ambiguity."""
    encoded = sorted(
        json.dumps(row, ensure_ascii=True, separators=(",", ":"))
        for row in rows
    )
    payload = "".join(f"{row}\n" for row in encoded).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def require_typed_zero(
    details: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if field not in details:
        failures.append(f"{label}: missing required {field} field")
        return
    value = details[field]
    if type(value) is not int or value != 0:
        failures.append(
            f"{label}: {field}={value!r}, expected explicit integer 0"
        )


def validate_results(
    payload: object,
    *,
    mode: str,
    expected_fuzz_runs: int,
    expected_invariant_runs: int,
    expected_invariant_depth: int,
    expected_manifest_sha256: str | None = None,
) -> tuple[list[str], dict[str, int]]:
    failures: list[str] = []
    counts = {"tests": 0, "fuzz": 0, "invariants": 0, "skips": 0}
    seen_fuzz: set[str] = set()
    seen_invariants: set[str] = set()
    seen_skips: set[str] = set()
    manifest_rows: list[list[object]] = []

    if not isinstance(payload, dict) or not payload:
        return ["Forge JSON contains no test suites"], counts

    for suite_name, suite in payload.items():
        if not isinstance(suite, dict):
            failures.append(f"{suite_name}: suite record is not an object")
            continue
        tests = suite.get("test_results")
        if not isinstance(tests, dict) or not tests:
            failures.append(f"{suite_name}: suite contains no test results")
            continue

        for test_name, result in tests.items():
            label = f"{suite_name}::{test_name}"
            counts["tests"] += 1
            if not isinstance(result, dict):
                failures.append(f"{label}: result is not an object")
                manifest_rows.append([label, "<malformed>", "<malformed>"])
                continue
            status = result.get("status")
            kind = result.get("kind")
            if not isinstance(kind, dict) or len(kind) != 1:
                failures.append(f"{label}: malformed result kind {kind!r}")
                manifest_rows.append([label, status, "<malformed>"])
                continue

            kind_name, details = next(iter(kind.items()))
            manifest_rows.append([label, status, kind_name])
            if not isinstance(details, dict):
                failures.append(f"{label}: {kind_name} details are not an object")
                continue

            if status == "Skipped":
                counts["skips"] += 1
                seen_skips.add(label)
                if label not in ALLOWED_SKIPS:
                    failures.append(f"{label}: unexpected skipped test")
                continue
            if status != "Success":
                reason = result.get("reason")
                failures.append(f"{label}: status={status!r}, reason={reason!r}")

            if kind_name == "Fuzz":
                counts["fuzz"] += 1
                seen_fuzz.add(label)
                runs = details.get("runs")
                if runs != expected_fuzz_runs:
                    failures.append(
                        f"{label}: fuzz runs={runs!r}, expected "
                        f"{expected_fuzz_runs}"
                    )
                require_typed_zero(
                    details, "failed_corpus_replays", label, failures
                )
            elif kind_name == "Invariant":
                counts["invariants"] += 1
                seen_invariants.add(label)
                runs = details.get("runs")
                calls = details.get("calls")
                expected_calls = expected_invariant_runs * expected_invariant_depth
                if runs != expected_invariant_runs:
                    failures.append(
                        f"{label}: invariant runs={runs!r}, expected "
                        f"{expected_invariant_runs}"
                    )
                if calls != expected_calls:
                    failures.append(
                        f"{label}: invariant calls={calls!r}, expected "
                        f"{expected_calls} "
                        f"({expected_invariant_runs}x{expected_invariant_depth})"
                    )
                require_typed_zero(
                    details, "failed_corpus_replays", label, failures
                )
                require_typed_zero(details, "reverts", label, failures)

    expected_counts = EXPECTED_MODE_COUNTS[mode]
    for count_name, expected in expected_counts.items():
        if counts[count_name] != expected:
            failures.append(
                f"{mode} Forge run has {counts[count_name]} {count_name}, "
                f"expected exactly {expected}"
            )

    expected_fuzz = EXPECTED_FUZZ_TESTS if mode == "full" else frozenset()
    if seen_fuzz != expected_fuzz:
        failures.append(
            f"{mode} Forge fuzz-test identity drift: "
            f"missing={sorted(expected_fuzz - seen_fuzz)}, "
            f"extra={sorted(seen_fuzz - expected_fuzz)}"
        )
    if seen_invariants != EXPECTED_INVARIANT_TESTS:
        failures.append(
            f"{mode} Forge invariant identity drift: "
            f"missing={sorted(EXPECTED_INVARIANT_TESTS - seen_invariants)}, "
            f"extra={sorted(seen_invariants - EXPECTED_INVARIANT_TESTS)}"
        )
    expected_skips = ALLOWED_SKIPS if mode == "full" else frozenset()
    if seen_skips != expected_skips:
        failures.append(
            f"{mode} Forge skip identity drift: "
            f"missing={sorted(expected_skips - seen_skips)}, "
            f"extra={sorted(seen_skips - expected_skips)}"
        )
    manifest_digest = result_manifest_digest(manifest_rows)
    expected_manifest = (
        expected_manifest_sha256
        if expected_manifest_sha256 is not None
        else EXPECTED_RESULT_MANIFEST_SHA256[mode]
    )
    if manifest_digest != expected_manifest:
        failures.append(
            f"{mode} Forge exact label/status/kind manifest drift: "
            f"sha256={manifest_digest}, expected {expected_manifest}"
        )
    return failures, counts


def self_test() -> int:
    full_results: dict[str, Any] = {
        f"test_unit_{index}()": {
            "status": "Success",
            "reason": None,
            "kind": {"Unit": {"gas": 1}},
        }
        for index in range(
            EXPECTED_MODE_COUNTS["full"]["tests"]
            - len(EXPECTED_FUZZ_TESTS)
            - len(EXPECTED_INVARIANT_TESTS)
            - len(ALLOWED_SKIPS)
        )
    }
    clean: dict[str, Any] = {
        "test/Example.t.sol:ExampleTest": {"test_results": full_results}
    }
    for label in EXPECTED_FUZZ_TESTS:
        suite_name, test_name = label.split("::", 1)
        clean.setdefault(suite_name, {"test_results": {}})["test_results"][
            test_name
        ] = {
            "status": "Success",
            "reason": None,
            "kind": {
                "Fuzz": {"runs": 256, "failed_corpus_replays": 0}
            },
        }
    for label in EXPECTED_INVARIANT_TESTS:
        suite_name, test_name = label.split("::", 1)
        clean.setdefault(suite_name, {"test_results": {}})["test_results"][
            test_name
        ] = {
            "status": "Success",
            "reason": None,
            "kind": {
                "Invariant": {
                    "runs": 256,
                    "calls": 128000,
                    "reverts": 0,
                    "failed_corpus_replays": 0,
                }
            },
        }
    for label in ALLOWED_SKIPS:
        suite_name, test_name = label.split("::", 1)
        clean.setdefault(suite_name, {"test_results": {}})["test_results"][
            test_name
        ] = {
            "status": "Skipped",
            "reason": None,
            "kind": {"Unit": {"gas": 1}},
        }

    def fixture_manifest(payload: dict[str, Any]) -> str:
        rows: list[list[object]] = []
        for suite_name, suite in payload.items():
            for test_name, result in suite["test_results"].items():
                kind_name = next(iter(result["kind"]))
                rows.append([
                    f"{suite_name}::{test_name}",
                    result["status"],
                    kind_name,
                ])
        return result_manifest_digest(rows)

    full_manifest = fixture_manifest(clean)

    def validate_full(payload: object) -> tuple[list[str], dict[str, int]]:
        return validate_results(
            payload,
            mode="full",
            expected_fuzz_runs=256,
            expected_invariant_runs=256,
            expected_invariant_depth=500,
            expected_manifest_sha256=full_manifest,
        )

    failures, _ = validate_full(clean)
    if failures:
        print(f"FAIL: clean Forge fixture rejected: {failures}", file=sys.stderr)
        return 1

    corruptions: list[tuple[str, object]] = [
        ("empty result", {}),
        (
            "failed test",
            {
                **json.loads(json.dumps(clean)),
                "test/Failure.t.sol:FailureTest": {
                    "test_results": {
                        "test_failure()": {
                            "status": "Failure",
                            "reason": "expected negative control",
                            "kind": {"Unit": {"gas": 1}},
                        }
                    }
                },
            },
        ),
        (
            "unexpected skipped test",
            {
                **json.loads(json.dumps(clean)),
                "test/Skip.t.sol:SkipTest": {
                    "test_results": {
                        "test_unpinned_skip()": {
                            "status": "Skipped",
                            "reason": None,
                            "kind": {"Unit": {"gas": 1}},
                        }
                    }
                },
            },
        ),
    ]
    identity_drift = json.loads(json.dumps(clean))
    invariant_label = sorted(EXPECTED_INVARIANT_TESTS)[0]
    suite_name, test_name = invariant_label.split("::", 1)
    del identity_drift[suite_name]["test_results"][test_name]
    identity_drift["test/Example.t.sol:ExampleTest"]["test_results"][
        "replacement_unit()"
    ] = {
        "status": "Success",
        "reason": None,
        "kind": {"Unit": {"gas": 1}},
    }
    corruptions.append(("coverage identity drift", identity_drift))
    unit_identity_drift = json.loads(json.dumps(clean))
    unit_tests = unit_identity_drift[
        "test/Example.t.sol:ExampleTest"
    ]["test_results"]
    unit_tests["replacement_weaker_unit()"] = unit_tests.pop("test_unit_0()")
    corruptions.append(
        ("one-for-one unit identity substitution", unit_identity_drift)
    )
    for label, payload in corruptions:
        detected, _ = validate_full(payload)
        if not detected:
            print(f"FAIL: {label} was accepted", file=sys.stderr)
            return 1

    for label, field, value in (
        ("reduced fuzz runs", "runs", 1),
        ("failed fuzz corpus replay", "failed_corpus_replays", 1),
    ):
        mutated = json.loads(json.dumps(clean))
        fuzz_label = sorted(EXPECTED_FUZZ_TESTS)[0]
        suite_name, test_name = fuzz_label.split("::", 1)
        mutated[suite_name]["test_results"][test_name]["kind"]["Fuzz"][
            field
        ] = value
        detected, _ = validate_full(mutated)
        if not detected:
            print(f"FAIL: {label} was accepted", file=sys.stderr)
            return 1

    for label, field, value in (
        ("missing fuzz corpus replay field", "failed_corpus_replays", None),
        ("non-integer fuzz corpus replay zero", "failed_corpus_replays", False),
    ):
        mutated = json.loads(json.dumps(clean))
        fuzz_label = sorted(EXPECTED_FUZZ_TESTS)[0]
        suite_name, test_name = fuzz_label.split("::", 1)
        details = mutated[suite_name]["test_results"][test_name]["kind"]["Fuzz"]
        if value is None:
            del details[field]
        else:
            details[field] = value
        detected, _ = validate_full(mutated)
        if not detected:
            print(f"FAIL: {label} was accepted", file=sys.stderr)
            return 1

    for label, field, value in (
        ("reduced invariant runs", "runs", 1),
        ("reduced invariant calls", "calls", 256),
        ("failed invariant corpus replay", "failed_corpus_replays", 1),
        ("invariant call reverted", "reverts", 1),
    ):
        mutated = json.loads(json.dumps(clean))
        invariant_label = sorted(EXPECTED_INVARIANT_TESTS)[0]
        suite_name, test_name = invariant_label.split("::", 1)
        mutated[suite_name]["test_results"][test_name]["kind"]["Invariant"][
            field
        ] = value
        detected, _ = validate_full(mutated)
        if not detected:
            print(f"FAIL: {label} was accepted", file=sys.stderr)
            return 1

    for label, field in (
        ("missing invariant corpus replay field", "failed_corpus_replays"),
        ("missing invariant reverts field", "reverts"),
    ):
        mutated = json.loads(json.dumps(clean))
        invariant_label = sorted(EXPECTED_INVARIANT_TESTS)[0]
        suite_name, test_name = invariant_label.split("::", 1)
        del mutated[suite_name]["test_results"][test_name]["kind"]["Invariant"][
            field
        ]
        detected, _ = validate_full(mutated)
        if not detected:
            print(f"FAIL: {label} was accepted", file=sys.stderr)
            return 1

    invariant_clean: dict[str, Any] = {}
    for invariant_label in EXPECTED_INVARIANT_TESTS:
        suite_name, test_name = invariant_label.split("::", 1)
        invariant_clean.setdefault(
            suite_name, {"test_results": {}}
        )["test_results"][test_name] = json.loads(json.dumps(
            clean[suite_name]["test_results"][test_name]
        ))
    # The invariant contract also carries plain unit tests (handler liveness
    # checks); the invariant-mode run counts them, so the fixture does too.
    invariant_suite = sorted(EXPECTED_INVARIANT_TESTS)[0].split("::", 1)[0]
    for index in range(
        EXPECTED_MODE_COUNTS["invariants"]["tests"] - len(EXPECTED_INVARIANT_TESTS)
    ):
        invariant_clean[invariant_suite]["test_results"][
            f"test_handler_unit_{index}()"
        ] = {
            "status": "Success",
            "reason": None,
            "kind": {"Unit": {"gas": 1}},
        }
    invariant_failures, _ = validate_results(
        invariant_clean,
        mode="invariants",
        expected_fuzz_runs=256,
        expected_invariant_runs=256,
        expected_invariant_depth=500,
        expected_manifest_sha256=fixture_manifest(invariant_clean),
    )
    if invariant_failures:
        print(
            "FAIL: clean invariant-only Forge fixture rejected: "
            f"{invariant_failures}",
            file=sys.stderr,
        )
        return 1

    invariant_missing_replay = json.loads(json.dumps(invariant_clean))
    invariant_label = sorted(EXPECTED_INVARIANT_TESTS)[0]
    suite_name, test_name = invariant_label.split("::", 1)
    del invariant_missing_replay[suite_name]["test_results"][test_name][
        "kind"
    ]["Invariant"]["failed_corpus_replays"]
    invariant_negative, _ = validate_results(
        invariant_missing_replay,
        mode="invariants",
        expected_fuzz_runs=256,
        expected_invariant_runs=256,
        expected_invariant_depth=500,
        expected_manifest_sha256=fixture_manifest(invariant_clean),
    )
    if not invariant_negative:
        print(
            "FAIL: invariant-only missing replay field was accepted",
            file=sys.stderr,
        )
        return 1

    print(
        "check_forge_results --self-test PASS "
        "(full+invariant controls; empty/failure/filter/exact-manifest/"
        "reduced-count/replay/revert negatives rejected)"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", nargs="?", type=Path)
    parser.add_argument("--mode", choices=("full", "invariants"), default="full")
    parser.add_argument("--expected-fuzz-runs", type=int, default=256)
    parser.add_argument("--expected-invariant-runs", type=int, default=256)
    parser.add_argument("--expected-invariant-depth", type=int, default=500)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if args.result is None:
        print("ERROR: result JSON path is required", file=sys.stderr)
        return 2
    if min(
        args.expected_fuzz_runs,
        args.expected_invariant_runs,
        args.expected_invariant_depth,
    ) <= 0:
        print("ERROR: expected execution counts must be positive", file=sys.stderr)
        return 2
    try:
        payload = json.loads(
            args.result.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"ERROR: cannot load Forge JSON: {error}", file=sys.stderr)
        return 2

    failures, counts = validate_results(
        payload,
        mode=args.mode,
        expected_fuzz_runs=args.expected_fuzz_runs,
        expected_invariant_runs=args.expected_invariant_runs,
        expected_invariant_depth=args.expected_invariant_depth,
    )
    if failures:
        print(f"FAIL: {len(failures)} Forge evidence error(s):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        "OK: Forge evidence complete "
        f"(mode={args.mode}, tests={counts['tests']}, "
        f"fuzz={counts['fuzz']}@{args.expected_fuzz_runs}, "
        f"invariants={counts['invariants']}@"
        f"{args.expected_invariant_runs}x{args.expected_invariant_depth}, "
        f"pinned-skips={counts['skips']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
