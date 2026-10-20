#!/usr/bin/env python3
"""Fail-closed controls for the PMF scheduler and same-run receipt aggregate."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_probability as gate
import probability_execution as execution
from probability_execution import authenticate_shards, canonical, digest, judge_control


class ExecutionTests(unittest.TestCase):
    def test_worker_admission(self):
        for capacity in (0, 1, 2, 4, 12, 24, 32):
            limits = {"capacity": capacity}
            for value in ("0", "-1", "1.5", "04", "true", "33", "999999", "", " 4"):
                with self.subTest(capacity=capacity, value=value), self.assertRaises(RuntimeError):
                    execution.worker_count(value, limits)
            for requested in (1, 4, 8, 12, 16, 32):
                if requested <= capacity:
                    self.assertEqual(execution.worker_count(str(requested), limits), requested)
                else:
                    with self.assertRaises(RuntimeError):
                        execution.worker_count(str(requested), limits)
            if capacity:
                self.assertEqual(execution.worker_count("auto", limits), min(12, capacity))
            else:
                with self.assertRaises(RuntimeError):
                    execution.worker_count("auto", limits)

    def test_cli_cannot_silently_drop_controls(self):
        for args in (["--shard-count", "4"], ["--shard-count", "0"], ["--shard-count", "9"],
                     ["--shard-index", "-1"], ["--shard-index", "1"],
                     ["--aggregate", "/tmp/x", "--shard-index", "0"]):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                gate.arguments(args)
        self.assertEqual(gate.arguments([]).shard_count, 1)

    def test_real_census_partition_is_total_and_disjoint(self):
        selected = gate.cases(gate.PROJECT)
        for count in (1, 4, 8):
            shards = [execution.shard_cases(selected, i, count) for i in range(count)]
            names = [case["name"] for shard in shards for case in shard]
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(set(names), {case["name"] for case in selected})
            self.assertLessEqual(max(map(len, shards)) - min(map(len, shards)), 1)
            if count > 1:
                self.assertEqual(shards, [execution.shard_cases(list(reversed(selected)), i, count)
                                          for i in range(count)])
        with self.assertRaises(RuntimeError):
            execution.shard_cases(selected + [selected[0]], 0, 4)

    def test_negative_judging(self):
        source = "def x := 0\ntheorem checked : x = 1 := by rfl\n"
        error = {"severity": "error", "pos": {"line": 2}, "fileName": "/fixture.lean",
                 "data": "Tactic `rfl` failed: the left-hand side is not definitionally equal"}
        self.assertEqual(judge_control({"exit": 1}, json.dumps(error), source,
                                       "/fixture.lean", False), [error])
        for change in ({"pos": {"line": 1}}, {"fileName": "/other.lean"},
                       *({"data": word} for word in ("unknown constant", "unexpected token",
                          "timeout", "maximum heartbeats", "recursion depth", "stack overflow",
                          "out of memory", "failed to synthesize", "typeclass instance problem is stuck",
                          "did not reduce to"))):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                judge_control({"exit": 1}, json.dumps(error | change), source, "/fixture.lean", False)
        for code in (0, 124, -9, 2, True):
            with self.subTest(exit=code), self.assertRaises(RuntimeError):
                judge_control({"exit": code}, json.dumps(error), source, "/fixture.lean", False)
        for output in ("", "not-json", "[]"):
            with self.subTest(output=output), self.assertRaises((RuntimeError, ValueError)):
                judge_control({"exit": 1}, output, source, "/fixture.lean", False)
        with self.assertRaises(RuntimeError):
            judge_control({"exit": 0}, json.dumps(error), source, "/fixture.lean", True)
        self.assertEqual(judge_control({"exit": 0}, "", source, "/fixture.lean", True), [])

    def test_local_caller_cannot_select_receipt_reuse(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            with self.assertRaises(RuntimeError):
                execution.producer_context(gate.ROOT)
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "incomplete CI producer context"):
                execution.producer_context(gate.ROOT)


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "receipts"
        self.directory.mkdir()
        self.manifest = {"theorems": {"C10Probability.fixture": {}}}
        self.identity = {"lean_sha256": "selected-compiler", "policy": "original",
                         "manifest_file_sha256": "manifest-file"}
        self.context = {"kind": "github", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                        "commit": "a" * 40, "tree": "b" * 40}
        self.cases = [{"name": name, "expected": expected,
                       **{stage: "def x := 0\ntheorem checked : x = 0 := rfl\n"
                          for stage in execution.STAGES}}
                      for name, expected in (("negative", False), ("equivalent", True))]
        for index in range(2):
            bundle = self.directory / f"shard-{index}"
            (bundle / "controls").mkdir(parents=True)
            result = {"passed": True, "mode": "shard", "shard": [index, 2], "workers": 1,
                      "identity": self.identity, "context": self.context,
                      "manifest_sha256": "manifest-file",
                      "lean": {"path": "/tools/lean", "sha256": "selected-compiler"},
                      "missing_closure_control": True, "controls": [],
                      "closures": {"C10Probability.fixture": ["propext"]}}
            for key, name, text in (
                ("build", "build.log", "Build completed successfully\n"),
                ("audit", "axioms.log", "'C10Probability.fixture' depends on axioms: [propext]\n"),
                ("closure_canary", "closure-canary.log",
                 "'ProbabilityGateCanary.checked' depends on axioms: [ProbabilityGateCanary.addedAssumption]\n")
            ):
                (bundle / name).write_text(text)
                result[key] = {"exit": 0, "log_sha256": digest(text.encode())}
            result["closure_canary"]["rejected_as_expected"] = True
            for case in execution.shard_cases(self.cases, index, 2):
                for stage in execution.STAGES:
                    stem = case["name"] + "-" + stage
                    path = bundle / "controls" / (stem + ".lean")
                    path.write_text(case[stage])
                    passed = stage != "checked" or case["expected"]
                    errors = [] if passed else [{"severity": "error", "pos": {"line": 2},
                                                "fileName": str(path), "data": "Tactic `rfl` failed"}]
                    text = "".join(json.dumps(error) + "\n" for error in errors)
                    (bundle / "controls" / (stem + ".log")).write_text(text)
                    result["controls"].append({"name": case["name"], "stage": stage,
                        "exit": 0 if passed else 1, "source_sha256": digest(case[stage].encode()),
                        "expected_pass": passed, "command": ["/tools/lean", "--json", str(path)],
                        "log_sha256": digest(text.encode()), "errors": errors})
            (bundle / "result.json").write_bytes(canonical(result))

    def aggregate(self, producer="success"):
        return authenticate_shards(self.directory, 2, self.identity, self.context, self.cases,
                                   self.manifest, gate.check_closures, producer)

    def mutate(self, fn, index=0):
        path = self.directory / f"shard-{index}" / "result.json"
        result = json.loads(path.read_text())
        fn(result)
        path.write_bytes(canonical(result))

    def test_complete_success(self):
        self.assertEqual(self.aggregate()["jobs"], 6)

    def test_failed_cancelled_skipped_incomplete_producer(self):
        for status in ("failure", "cancelled", "skipped", "", "in_progress"):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                self.aggregate(status)

    def test_missing_and_unexpected_bundle(self):
        bundle = self.directory / "shard-0"
        renamed = self.directory / "unexpected"
        bundle.rename(renamed)
        with self.assertRaises(RuntimeError):
            self.aggregate()
        renamed.rename(bundle)
        (self.directory / "unexpected").mkdir()
        with self.assertRaises(RuntimeError):
            self.aggregate()

    def test_receipt_mutations(self):
        mutations = {
            "failed": lambda r: r.update(passed=False),
            "truthy": lambda r: r.update(passed=1),
            "not-shard": lambda r: r.update(mode="full"),
            "duplicate-shard": lambda r: r.update(shard=[1, 2]),
            "count": lambda r: r.update(shard=[0, 4]),
            "bool-index": lambda r: r.update(shard=[False, 2]),
            "stale-run": lambda r: r["context"].update(GITHUB_RUN_ID="122"),
            "stale-attempt": lambda r: r["context"].update(GITHUB_RUN_ATTEMPT="2"),
            "foreign-checkout": lambda r: r["context"].update(commit="c"*40),
            "policy": lambda r: r["identity"].update(policy="changed"),
            "compiler": lambda r: r["lean"].update(sha256="other"),
            "manifest": lambda r: r.update(manifest_sha256="other"),
            "failed-build": lambda r: r["build"].update(exit=1),
            "false-build": lambda r: r["build"].update(exit=False),
            "incomplete-closures": lambda r: r.update(closures={}),
            "missing-canary": lambda r: r.update(missing_closure_control=False),
            "canary-not-rejected": lambda r: r["closure_canary"].update(rejected_as_expected=False),
            "missing-stage": lambda r: r["controls"].pop(),
            "duplicate-stage": lambda r: r["controls"].__setitem__(1, copy.deepcopy(r["controls"][0])),
            "unexpected-stage": lambda r: r["controls"][0].update(stage="extra"),
            "unexpected-case": lambda r: r["controls"][0].update(name="extra"),
            "wrong-expectation": lambda r: r["controls"][0].update(expected_pass=False),
            "source-pin": lambda r: r["controls"][0].update(source_sha256="wrong"),
            "compiler-flags": lambda r: r["controls"][0].update(command=["/tools/lean", "--run", "x"]),
            "raw-log-pin": lambda r: r["controls"][0].update(log_sha256="wrong"),
            "reported-errors": lambda r: r["controls"][0].update(errors=[{"severity": "error"}]),
        }
        path = self.directory / "shard-0/result.json"
        original = path.read_bytes()
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                path.write_bytes(original)
                self.mutate(mutation)
                with self.assertRaises(RuntimeError):
                    self.aggregate()
        path.write_bytes(original)
        self.assertTrue(self.aggregate()["passed"])

    def test_altered_raw_bytes(self):
        bundle = self.directory / "shard-0"
        for name in ("build.log", "axioms.log", "closure-canary.log",
                     "controls/equivalent-definition.lean", "controls/equivalent-definition.log"):
            with self.subTest(file=name):
                path = bundle / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaises(RuntimeError):
                    self.aggregate()
                path.write_bytes(original)

    def test_malformed_compiler_diagnostics(self):
        bundle = self.directory / "shard-1"
        path, log = bundle / "result.json", bundle / "controls/negative-checked.log"
        result = json.loads(path.read_text())
        row = next(row for row in result["controls"] if not row["expected_pass"])
        original = log.read_text()
        malformed = [
            original.replace('"data":', '"data":"maximum heartbeats exceeded","data":', 1),
            original.replace('"line": 2', '"line":1,"line":2', 1),
            original + '{"severity":"error","severity":"information","data":"timeout"}\n',
            *(original + '{"severity":"information","unused":' + value + '}\n'
              for value in ("NaN", "Infinity", "-Infinity")),
        ]
        for text in malformed:
            with self.subTest(diagnostic=text):
                self.assertNotEqual(text, original)
                log.write_text(text)
                row["log_sha256"] = digest(text.encode())
                path.write_bytes(canonical(result))
                with self.assertRaisesRegex(
                        RuntimeError, "duplicate JSON key|non-finite JSON constant"):
                    self.aggregate()
        log.write_text(original)
        row["log_sha256"] = digest(original.encode())
        path.write_bytes(canonical(result))
        self.assertTrue(self.aggregate()["passed"])

    def test_duplicate_json_keys_and_symlink(self):
        path = self.directory / "shard-0/result.json"
        original = path.read_bytes()
        path.write_bytes(b'{"passed":false,"passed":true}')
        with self.assertRaises(RuntimeError):
            self.aggregate()
        path.write_bytes(original[:-1] + b',"invalid":NaN}')
        with self.assertRaises(RuntimeError):
            self.aggregate()
        path.write_bytes(original)
        log = self.directory / "shard-0/build.log"
        target = self.directory / "replacement"
        log.rename(target)
        log.symlink_to(target)
        with self.assertRaises(RuntimeError):
            self.aggregate()


if __name__ == "__main__":
    unittest.main()
