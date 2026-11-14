#!/usr/bin/env python3
"""Rejection controls for recorded evidence; no compiler or solver is run.

Transport tests edit temporary archive copies. Semantic tests deliberately
mutate already-authenticated data in memory, so a passing digest check cannot
hide a missing semantic check.
"""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import check
import inputs
import replay
from common import Evidence, HERE, Rejected, input_contract, read_json, sha


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = input_contract()
        cls.evidence = Evidence()
        cls.evidence.authenticate_all()
        cls.root = Path(cls.contract['historical_root'])
        cls.info = check.runtime(cls.evidence, cls.root)
        cls.collector = check.protocol(cls.evidence, cls.root.parent.parent)
        cls.parser = cls.collector.partition
        cls.properties = cls.evidence.json(cls.root / 'census/properties.json')
        cls.required, cls.output_assertion = check.roots(cls.properties, cls.parser, 'positive')
        cls.parts = cls.evidence.json(cls.root / 'root-probe-unwind65/selection.json')['parts']
        cls.root_log = cls.evidence.raw(cls.root / 'root-probe-unwind65/run/command.log').decode()
        cls.tail_log = cls.evidence.raw(cls.root / 'tail-probe-v1/run/command.log').decode()
        cls.root_report = cls.parser.parse_report(cls.root_log, cls.properties, cls.parts[0], 10)
        cls.tails = cls.collector.parse_partial(cls.tail_log, cls.properties, cls.parts[1:], 10)

    def overlay(self, path, value):
        """Bypass transport authentication only for semantic negative tests."""
        evidence = Evidence()
        evidence.cache = {**self.evidence.cache, str(path): json.dumps(value).encode()}
        return evidence

    def parse(self, text, code=10):
        return self.parser.parse_report(text, self.properties, self.parts[0], code)

    def compose(self, root=None, tails=None):
        return self.collector.compose_reports(self.properties, self.parts, list(range(19)),
            self.root_report if root is None else root, self.tails if tails is None else tails, self.required)

    def test_all_original_evidence(self):
        result = check.check()
        self.assertTrue(result['recorded_evidence_complete'])
        self.assertFalse(result['solver_replay'])
        self.assertFalse(result['full_Digest_correspondence'])
        self.assertEqual(len(result['cases']), 4)

    def test_coherent_input_contract_change_cannot_repin_itself(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp)
            (profile / 'frozen').mkdir()
            contract = copy.deepcopy(self.contract)
            contract['case_source_sha256']['positive'] = '0' * 64
            (profile / 'frozen/input-contract.json').write_text(json.dumps(contract))
            with self.assertRaisesRegex(Rejected, 'input contract changed'):
                input_contract(profile)

    def test_coherent_archive_repinning_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp)
            (profile / 'frozen').mkdir()
            index = copy.deepcopy(self.evidence.index)
            next(iter(index.values()))['raw_sha256'] = '0' * 64
            (profile / 'frozen/evidence-index.json').write_text(json.dumps(index))
            with self.assertRaisesRegex(Rejected, 'evidence index changed'):
                Evidence(profile)

    def test_corrupt_archive_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp)
            (profile / 'frozen').mkdir()
            shutil.copyfile(HERE / 'frozen/evidence-index.json', profile / 'frozen/evidence-index.json')
            original = str(self.root / 'root-probe-unwind65/run/command.log')
            path = profile / self.evidence.index[original]['artifact']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((HERE / self.evidence.index[original]['artifact']).read_bytes() + b'changed')
            with self.assertRaisesRegex(Rejected, 'evidence archive changed'):
                Evidence(profile).raw(original)

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'data.json'
            path.write_text('{"exit": 1, "exit": 0}')
            with self.assertRaisesRegex(Rejected, 'duplicate JSON key'):
                read_json(path)

    def test_prepared_source_and_forged_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'case'
            inputs.prepare(path)
            self.assertEqual(len(inputs.check_prepared(path)), 563)
            source = path / 'inputs/sha2-probe/src/core_api.rs'
            source.write_text(source.read_text().replace('position < 64', 'position < 63'))
            receipt = read_json(path / 'prepared.json')
            receipt['files'][source.relative_to(path).as_posix()] = sha(source)
            (path / 'prepared.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(Rejected, 'prepared source changed'):
                inputs.check_prepared(path)

    def test_extra_build_script_or_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'case'
            inputs.prepare(path)
            extra = path / 'inputs/sha2-probe/build.rs'
            extra.write_text('fn main() {}\n')
            with self.assertRaisesRegex(Rejected, 'inventory changed'):
                inputs.check_prepared(path)
            extra.unlink()
            extra.symlink_to(path / 'inputs/sha2-probe/src/core_api.rs')
            with self.assertRaisesRegex(Rejected, 'symlink'):
                inputs.check_prepared(path)

    def test_missing_or_relocated_semantic_root_rejected(self):
        for field, value in [('line', '188'), ('file', 'other.rs'), ('function', 'another_harness')]:
            properties = copy.deepcopy(self.properties)
            properties[self.output_assertion]['sourceLocation'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, 'semantic root'):
                check.roots(properties, self.parser, 'positive')

    def test_missing_duplicate_or_unknown_report_property_rejected(self):
        line = next(row for row in self.root_log.splitlines(keepends=True)
                    if row.startswith('[' + self.output_assertion + ']'))
        for replacement in ['', line + line, line.replace(self.output_assertion, 'unknown.assertion.1')]:
            with self.subTest(replacement=replacement[:80]), self.assertRaises(ValueError):
                self.parse(self.root_log.replace(line, replacement, 1))

    def test_inline_source_location_must_match_census(self):
        old = 'file library/kani_core/src/mem_init.rs line 587'
        self.assertIn(old, self.root_log)
        with self.assertRaises(ValueError):
            self.parse(self.root_log.replace(old, 'file unrelated.rs line 587', 1))

    def test_report_needs_terminal_summary_and_matching_exit(self):
        for text, code in [(self.root_log.rsplit('VERIFICATION ', 1)[0], 10),
                           (self.root_log, 0), (self.root_log, -9), ('compiler setup failed\n', 1)]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.parse(text, code)

    def test_unreachable_cover_cannot_pass_positive_semantics(self):
        name = next(n for n in self.required if self.properties[n]['class'] == 'cover')
        report = copy.deepcopy(self.root_report)
        report['rows'][name] = 'SUCCESS'
        with self.assertRaisesRegex(ValueError, 'required root unreachable or wrong'):
            self.parser.semantic_check(self.properties, report, self.required)

    def test_ordinary_failure_cannot_be_treated_as_a_cover(self):
        report = copy.deepcopy(self.root_report)
        report['rows'][self.output_assertion] = 'FAILURE'
        with self.assertRaises(ValueError):
            self.parser.semantic_check(self.properties, report, self.required)

    def test_positive_dynamic_unwind_must_succeed_in_every_partition(self):
        for part in [0, 9, 18]:
            reports = copy.deepcopy([self.root_report, *self.tails])
            name = next(iter(reports[part]['dynamic']))
            reports[part]['rows'][name] = 'FAILURE'
            with self.subTest(part=part), self.assertRaises(ValueError):
                self.compose(reports[0], reports[1:])

    def test_dynamic_inventory_must_agree_across_partitions(self):
        tails = copy.deepcopy(self.tails)
        name = next(iter(tails[0]['dynamic']))
        del tails[0]['rows'][name]
        del tails[0]['dynamic'][name]
        with self.assertRaises(ValueError):
            self.compose(tails=tails)

    def test_partial_tail_cannot_claim_complete_proof(self):
        with self.assertRaisesRegex(ValueError, 'missing tail group'):
            self.compose(tails=self.tails[:-1])
        truncated = self.tail_log.rsplit('PQ1-SCOPED-PARTIAL-COMPLETE', 1)[0]
        with self.assertRaises(ValueError):
            self.collector.parse_partial(truncated, self.properties, self.parts[1:], 10)

    def test_partition_coverage_and_pair_integrity(self):
        for mutation in ['missing', 'duplicate', 'split']:
            parts = copy.deepcopy(self.parts)
            if mutation == 'missing':
                parts[-1].pop()
            elif mutation == 'duplicate':
                parts[-1].append(parts[1][0])
            else:
                probe = next(n for n in self.required if self.properties[n]['class'] == 'reachability_check')
                parts[0].remove(probe)
                parts[-1].append(probe)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.parser.validate_partition(self.properties, parts, list(self.required))

    def test_negative_control_needs_exact_intended_failure(self):
        case = self.root / 'controls-v1/little-endian'
        properties = self.evidence.json(case / 'census/properties.json')
        required, intended = check.roots(properties, self.parser, 'little-endian')
        selected = self.evidence.json(case / 'partitioned-v1/selection.json')['parts'][0]
        raw = self.evidence.raw(case / 'partitioned-v1/root/run/command.log').decode()
        original = self.parser.parse_report(raw, properties, selected, 10)
        for change in ['missing', 'extra']:
            report = copy.deepcopy(original)
            name = intended if change == 'missing' else next(n for n in required
                    if properties[n]['class'] == 'assertion' and n != intended)
            report['rows'][name] = 'SUCCESS' if change == 'missing' else 'FAILURE'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parser.semantic_check(properties, report, required, intended)

    def test_different_runtime_or_unfinished_adoption_rejected(self):
        path = self.root.parent / 'combined-digest-private-adoption-v1.json'
        for role in ['compiler', 'driver', 'backend', 'incomplete']:
            adoption = self.evidence.json(path)
            if role == 'incomplete':
                adoption['mandatory_gaps'] = ['review unavailable']
            else:
                adoption[role]['sha256'] = '0' * 64
            with self.subTest(role=role), self.assertRaises(Rejected):
                check.runtime(self.overlay(path, adoption), self.root)

    def test_later_stage_cannot_change_tools_or_prepared_program(self):
        path = self.root / 'tail-probe-v1/pins.json'
        original = self.evidence.json(path)
        for key in [self.info[2]['backend']['path'], str(self.root / 'census/prepared.out')]:
            pins = {**original, key: '0' * 64}
            with self.subTest(key=key), self.assertRaisesRegex(Rejected, 'stage source/tool/artifact'):
                check.pinned_stage(self.evidence, pins, {key: original[key]})

    def test_execution_needs_exact_bounds_clean_exit_and_environment(self):
        folder = self.root / 'root-probe-unwind65'
        spec = self.evidence.json(folder / 'spec.json')
        command = spec['command'][spec['command'].index('--') + 1:]
        variants = [('spec.json', 'active_seconds', 999),
                    ('spec.json', 'host_floor', 0),
                    ('spec.json', 'environment', {}),
                    ('run/execution.json', 'execution_complete', False),
                    ('run/execution.json', 'exit', -9),
                    ('run/execution.json', 'seconds', 0),
                    ('run/worker.json', 'stop', 'active deadline'),
                    ('run/worker.json', 'zero_descendants', False),
                    ('run/worker.json', 'cleanup_on_time', False),
                    ('run/observation.json', 'proof_accepted', True)]
        for filename, key, value in variants:
            path = folder / filename
            record = self.evidence.json(path)
            record[key] = value
            with self.subTest(file=filename, field=key), self.assertRaises(Rejected):
                check.execution(self.overlay(path, record), folder, command, 180, (170, 175),
                    16*1024**2, spec['environment'], self.root, self.info[0], {0, 10})

    def test_replay_relocation_preserves_checks_and_resource_bounds(self):
        for kind in check.CASES:
            case, folders, parts = replay.selected_queries(self.evidence, self.contract, kind)
            for index, folder in enumerate(folders):
                original = self.evidence.json(folder / 'spec.json')
                command = original['command']
                old_groups = (Path(command[command.index('--pq1-scoped-partitions') + 1])
                              if '--pq1-scoped-partitions' in command else None)
                output = Path('/unused/replay')
                relocated = replay.relocate_spec(original, case / 'census/prepared.out', old_groups,
                                                 output, 'phase', 123)
                mapping = {str(case / 'census/prepared.out'): str(output / 'prepared.out')}
                if old_groups is not None:
                    mapping[str(old_groups)] = str(output / 'groups.json')
                with self.subTest(case=kind, phase=index):
                    self.assertEqual(relocated['command'], [mapping.get(arg, arg) for arg in command])
                    for key in ['active_seconds', 'aggregate_cap', 'workspace', 'host_floor', 'reserve',
                                'storage_root']:
                        self.assertEqual(relocated[key], original[key])
                    self.assertEqual(relocated['environment']['RUSTUP_HOME'],
                                     original['environment']['RUSTUP_HOME'])
                    self.assertEqual(relocated['environment']['LD_LIBRARY_PATH'],
                                     original['environment']['LD_LIBRARY_PATH'])
                    self.assertIn('--unwinding-assertions', relocated['command'])


if __name__ == '__main__':
    unittest.main()
