#!/usr/bin/env python3
"""Behavioral controls for the evidence and reconstruction gates."""
import copy
import gzip
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import streaming as gate
from prepare_streaming import prepare, check_prepared


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = gate.sources()
        cls.logs = {case: gzip.decompress((gate.HERE / f'frozen/logs/{case}.log.gz').read_bytes()).decode()
                    for case in gate.CASES}

    def check(self, case='positive', text=None, code=None, stop=None, config=None):
        return gate.accept(config or self.config, case, self.logs[case] if text is None else text,
                           self.config['cases'][case]['expected_exit'] if code is None else code, stop)

    def test_all_recorded_cases(self):
        self.assertEqual(len(gate.recorded(self.config)), 3)

    def test_timeout_is_not_a_control(self):
        for case in gate.CASES:
            with self.subTest(case=case), self.assertRaises(gate.Rejected):
                self.check(case, stop='active-time limit')

    def test_setup_failure_is_not_a_control(self):
        for case in gate.CASES:
            with self.subTest(case=case), self.assertRaises(gate.Rejected):
                self.check(case, code=101)

    def test_mutant_must_fail(self):
        for case in gate.CASES[1:]:
            with self.subTest(case=case), self.assertRaises(gate.Rejected):
                self.check(case, self.logs[case].replace('- Status: FAILURE', '- Status: SUCCESS'))

    def test_safety_failure_is_not_semantic_control(self):
        case = 'wrong-remainder'
        text = self.logs[case].replace('- Status: FAILURE', '- Status: SUCCESS')
        text = text.replace('- Status: SUCCESS', '- Status: FAILURE', 1)
        with self.assertRaises(gate.Rejected):
            self.check(case, text)

    def test_unreachable_semantic_assertion_refused(self):
        text = self.logs['positive'].replace('assertion failed: byte == expected', 'wrong description')
        with self.assertRaises(gate.Rejected):
            self.check(text=text)
        marker = 'observe_step.assertion.10\n'
        before, after = self.logs['positive'].split(marker, 1)
        with self.assertRaises(gate.Rejected):
            self.check(text=before + marker + after.replace('- Status: SUCCESS', '- Status: UNREACHABLE', 1))

    def test_cover_must_reach_source_case(self):
        marker = gate.HARNESS + '.cover.4\n'
        before, after = self.logs['positive'].split(marker, 1)
        with self.assertRaises(gate.Rejected):
            self.check(text=before + marker + after.replace('- Status: SATISFIED', '- Status: UNSATISFIABLE', 1))

    def test_false_duplicate_is_audited_exactly(self):
        marker = gate.HARNESS + '.cover.3\n'
        before, after = self.logs['positive'].split(marker, 1)
        with self.assertRaises(gate.Rejected):
            self.check(text=before + marker + after.replace('- Status: UNSATISFIABLE', '- Status: SATISFIED', 1))

    def test_missing_or_duplicate_verdict(self):
        for tail in ['', 'VERIFICATION:- SUCCESSFUL\nVERIFICATION:- SUCCESSFUL']:
            with self.subTest(tail=tail), self.assertRaises(gate.Rejected):
                self.check(text=self.logs['positive'].replace('VERIFICATION:- SUCCESSFUL', tail))

    def test_missing_property(self):
        text = self.logs['positive'].replace('observe_step.assertion.10', 'unrelated.assertion.10')
        with self.assertRaises(gate.Rejected):
            self.check(text=text)

    def test_runtime_inventory_and_flags(self):
        original = gate.read_json(gate.HERE / 'frozen/receipts/positive-result.json')
        for mutation in ('tool', 'flag', 'solver', 'environment'):
            result = copy.deepcopy(original)
            if mutation == 'tool':
                del result['tool_sha256'][next(iter(result['tool_sha256']))]
            elif mutation == 'flag':
                result['command'].append('--no-unwinding-checks')
            elif mutation == 'solver':
                result['solver_requested'] = False
            else:
                result['environment']['RUSTFLAGS'] += ' --cfg unsafe_assumption'
            with self.subTest(mutation=mutation), self.assertRaises(gate.Rejected):
                gate.recorded_runtime(result)

    def test_rehashed_old_log_cannot_bless_changed_harness(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / 'profile'
            shutil.copytree(gate.HERE, profile)
            lib = profile / 'frozen/lib.rs'
            lib.write_text(lib.read_text().replace('len <= 192', 'len <= 191'))
            config = gate.read_json(profile / 'profile.json')
            config['frozen_sha256']['frozen/lib.rs'] = gate.sha(lib)
            (profile / 'profile.json').write_text(json.dumps(config))
            with self.assertRaises(gate.Rejected):
                gate.sources(profile)

    def test_reconstruction_rejects_source_and_inventory_forgery(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'inputs'
            prepare(output)
            self.assertGreater(len(check_prepared(output)), 100)
            path = output / 'vendor/block-buffer-0.10.4/src/lib.rs'
            path.write_text(path.read_text().replace('input = right;', 'input = left;'))
            record = gate.read_json(output / 'prepared.json')
            record['files']['vendor/block-buffer-0.10.4/src/lib.rs'] = gate.sha(path)
            (output / 'prepared.json').write_text(json.dumps(record))
            with self.assertRaises(gate.Rejected):
                check_prepared(output)

    def test_additional_build_script_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'inputs'
            prepare(output)
            (output / 'positive/build.rs').write_text('fn main() {}')
            with self.assertRaises(gate.Rejected):
                check_prepared(output)


if __name__ == '__main__':
    unittest.main()
