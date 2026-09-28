#!/usr/bin/env python3
"""Offline controls for exact Kani mutation attribution and source restoration."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_kani_mutations as runner


def output(name='proofs::selected', passed=True):
    return (f'Checking harness {name}...\nVERIFICATION:- '
            + ('SUCCESSFUL' if passed else 'FAILED')
            + f'\nComplete - {int(passed)} successfully verified harnesses, '
            + f'{int(not passed)} failures, 1 total.\n')


class AttributionTests(unittest.TestCase):
    def test_complete_exact_verdicts(self):
        self.assertEqual(runner.classify_kani(output(), 0, 'proofs::selected'), 'kani_passes')
        self.assertEqual(runner.classify_kani(output(passed=False), 1, 'proofs::selected'), 'kani_fails')

    def test_collision_wrong_identity_truncation_and_crash(self):
        cases = [(output() + output('proofs::unrelated_selected', False), 1),
                 (output('proofs::unrelated_selected', False), 1),
                 ('VERIFICATION:- FAILED\n', 1),
                 (output(passed=False), -9), (output(passed=False), 2),
                 (output(passed=False), 0), (output(), 1),
                 (output().replace('1 total', '2 total'), 0)]
        for text, rc in cases:
            with self.subTest(rc=rc, text=text), self.assertRaises(runner.HarnessError):
                runner.classify_kani(text, rc, 'proofs::selected')

    def test_command_selects_exact_path(self):
        with patch.object(runner.subprocess, 'run') as run:
            run.return_value.stdout = output()
            run.return_value.stderr = ''
            run.return_value.returncode = 0
            runner.run_kani('crate', 'proofs::selected', [])
            self.assertEqual(run.call_args.args[0][-5:],
                             ['--harness', 'proofs::selected', '--exact', '--output-format', 'regular'])

    def test_complete_failure_plus_tool_error_gets_no_credit(self):
        for diagnostic in ('error: post-verification tool failure\n',
                           'error[E0001]: compiler failure\n',
                           '\x1b[31merror:\x1b[0m backend failure\n',
                           'FATAL ERROR: solver failure\n',
                           "thread 'main' panicked at backend.rs:1\n"):
            for text in (diagnostic + output(passed=False), output(passed=False) + diagnostic):
                with self.subTest(diagnostic=diagnostic), self.assertRaisesRegex(runner.HarnessError, 'fatal tool'):
                    runner.classify_kani(text, 1, 'proofs::selected')

    def test_baseline_failure_gets_no_credit_and_never_mutates(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, 'REPO_ROOT', Path(temp)):
            path = Path(temp) / 'source.rs'
            path.write_text('original')
            m = dict(id='case', file='source.rs', find='original', replace='mutant',
                     crate='crate', harness_path='proofs::selected', expect='kani_fails')
            with patch.object(runner, 'run_kani', return_value=('kani_fails', '')) as run:
                with self.assertRaisesRegex(runner.HarnessError, 'baseline'):
                    runner.apply_and_test(m)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(path.read_text(), 'original')

    def test_mutation_is_bracketed_by_baseline_and_restore(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, 'REPO_ROOT', Path(temp)):
            path = Path(temp) / 'source.rs'
            path.write_text('original')
            m = dict(id='case', file='source.rs', find='original', replace='mutant',
                     crate='crate', harness_path='proofs::selected', expect='kani_fails')
            seen = []
            def verify(*args):
                seen.append(path.read_text())
                return ('kani_passes' if len(seen) == 1 else 'kani_fails', '')
            with patch.object(runner, 'run_kani', side_effect=verify):
                self.assertTrue(runner.apply_and_test(m)[0])
            self.assertEqual(seen, ['original', 'mutant'])
            self.assertEqual(path.read_text(), 'original')
            with patch.object(runner, 'run_kani', side_effect=[('kani_passes', ''), runner.HarnessError('crash')]):
                with self.assertRaises(runner.HarnessError):
                    runner.apply_and_test(m)
            self.assertEqual(path.read_text(), 'original')

    def test_real_manifest_and_removed_canary_or_overridden_selection(self):
        muts = json.loads(runner.MANIFEST.read_text())['mutations']
        runner.validate_manifest(muts)
        with self.assertRaises(runner.HarnessError):
            runner.validate_manifest([m for m in muts if m['id'] != 'canary'])
        for change in ({'expect': 'kani_passes'}, {'harness_path': 'wrong::name'},
                       {'z_flags': ['--harness', 'unrelated']}, {'z_flags': ['--only-codegen']}):
            bad = copy.deepcopy(muts)
            bad[0].update(change)
            with self.assertRaises(runner.HarnessError):
                runner.validate_manifest(bad)

    def test_heavy_feature_cannot_enter_nightly_or_lose_its_flag(self):
        muts = json.loads(runner.MANIFEST.read_text())['mutations']
        for change in ({'tier': 'default'}, {'tier': 'full'}, {'z_flags': []},
                       {'tier': 'default', 'z_flags': ['--features', 'pqsigner-tx/kani-heavy']}):
            bad = copy.deepcopy(muts)
            next(m for m in bad if m['tier'] == 'heavy').update(change)
            with self.assertRaisesRegex(runner.HarnessError, 'local heavy tier'):
                runner.validate_manifest(bad)


if __name__ == '__main__':
    unittest.main()
