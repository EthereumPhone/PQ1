"""Adversarial controls for the recorded-evidence and reconstruction gate."""
import copy
import gzip
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import check
import inputs
import run


class EvidenceGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = check.sources()

    def text(self, case):
        return gzip.decompress((check.HERE / f'frozen/logs/{case}.log.gz').read_bytes()).decode()

    def rebind(self, config, case, text):
        _, rows = check.padding.properties(text)
        config['cases'][case]['census_sha256'] = check.census_digest(rows)
        config['cases'][case]['properties'] = len(rows)
        config['cases'][case]['statuses'] = dict(check.Counter(row['Status'] for row in rows.values()))
        return config

    def test_frozen_acceptance(self):
        self.assertEqual(len(check.recorded(self.config)), 6)
        self.assertEqual(check.finite(self.config)['cases'], 110)

    def test_incomplete_run_not_a_negative(self):
        with self.assertRaises(check.Rejected):
            check.accept(self.config, 'corrupt-byte', self.text('corrupt-byte'), 1, 'active elapsed cap')

    def test_wrong_assertion_even_after_census_rebinding(self):
        text = self.text('corrupt-byte').replace('proofs::actual_default_shapes.assertion.2',
                                                 'proofs::actual_default_shapes.assertion.99')
        config = self.rebind(copy.deepcopy(self.config), 'corrupt-byte', text)
        config['cases']['corrupt-byte']['failures'] = ['proofs::actual_default_shapes.assertion.99']
        with self.assertRaises(check.Rejected):
            check.accept(config, 'corrupt-byte', text, 1)

    def test_unreached_semantic_assertion_even_after_census_rebinding(self):
        text = self.text('default').replace('proofs::actual_default_shapes.assertion.2\n\t - Status: SUCCESS',
                                            'proofs::actual_default_shapes.assertion.2\n\t - Status: UNREACHABLE')
        self.assertNotEqual(text, self.text('default'))
        config = self.rebind(copy.deepcopy(self.config), 'default', text)
        with self.assertRaises(check.Rejected):
            check.accept(config, 'default', text, 0)

    def test_missing_cover_even_after_census_rebinding(self):
        text = self.text('generate').replace('Status: SATISFIED', 'Status: UNSATISFIABLE')
        config = self.rebind(copy.deepcopy(self.config), 'generate', text)
        with self.assertRaises(check.Rejected):
            check.accept(config, 'generate', text, 0)

    def test_changed_assertion_location_even_after_census_rebinding(self):
        text = self.text('generate').replace('src/lib.rs:13:9', 'src/lib.rs:14:9')
        config = self.rebind(copy.deepcopy(self.config), 'generate', text)
        with self.assertRaises(check.Rejected):
            check.accept(config, 'generate', text, 0)

    def test_duplicate_and_truncated_output(self):
        text = self.text('default')
        for invalid in (text + text, text[:text.index('SUMMARY:')]):
            with self.subTest(case=len(invalid)), self.assertRaises(check.Rejected):
                check.accept(self.config, 'default', invalid, 0)

    def test_tool_inventory_drift(self):
        receipt = check.read_json(check.HERE / 'frozen/receipts/default.json')
        receipt['tool_sha256'].pop(next(iter(receipt['tool_sha256'])))
        with self.assertRaises(check.Rejected):
            check.runtime_receipt(self.config, receipt)

    def test_recorded_command_control_and_count_edits_are_rejected(self):
        original = check.read_json
        edits = [
            ('default.json', lambda r: r['command'].__setitem__(2, '--cpu=999999')),
            ('default.json', lambda r: r['command'].__setitem__(4, '/tmp/other-kani')),
            ('corrupt-byte.json', lambda r: r.pop('control_source')),
            ('default.json', lambda r: r.__setitem__('reused_codegen_receipt_sha256', '0' * 64)),
            ('cleanup-baseline.json', lambda r: r['results'][-1].__setitem__('command', r['results'][2]['command'])),
        ]
        for filename, mutate in edits:
            def altered(path):
                value = original(path)
                if Path(path).name == filename:
                    mutate(value)
                return value
            with self.subTest(case=filename), patch.object(check, 'read_json', side_effect=altered):
                with self.assertRaises(check.Rejected):
                    if filename.startswith('cleanup'):
                        check.finite(self.config)
                    else:
                        check.recorded(self.config)
        for field, value in [('properties', 999), ('statuses', {'SUCCESS': 999})]:
            config = copy.deepcopy(self.config)
            config['cases']['default'][field] = value
            with self.subTest(field=field), self.assertRaises(check.Rejected):
                check.accept(config, 'default', self.text('default'), 0)

    def test_child_exiting_between_polls_cannot_bypass_bounds(self):
        # Surrogate child completes immediately with a genuine successful log.
        # Exercise execute(), including its acceptance/receipt path, not merely
        # the resource comparison helper. Also retain a below-bound control.
        for elapsed, allocated, expected in [(180, 0, 'active-time limit'),
                                             (181, 0, 'active-time limit'),
                                             (1, 6442450944, 'allocation limit'),
                                             (1, [0, 0, 0, 6442450944], 'allocation limit'),
                                             (179, 0, None)]:
            with self.subTest(stop=expected), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                prepared = root / 'prepared'
                prepared.mkdir()
                args = SimpleNamespace(prepared=prepared, output=root / 'out', budget_root=root,
                    case='focused-corrected', check_only=False, codegen_only=False,
                    kani_root=root / 'kani', rustup_home=root / 'rustup',
                    rustup=root / 'rustup-bin', solver_bin=root / 'solvers', compat_libs=root / 'libs')
                text = self.text('focused-corrected')
                class Completed:
                    def __init__(self, *args, **kwargs):
                        kwargs['stdout'].write(text.encode())
                        kwargs['stdout'].flush()
                    def poll(self): return 0
                    def wait(self, **kwargs): return 0
                calls = []
                def measure(*args):
                    calls.append(True)
                    if isinstance(allocated, list):
                        return allocated[min(len(calls) - 1, len(allocated) - 1)]
                    return 0 if len(calls) == 1 else allocated
                with patch.object(run, 'sources', return_value=self.config), \
                     patch.object(run, 'check_prepared', return_value={}), \
                     patch.object(run, 'runtime', return_value=(root / 'toolchain', {})), \
                     patch.object(run.padding, 'sources', return_value={'compiler': {'rust_toolchain': 'test'}}), \
                     patch.object(run, 'tool_bindings', return_value={}), \
                     patch.object(run, 'install_tools'), patch.object(run, 'check_cargo_ancestors'), \
                     patch.object(run, 'check_tool_resolution', return_value={}), \
                     patch.object(run, 'measure_allocated_bytes', side_effect=measure), \
                     patch.object(run.subprocess, 'Popen', Completed), \
                     patch.object(run.time, 'monotonic', side_effect=[0, elapsed]):
                    if expected:
                        with self.assertRaises(check.Rejected):
                            run.execute(args)
                    else:
                        run.execute(args)
                receipt = check.read_json(args.output / 'result.json')
                self.assertEqual(receipt['stop'], expected)
                self.assertEqual(receipt['proof_accepted'], expected is None)
                self.assertEqual((args.output / 'acceptance.json').exists(), expected is None)
                self.assertGreaterEqual(len(calls), 2)

    def test_reconstruction_rejects_self_reported_edits_and_extra_build_script(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'prepared'
            inputs.prepare(root)
            inputs.check_prepared(root)
            lib = root / 'inputs/generic-array/src/lib.rs'
            original = lib.read_bytes()
            lib.write_bytes(original + b'\n// changed\n')
            receipt = root / 'prepared.json'
            data = check.read_json(receipt)
            data['files']['inputs/generic-array/src/lib.rs'] = check.sha(lib)
            receipt.write_text(json.dumps(data))
            with self.assertRaises(check.Rejected):
                inputs.check_prepared(root)
            lib.write_bytes(original)
            (root / 'constructor/build.rs').write_text('fn main() {}\n')
            with self.assertRaises(check.Rejected):
                inputs.check_prepared(root)

    def test_cleanup_wrong_reason(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp) / 'profile'
            shutil.copytree(check.HERE / 'frozen', profile / 'frozen')
            log = profile / 'frozen/logs/cleanup-wrong-prefix-native.log.gz'
            raw = gzip.decompress(log.read_bytes()).replace(b'initialized-prefix drop mismatch', b'unrelated failure')
            log.write_bytes(gzip.compress(raw, mtime=0))
            path = profile / 'frozen/receipts/cleanup-wrong-prefix.json'
            receipt = check.read_json(path)
            receipt['results'][-1]['log_sha256'] = check.digest(raw)
            path.write_text(json.dumps(receipt))
            with self.assertRaises(check.Rejected):
                check.finite(self.config, profile)


if __name__ == '__main__':
    unittest.main()
