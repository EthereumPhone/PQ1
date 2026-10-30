"""Adversarial controls for the recorded-evidence and reconstruction gate."""
import copy
import gzip
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import check
import inputs


class EvidenceGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = check.sources()

    def text(self, case):
        return gzip.decompress((check.HERE / f'frozen/logs/{case}.log.gz').read_bytes()).decode()

    def rebind(self, config, case, text):
        _, rows = check.padding.properties(text)
        config['cases'][case]['census_sha256'] = check.census_digest(rows)
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
