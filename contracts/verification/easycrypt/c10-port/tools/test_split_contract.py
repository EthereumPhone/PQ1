#!/usr/bin/env python3
"""Negative regression controls for the split gate's evidence contract."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import split_contract as gate


@contextmanager
def fixture():
    here = Path.cwd()
    with tempfile.TemporaryDirectory() as temp:
        os.chdir(temp)
        try:
            yield Path(temp)
        finally:
            os.chdir(here)


class ContractTests(unittest.TestCase):
    def test_proof_controls_reject_a_false_green_driver_with_optimization(self):
        with tempfile.TemporaryDirectory() as temp:
            driver = Path(temp) / 'easycrypt'
            driver.write_text('#!/bin/sh\nexit 0\n')
            driver.chmod(0o755)
            for optimize in ('0', '1', '2'):
                with self.subTest(optimize=optimize):
                    env = dict(os.environ, PATH=temp + os.pathsep + os.environ['PATH'],
                               PYTHONOPTIMIZE=optimize)
                    result = subprocess.run([sys.executable, 'tools/split_proof_controls.py'],
                                            env=env, text=True, capture_output=True, timeout=20)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('broken dependency must fail its own proof', result.stderr)
                    self.assertNotIn('OK proof controls', result.stdout)

    def test_duplicate_replacing_deleted_pin_is_rejected(self):
        with fixture() as p:
            (p / 'cert_gate_split.sh').write_text('EXPECT_PINS=2\n')
            (p / 'cert-statements-split.tsv').write_text('op:A.ec::x\tabc\nop:A.ec::x\tabc\n')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                gate.check_pins()

    def test_missing_unique_pin_is_rejected(self):
        with fixture() as p:
            (p / 'cert_gate_split.sh').write_text('EXPECT_PINS=2\n')
            (p / 'cert-statements-split.tsv').write_text('op:A.ec::x\tabc\n')
            with self.assertRaisesRegex(ValueError, 'count'):
                gate.check_pins()

    def test_path_alias_cannot_substitute_for_a_deleted_pin(self):
        with fixture() as p:
            (p / 'cert_gate_split.sh').write_text('EXPECT_PINS=2\n')
            (p / 'cert-cone-files-split.tsv').write_text('A.ec\n')
            digest = 'a' * 32
            (p / 'cert-statements-split.tsv').write_text(
                f'op:A.ec::a\t{digest}\nop:./A.ec::a\t{digest}\n')
            with patch.object(gate.stmt_digest, 'digest_op', return_value=digest):
                with self.assertRaisesRegex(ValueError, 'noncanonical'):
                    gate.check_pins()

    def test_missing_or_changed_tool_identity_is_rejected(self):
        lock = json.loads(Path('cert-toolchain-split.json').read_text())
        good = f"git-hash: {lock['easycrypt']}\nknown provers: {', '.join(lock['provers'])}\n"
        with patch.dict(os.environ, {'PQ_EASYCRYPT_IMAGE': lock['image']}):
            gate.check_toolchain(good, lock)
            for bad in ('', good.replace(lock['easycrypt'], 'unexpected'),
                        good.replace(lock['provers'][0], 'unexpected'), good + good):
                with self.assertRaises(ValueError):
                    gate.check_toolchain(bad, lock)
        with patch.dict(os.environ, {'PQ_EASYCRYPT_IMAGE': 'wrong'}):
            with self.assertRaises(ValueError):
                gate.check_toolchain(good, lock)

    def test_targets_cover_pinned_dependencies_in_order(self):
        targets = gate.targets()
        self.assertEqual(len(targets), 53)
        self.assertEqual(set(targets), set(gate.rows('cert-cone-files-split.tsv')))
        self.assertIn('base-c10-split/HashAddresses.eca', targets)
        for i, p in enumerate(targets):
            code = gate.cert_cone.strip_comments(Path(p).read_text())
            for name in gate.cert_cone.requires_of(p, code):
                q = gate.cert_cone.resolve(name)
                if q:
                    self.assertLess(targets.index(q), i)

    def test_unpinned_dependency_and_duplicate_file_are_rejected(self):
        with fixture() as p, patch.object(gate.stmt_coverage, 'roots', return_value=['base-c10-split/A.ec']):
            (p / 'base-c10-split').mkdir()
            (p / 'base-c10-split/A.ec').write_text('require import B.\n')
            (p / 'base-c10-split/B.eca').write_text('')
            pin = p / 'cert-cone-files-split.tsv'
            pin.write_text('base-c10-split/A.ec\n')
            with self.assertRaisesRegex(ValueError, 'differs'):
                gate.targets()
            pin.write_text('base-c10-split/A.ec\nbase-c10-split/A.ec\n')
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                gate.targets()


if __name__ == '__main__':
    unittest.main()
