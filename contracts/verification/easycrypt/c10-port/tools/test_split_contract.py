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
import check_source_binding as binding


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
    def test_manual_source_binding_rejects_drift_and_missing_inputs(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = {}
            for name in binding.SOURCES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('reviewed input\n')
                sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = root / binding.PORT / 'cert-source-binding.json'
            manifest.write_text(json.dumps({'schema': 1, 'sources': sources}))
            binding.check(root)
            for name in binding.SOURCES:
                path = root / name
                path.write_text('changed input\n')
                with self.assertRaisesRegex(ValueError, 'source binding changed'):
                    binding.check(root)
                path.write_text('reviewed input\n')
            sources.pop(binding.SOURCES[0])
            manifest.write_text(json.dumps({'schema': 1, 'sources': sources}))
            with self.assertRaisesRegex(ValueError, 'source set'):
                binding.check(root)

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

    def test_identifier_alias_cannot_substitute_for_a_deleted_operator_pin(self):
        with fixture() as p:
            (p / 'cert_gate_split.sh').write_text('EXPECT_PINS=2\n')
            (p / 'cert-cone-files-split.tsv').write_text('A.ec\n')
            (p / 'A.ec').write_text('op kept : int.\nop dropped : int.\n')
            digest = gate.stmt_digest.digest_op('A.ec', 'kept')
            # These distinct keys resolve to the same declaration in the
            # textual digester. They must not replace the dropped op's pin.
            for alias in ('kept ', 'kept :', 'kept : int'):
                with self.subTest(alias=alias):
                    self.assertEqual(gate.stmt_digest.digest_op('A.ec', alias), digest)
                    (p / 'cert-statements-split.tsv').write_text(
                        f'op:A.ec::kept\t{digest}\nop:A.ec::{alias}\t{digest}\n')
                    with self.assertRaisesRegex(ValueError, 'noncanonical.*identifier'):
                        gate.check_pins()

    def test_pin_kind_prefix_does_not_create_a_second_declaration_identity(self):
        with fixture() as p:
            (p / 'cert_gate_split.sh').write_text('EXPECT_PINS=2\n')
            (p / 'cert-cone-files-split.tsv').write_text('A.ec\n')
            (p / 'A.ec').write_text('op kept : int.\n')
            digest = gate.stmt_digest.digest_op('A.ec', 'kept')
            (p / 'cert-statements-split.tsv').write_text(
                f'op:A.ec::kept\t{digest}\nA.ec::kept\t{digest}\n')
            with self.assertRaisesRegex(ValueError, 'duplicate.*declaration'):
                gate.check_pins()

    def test_shuffle_u16_magnitude_exception_is_source_and_path_exact(self):
        port = Path(__file__).resolve().parents[1]
        checker = port / 'tools/policy_cap_fence.py'
        original = (port / 'cdrafts-split/RawShuffle.ec').read_text()
        fenced = (port / 'cdrafts-split/C10DeployedScope.ec').read_text()
        manifest = (port / 'cert-quarantine-split.tsv').read_text()
        variants = {
            'unmodified arithmetic': ('RawShuffle.ec', original, True),
            'policy appended': ('RawShuffle.ec', original + '\nop policy_limit = 65536.\n', False),
            'arithmetic changed': ('RawShuffle.ec', original.replace('hi*256', 'hi*257'), False),
            'copied to another file': ('Other.ec', original, False),
            'alternate policy spelling': ('RawShuffle.ec', original + '\nop policy_limit = 2^16.\n', False),
            'whole-file substitution': ('RawShuffle.ec', 'op policy_limit = 65536.\n', False),
        }
        for name, (filename, source, expected) in variants.items():
            with self.subTest(name=name), fixture() as root:
                (root / 'cdrafts-split').mkdir()
                (root / 'cdrafts-split/C10DeployedScope.ec').write_text(fenced)
                (root / 'cert-quarantine-split.tsv').write_text(manifest)
                (root / 'cdrafts-split' / filename).write_text(source)
                result = subprocess.run([sys.executable, str(checker)],
                                        text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode == 0, expected, result.stdout + result.stderr)
                if not expected:
                    self.assertIn('FENCE Q5 deployment magnitude', result.stdout)
                # Even the exact shuffle exception cannot conceal another file's policy.
                (root / 'cdrafts-split/Policy.ec').write_text('op policy_limit = 65536.\n')
                result = subprocess.run([sys.executable, str(checker)],
                                        text=True, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('FENCE Q5 deployment magnitude', result.stdout)

    def test_targets_cover_pinned_dependencies_in_order(self):
        targets = gate.targets()
        self.assertEqual(len(targets), 213)
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
