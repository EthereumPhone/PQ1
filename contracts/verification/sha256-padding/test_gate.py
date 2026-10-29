#!/usr/bin/env python3
"""Evidence rejection controls; these do not run the symbolic solver."""
import copy
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
import prepare
import replay
import verify


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = verify.sources()
        cls.logs = {name: gzip.decompress(
            (verify.HERE / f'frozen/logs/{name}.log.gz').read_bytes()).decode()
                    for name in verify.CASES}

    def rejected(self, text, name='single-block', code=0, stop=None):
        with self.assertRaises(verify.Rejected):
            verify.accept(self.config, name, text, code, stop)

    def test_all_original_receipts(self):
        self.assertEqual(len(verify.recorded(self.config)), 4)

    def test_timeout_and_setup_failure_are_not_controls(self):
        self.rejected(self.logs['single-block'], stop='timeout')
        self.rejected(self.logs['wrong-endian'], 'wrong-endian', 101)
        self.rejected('compiler setup failed', 'wrong-endian', 1)

    def test_unknown_or_unsupported_check_rejected(self):
        for status in ('ERROR', 'UNDETERMINED', 'FAILURE', 'UNSATISFIABLE'):
            with self.subTest(status=status):
                self.rejected(self.logs['single-block'].replace('- Status: SUCCESS',
                                                               '- Status: ' + status, 1))

    def test_missing_property_rejected(self):
        text = re.sub(r'Check 1:.*?(?=Check 2:)', '', self.logs['single-block'], count=1, flags=re.S)
        self.rejected(text)

    def test_duplicate_property_rejected(self):
        text = self.logs['single-block']
        names = re.findall(r'^Check \d+: (.+)$', text, re.M)
        self.rejected(text.replace('Check 2: ' + names[1], 'Check 2: ' + names[0], 1))

    def test_wrong_source_location_rejected(self):
        self.rejected(self.logs['single-block'].replace(
            'src/lib.rs:52:13 in function proofs::check', 'src/lib.rs:53:13 in function proofs::check'))

    def test_missing_reachable_cover_rejected(self):
        self.rejected(self.logs['single-block'].replace('- Status: SATISFIED',
                                                       '- Status: UNREACHABLE', 1))

    def test_mutant_needs_exact_failure(self):
        self.rejected(self.logs['wrong-endian'], 'wrong-endian', 0)
        self.rejected(self.logs['wrong-endian'].replace('- Status: FAILURE',
                                                       '- Status: SUCCESS'), 'wrong-endian', 1)
        self.rejected(self.logs['wrong-threshold'], 'wrong-endian', 1)

    def test_second_harness_rejected(self):
        self.rejected(self.logs['single-block'] + '\nChecking harness unrelated\n')

    def test_duplicate_json_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'bad.json'
            p.write_text('{"exit": 1, "exit": 0}')
            with self.assertRaises(verify.Rejected):
                verify.read_json(p)

    def test_source_drift_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / 'profile'
            shutil.copytree(verify.HERE, profile)
            p = profile / 'frozen/lib.rs'
            p.write_text(p.read_text().replace('pos < 64', 'pos < 63'))
            with self.assertRaisesRegex(verify.Rejected, 'frozen input changed'):
                verify.sources(profile)

    def test_dependency_closure_is_selective(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'Cargo.lock'
            text = (verify.ROOT / 'Cargo.lock').read_text()
            p.write_text(text + '\n[[package]]\nname = "unrelated-gate-control"\nversion = "1.0.0"\n')
            self.assertEqual(verify.lock_closure(p), verify.lock_closure(verify.ROOT / 'Cargo.lock'))
            # The selected package checksum is load-bearing even with the same version.
            p.write_text(text.replace(self.config['crates']['block-buffer-0.10.4'], '0' * 64))
            self.assertNotEqual(verify.lock_closure(p), verify.lock_closure(verify.ROOT / 'Cargo.lock'))

    def test_dependency_version_disambiguation_is_selective(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'Cargo.lock'
            text = (verify.ROOT / 'Cargo.lock').read_text()
            qualified = text.replace('"generic-array",', '"generic-array 0.14.7",')
            p.write_text(qualified + '\n[[package]]\nname = "generic-array"\nversion = "1.0.0"\n')
            self.assertEqual(verify.lock_closure(p), verify.lock_closure(verify.ROOT / 'Cargo.lock'))
            p.write_text(p.read_text().replace('"generic-array 0.14.7",', '"generic-array 1.0.0",'))
            self.assertNotEqual(verify.lock_closure(p), verify.lock_closure(verify.ROOT / 'Cargo.lock'))

    def test_pinned_tools_win_over_adjacent_executables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, verified, adjacent = (root / n for n in ('bin', 'verified', 'adjacent'))
            for directory in (private, verified, adjacent):
                directory.mkdir()
            for directory, label in ((verified, 'verified'), (adjacent, 'shadow')):
                p = directory / 'cbmc'
                p.write_text(f'#!/bin/sh\nprintf "{label}\\n"\n')
                p.chmod(0o755)
            bindings = {'cbmc': verified / 'cbmc'}
            replay.install_tools(private, bindings)
            path = os.pathsep.join(map(str, (private, adjacent, Path('/usr/bin'), Path('/bin'))))
            replay.check_tool_resolution(private, bindings, path)
            self.assertEqual(subprocess.check_output(['cbmc'], env={'PATH': path}, text=True),
                             'verified\n')
            wrong_path = os.pathsep.join(map(str, (adjacent, private)))
            with self.assertRaises(verify.Rejected):
                replay.check_tool_resolution(private, bindings, wrong_path)
            (private / 'cbmc').unlink()
            (private / 'cbmc').symlink_to(adjacent / 'cbmc')
            with self.assertRaises(verify.Rejected):
                replay.check_tool_resolution(private, bindings, path)

    def test_c_model_source_drift_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rel = 'library/kani/kani_lib.c'
            p = root / rel
            p.parent.mkdir(parents=True)
            shutil.copyfile(verify.HERE / 'frozen/kani_lib.c', p)
            pins = {rel: verify.read_json(verify.HERE / 'frozen/kani-runtime.json')[rel]}
            replay.check_runtime_files(root, pins)
            p.write_bytes(p.read_bytes() + b'\n/* altered model input */\n')
            with self.assertRaisesRegex(verify.Rejected, 'Kani runtime differs'):
                replay.check_runtime_files(root, pins)

    def test_driver_cannot_redirect_model_source_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'requested'
            outside = Path(tmp) / 'other-installation/kani-driver'
            outside.parent.mkdir()
            outside.write_text('not executed\n')
            driver = root / 'target/kani/bin/kani-driver'
            driver.parent.mkdir(parents=True)
            driver.symlink_to(outside)
            with self.assertRaisesRegex(verify.Rejected, 'different installation'):
                replay.runtime(types.SimpleNamespace(kani_root=root), {})

    def test_preparation_reconstructs_and_rejects_forged_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'inputs'
            prepare.prepare(output)
            self.assertEqual(len(prepare.check_prepared(output)), 124)
            p = output / 'single-block/src/lib.rs'
            p.write_text(p.read_text().replace('pos < 64', 'pos < 63'))
            receipt = json.loads((output / 'prepared.json').read_text())
            receipt['files']['single-block/src/lib.rs'] = verify.sha(p)
            (output / 'prepared.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(verify.Rejected, 'prepared input changed'):
                prepare.check_prepared(output)

    def test_unlisted_build_script_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'inputs'
            prepare.prepare(output)
            (output / 'single-block/build.rs').write_text('fn main() {}\n')
            with self.assertRaisesRegex(verify.Rejected, 'inventory changed'):
                prepare.check_prepared(output)


if __name__ == '__main__':
    unittest.main()
