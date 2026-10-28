#!/usr/bin/env python3
"""Controls for profile/source binding and theorem-closure enrollment."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify
import profile_guard as guard


class GuardControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (verify.HERE / 'frozen/input.llbc').read_bytes()
        cls.manifest = (verify.HERE / 'profile-manifest.json').read_bytes()
        cls.document = guard.load_strict(cls.raw)

    def reject(self, data, reason, manifest=None):
        with self.assertRaisesRegex(guard.ProfileRejected, reason):
            guard.check(data, self.manifest if manifest is None else manifest)

    def test_original(self):
        self.assertTrue(guard.check(self.raw, self.manifest)['accepted'])

    def test_structural_and_hidden_changes(self):
        for section, ident in [('type_decls', 7), ('type_decls', 8), ('type_decls', 9),
                               ('fun_decls', 24), ('fun_decls', 26), ('trait_impls', 9)]:
            with self.subTest(section=section, ident=ident):
                doc = copy.deepcopy(self.document)
                row = next(x for x in doc['translated'][section] if x and x['def_id'] == ident)
                row['profile_mutation'] = True
                self.reject(guard.canonical(doc), 'mapped declarations or structural use census changed')
        doc = copy.deepcopy(self.document)
        doc['translated']['options']['hidden_change'] = True
        self.reject(guard.canonical(doc), 'complete LLBC identity changed')

    def test_serialization_and_bounds(self):
        self.reject(b'{"has_errors":true,' + self.raw[1:], 'duplicate JSON key')
        self.reject(self.raw, 'profile manifest identity changed', self.manifest + b' ')
        self.reject(b' ' * (guard.MAX_INPUT_BYTES + 1), 'input size exceeds profile bound')
        self.reject(guard.canonical(self.document), 'complete LLBC identity changed')
        doc = copy.deepcopy(self.document)
        doc['has_errors'] = True
        self.reject(guard.canonical(doc), 'wrong Charon schema or extraction errors')


class SourceControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sha-byte-gate-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / 'contracts/verification/sha256-byte'
        shutil.copytree(verify.HERE, self.profile, ignore=shutil.ignore_patterns('__pycache__'))
        source = verify.load_module('source_control',
            verify.ROOT / 'contracts/verification/scripts/check_sha256_portable_source.py')
        config = json.loads((verify.HERE / 'profile.json').read_text())
        paths = [Path('Cargo.lock'), Path('sphincs-c10/Cargo.toml'),
                 Path(config['spec_owner']), source.MODEL / 'lib.rs',
                 Path('contracts/verification/scripts/check_sha256_portable_source.py'),
                 *(source.VENDOR / name for name in source.PINS)]
        for relative in paths:
            dest = self.root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(verify.ROOT / relative, dest)
        self.assertTrue(verify.sources(self.profile, self.root)[1]['accepted'])

    def test_frozen_sources(self):
        for name in ['frozen/input.llbc', 'Input/Funs.lean', 'MutableZipModel.lean',
                     'frozen/compiler.patch', 'profile_guard.py', 'AxiomCheck.lean']:
            with self.subTest(name=name):
                path = self.profile / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaisesRegex(verify.Rejected, 'profile source changed'):
                    verify.sources(self.profile, self.root)
                path.write_bytes(original)

    def test_dependency_and_spec_drift(self):
        for name, reason in [
            ('Cargo.lock', 'Rust source binding'),
            ('contracts/verification/tools/sha256-portable-model/vendor/sha2-0.10.9/src/sha256/soft.rs', 'Rust source binding'),
            ('contracts/verification/lean/SphincsCVerify/Spec/Sha256Impl.lean', 'SHA specification owner changed')]:
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                if name == 'Cargo.lock':
                    changed = original.replace(b'a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283', b'0' * 64)
                    self.assertNotEqual(changed, original)
                else:
                    changed = original + b'\n'
                path.write_bytes(changed)
                with self.assertRaisesRegex(verify.Rejected, reason):
                    verify.sources(self.profile, self.root)
                path.write_bytes(original)

    def test_unlisted_module(self):
        (self.profile / 'Unlisted.lean').write_text('axiom unlisted : False\n')
        with self.assertRaisesRegex(verify.Rejected, 'unlisted Lean source'):
            verify.sources(self.profile, self.root)


class CensusControls(unittest.TestCase):
    def test_census(self):
        config = json.loads((verify.HERE / 'profile.json').read_text())
        lines = [f"'{name}' depends on axioms: [propext, Classical.choice, Quot.sound]"
                 for name in config['axiom_theorems']]
        clean = '\n'.join(lines)
        self.assertEqual(len(verify.census(clean, config)), 98)
        bad = [clean.replace('propext', 'sorryAx', 1),
               clean.replace('propext', 'Lean.ofReduceBool', 1),
               '\n'.join(lines[:-1]), clean + '\n' + lines[0],
               clean.replace(config['axiom_theorems'][0], 'Wrong.theorem', 1)]
        for text in bad:
            with self.subTest(text=text[:100]), self.assertRaises(verify.Rejected):
                verify.census(text, config)


if __name__ == '__main__':
    unittest.main()
