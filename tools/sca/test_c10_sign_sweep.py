#!/usr/bin/env python3
"""Fast outcome-classification controls without an emulator installation."""
import ast
import glob
import os
from pathlib import Path
import tempfile
import unittest

# Exercise the actual small decision functions without loading Rainbow or ELF.
source = Path(__file__).with_name('fault_sweep_c10_sign.py')
tree = ast.parse(source.read_text())
names = {'classify_release', 'offboard_verify', 'load_pk_root'}
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
assert {node.name for node in functions} == names
scope = dict(os=os, glob=glob, RET=42, STACK_TOP=4096, _STACK_LEN=16,
             COUNT_BUDGET=100, UcError=type('UcError', (Exception,), {}))
exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), scope)


class Emulator(dict):
    functions = {'sca_c10_verify_real': (100,)}

    def __init__(self, result=1, pc=42, error=None):
        super().__init__()
        self.result, self.pc, self.error = result, pc, error

    def reset(self):
        self.clear()

    def start(self, *args, **kwargs):
        if self.error:
            raise self.error
        self['r0'], self['pc'] = self.result, self.pc


class OutcomeControls(unittest.TestCase):
    def test_every_changed_success_needs_verification(self):
        classify = scope['classify_release']
        baseline = b'\x01\x02\x03'
        for changed in (b'\x01\x00\x03', b'\xff\x02\x03', b'\x00'*3):
            self.assertEqual(classify(1, changed, baseline), 'needs_verify')
        self.assertEqual(classify(1, baseline, baseline), 'clean')
        self.assertEqual(classify(0, baseline, baseline), 'rejected')
        for ret in (2, 255, 0xffffffff):
            self.assertEqual(classify(ret, baseline, baseline), 'invalid_return')

    def test_verifier_failure_is_not_signature_rejection(self):
        original = scope['load_pk_root']
        scope['load_pk_root'] = lambda: bytes(16)
        try:
            verify = scope['offboard_verify']
            self.assertTrue(verify(Emulator(1), bytes(32), bytes(4008)))
            self.assertFalse(verify(Emulator(0), bytes(32), bytes(4008)))
            for emulator in (Emulator(2), Emulator(pc=0),
                             Emulator(error=RuntimeError('crash')),
                             Emulator(error=scope['UcError']('crash'))):
                with self.assertRaises(RuntimeError):
                    verify(emulator, bytes(32), bytes(4008))
        finally:
            scope['load_pk_root'] = original

    def test_root_missing_conflicting_and_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope['HERE'] = tmp
            base = Path(tmp)/'c10_sign_target/target/thumbv8m.main-none-eabi/release/build'
            load = scope['load_pk_root']
            with self.assertRaises(RuntimeError):
                load()
            p = base/'sca-c10-sign-target-a/out/pk_root.bin'
            p.parent.mkdir(parents=True)
            p.write_bytes(bytes(16))
            self.assertEqual(load(), bytes(16))
            q = base/'sca-c10-sign-target-b/out/pk_root.bin'
            q.parent.mkdir(parents=True)
            q.write_bytes(bytes(16))
            self.assertEqual(load(), bytes(16))
            q.write_bytes(b'\x01'*16)
            with self.assertRaises(RuntimeError):
                load()
            q.write_bytes(bytes(15))
            with self.assertRaises(RuntimeError):
                load()


if __name__ == '__main__':
    unittest.main()
