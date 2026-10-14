#!/usr/bin/env python3
"""Typed mutations of the extracted seed derivation must break its exact proof."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

CHANGES = [
    ('zero-test', 'core.cmp.PartialEqU8 self a', 'core.cmp.PartialEqU8 self self'),
    ('zero-result', 'then ok (Array.repeat 32#usize 0#u8)',
     'then ok (Array.repeat 32#usize 1#u8)'),
    ('zero-branch', 'if b\n', 'if !b\n'),
    ('domain-byte', '101#u8, 45#u8, 118#u8, 49#u8',
     '101#u8, 45#u8, 118#u8, 50#u8'),
    ('part-order', '[ s, s1, label ]', '[ s, label, s1 ]'),
    ('seed-part', '[ s, s1, label ]', '[ s, s, label ]'),
    ('label-part', '[ s, s1, label ]', '[ s, s1, s1 ]'),
    ('nonzero-result', 'shuffle.shuffle_hash_parts s2',
     'ok (Array.repeat 32#usize 0#u8)'),
]


def fixture(before=None, after=None):
    definitions = (ROOT / 'Extracted/ShuffleDerive/Funs.lean').read_text()
    if before is not None:
        if definitions.count(before) != 1:
            raise ValueError('seed-derivation mutation anchor drift')
        definitions = definitions.replace(before, after)
    definitions = definitions.replace('shuffle.ShuffleSeed.derive',
                                      'shuffle.ShuffleSeed.derive_probe')
    proof = (ROOT / 'Extracted/ShuffleDeriveSpec.lean').read_text()
    proof = proof.replace('import Extracted.ShuffleDerive.Funs\n', '')
    proof = proof.replace('shuffle.ShuffleSeed.derive',
                          'shuffle.ShuffleSeed.derive_probe')
    proof = proof.replace('Extracted.Equiv', 'Extracted.ShuffleDeriveControl')
    return definitions, definitions + '\n' + proof


def main():
    with tempfile.TemporaryDirectory(prefix='shuffle-derive-controls-') as tmp:
        def run(name, source):
            path = Path(tmp) / (name + '.lean')
            path.write_text(source)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        baseline = run('positive', fixture()[1])
        if baseline.returncode:
            raise RuntimeError('seed derivation positive failed:\n' + baseline.stdout + baseline.stderr)
        print('PASS shuffle derive: actual extracted body and unchanged exact proof', flush=True)

        def negative(row):
            name, before, after = row
            definitions, proof = fixture(before, after)
            typed = run(name + '_definitions', definitions)
            if typed.returncode:
                raise RuntimeError(name + ': changed definition failed typing:\n' + typed.stdout + typed.stderr)
            rejected = run(name, proof)
            require_semantic_rejection(rejected, name)
            diagnostic = re.search(r':(\d+):\d+: error:', rejected.stdout + rejected.stderr)
            if diagnostic is None:
                raise RuntimeError(name + ': missing located proof diagnostic')
            prefix = '\n'.join(proof.splitlines()[:int(diagnostic[1])])
            theorems = re.findall(r'^(?:private )?theorem (\w+)', prefix, re.M)
            if not theorems or theorems[-1] != 'shuffle_derive_exact':
                raise RuntimeError(name + ': rejection missed the intended exact theorem')
            print('PASS shuffle derive typed rejection at shuffle_derive_exact: ' + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, CHANGES))
    print(f'OK shuffle derive: one positive baseline and {len(CHANGES)} typed rejections at the exact theorem')


if __name__ == '__main__':
    main()
