#!/usr/bin/env python3
"""Paired shuffle definition changes must break unchanged Lean endpoint proofs."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_c10_representation_controls import fixture as representation_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_shuffle_controls import SHUFFLE_CHANGES

ACTUAL_CHANGES = [
    ('actual-zero-detection', 'lift (nonzero ||| i)', 'lift nonzero'),
    ('actual-copy-value', 'Array.index_usize d b', 'Array.index_usize d 0#usize'),
    ('actual-block-counter', 'shuffle.shuffle_hash_block seed blk', 'shuffle.shuffle_hash_block seed 0#u32'),
    ('actual-low-byte', 'lift (i5 ||| lo)', 'lift (i5 ||| hi)'),
    ('actual-zero-tail', 'Array.repeat 64#usize 0#u8', 'Array.repeat 64#usize 1#u8'),
]


def fixture(definitions):
    base = representation_fixture(definitions)
    labels = (ROOT / 'Extracted/C10ShuffleLabels.lean').read_text()
    base += '\n' + labels.replace('import Extracted.C10HashInputBridge\n', '')
    proof = (ROOT / 'Extracted/C10ShuffleBridge.lean').read_text()
    imports, body = [], []
    for line in proof.splitlines():
        if line.startswith('import '):
            if line in ('import Extracted.C10Representation', 'import Extracted.C10HashInputBridge',
                        'import Extracted.C10ShuffleLabels'):
                continue
            if line not in base.splitlines():
                imports.append(line)
        else:
            body.append(line)
    return '\n'.join(imports) + '\n' + base + '\n' + '\n'.join(body)


def actual_fixture(before=None, after=None):
    original = (ROOT / 'Extracted/Shuffle/Funs.lean').read_text()
    start = original.index('/-- [sphincs_c10::shuffle::fisher_yates]: loop body 0:')
    declaration = original[start:].rsplit('end sphincs_c10', 1)[0]
    if before is not None:
        if declaration.count(before) != 1:
            raise ValueError('actual shuffle mutation anchor drift')
        declaration = declaration.replace(before, after)
    imports, bodies = [], []
    for name in ('ShuffleSpec', 'ShuffleOrder', 'C10ShuffleBridge'):
        body = []
        for line in (ROOT / ('Extracted/' + name + '.lean')).read_text().splitlines():
            if line.startswith('import '):
                if line in ('import Extracted.ShuffleSpec', 'import Extracted.ShuffleOrder'):
                    continue
                if line not in imports:
                    imports.append(line)
            else:
                body.append(line)
        bodies.append('\n'.join(body))
    proof = '\n'.join(bodies).replace('Extracted.Equiv', 'Extracted.ShuffleControl')
    # Concatenation retains the first file-local opacity setting across both
    # proofs. Reapplying that identical attribute is an elaboration error.
    opaque = 'attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes'
    if proof.count(opaque) != 2:
        raise ValueError('shuffle opacity boundary changed')
    first, rest = proof.split(opaque, 1)
    proof = first + opaque + rest.replace(opaque, '')
    proof = proof.replace('Extracted.C10ShuffleBridge', 'Extracted.C10ShuffleBridgeProbe')
    proof = proof.replace('C10HashInputBridge Equiv', 'C10HashInputBridge Equiv ShuffleControl')
    names = ['shuffle.fisher_yates_loop2_loop0', 'shuffle.fisher_yates_loop0',
             'shuffle.fisher_yates_loop1', 'shuffle.fisher_yates_loop2',
             'shuffle.fisher_yates_loop3', 'shuffle.fisher_yates']
    for name in names:
        pattern = re.escape(name) + r'(?![A-Za-z0-9_])'
        declaration = re.sub(pattern, name + '_probe', declaration)
        proof = re.sub(pattern, name + '_probe', proof)
    definitions = '\n'.join(imports) + '\nnamespace sphincs_c10\n'
    definitions += 'open Aeneas Aeneas.Std Result ControlFlow Error\n'
    definitions += declaration + '\nend sphincs_c10\n'
    return definitions, definitions + proof


def main():
    with tempfile.TemporaryDirectory(prefix='c10-shuffle-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        baseline = run('positive', fixture(original))
        if baseline.returncode:
            raise RuntimeError('positive shuffle proof failed:\n' + baseline.stdout + baseline.stderr)
        print('PASS C10 shuffle: unchanged endpoint proofs', flush=True)

        def negative(row):
            name, func, before, after, _, _ = row
            definitions = changed(original, func, before, after, True)
            typed = run(name + '_definitions', definitions)
            if typed.returncode:
                raise RuntimeError(name + ': changed definition failed typing:\n' + typed.stdout + typed.stderr)
            require_semantic_rejection(run(name, fixture(definitions)), name)
            print('PASS C10 shuffle typed rejection: ' + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, SHUFFLE_CHANGES))
        baseline = run('actual_positive', actual_fixture()[1])
        if baseline.returncode:
            raise RuntimeError('positive actual shuffle proof failed:\n' + baseline.stdout + baseline.stderr)
        print('PASS C10 shuffle: actual extracted loops and unchanged proofs', flush=True)

        def actual_negative(row):
            name, before, after = row
            definitions, proof = actual_fixture(before, after)
            typed = run(name + '_definitions', definitions)
            if typed.returncode:
                raise RuntimeError(name + ': changed loop failed typing:\n' + typed.stdout + typed.stderr)
            require_semantic_rejection(run(name, proof), name)
            print('PASS C10 shuffle typed rejection: ' + name, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(actual_negative, ACTUAL_CHANGES))
    print(f'OK C10 shuffle: two positive baselines and {len(SHUFFLE_CHANGES) + len(ACTUAL_CHANGES)} typed semantic rejections')


if __name__ == '__main__':
    main()
