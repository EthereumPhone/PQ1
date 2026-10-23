#!/usr/bin/env python3
"""Type-correct functional trees changes must fail the unchanged Lean consumers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_c10_functional_wots_controls import fixture as wots_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_functional_tree_controls import TREE_CHANGES


def fixture(definitions):
    base = wots_fixture(definitions)
    text = (ROOT / 'Extracted/C10FunctionalTrees.lean').read_text()
    body = '\n'.join(line for line in text.splitlines()
                     if not line.startswith(('import ', 'attribute [local irreducible] ')))
    return 'import Extracted.ForsRecoverySpec\n' + base + '\n' + body


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-tree-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        benign = changed(original, 'tree_path_step', 'height + 1', 'height + (2-1)', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' functional trees proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 functional trees: ' + name, flush=True)

        def negative(row):
            name, operator, before, after, _, _, theorem, _ = row
            definitions = changed(original, operator, before, after, True)
            typed = run(name + '_definitions', definitions)
            if typed.returncode:
                raise RuntimeError(name + ': definition failed typing:\n' + typed.stdout + typed.stderr)
            text = fixture(definitions)
            result = run(name, text)
            require_semantic_rejection(result, name)
            start = text.index('theorem ' + theorem + ' ')
            stop = text.find('\ntheorem ', start + 1)
            if stop < 0:
                stop = len(text)
            lo, hi = text[:start].count('\n') + 1, text[:stop].count('\n') + 1
            errors = re.findall(r'\.lean:(\d+):\d+: error:', result.stdout + result.stderr)
            if not errors or not lo <= int(errors[0]) < hi:
                raise RuntimeError(name + ': rejection missed ' + theorem + '\n' + result.stdout + result.stderr)
            print('PASS C10 functional trees typed rejection: ' + name + ' at ' + theorem, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, TREE_CHANGES))
    print(f'OK C10 functional trees: 2 positives and {len(TREE_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
