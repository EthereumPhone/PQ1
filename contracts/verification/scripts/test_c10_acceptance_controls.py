#!/usr/bin/env python3
"""Paired search-test mutations must fail the unchanged consuming Lean theorem."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_c10_representation_controls import fixture as representation_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_acceptance_controls import ACCEPTANCE_CHANGES


def fixture(definitions):
    base = representation_fixture(definitions)
    imports, body = [], []
    for line in (ROOT / 'Extracted/C10AcceptanceBridge.lean').read_text().splitlines():
        if line.startswith('import '):
            if line in ('import Extracted.C10Representation', 'import Extracted.C10RepresentationBridge'):
                continue
            if line not in base.splitlines():
                imports.append(line)
        else:
            body.append(line)
    return '\n'.join(imports) + '\n' + base + '\n' + '\n'.join(body)


def main():
    with tempfile.TemporaryDirectory(prefix='c10-acceptance-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        benign = changed(original, 'wots_target', '205', '(200 + 5)', True)
        benign = changed(benign, 'fors_zero_field', '11', '(5 + 6)', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' acceptance proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 acceptance: ' + name, flush=True)

        def negative(row):
            name, func, before, after, _, _, theorem = row
            definitions = changed(original, func, before, after, True)
            typed = run(name + '_definitions', definitions)
            if typed.returncode:
                raise RuntimeError(name + ': definition failed typing:\n' + typed.stdout + typed.stderr)
            text = fixture(definitions)
            result = run(name, text)
            require_semantic_rejection(result, name)
            theorem = {'wots_sum_common': 'wots_sum_value'}.get(theorem, theorem)
            start = text.index('theorem ' + theorem + ' ')
            stop = text.find('\ntheorem ', start + 1)
            if stop < 0:
                stop = len(text)
            lo, hi = text[:start].count('\n') + 1, text[:stop].count('\n') + 1
            errors = re.findall(r'\.lean:(\d+):\d+: error:', result.stdout + result.stderr)
            if not errors or not lo <= int(errors[0]) < hi:
                raise RuntimeError(name + ': rejection missed ' + theorem + '\n' + result.stdout + result.stderr)
            print('PASS C10 acceptance typed rejection: ' + name + ' at ' + theorem, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, ACCEPTANCE_CHANGES))
    print('OK C10 acceptance: 2 positive fixtures and 5 typed intended-theorem rejections')


if __name__ == '__main__':
    main()
