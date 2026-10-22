#!/usr/bin/env python3
"""Typed shared-selector changes must fail the actual Lean endpoint corpus."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_c10_acceptance_controls import fixture as acceptance_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_functional_search_controls import SELECTOR_CHANGES


def fixture(definitions):
    base = acceptance_fixture(definitions)
    bodies = []
    for name in ('C10FirstHit', 'C10FunctionalSearch'):
        text = (ROOT / 'Extracted' / (name + '.lean')).read_text()
        bodies.append('\n'.join(line for line in text.splitlines() if not line.startswith('import ')))
    return 'import Aeneas\n' + base + '\n' + '\n'.join(bodies)


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        benign = original
        for name in ('wots_first_slot', 'fors_first_slot'):
            benign = changed(benign, name, 'slot + 1', 'slot + (2 - 1)', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' functional proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 functional search: ' + name, flush=True)

        def negative(row):
            name, operator, before, after, theorem = row
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
            print('PASS C10 functional typed rejection: ' + name + ' at ' + theorem, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, SELECTOR_CHANGES))
    print(f'OK C10 functional search: 2 positives and {len(SELECTOR_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
