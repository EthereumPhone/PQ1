#!/usr/bin/env python3
"""Type-correct functional WOTS changes must fail the unchanged Lean consumers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess
import tempfile
from test_c10_functional_search_controls import fixture as search_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_functional_wots_controls import WOTS_CHANGES


def fixture(definitions):
    base = search_fixture(definitions)
    inlined = {'C10Representation', 'C10RepresentationBridge', 'C10HashInputBridge',
               'C10AddressInputBridge', 'C10AcceptanceBridge', 'C10FirstHit', 'C10FunctionalSearch',
               'C10FunctionalWots', 'C10FunctionalWotsSign', 'C10FunctionalWotsRecover'}
    imports, bodies = [], []
    # The combined fixture has one file scope. Repeating a module-local
    # reducibility declaration there is rejected by Lean; preserve it once.
    attributes = {line for line in base.splitlines() if line.startswith('attribute [local irreducible] ')}
    for name in ('C10FunctionalWots', 'C10FunctionalWotsSign', 'C10FunctionalWotsRecover'):
        body = []
        for line in (ROOT / 'Extracted' / (name + '.lean')).read_text().splitlines():
            if line.startswith('import '):
                if line.removeprefix('import Extracted.') in inlined:
                    continue
                if line not in base.splitlines() and line not in imports:
                    imports.append(line)
            elif line.startswith('attribute [local irreducible] '):
                if line not in attributes:
                    body.append(line)
                    attributes.add(line)
            else:
                body.append(line)
        bodies.append('\n'.join(body))
    return '\n'.join(imports) + '\n' + base + '\n' + '\n'.join(bodies)


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-wots-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return subprocess.run([str(LAKE), 'env', 'lean', str(path)], cwd=ROOT,
                                  capture_output=True, text=True, timeout=90)
        original = source(True)
        benign = changed(original, 'hash_bytes_node', 'List.take 16', 'List.take (8+8)', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' functional WOTS proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 functional WOTS: ' + name, flush=True)

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
            print('PASS C10 functional WOTS typed rejection: ' + name + ' at ' + theorem, flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(negative, WOTS_CHANGES))
    print(f'OK C10 functional WOTS: 2 positives and {len(WOTS_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
