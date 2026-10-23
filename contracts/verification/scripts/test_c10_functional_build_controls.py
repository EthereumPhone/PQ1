#!/usr/bin/env python3
"""Type-correct functional construction changes must fail the unchanged Lean consumers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import signal
import subprocess
import tempfile
from test_c10_functional_tree_controls import fixture as tree_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_functional_build_controls import BUILD_CHANGES


def run_lean(path, timeout=300):
    """Keep a finite bound and terminate lake's Lean children on failure."""
    command = [str(LAKE), 'env', 'lean', str(path)]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        # Killing only lake leaves its Lean child running, holding the pipes
        # and competing with the remaining controls after a timeout.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def fixture(definitions):
    base = tree_fixture(definitions)
    imports = ['import Mathlib.Data.Nat.Bitwise', 'import Extracted.ForsAuthSpec',
               'import Extracted.XmssAuthSpec']
    bodies = []
    attributes = {line for line in base.splitlines() if line.startswith('attribute [local irreducible] ')}
    for name in ('C10FunctionalBuildValues', 'ForsAuthOutside', 'XmssAuthOutside', 'C10FunctionalBuilders'):
        text = (ROOT / 'Extracted' / (name + '.lean')).read_text()
        body = []
        for line in text.splitlines():
            if line.startswith('import '):
                continue
            if line.startswith('attribute [local irreducible] '):
                if line in attributes:
                    continue
                attributes.add(line)
            body.append(line)
        bodies.append('\n'.join(body))
    return '\n'.join(imports) + '\n' + base + '\n' + '\n'.join(bodies)


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-build-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return run_lean(path)
        original = source(True)
        benign = changed(original, 'tree_nodes_value', '(i + 1)', '(i + (2-1))', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' functional construction proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 functional construction: ' + name, flush=True)

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
            print('PASS C10 functional construction typed rejection: ' + name + ' at ' + theorem, flush=True)
        # CI needs about a minute even for one positive fixture. Two workers
        # keep these larger construction fixtures within the runner's budget.
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(negative, BUILD_CHANGES))
    print(f'OK C10 functional construction: 2 positives and {len(BUILD_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
