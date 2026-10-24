#!/usr/bin/env python3
"""Type-correct functional caller changes must fail the unchanged Lean consumers."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import signal
import subprocess
import tempfile
from test_c10_functional_build_controls import fixture as build_fixture
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection
from c10_representation import source
from c10_representation_controls import changed
from c10_functional_caller_controls import CALLER_CHANGES, LAYER_VALUE_CHANGES, layer_value_fixture


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
    base = build_fixture(definitions)
    provided = set(re.findall(r'^namespace (\S+)', base, re.M))
    provided.add('C10Representation')
    provided.add('Extracted.C10Representation')
    imports = {line for line in base.splitlines() if line.startswith('import ')}
    bodies, seen = [], set()
    attributes = {line for line in base.splitlines() if line.startswith('attribute [local irreducible] ')}

    def path(module):
        return ROOT / (module.replace('.', '/') + '.lean')

    def dependencies(module):
        file = path(module)
        return re.findall(r'^import (\S+)', file.read_text(), re.M) if file.is_file() else []

    def depends_on_representation(module):
        return module == 'Extracted.C10Representation' or any(
            depends_on_representation(dep) for dep in dependencies(module))

    def inline(module):
        if module in provided or module in seen:
            return
        seen.add(module)
        for dep in dependencies(module):
            if dep in provided:
                continue
            if depends_on_representation(dep):
                inline(dep)
            else:
                imports.add('import ' + dep)
        body = []
        text = path(module).read_text()
        # The base fixture already sets this backend's reducibility globally.
        # Remove only that repeated attribute, including multiline lists;
        # preserve every other module-local reducibility declaration.
        def deduplicate_backend(match):
            names = match.group(1).split()
            names = [name for name in names if name != 'SphincsCVerify.Spec.Sha256Impl.sha256Bytes']
            return 'attribute [local irreducible] ' + ' '.join(names) if names else ''
        text = re.sub(r'(?m)^attribute \[local irreducible\] ([^\n]*(?:\n[ \t]+[^\n]+)*)',
                      deduplicate_backend, text)
        for line in text.splitlines():
            if line.startswith('import '):
                continue
            if line.startswith('attribute [local irreducible] '):
                if line in attributes:
                    continue
                attributes.add(line)
            body.append(line)
        bodies.append('\n'.join(body))

    for name in ('C10FunctionalForest', 'C10FunctionalForestRecover', 'C10FunctionalLayer'):
        inline('Extracted.' + name)
    base = '\n'.join(line for line in base.splitlines() if not line.startswith('import '))
    return '\n'.join(sorted(imports)) + '\n' + base + '\n' + '\n'.join(bodies)


def check_value_fixtures(run):
    """Finite expected values must reject the selected well-typed changes."""
    original = source(True)
    benign = changed(original, 'layer_recover_value', 'nonce) kp auth', 'nonce) (kp+0) auth', True)
    for name, definitions in [('positive', original), ('preserving', benign)]:
        result = run('examples_' + name, layer_value_fixture(definitions, True))
        if result.returncode:
            raise RuntimeError(name + ' layer value examples failed:\n' + result.stdout + result.stderr)
        print('PASS C10 layer value examples: ' + name, flush=True)

    def negative(row):
        name, before, after, _, _ = row
        definitions = changed(original, 'layer_recover_value', before, after, True)
        typed = run('examples_' + name + '_typed', definitions)
        if typed.returncode:
            raise RuntimeError(name + ': layer value definition failed typing:\n' + typed.stdout + typed.stderr)
        text = layer_value_fixture(definitions, True)
        result = run('examples_' + name, text)
        require_semantic_rejection(result, name)
        start = text.index('theorem layer_zero_complete ')
        stop = text.index('\ntheorem ', start + 1) + 1
        lo, hi = text[:start].count('\n') + 1, text[:stop].count('\n') + 1
        errors = re.findall(r'\.lean:(\d+):\d+: error:', result.stdout + result.stderr)
        if not errors or not lo <= int(errors[0]) < hi:
            raise RuntimeError(name + ': rejection missed layer_zero_complete\n' + result.stdout + result.stderr)
        if 'Tactic `decide` proved that the proposition' not in result.stdout + result.stderr:
            raise RuntimeError(name + ': value rejection was not a computed false proposition')
        print('PASS C10 layer value typed rejection: ' + name + ' at layer_zero_complete', flush=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative, LAYER_VALUE_CHANGES))


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-caller-controls-') as tmp:
        def run(name, text):
            path = Path(tmp) / (name + '.lean')
            path.write_text(text)
            return run_lean(path)
        check_value_fixtures(run)
        original = source(True)
        benign = changed(original, 'forest_compress_value', '0 ht 4 0', '0 ht (2+2) 0', True)
        for name, definitions in [('positive', original), ('preserving', benign)]:
            result = run(name, fixture(definitions))
            if result.returncode:
                raise RuntimeError(name + ' functional caller proof failed:\n' + result.stdout + result.stderr)
            print('PASS C10 functional caller: ' + name, flush=True)

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
            print('PASS C10 functional caller typed rejection: ' + name + ' at ' + theorem, flush=True)
        # CI needs about a minute even for one positive fixture. Two workers
        # keep these larger construction fixtures within the runner's budget.
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(negative, CALLER_CHANGES))
    print(f'OK C10 functional caller: 2 positives and {len(CALLER_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
