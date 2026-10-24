#!/usr/bin/env python3
"""Require typed signer changes to reject at their unchanged consuming proof."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import re
import signal
import subprocess
import sys
import tempfile
from test_fors_auth_proof_controls import LAKE, ROOT, require_semantic_rejection

sys.path.insert(0, str(ROOT.parent / "easycrypt/c10-port/tools"))
from c10_representation_controls import changed
from c10_functional_signer_controls import (
    GROUPS, SIGNER_CHANGES, functional_definitions, preserving_definitions, lean_fixture,
)
from c10_functional_signer_composition_controls import (
    COMPOSITION_CHANGES, lean_fixture as composition_fixture,
)


def run_lean(path):
    command = [str(LAKE), 'env', 'lean', '-M', '4096', '-j', '1', str(path)]
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=300)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def require_intended(result, text, theorem, name):
    require_semantic_rejection(result, name)
    start = text.index('theorem '+theorem+' ')
    match = re.search(r'\n(?:theorem|def|end) ', text[start+1:])
    stop = start+1+match.start()+1 if match else len(text)
    lo, hi = text[:start].count('\n')+1, text[:stop].count('\n')+1
    errors = re.findall(r'\.lean:(\d+):\d+: error:', result.stdout+result.stderr)
    if not errors or not lo <= int(errors[0]) < hi:
        raise RuntimeError(name+': rejection missed '+theorem+'\n'+result.stdout+result.stderr)


def check_controls(run):
    for group in GROUPS:
        for name, definitions in [('positive', functional_definitions(group, True)),
                                  ('preserving', preserving_definitions(group, True))]:
            result = run(group+'_'+name, lean_fixture(ROOT, group, definitions))
            if result.returncode:
                raise RuntimeError(group+' '+name+' failed:\n'+result.stdout+result.stderr)
            print('PASS C10 functional signer: '+group+' '+name, flush=True)

    def negative(row):
        name, group, operator, before, after, _, _, theorem, _ = row
        definitions = changed(functional_definitions(group, True), operator, before, after, True)
        typed = run(name+'_typed', lean_fixture(ROOT, group, definitions, True))
        if typed.returncode:
            raise RuntimeError(name+': definition failed typing:\n'+typed.stdout+typed.stderr)
        text = lean_fixture(ROOT, group, definitions)
        result = run(name, text)
        require_intended(result, text, theorem, name)
        print('PASS C10 functional signer typed rejection: '+name+' at '+theorem, flush=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative, SIGNER_CHANGES))


def check_composition(run):
    for name, preserving in [('positive', False), ('preserving', True)]:
        text = composition_fixture(ROOT, preserving=preserving)
        result = run('composition_'+name, text)
        if result.returncode:
            raise RuntimeError('composition '+name+' failed:\n'+result.stdout+result.stderr)
        print('PASS C10 signer composition: '+name, flush=True)

    def negative(row):
        name, operator, before, after, theorem, *_ = row
        mutation = (operator, before, after)
        typed = run('composition_'+name+'_typed', composition_fixture(ROOT, mutation, True))
        if typed.returncode:
            raise RuntimeError(name+': composition definition failed typing:\n'+typed.stdout+typed.stderr)
        text = composition_fixture(ROOT, mutation)
        result = run('composition_'+name, text)
        require_intended(result, text, theorem, name)
        print('PASS C10 signer composition typed rejection: '+name+' at '+theorem, flush=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative, COMPOSITION_CHANGES))


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-signer-controls-') as tmp:
        def run(name, text):
            path = Path(tmp)/(name+'.lean')
            path.write_text(text)
            return run_lean(path)
        check_controls(run)
        check_composition(run)
    print(f'OK C10 functional signer: {2*len(GROUPS)+2} positives and '
          f'{len(SIGNER_CHANGES)+len(COMPOSITION_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
