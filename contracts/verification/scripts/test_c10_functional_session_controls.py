#!/usr/bin/env python3
"""Typecheck each changed claim, then require its unchanged proof to reject."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile

from test_fors_auth_proof_controls import ROOT
from test_c10_functional_signer_controls import run_lean, require_intended

sys.path.insert(0, str(ROOT.parent / "easycrypt/c10-port/tools"))
from c10_functional_session_controls import LEAN_MODULES, LEAN_CHANGES, lean_fixture


def check_controls(run):
    for group in LEAN_MODULES:
        for label, preserving in [('positive', False), ('preserving', True)]:
            text = lean_fixture(ROOT, group, preserving=preserving)
            result = run(group+'_'+label, text)
            if result.returncode:
                raise RuntimeError(group+' '+label+' failed:\n'+result.stdout+result.stderr)
            print('PASS C10 functional session: '+group+' '+label, flush=True)

    def negative(row):
        name, group, theorem, before, after = row
        mutation = (theorem, before, after)
        typed = run(name+'_typed', lean_fixture(ROOT, group, mutation, typed=True))
        if typed.returncode:
            raise RuntimeError(name+': changed claim did not typecheck:\n'+typed.stdout+typed.stderr)
        text = lean_fixture(ROOT, group, mutation)
        result = run(name+'_reject', text)
        require_intended(result, text, theorem, name)
        print('PASS C10 functional session typed rejection: '+name+' at '+theorem, flush=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative, LEAN_CHANGES))


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-session-controls-') as tmp:
        def run(name, text):
            path = Path(tmp)/(name+'.lean')
            path.write_text(text)
            return run_lean(path)
        check_controls(run)
    print(f'OK C10 functional session: {2*len(LEAN_MODULES)} positives and '
          f'{len(LEAN_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
