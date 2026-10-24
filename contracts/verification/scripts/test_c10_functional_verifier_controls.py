#!/usr/bin/env python3
"""Compile typed complete-verifier changes; require intended proof rejection."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import tempfile
from test_c10_functional_caller_controls import run_lean
from test_fors_auth_proof_controls import ROOT, require_semantic_rejection
from c10_representation_controls import changed
from c10_functional_verifier_controls import VERIFIER_CHANGES, functional_definitions, lean_fixture


def check_controls(run):
    original = functional_definitions(True)
    benign = changed(original, 'hypertree_recover_value', 'hash_fn seed 1', 'hash_fn seed (2-1)', True)
    for name, definitions in [('positive',original),('preserving',benign)]:
        result = run(name,lean_fixture(ROOT,definitions))
        if result.returncode:
            raise RuntimeError(name+' verifier proof failed:\n'+result.stdout+result.stderr)
        print('PASS C10 functional verifier: '+name,flush=True)

    def negative(row):
        name,operator,before,after,_,_,theorem,_ = row
        definitions = original if operator == 'decision' else changed(original,operator,before,after,True)
        mutation = (before,after) if operator == 'decision' else None
        typed = run(name+'_typed',lean_fixture(ROOT,definitions,mutation,True))
        if typed.returncode:
            raise RuntimeError(name+': definition failed typing:\n'+typed.stdout+typed.stderr)
        text = lean_fixture(ROOT,definitions,mutation)
        result = run(name,text)
        require_semantic_rejection(result,name)
        start = text.index('theorem '+theorem+' ')
        match = re.search(r'\n(?:theorem|def|end) ',text[start+1:])
        stop = start+1+match.start()+1 if match else len(text)
        lo,hi = text[:start].count('\n')+1,text[:stop].count('\n')+1
        errors = re.findall(r'\.lean:(\d+):\d+: error:',result.stdout+result.stderr)
        if not errors or not lo <= int(errors[0]) < hi:
            raise RuntimeError(name+': rejection missed '+theorem+'\n'+result.stdout+result.stderr)
        print('PASS C10 functional verifier typed rejection: '+name+' at '+theorem,flush=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(negative,VERIFIER_CHANGES))


def main():
    with tempfile.TemporaryDirectory(prefix='c10-functional-verifier-controls-') as tmp:
        def run(name,text):
            path=Path(tmp)/(name+'.lean');path.write_text(text)
            return run_lean(path)
        check_controls(run)
    print(f'OK C10 functional verifier: 2 positives and {len(VERIFIER_CHANGES)} typed intended-theorem rejections')


if __name__ == '__main__':
    main()
