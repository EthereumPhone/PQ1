#!/usr/bin/env python3
"""Each promoted control must equal the experiment's control, comments stripped.
The source code is identical (promote_tcoll_chain.py asserts it), so any difference
here is a porting slip in the generator."""
import importlib.util, os, re, sys
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
spec = importlib.util.spec_from_file_location('_pf', 'tools/policy_cap_fence.py')
pf = importlib.util.module_from_spec(spec); spec.loader.exec_module(pf)
T, R = 'experiments/wots-badenc/tcoll/controls', 'experiments/wots-badenc/red/controls'
pairs  = [(f'scratch/tcoll_ctl{x}.ec', f'{T}/Ctl{x}.ec')   for x in 'ABCDEF']
pairs += [(f'scratch/bered_ctl{x}.ec', f'{R}/Ctl{x}.ec')   for x in 'ABCDEFGZ']
pairs += [(f'scratch/bes4_ctl{x}.ec',  f'{R}/S4Ctl{x}.ec') for x in 'ABCDEFG']
toks = lambda p: re.findall(r'\S+', pf.strip_comments(open(p).read()))
bad = 0
for new, old in pairs:
    ok = toks(new) == toks(old); bad += not ok
    print(('OK  ' if ok else 'DIFF') + f'  {new}  ==  {old}')
print(f'{len(pairs)} pairs, {bad} differ'); sys.exit(1 if bad else 0)
