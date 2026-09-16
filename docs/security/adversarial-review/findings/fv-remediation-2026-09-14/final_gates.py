from pathlib import Path
import concurrent.futures,json,os,subprocess
ROOT=Path(__file__).resolve().parent
REPO=ROOT/'checks'
LOGS=ROOT/'logs'
rows=[]
def run(label,cmd,env=None):
    with (LOGS/(label+'.log')).open('w') as log:
        p=subprocess.run(cmd,cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=900)
    row={'label':label,'command':cmd,'status':p.returncode,'log':str(LOGS/(label+'.log'))}
    print(label,p.returncode,flush=True)
    return row
jobs=[('fv-lints',['make','-C','contracts/verification','verify-fv-lints']),
      ('extracted',['make','-C','contracts/verification','verify-extracted']),
      ('tla',['make','-C','contracts/verification','verify-tla']),
      ('protocol-selftest',['/usr/bin/python3','-E','-S','scripts/check_protocol_models.py','--self-test']),
      ('verity-ci',['make','-C','contracts/verity','ci']),
      ('gate-enforcement',['/usr/bin/python3','-E','-S','scripts/check_gate_enforcement.py'])]
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
    for result in pool.map(lambda item:run(*item),jobs):rows.append(result)
# Both use the same Lean project; run after its other gates finish.
rows.append(run('axiom-lint',['bash','contracts/verification/scripts/lint_axioms.sh']))
rows.append(run('ledger-authoritative',['/usr/bin/bash','-c','[[ ${UID} -ne 0 && -u /usr/bin/sudo && -x /usr/bin/sudo ]] && /usr/bin/sudo -n -u "#${UID}" -- /usr/bin/env -i /usr/bin/bash --noprofile --norc -p contracts/verification/scripts/run_authoritative_make.sh make -C contracts/verification verify-ledger-consistency']))
rows.append(run('cryptoverif',['/usr/bin/python3','-E','-S','scripts/check_protocol_models.py'],dict(os.environ,PROTOCOL_MODELS='cryptoverif')))
(ROOT/'final-gates.json').write_text(json.dumps(rows,indent=2)+'\n')
assert all(r['status']==0 for r in rows),rows
