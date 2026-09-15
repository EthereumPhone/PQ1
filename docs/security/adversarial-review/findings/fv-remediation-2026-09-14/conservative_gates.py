from pathlib import Path
import concurrent.futures,json,subprocess
root=Path(__file__).resolve().parent;repo=root/'checks'
jobs=[('fv-lints',['make','-C','contracts/verification','verify-fv-lints']),('extracted',['make','-C','contracts/verification','verify-extracted']),('verity-ci',['make','-C','contracts/verity','ci'])]
def run(item):
 label,cmd=item
 with (root/'logs'/('conservative-'+label+'.log')).open('w') as log:
  p=subprocess.run(cmd,cwd=repo,stdout=log,stderr=subprocess.STDOUT,timeout=180)
 row={'label':label,'command':cmd,'status':p.returncode,'log':'conservative-'+label+'.log'}
 print(label,p.returncode,flush=True)
 return row
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(run,jobs))
(root/'conservative-gates.json').write_text(json.dumps(rows,indent=2)+'\n')
assert all(r['status']==0 for r in rows),rows
