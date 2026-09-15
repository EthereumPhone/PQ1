from pathlib import Path
import sys,json,subprocess
p=Path('/tmp/pq-fv-gates-20260915-u0_8a4pb');t=p/'target';sys.path.insert(0,str(t/'scripts'));import test_gate_enforcement as tests
f=tests.GateControls();f.setUp();records=[]
try:
 f.run_checker(accept=True)
 row=next(r for r in tests.BLOCKING if r['id']=='verify-proof-mutation')
 for schedule in [[],[{'cron':'0 0 1 1 *'}]]:
  rel=f.change_workflow(row,lambda wf,job,step:tests.gate._get_on(wf).update(schedule=schedule));f.run_checker(accept=True)
  lint=subprocess.run(['actionlint',str(f.root/rel)],text=True,capture_output=True)
  records.append({'case':'scheduled gate cadence','schedule':schedule,'checker_exit':0,'actionlint_exit':lint.returncode,'actionlint_output':lint.stdout+lint.stderr});f.restore_workflow(rel)
 row=next(r for r in tests.BLOCKING if r['id']=='miri')
 for key,pattern in [('branches-ignore','master+'),('branches','maste?')]:
  def change_branch(wf,job,step):
   on=tests.gate._get_on(wf)
   if on.get('pull_request') is None:on['pull_request']={}
   on['pull_request'][key]=[pattern]
  rel=f.change_workflow(row,change_branch);f.run_checker(accept=True)
  lint=subprocess.run(['actionlint',str(f.root/rel)],text=True,capture_output=True);assert lint.returncode==0,lint.stdout+lint.stderr
  records.append({'case':'protected branch grammar mismatch','filter':key,'pattern':pattern,'checker_exit':0,'actionlint_exit':0});f.restore_workflow(rel)
 records.append({'case':'future target discovery limitation','match':[m.group(1) for m in tests.gate.SOUNDNESS_TARGET.finditer('make verify-a verify-b')],'existing_manifest_policy':'all 65 current IDs independently pinned; no unregistered live second target identified by reviewer','disposition':'NOTE: future discovery coverage, defer with #509'})
finally:f.doCleanups()
(p/'review3-reproductions.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(records,indent=2))
