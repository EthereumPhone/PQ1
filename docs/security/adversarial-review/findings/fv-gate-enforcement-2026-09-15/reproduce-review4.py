from pathlib import Path
import sys,json,subprocess
p=Path('/tmp/pq-fv-gates-20260915-u0_8a4pb');t=p/'target';sys.path.insert(0,str(t/'scripts'));import test_gate_enforcement as tests
f=tests.GateControls();f.setUp();records=[]
try:
 row=next(r for r in tests.BLOCKING if r['id']=='miri');f.run_checker(accept=True)
 for value in [False,True,[],['opened']]:
  rel=f.change_workflow(row,lambda wf,job,step:tests.gate._get_on(wf).update(pull_request=value));f.run_checker(accept=True)
  lint=subprocess.run(['actionlint',str(f.root/rel)],text=True,capture_output=True)
  records.append({'case':'malformed PR payload','value':value,'checker_exit':0,'actionlint_exit':lint.returncode});f.restore_workflow(rel)
 for pattern in ['**/master','**/**']:
  def exclude(wf,job,step):
   on=tests.gate._get_on(wf)
   if on.get('pull_request') is None:on['pull_request']={}
   on['pull_request']['branches-ignore']=[pattern]
  rel=f.change_workflow(row,exclude);f.run_checker(accept=True)
  lint=subprocess.run(['actionlint',str(f.root/rel)],text=True,capture_output=True);assert lint.returncode==0,lint.stdout+lint.stderr
  records.append({'case':'unmodelled zero-directory branch globstar','pattern':pattern,'checker_exit':0,'actionlint_exit':0,'semantic_boundary':'GitHub filter reference documents zero-directory **/ patterns; branch applicability inferred from shared filter grammar, no hosted trigger experiment'});f.restore_workflow(rel)
finally:f.doCleanups()
(p/'review4-reproductions.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(records,indent=2))
