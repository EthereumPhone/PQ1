from pathlib import Path
import sys,json,subprocess
p=Path('/tmp/pq-fv-gates-20260915-u0_8a4pb');t=p/'target';sys.path.insert(0,str(t/'scripts'));import test_gate_enforcement as tests
records=[];fixture=tests.GateControls();fixture.setUp()
def valid_yaml(relative):
 path=fixture.root/relative;wf=tests.gate.load_workflow(path)
 if True in wf:wf['on']=wf.pop(True)
 path.write_text(tests.gate.yaml.safe_dump(wf))
 lint=subprocess.run(['actionlint',str(path)],text=True,capture_output=True)
 assert lint.returncode==0,lint.stdout+lint.stderr
 return wf
try:
 fixture.run_checker(accept=True);row=next(r for r in tests.BLOCKING if r['id']=='miri')
 for child in ['secure/src/nsc/mod.rs','secure/src/nsc/ns_ptr.rs']:
  def ignore_child(wf,job,step):
   event=tests.gate._get_on(wf)
   if event.get('pull_request') is None:event['pull_request']={}
   event['pull_request']['paths-ignore']=[child]
  relative=fixture.change_workflow(row,ignore_child);wf=valid_yaml(relative)
  per_gate=tests.gate.check_gate(row,_wf_override=wf);out=fixture.run_checker(accept=child.endswith('/ns_ptr.rs'))
  records.append({'case':'Miri child-file PR exclusion','ignore':child,'per_gate_failures':per_gate,'checker_exit':0 if child.endswith('/ns_ptr.rs') else 1,'actionlint_exit':0,'diagnostics':[l for l in out.splitlines() if 'EXCLUDES' in l]});fixture.restore_workflow(relative)
 row=next(r for r in fixture.manifest['gates'] if r['id']=='verify-easycrypt-pins');row['polices_paths'].remove('contracts/verification/easycrypt/**')
 def omit_model(wf,job,step):
  for trig in ['push','pull_request']:tests.gate._get_on(wf)[trig]['paths'].remove('contracts/verification/easycrypt/**')
 relative=fixture.change_workflow(row,omit_model);valid_yaml(relative);out=fixture.run_checker(accept=True)
 records.append({'case':'EasyCrypt model surface removed from manifest and triggers','checker_exit':0,'actionlint_exit':0,'diagnostic':next(l for l in out.splitlines() if '[ok]' in l and 'verify-easycrypt-pins ' in l)})
finally:fixture.doCleanups()
(p/'review2-reproductions.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(records,indent=2))
