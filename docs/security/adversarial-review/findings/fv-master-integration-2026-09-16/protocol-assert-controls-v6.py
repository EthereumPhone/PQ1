import contextlib,io,json,os,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve()
setup="import sys\nsys.path.insert(0, 'scripts')\nimport check_protocol_models as g\n"
cases={
'count': ("real=g.parse_proverif\ndef bad(s):\n a,b,c=real(s)\n return a,b,c+1\ng.parse_proverif=bad\n", 'clean ProVerif raw result count differs'),
'no-op': ("real=g._SPTHY_LEMMA_RE\nclass NoEdit:\n def match(self,*a,**k): return real.match(*a,**k)\n def finditer(self,*a,**k): return real.finditer(*a,**k)\n def sub(self, repl, source): return source\ng._SPTHY_LEMMA_RE=NoEdit()\n", 'gut substitution did not apply'),
'wrong-reason': ("real=g.check_tamarin_source\ndef bad(name, source):\n if any(m.group(1)=='seed_secret_under_single_compromise' and m.group(3)=='T' for m in g._SPTHY_LEMMA_RE.finditer(source)):\n  return ['unrelated parser failure']\n return real(name,source)\ng.check_tamarin_source=bad\n", 'expected a full-source DRIFT')}
results=[]
for opt in ('0','1','2'):
 for name,(patch,reason) in cases.items():
  check="try:\n g.self_test()\nexcept g.HarnessError as e:\n print('CONTROL_EXCEPTION:', str(e))\n raise SystemExit(0 if "+repr(reason)+" in str(e) else 2)\nraise SystemExit('expected explicit self-test failure was absent')\n"
  cp=subprocess.run([sys.executable,'-B','-c',setup+patch+check],cwd=root,env=dict(os.environ,PYTHONOPTIMIZE=opt),text=True,capture_output=True,timeout=20)
  result={'optimization':opt,'case':name,'exit_code':cp.returncode,'decisive_output':cp.stdout.splitlines()[-1:]}
  results.append(result)
  if cp.returncode: raise SystemExit(json.dumps(result)+'\n'+cp.stderr)
print(json.dumps(results,indent=2))
