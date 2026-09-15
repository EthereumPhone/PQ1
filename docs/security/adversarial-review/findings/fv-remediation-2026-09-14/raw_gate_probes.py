from pathlib import Path
import json,shutil,subprocess,sys
r=Path(__file__).resolve().parent;c=Path('/home/nicola/repos/PQSigner_OS');repo=r/'checks'
sys.path.insert(0,str(c/'contracts/verification/scripts'))
from test_axiom_inventory import CUSTOM_AXIOMS,CUSTOM_HOLES
rels=['contracts/verification/scripts/'+s for s in ['lean_source.py','check_axiom_inventory.py','check_verity_holes.py','test_axiom_inventory.py','axiom_inventory_lean.json','axiom_inventory_extracted.json']]+['contracts/verity/Makefile','contracts/verity/PQSigner/Theorems.lean','contracts/verity/PQSigner/Verifier/Top.lean','contracts/verity/PQSigner/Verifier/Hypertree.lean']
for rel in rels:shutil.copy2(c/rel,repo/rel)
(repo/'contracts/verification/scripts/verity_comment_pins.json').unlink(missing_ok=True)
rows=[]
def run(label,cmd):
 p=subprocess.run(cmd,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
 (r/'logs'/(label+'.log')).write_text(p.stdout);rows.append({'label':label,'command':cmd,'status':p.returncode,'expected':'nonzero','implementation':'raw mentions, no exceptions'})
 print(label,p.returncode,flush=True);assert p.returncode!=0,p.stdout[-2000:]
for n,source in enumerate(CUSTOM_AXIOMS):
 p=repo/'contracts/verification/extracted/Extracted/CustomProbe.lean'
 try:
  p.write_text(source);run(f'custom-after-axiom-{n}',['/usr/bin/python3','-E','-S','contracts/verification/scripts/check_axiom_inventory.py','extracted'])
 finally:p.unlink()
for n,source in enumerate(CUSTOM_HOLES):
 p=repo/'contracts/verity/PQSigner/Verifier/Top.lean';data=p.read_bytes()
 try:
  p.write_bytes(data+b'\nnamespace CustomProbe\n'+source.encode()+b'end CustomProbe\n');run(f'custom-after-hole-{n}',['make','-C','contracts/verity','ci'])
 finally:p.write_bytes(data)
old=json.loads((r/'custom-gate-probes.json').read_text());old=[row for row in old if 'before' in row['label']]
(r/'custom-gate-probes.json').write_text(json.dumps(old+rows,indent=2)+'\n')
