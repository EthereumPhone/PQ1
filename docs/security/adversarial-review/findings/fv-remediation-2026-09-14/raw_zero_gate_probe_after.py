from pathlib import Path
import json,subprocess
root=Path(__file__).resolve().parent;repo=root/'checks';rows=[]
def run(label,cmd):
 p=subprocess.run(cmd,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
 (root/'logs'/(label+'.log')).write_text(p.stdout)
 rows.append({'label':label,'command':cmd,'status':p.returncode})
 print(label,p.returncode,flush=True)
 assert p.returncode!=0,p.stdout[-2000:]
module=repo/'contracts/verification/extracted/Extracted/RawZeroProbe.lean'
try:
 module.write_text('namespace RawZeroProbe\ndef a := r"\\" def b := "--" private axiom Hidden : False\nend RawZeroProbe\n')
 run('raw-zero-extracted-gate-after',['python3','contracts/verification/scripts/check_axiom_inventory.py','extracted'])
finally:module.unlink()
top=repo/'contracts/verity/PQSigner/Verifier/Top.lean';original=top.read_bytes()
try:
 top.write_bytes(original+b'\nnamespace RawZeroProbe\ndef a := r"\\" def b := "--" theorem Hidden : False := by admit\nend RawZeroProbe\n')
 run('raw-zero-verity-gate-after',['make','-C','contracts/verity','ci'])
finally:top.write_bytes(original)
(root/'raw-zero-gate-after.json').write_text(json.dumps(rows,indent=2)+'\n')
