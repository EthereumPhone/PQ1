"""Owner-authorized local defensive checks for Lean comments and token adjacency."""
from pathlib import Path
import importlib.util,json,shutil,subprocess,sys
r=Path(__file__).resolve().parent;c=Path('/home/nicola/repos/PQSigner_OS');repo=r/'checks'
sys.path.insert(0,str(c/'contracts/verification/scripts'))
from test_axiom_inventory import COMMENT_AXIOMS,COMMENT_HOLES
from lean_source import keyword_count
s=importlib.util.spec_from_file_location('old',repo/'contracts/verification/scripts/lean_source.py');old=importlib.util.module_from_spec(s);s.loader.exec_module(old)
rows=[]
for project in ['lean','extracted']:
 for kind,inputs,word in [('axiom',COMMENT_AXIOMS,'axiom'),('hole',COMMENT_HOLES,'(?:sorry|admit|sorryAx|proof_wanted)')]:
  for n,source in enumerate(inputs):
   f=r/'CommentProbe.lean';f.write_text(source+'#print axioms X\n')
   p=subprocess.run([str(Path.home()/'.elan/bin/lake'),'env','lean',str(f)],cwd=repo/'contracts/verification'/project,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
   row={'project':project,'kind':kind,'index':n,'source':source,'status':p.returncode,'old_count':old.keyword_count(source,word),'new_count':keyword_count(source,word),'output':p.stdout}
   rows.append(row);print(project,kind,n,p.returncode,row['old_count'],row['new_count'],flush=True)
   assert p.returncode==0,p.stdout
   assert row['old_count']==0 and row['new_count']==1,row
(r/'comment-compiler-probes.json').write_text(json.dumps(rows,indent=2)+'\n')
rows=[]
def run(label,cmd,expected):
 p=subprocess.run(cmd,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
 (r/'logs'/(label+'.log')).write_text(p.stdout);rows.append({'label':label,'command':cmd,'status':p.returncode,'expected':expected})
 print(label,p.returncode,flush=True);assert (p.returncode==0)==(expected==0),p.stdout[-2000:]
for phase in ['before','after']:
 if phase=='after':
  for name in ['lean_source.py','check_axiom_inventory.py','test_axiom_inventory.py','axiom_inventory_lean.json','axiom_inventory_extracted.json']:
   rel=Path('contracts/verification/scripts')/name;shutil.copy2(c/rel,repo/rel)
 for n,source in enumerate(COMMENT_AXIOMS):
  path=repo/'contracts/verification/extracted/Extracted/CommentProbe.lean'
  try:
   path.write_text(source)
   run(f'comment-{phase}-axiom-{n}',['/usr/bin/python3','-E','-S','contracts/verification/scripts/check_axiom_inventory.py','extracted'],0 if phase=='before' else 1)
  finally:path.unlink()
 for n,source in enumerate(COMMENT_HOLES):
  path=repo/'contracts/verity/PQSigner/Verifier/Top.lean';data=path.read_bytes()
  try:
   path.write_bytes(data+b'\nnamespace CommentProbe\n'+source.encode()+b'end CommentProbe\n')
   run(f'comment-{phase}-hole-{n}',['make','-C','contracts/verity','ci'],0 if phase=='before' else 1)
  finally:path.write_bytes(data)
(r/'comment-gate-probes.json').write_text(json.dumps(rows,indent=2)+'\n')
