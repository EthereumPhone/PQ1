"""Owner-authorized local defensive Lean gate regression controls."""
from pathlib import Path
import importlib.util,json,subprocess,sys
root=Path(__file__).resolve().parent; repo=root/'checks'; canonical=Path('/home/nicola/repos/PQSigner_OS')
prefixes={
 'leading-parser':'import Lean\nopen Lean Parser\ndef p : Parser := leading_parser"\\" -- " ',
 'refine-apostrophe':'example : String := by refine\'"\' -- " ',
 'interpolation-space':'def a := s! "{ "--" }" ',
 'interpolation-comment':'def a := s! /- gap -/ "{ "--" }" ',
 'interpolation-newline':'def a := s!\n"{ "--" }" ',
 'trace-interpolation':'def a : String := dbg_trace "{ "--" }"; "" ',
}
def scanner(path,name):
 s=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
old=scanner(repo/'contracts/verification/scripts/lean_source.py','old_source')
new=scanner(canonical/'contracts/verification/scripts/lean_source.py','new_source')
rows=[]
for project in ['lean','extracted']:
 for label,prefix in prefixes.items():
  for kind,ending,word in [('axiom','axiom Hidden : False\ntheorem t : False := Hidden\n#print axioms t\n','axiom'),('admit','theorem Hidden : False := by admit\n#print axioms Hidden\n','admit')]:
   source=prefix+ending; path=root/'LexicalProbe.lean';path.write_text(source)
   # Count without the reporting command, which contains the plural word axioms.
   row={'project':project,'case':label,'kind':kind,'old_count':old.keyword_count(source,word),'new_count':new.keyword_count(source,word)}
   p=subprocess.run([str(Path.home()/'.elan/bin/lake'),'env','lean',str(path)],cwd=repo/'contracts/verification'/project,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
   (root/'logs'/f'lexical-{project}-{label}-{kind}.log').write_text(p.stdout)
   row['status']=p.returncode;row['output']=p.stdout;rows.append(row)
   print(project,label,kind,row['old_count'],row['new_count'],p.returncode,flush=True)
   assert p.returncode==0,p.stdout
   assert row['new_count']==1,row
(root/'lexical-compiler-probes.json').write_text(json.dumps(rows,indent=2)+'\n')

# Exercise the actual inventory and default-built Verity CI, restoring sources
# even on failure. "before" uses the immutable second candidate's scanner.
rows=[]
def run(label,cmd,expected):
 p=subprocess.run(cmd,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
 (root/'logs'/(label+'.log')).write_text(p.stdout)
 rows.append({'label':label,'command':cmd,'status':p.returncode,'expected':expected})
 print(label,p.returncode,flush=True)
 assert (p.returncode==0)==(expected==0),p.stdout[-2500:]
for phase in ['before','after']:
 if phase=='after':
  import shutil
  for name in ['lean_source.py','check_axiom_inventory.py','test_axiom_inventory.py']:
   rel=Path('contracts/verification/scripts')/name;shutil.copy2(canonical/rel,repo/rel)
 for label in ['leading-parser','refine-apostrophe','interpolation-comment','trace-interpolation']:
  prefix=prefixes[label];expected=0 if phase=='before' else 1
  module=repo/'contracts/verification/extracted/Extracted/LexicalProbe.lean'
  try:
   module.write_text(prefix+'axiom Hidden : False\n')
   run(f'lexical-{phase}-extracted-{label}',['/usr/bin/python3','-E','-S','contracts/verification/scripts/check_axiom_inventory.py','extracted'],expected)
  finally:module.unlink()
  top=repo/'contracts/verity/PQSigner/Verifier/Top.lean';original=top.read_bytes()
  try:
   body=prefix.removeprefix('import Lean\n')+'theorem Hidden : False := by admit\n'
   top.write_bytes(b'import Lean\n'+original+b'\nnamespace LexicalProbe\n'+body.encode()+b'end LexicalProbe\n')
   run(f'lexical-{phase}-verity-{label}',['make','-C','contracts/verity','ci'],expected)
  finally:top.write_bytes(original)
(root/'lexical-gate-probes.json').write_text(json.dumps(rows,indent=2)+'\n')
