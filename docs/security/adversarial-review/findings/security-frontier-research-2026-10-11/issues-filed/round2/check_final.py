#!/usr/bin/env python3
"""Check every path:line in final/*.md against master. A ref is VERIFIED when some reviewer's dispositions.json has a citation
for the same (path, line) whose snippet is a substring of that master line. Other refs are printed with the master line for a manual read."""
import json,os,re,glob,sys
W=os.path.expanduser('~/.local/state/pqsigner-research/security-frontier-2026-10/landing')
HERE=os.path.dirname(os.path.abspath(__file__))
cits={}
for dp in glob.glob(os.path.join(HERE,'drafts','*','dispositions.json')):
    for c in json.load(open(dp)).get('citations',[]):
        cits.setdefault((c['path'],int(c['line'])),[]).append(c['snippet'])
cache={}
def line(path,n):
    if path not in cache:
        p=os.path.join(W,path); cache[path]=open(p,encoding='utf-8',errors='replace').read().split('\n') if os.path.isfile(p) else None
    L=cache[path]
    return None if L is None else (L[n-1] if 0<n<=len(L) else '')
RX=re.compile(r'`((?:[A-Za-z0-9_.\-]+/)+[A-Za-z0-9_.\-]+|Makefile|CLAUDE\.md|README\.md|Cargo\.lock|Cargo\.toml)`?:(\d+)(?:-(\d+))?')
tot=ver=0; manual=[]
for f in sorted(glob.glob(os.path.join(HERE,'final','*.md'))):
    t=open(f).read(); b=os.path.basename(f); seen=set()
    for path,a,z in RX.findall(t):
        if (path,a) in seen: continue
        seen.add((path,a)); tot+=1; n=int(a); l=line(path,n)
        if l is None: manual.append((b,path,a,z,'!! NO SUCH FILE')); continue
        if any(s.strip() in l for s in cits.get((path,n),[])): ver+=1
        else: manual.append((b,path,a,z,l.strip()[:150]))
print(f'{tot} path:line refs in final/; {ver} verified against a reviewer citation; {len(manual)} need a manual read')
if '--manual' in sys.argv:
    for b,p,a,z,l in manual: print(f'{b.split("__")[0][:9]:9} {p}:{a}{"-"+z if z else ""}  | {l}')
