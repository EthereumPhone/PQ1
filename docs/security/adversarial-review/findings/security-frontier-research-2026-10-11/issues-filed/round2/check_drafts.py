#!/usr/bin/env python3
"""Mechanical checks on draft files.
  check_drafts.py <group-dir> [--show]   verify dispositions.json citations (snippet must be a substring of the cited master line),
                                         list every path:line in each draft that has no citation entry, validate labels and #refs.
  --show prints the master line for every path:line found in the drafts."""
import json,os,re,sys,glob
W=os.path.expanduser('~/.local/state/pqsigner-research/security-frontier-2026-10/landing')
HERE=os.path.dirname(os.path.abspath(__file__))
ISS={i['number']:i for i in json.load(open(os.path.join(HERE,'all_issues.json')))}
LABELS={'enhancement','documentation','question','priority:high','priority:medium','priority:low','source:frontier-research-2026-10',
 'surface:secure-element','surface:clear-signing','surface:sca-fi','surface:trusted-ui','surface:lifecycle','surface:hardware','surface:release','surface:docs','surface:trustzone','surface:runtime','surface:lockdown','surface:prodtest','surface:fw-update','surface:entropy','surface:onchain','surface:offchain','surface:contracts','surface:usb','surface:companion','surface:fv'}
g=sys.argv[1]; show='--show' in sys.argv
cache={}
def line(path,n):
    if path not in cache:
        p=os.path.join(W,path)
        cache[path]=open(p,encoding='utf-8',errors='replace').read().split('\n') if os.path.isfile(p) else None
    L=cache[path]
    if L is None: return None
    return L[n-1] if 0<n<=len(L) else ''
cits=[]
dp=os.path.join(g,'dispositions.json')
if os.path.exists(dp):
    d=json.load(open(dp)); cits=d.get('citations',[])
    bad=0
    for c in cits:
        l=line(c['path'],int(c['line']))
        if l is None: print('CIT NOFILE',c['draft'],c['path']); bad+=1
        elif c['snippet'].strip() not in l: print('CIT MISMATCH',c['draft'],f"{c['path']}:{c['line']}",'\n    want:',c['snippet'][:110],'\n    have:',l.strip()[:110]); bad+=1
    print(f'citations: {len(cits)} entries, {bad} bad')
cited={(c['draft'],c['path'],int(c['line'])) for c in cits}
RX=re.compile(r'`?((?:[A-Za-z0-9_.\-]+/)*[A-Za-z0-9_.\-]+\.(?:rs|md|py|toml|json|yml|yaml|sol|x|ld|sh|lean|ec|txt)|Makefile|CLAUDE\.md)`?:(\d+)(?:-(\d+))?')
for f in sorted(glob.glob(os.path.join(g,'*.md'))):
    t=open(f,encoding='utf-8').read(); b=os.path.basename(f)
    head=t.split('\n---\n',1)[0]
    probs=[]
    m=re.search(r'^LABELS: (.*)$',head,re.M)
    if m:
        for l in m.group(1).split(','):
            if l.strip() not in LABELS: probs.append('bad label '+l)
        ti=re.search(r'^TITLE: (.*)$',head,re.M).group(1)
        if len(ti)>200: probs.append(f'title {len(ti)} chars')
    elif not re.search(r'^COMMENT_ON: \d+',head,re.M): probs.append('no LABELS/COMMENT_ON header')
    else:
        n=int(re.search(r'^COMMENT_ON: (\d+)',head,re.M).group(1))
        if n not in ISS: probs.append(f'comment target #{n} not in dump')
        elif ISS[n]['state']!='OPEN': probs.append(f'comment target #{n} is {ISS[n]["state"]}')
    if re.search('[—–]',t.split('\n---\n',1)[1]): probs.append('dash chars: '+str(len(re.findall('[—–]',t))))
    for n in sorted({int(x) for x in re.findall(r'(?<![A-Za-z0-9&/])#(\d{1,4})\b',t)}):
        if n not in ISS: probs.append(f'#{n} not an issue in dump')
        elif ISS[n]['state']!='OPEN': probs.append(f'#{n} is CLOSED')
    if re.search(r'invariant #\d',t): probs.append('"invariant #N" autolink')
    pl=RX.findall(t)
    seen=set(); unc=0; nofile=0
    # carry forward the last full path for bare `:123` continuations is not attempted
    for path,a,bn in pl:
        if (path,a) in seen: continue
        seen.add((path,a))
        cands=[path] if os.path.isfile(os.path.join(W,path)) else []
        if not cands:
            nofile+=1; probs.append(f'no such file at master: {path}'); continue
        l=line(path,int(a))
        if (b,path,int(a)) not in cited and cits: unc+=1
        if show: print(f'  {b}  {path}:{a}{"-"+bn if bn else ""}  | {(l or "").strip()[:130]}')
    print(f'{b}: {len(t.split())} words, {len(seen)} path:line refs, {unc} without a citation entry' + (('  !! '+'; '.join(probs)) if probs else ''))
