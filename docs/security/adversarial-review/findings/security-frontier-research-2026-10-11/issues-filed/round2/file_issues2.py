#!/usr/bin/env python3
"""File approved drafts from ./final/. New issues: <KEY>__slug.md with TITLE/LABELS header. Comments: c-<num>__<KEY>__slug.md with COMMENT_ON header.
Appends to ../issues/filed.json under keys 'r2:<KEY>' and 'r2:c-<num>:<KEY>'. `{{KEY}}` in a body resolves to the issue filed for KEY.
Usage: file_issues2.py [--dry]"""
import re, glob, json, os, subprocess, sys, time
REPO='EthereumPhone/PQ1'
HERE=os.path.dirname(os.path.abspath(__file__))
LOG=os.path.join(HERE,'..','issues','filed.json')
DRY='--dry' in sys.argv
filed=json.load(open(LOG))
def save():
    if not DRY: json.dump(filed,open(LOG,'w'),indent=1)
def resolve(body, final=False):
    pending=False
    def rep(m):
        nonlocal pending
        k='r2:'+m.group(1)
        if k in filed: return '#%d'%filed[k]['number']
        pending=True
        if final: raise SystemExit('unresolved token '+m.group(1))
        return 'a companion issue being filed with this one'
    return re.sub(r'\{\{([A-Za-z0-9\-]+)\}\}',rep,body), pending
def gh(cmd):
    if DRY: print('DRY', ' '.join(cmd[:6]), '...'); return 'https://github.com/EthereumPhone/PQ1/issues/0'
    r=subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode!=0: print('FAILED',cmd[:4],r.stderr[:400]); save(); sys.exit(1)
    time.sleep(3); return r.stdout.strip().splitlines()[-1]
issues=sorted(f for f in glob.glob(os.path.join(HERE,'final','*.md')) if not os.path.basename(f).startswith('c-'))
order=os.path.join(HERE,'final','ORDER.txt')
if os.path.exists(order):
    want=[l.strip() for l in open(order) if l.strip()]
    issues.sort(key=lambda f: (want.index(os.path.basename(f).split('__')[0]) if os.path.basename(f).split('__')[0] in want else 999, f))
needs_edit=[]
for f in issues:
    key=os.path.basename(f).split('__')[0]; k='r2:'+key
    head,body=open(f).read().split('\n---\n',1)
    title=re.search(r'^TITLE: (.*)$',head,re.M).group(1).strip()
    labels=[l.strip() for l in re.search(r'^LABELS: (.*)$',head,re.M).group(1).split(',')]
    b,pending=resolve(body)
    if k in filed:
        if filed[k].get('pending'): needs_edit.append((f,k))
        continue
    out=os.path.join(HERE,'out',key+'.body.md'); open(out,'w').write(b)
    cmd=['gh','issue','create','-R',REPO,'--title',title,'--body-file',out]
    for l in labels: cmd+=['--label',l]
    url=gh(cmd); num=int(url.rsplit('/',1)[1])
    if not DRY: filed[k]={'number':num,'url':url,'title':title,'file':os.path.basename(f),'pending':pending}
    save(); print('created',key,'->',num,title[:80])
    if pending: needs_edit.append((f,k))
for f,k in needs_edit:
    if DRY: print('DRY would edit',k); continue
    head,body=open(f).read().split('\n---\n',1)
    b,_=resolve(body,final=True)
    out=os.path.join(HERE,'out',k[3:]+'.body.md'); open(out,'w').write(b)
    gh(['gh','issue','edit',str(filed[k]['number']),'-R',REPO,'--body-file',out])
    filed[k]['pending']=False; save(); print('edited',k,filed[k]['number'])
for f in sorted(glob.glob(os.path.join(HERE,'final','c-*.md'))):
    parts=os.path.basename(f)[:-3].split('__'); n=int(parts[0][2:]); k='r2:c-%d:%s'%(n,parts[1])
    if k in filed: continue
    head,body=open(f).read().split('\n---\n',1)
    assert int(re.search(r'^COMMENT_ON: (\d+)',head,re.M).group(1))==n, f
    b,_=resolve(body,final=not DRY)
    out=os.path.join(HERE,'out','c-%d-%s.body.md'%(n,parts[1])); open(out,'w').write(b)
    url=gh(['gh','issue','comment',str(n),'-R',REPO,'--body-file',out])
    if not DRY: filed[k]={'comment_on':n,'url':url,'file':os.path.basename(f)}
    save(); print('commented',parts[1],'on',n)
print('DONE', len([k for k in filed if k.startswith('r2:') and not k.startswith('r2:c-')]),'new issues',len([k for k in filed if k.startswith('r2:c-')]),'new comments')
