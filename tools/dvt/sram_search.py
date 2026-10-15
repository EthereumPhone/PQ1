import sys,re
vals={}
for line in open(sys.argv[1]):
    n,h=line.split(); vals[n]=bytes.fromhex(h)
vals['master_pk_seed']=vals['master_pk_seed'][:16]
W=12
for f in sys.argv[2:]:
    d=open(f,'rb').read()
    base=0x38020000 if 'sram4' in f else 0x30000000
    print(f"== {f.split('/')[-1]} ({len(d)} B)")
    for n,v in vals.items():
        hits=set()
        for i in range(0,len(v)-W+1,4):
            for m in re.finditer(re.escape(v[i:i+W]),d):
                hits.add(m.start()-i)
        if hits: print(f"  {n:22s} {len(hits)} hit(s) at", ", ".join(hex(base+h) for h in sorted(hits)[:8]))
