# host reference for the C probe: same 2,000 chained compressions in Python
K=[int(x,16) for x in open('sha512c.c').read().split('static const uint64_t K[80] = {')[1].split('};')[0].replace('ULL','').replace('\n','').split(',')]
M=(1<<64)-1
R=lambda x,n:((x>>n)|(x<<(64-n)))&M
def comp(st,inp):
    w=list(inp); a,b,c,d,e,f,g,h=st
    for r in range(80):
        if r>=16:
            j=r&15; x14=w[(j+14)&15]; x1=w[(j+1)&15]
            w[j]=(w[j]+(R(x14,19)^R(x14,61)^(x14>>6))+w[(j+9)&15]+(R(x1,1)^R(x1,8)^(x1>>7)))&M
        t1=(h+(R(e,14)^R(e,18)^R(e,41))+(g^(e&(f^g)))+K[r]+w[r&15])&M
        t2=((R(a,28)^R(a,34)^R(a,39))+((a&b)|(c&(a|b))))&M
        h,g,f,e,d,c,b,a=g,f,e,(d+t1)&M,c,b,a,(t1+t2)&M
    return [(x+y)&M for x,y in zip(st,[a,b,c,d,e,f,g,h])]
st=[0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1,0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179]
blk=[(0x0123456789abcdef*(i+1))&M for i in range(16)]
for n in range(2000):
    st=comp(st,blk); blk[0]^=st[0]
print('%08x %08x'%(st[0]>>32, st[0]&0xffffffff))
