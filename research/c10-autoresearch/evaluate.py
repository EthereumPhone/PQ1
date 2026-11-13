#!/usr/bin/env python3
"""evaluate.py <openocd.log> <golden.bin> — FROZEN evaluator for the C10 autoresearch loop.
Checks the kit run (status DONE, all stages reached, both verifies true, pass A == pass B, pk_root and
both signatures byte-identical to golden.bin) and prints the metrics. Exit 0 only if every check passes."""
import sys, json
log, golden = sys.argv[1], open(sys.argv[2], 'rb').read()
L = open(log).read().splitlines()
def words(tag):
    for l in L:
        if l.startswith(tag + ' 0x'):
            return [int(x, 16) for x in l.split()[1:]]
    return None
w, s0, s1 = words('RESULT_WORDS'), words('SIG0_WORDS'), words('SIG1_WORDS')
res = {'ok': False}
def fail(why):
    res['why'] = why; print(json.dumps(res)); sys.exit(1)
if not w or len(w) < 96: fail('no result words')
st = w[0]
res['status'] = '%08x' % st
if st != 0x444F4E45:
    if st >> 16 == 0xFA17: fail('FAULT exc %d CFSR=%08x PC=%08x' % (st & 0x1ff, w[16], w[22]))
    if st >> 16 == 0x4841: fail('HALT code %04x stage %d' % (st & 0xffff, w[65]))
    fail('status not DONE')
o = w[64:96]
if o[0] != 0x43313042: fail('bad magic')
if o[1] != 8: fail('stopped at stage %d' % o[1])
names = ['hashinit', 'keygen', 'signA_m0', 'signB_m0', 'verify_m0', 'signA_m1', 'verify_m1']
cyc = dict(zip(names, o[2:9]))
res.update(cyc)
if o[9] != 7: fail('flags %d (bit0 verify m0, bit1 verify m1, bit2 passA==passB)' % o[9])
pk = b''.join(x.to_bytes(4, 'little') for x in o[10:14])
b0 = b''.join(x.to_bytes(4, 'little') for x in s0 or [])[:4008]
b1 = b''.join(x.to_bytes(4, 'little') for x in s1 or [])[:4008]
if pk != golden[:16]: fail('pk_root differs from golden')
if b0 != golden[16:16 + 4008]: fail('sig m0 differs from golden')
if b1 != golden[16 + 4008:]: fail('sig m1 differs from golden')
# Headline metrics (cycles @ any clock; seconds at 160 MHz):
#  cached_sign = 2 passes + verify on m0 (the production FI chain's hashing work)
#  total       = keygen + every sign + every verify
res['cached_sign'] = cyc['signA_m0'] + cyc['signB_m0'] + cyc['verify_m0']
res['total'] = sum(cyc[k] for k in names[1:])
res['cached_sign_s'] = round(res['cached_sign'] / 160e6, 4)
res['keygen_s'] = round(cyc['keygen'] / 160e6, 4)
res['ok'] = True
print(json.dumps(res))
