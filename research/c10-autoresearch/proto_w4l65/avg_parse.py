#!/usr/bin/env python3
"""avg_parse.py <openocd.log> <name> — the 16-message mean of bench_avg_v2f (experiment_avg.sh's parser);
exit 1 unless status DONE, magic/stage right and all 16 signatures verified."""
import json, sys
L = open(sys.argv[1]).read().splitlines()
w = next(([int(x, 16) for x in l.split()[1:]] for l in L if l.startswith('RESULT_WORDS 0x')), None)
r = {'ok': False, 'variant': sys.argv[2]}
if not w or w[0] != 0x444F4E45: r['why'] = 'status %s' % (hex(w[0]) if w else None); print(json.dumps(r)); sys.exit(1)
o = w[64:96]
if o[0] != 0x43313041 or o[1] != 100: r['why'] = 'magic/stage %x %d' % (o[0], o[1]); print(json.dumps(r)); sys.exit(1)
if o[7] != 16: r['why'] = 'only %d/16 verified' % o[7]; print(json.dumps(r)); sys.exit(1)
per = o[16:32]; tot = o[4] | o[5] << 32
r.update(ok=True, keygen=o[3], mean_sign=tot // 16, min_sign=min(per), max_sign=max(per), mean_verify=o[6] // 16,
         cached_est=2 * (tot // 16) + o[6] // 16, cached_est_s=round((2 * (tot // 16) + o[6] // 16) / 160e6, 4), per_sign=per)
print(json.dumps(r))
