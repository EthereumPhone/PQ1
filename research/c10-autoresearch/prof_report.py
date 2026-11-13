#!/usr/bin/env python3
"""prof_report.py <elf> <openocd.log> — histogram of DWT_PCSR samples by function (and hottest PCs)."""
import sys, subprocess, bisect, collections
elf, log = sys.argv[1], sys.argv[2]
pcs = [int(x, 16) for x in next(l for l in open(log) if l.startswith('PCS')).split()[1:]]
syms = []
for l in subprocess.run(['arm-none-eabi-nm', '-C', '-S', '--size-sort', elf], capture_output=True, text=True).stdout.splitlines():
    p = l.split(None, 3)
    if len(p) == 4 and p[2].lower() in 'tw':
        syms.append((int(p[0], 16), int(p[1], 16), p[3]))
syms.sort()
starts = [s[0] for s in syms]
halt = collections.Counter(pcs).most_common(1)[0][0]
run = [p for p in pcs if p != halt and p != 0xffffffff]
by = collections.Counter(); exact = collections.Counter()
for p in run:
    q = p & ~1
    i = bisect.bisect_right(starts, q) - 1
    name = syms[i][2] if i >= 0 and q < syms[i][0] + syms[i][1] else '?%x' % q
    by[name[:90]] += 1; exact[q] += 1
n = len(run)
print('samples: %d total, %d while running (halt pc %x excluded)' % (len(pcs), n, halt))
for name, c in by.most_common(25):
    print('%6.2f%%  %6d  %s' % (100 * c / n, c, name))
print('hottest PCs:')
for q, c in exact.most_common(15):
    print('  %08x %6.2f%%' % (q, 100 * c / n))
