#!/usr/bin/env python3
"""prof_classify.py <elf> <openocd.log> — round 13: DWT_PCSR samples grouped into the HASH driver,
the UI tick, the signer (sphincs-c10 Rust), the FI chain (pqsigner-fi, subtle, zeroize), memory
builtins, and bench glue; plus the top functions outside the driver. JSON on the last line."""
import sys, subprocess, bisect, collections, json
elf, log = sys.argv[1], sys.argv[2]
pcs = [int(x, 16) for x in next(l for l in open(log) if l.startswith('PCS')).split()[1:]]
syms = []
for l in subprocess.run(['arm-none-eabi-nm', '-C', '-S', '--size-sort', elf], capture_output=True, text=True).stdout.splitlines():
    p = l.split(None, 3)
    if len(p) == 4 and p[2].lower() in 'tw':
        syms.append((int(p[0], 16), int(p[1], 16), p[3]))
syms.sort()
starts = [s[0] for s in syms]
# DWT_PCSR reads 0xFFFFFFFF while the core is halted; that is the only value dropped. (prof_report.py
# also drops the most common PC as the halt loop, which discards the hottest driver PC, the DCIS poll,
# whenever the sampling window ends before the bench halts.)
run = [p for p in pcs if p != 0xffffffff]

def name_of(q):
    i = bisect.bisect_right(starts, q) - 1
    return syms[i][2] if i >= 0 and q < syms[i][0] + syms[i][1] else '?%x' % q

def cls(n):
    if n.startswith(('pqsigner_hash_tick', 'c10_bench_chain::tick', 'film_tick')) or 'film_tick_paced' in n:
        return 'tick'
    if n.startswith(('pqsigner_sha256', 'pqsigner_wots', 'pqsigner_fors', 'pqsigner_node16', 'pqsigner_th_multi16',
                     'pqsigner_v1_grind', 'pq1_', 'pqsigner_hw::')):
        return 'driver'
    if 'sphincs_c10::' in n:
        return 'signer'
    if 'pqsigner_fi::' in n or 'subtle::' in n or 'zeroize::' in n:
        return 'fi_chain'
    if n.startswith(('compiler_builtins::mem', '__aeabi_mem', 'memcpy', 'memset', 'memmove', 'memcmp', '__aeabi_')):
        return 'mem'
    if n.startswith(('c10_bench_chain::', 'c10_bench_main', 'chain', 'sink')):
        return 'bench_glue'
    return 'other'

# Outlined fragments (MachineOutliner, "z" code) and out-of-line helpers have no class of their
# own: give each the class its callers share (from the disassembly's direct calls), else 'other'.
import re
callers = collections.defaultdict(set)
cur = None
for l in subprocess.run(['arm-none-eabi-objdump', '-d', '-C', '--no-show-raw-insn', elf], capture_output=True, text=True).stdout.splitlines():
    m = re.match(r'^([0-9a-f]+) <.+>:', l)
    if m:
        cur = name_of(int(m.group(1), 16))
        continue
    # Any direct branch (bl, blx, b, b.w, b.n, conditional b<cc>, each with an optional .w/.n) to an
    # address: the target is resolved through the symbol table (the printed <name> of a nested Rust
    # symbol cannot be parsed reliably).
    m = re.search(r'\t(?:blx?|b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?)(?:\.[wn])?\s+([0-9a-f]+)\b', l)
    if m and cur:
        tgt = name_of(int(m.group(1), 16))
        if tgt != cur:
            callers[tgt].add(cur)
def cls2(n, depth=0):
    c = cls(n)
    if c != 'other' or depth > 3:
        return c
    cs = {cls2(x, depth + 1) for x in callers.get(n, ())}
    return cs.pop() if len(cs) == 1 else 'other'
by = collections.Counter(); cat = collections.Counter(); memo = {}
for p in run:
    n = name_of(p & ~1)
    if n not in memo:
        memo[n] = cls2(n)
    by[n[:100]] += 1
    cat[memo[n]] += 1
n = len(run)
print('samples: %d total, %d while running' % (len(pcs), n))
for k, c in cat.most_common():
    print('  %-11s %6.2f%%  %6d' % (k, 100 * c / n, c))
print('top outside the driver:')
for name, c in by.most_common(60):
    if memo.get(name, cls(name)) != 'driver':
        print('  %6.2f%%  %6d  %s' % (100 * c / n, c, name))
print('top driver:')
for name, c in by.most_common(12):
    if memo.get(name, cls(name)) == 'driver':
        print('  %6.2f%%  %6d  %s' % (100 * c / n, c, name))
print(json.dumps({k: round(100 * c / n, 3) for k, c in cat.items()}))
