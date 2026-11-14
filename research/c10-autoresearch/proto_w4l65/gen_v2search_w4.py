#!/usr/bin/env python3
"""gen_v2search_w4.py — round 18: the dt32 count search (gen_v2search_dt.py, reused verbatim: issue, ladder,
reload, frame) with the w = 4 digit sum: 65 two-bit digits, the low 130 bits — HR7 (r10), HR6 (r3), HR5 (r2),
HR4 (r1) whole and the two low bits of HR3 (r0). Pairs into nibbles (<= 6), nibbles into bytes (<= 12), four
words summed bytewise (<= 48), one multiply folds the bytes (<= 192), plus w3 & 3. Scratch lr, r9, r5, r11, r12
(the w = 8 sum's set); target at [sp, #48]. No early reject."""
import os, sys, io, contextlib
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gen_v2search_dt.py")).read()
i, j = src.index("def digit_sum("), src.index("def reload(")
w4 = '''def digit_sum(hit, rej, rz):
    a('movw lr, #0x3333', 'movt lr, #0x3333', 'movw r9, #0x0F0F', 'movt r9, #0x0F0F')
    for n, v in enumerate(('r10', 'r3', 'r2', 'r1')):
        a(f'and r11, {v}, lr', f'and r12, lr, {v}, lsr #2', 'add r11, r11, r12',
          'and r12, r11, r9', 'and r11, r9, r11, lsr #4', 'add r11, r11, r12')
        a('mov r5, r11' if n == 0 else 'add r5, r5, r11')
    a('movw r11, #0x0101', 'movt r11, #0x0101', 'mul r5, r5, r11', 'lsr r5, r5, #24',
      'and r11, r0, #3', 'add r5, r5, r11',
      'ldr r12, [sp, #48]', 'cmp r5, r12', f'beq {hit}f',
      f'{rej}:')
'''
src = src[:i] + w4 + src[j:]
assert src.count("F='pq1_v2_search_dt'") == 1
src = src.replace("F='pq1_v2_search_dt'", "F='pq1_v2_search_w4'")
exec(compile(src, "gen_v2search_w4", "exec"), {})
