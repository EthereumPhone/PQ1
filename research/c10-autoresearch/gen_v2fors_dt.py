# Generates the global_asm! text for pq1_v2_fors_sub (round 11, E13).
import sys
# Round 12 (E19): optional timed spins before the F, H, PRF waits (argv: SF SH SP; 3 cycles/iteration).
SP_F, SP_H, SP_P = (int(x) for x in (sys.argv[1:4] if len(sys.argv) >= 4 else (0, 0, 0)))
L=[]
def a(*xs): L.extend(xs)
def spin(n, lab):
    if n:
        a(f'movs r0, #{n}', f'{lab}:', 'subs r0, r0, #1', f'bne {lab}b')
def c(t): L.append('// '+t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #-8]')
def ladder(hit, cnt):
    # polls with dead r0 (scratch) / r1 (counter): r0..r3 are rewritten by the HR read
    a('.rept 16', 'ldr r0, [r4, #0x18]', 'lsls r0, r0, #30', f'bmi {hit}f', '.endr',
      'mov.w r1, #16777216',
      f'{cnt}:', 'ldr r0, [r4, #0x18]', 'lsls r0, r0, #30', f'bmi {hit}f', 'subs r1, r1, #1', f'bne {cnt}b', 'b 99f')
def ha(dst, src, tmp):
    # dst = rev(v2_ha(src)) = (src & 0x7F) << 9 | (src >> 7) << 16  (big-endian form, DATATYPE 00)
    a(f'and {dst}, {src}, #0x7F', f'lsls {dst}, {dst}, #9', f'lsrs {tmp}, {src}, #7', f'orr {dst}, {dst}, {tmp}, lsl #16')
F='pq1_v2_fors_sub'
a('.syntax unified', '.section .text.'+F+',\\"ax\\",%progbits', '.p2align 2', '.global '+F, '.type '+F+',%function', '.thumb_func', F+':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #276')
c('frame: 0 S0..S3, 16 a0, 20 a1, 24 p0, 28 p1 | ha(j), 32 p1, 36 sk_seed, 40 j, 44 end, 48 h, 52 k, 56 idx,')
c('60 depth, 64 a1 | k << 12 | ha(idx), 68 ctx, 72 L3, 76 stack (12 x 16)')
c('ctx: 0..4 S, 4 a0, 5 a1, 6 p0, 7 p1, 8 sk_seed, 9 j0, 10 h, 11..15 the root (out)')
a('str r0, [sp, #68]',
  'ldm r0, {{r1, r2, r3, r5, r6, r7, r8, r9, r10, r11, r12}}',
  'rev r1, r1', 'rev r2, r2', 'rev r3, r3', 'rev r5, r5', 'rev r6, r6', 'rev r7, r7', 'rev r8, r8', 'rev r9, r9',
  'str r1, [sp, #0]', 'str r2, [sp, #4]', 'str r3, [sp, #8]', 'str r5, [sp, #12]',
  'str r6, [sp, #16]', 'str r7, [sp, #20]', 'str r8, [sp, #24]', 'str r9, [sp, #32]', 'str r10, [sp, #36]',
  'str r11, [sp, #40]', 'str r12, [sp, #48]',
  'movs r0, #1', 'lsls r0, r0, r12', 'add r0, r0, r11', 'str r0, [sp, #44]',
  'movs r0, #0', 'str r0, [sp, #60]')
ha('r1', 'r11', 'r2')
a('orr r1, r1, r9', 'str r1, [sp, #28]',
  'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}', 'movw lr, #0x4', 'movt lr, #0x6')
c('first PRF (leaf j0), issued here so the caller never holds sk_seed words: idle and no stale DCIS (v2_begin), INIT')
a('ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 80f',
  '81:', 'str lr, [r4, #-12]', 'ldr r12, [sp, #36]',
  'ldr r0, [r12]', 'ldr r1, [r12, #4]', 'ldr r2, [r12, #8]', 'ldr r3, [r12, #12]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3')
din('r0','r1','r2','r3')
a('ldr r0, [r12, #16]', 'ldr r1, [r12, #20]', 'ldr r2, [r12, #24]', 'ldr r3, [r12, #28]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3')
din('r0','r1','r2','r3')
a('ldrd r0, r1, [sp, #24]')
din('r0','r1')
a('mov.w r12, #280', 'str r12, [r4, #-4]')
c('==== F (leaf j; its PRF in flight): S, a0 in r5..r9, a1 | ha(j) in r10 ====')
a('10:', 'mov r12, sp', 'ldm r12, {{r5, r6, r7, r8, r9}}', 'ldr r0, [sp, #40]')
ha('r10', 'r0', 'r1')
a('ldr r1, [sp, #20]', 'orr r10, r10, r1')
spin(SP_F, 40)
ladder(11, 12)
a('11:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 13f',
  '14:', 'str lr, [r4, #-12]')
din('r5','r6','r7','r8','r0','r1','r2','r3','r9','r10')
a('mov.w r12, #280', 'str r12, [r4, #-4]',
  'ldr r0, [sp, #40]', 'str r0, [sp, #56]', 'movs r1, #0', 'str r1, [sp, #52]')
c('==== merges: while k < h and idx is odd ====')
a('20:', 'ldr r0, [sp, #52]', 'ldr r1, [sp, #48]', 'cmp r0, r1', 'bhs 30f',
  'ldr r2, [sp, #56]', 'tst r2, #1', 'beq 30f',
  'lsrs r2, r2, #1', 'str r2, [sp, #56]', 'adds r0, r0, #1', 'str r0, [sp, #52]')
ha('r3', 'r2', 'r1')
a('orr r3, r3, r0, lsl #20', 'ldr r1, [sp, #20]', 'orr r3, r3, r1', 'str r3, [sp, #64]',
  'ldr r1, [sp, #60]', 'subs r1, r1, #1', 'str r1, [sp, #60]',
  'add r3, sp, #76', 'add r3, r3, r1, lsl #4',
  'ldr r2, [r3, #12]', 'str r2, [sp, #72]',
  'ldm r3, {{r10, r11, r12}}')
c('H (R in flight): L0..L2 in r10..r12; lr does the status work, so the CR value is re-made')
spin(SP_H, 41)
ladder(21, 22)
a('21:', 'ldm r4, {{r0, r1, r2, r3}}', 'mov.w lr, #1', 'str lr, [r4, #0x18]',
  'ldr lr, [r4, #0x18]', 'tst lr, #10', 'bne 23f',
  '24:', 'movw lr, #0x4', 'movt lr, #0x6', 'str lr, [r4, #-12]', 'ldr lr, [sp, #72]')
din('r5','r6','r7','r8','r10')
a('ldr r10, [sp, #64]')
din('r11','r12','lr')
din('r0','r1','r2','r3','r9','r10')
a('mov.w r11, #280', 'str r11, [r4, #-4]', 'movw lr, #0x4', 'movt lr, #0x6', 'b 20b')
c('==== next leaf: its PRF, or the root ====')
a('30:', 'ldr r0, [sp, #40]', 'adds r0, r0, #1', 'str r0, [sp, #40]', 'ldr r1, [sp, #44]', 'cmp r0, r1', 'beq 70f')
ha('r2', 'r0', 'r3')
a('ldr r1, [sp, #32]', 'orr r2, r2, r1', 'str r2, [sp, #28]',
  'ldr r12, [sp, #36]',
  'ldr r5, [r12]', 'ldr r6, [r12, #4]', 'ldr r7, [r12, #8]', 'ldr r8, [r12, #12]',
  'ldr r9, [r12, #16]', 'ldr r10, [r12, #20]', 'ldr r11, [r12, #24]',
  'rev r5, r5', 'rev r6, r6', 'rev r7, r7', 'rev r8, r8', 'rev r9, r9', 'rev r10, r10', 'rev r11, r11')
c('PRF (the finished node in flight): sk_seed[0..7) in r5..r11')
spin(SP_P, 42)
ladder(31, 32)
a('31:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 33f',
  '34:', 'str lr, [r4, #-12]', 'ldr lr, [sp, #36]')
din('r5','r6')
a('ldr r12, [lr, #28]')
din('r7','r8','r9','r10')
a('rev r12, r12')
din('r11')
a('ldrd r5, r6, [sp, #24]')
din('r12','r5','r6')
a('mov.w r12, #280', 'str r12, [r4, #-4]')
c('PRF window: push the finished node')
a('ldr r5, [sp, #60]', 'add r6, sp, #76', 'add r6, r6, r5, lsl #4', 'stm r6, {{r0, r1, r2, r3}}',
  'adds r5, r5, #1', 'str r5, [sp, #60]', 'movw lr, #0x4', 'movt lr, #0x6', 'b 10b')
c('==== the root ====')
a('70:')
ladder(71, 72)
a('71:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'ldr r12, [sp, #68]', 'add r12, r12, #44', 'stm r12, {{r0, r1, r2, r3}}', 'b 98f')
c('BUSY still set, or a stale DCIS before an INIT (first PRF: r0 counts)')
a('80:', 'mov.w r0, #16777216',
  '82:', 'tst r12, #8', 'beq 83f', 'subs r0, r0, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', 'b 82b',
  '83:', 'tst r12, #2', 'beq 81b', 'b 99f')
c('F: r11 is free, it counts')
a('13:', 'mov.w r11, #16777216',
  '15:', 'tst r12, #8', 'beq 16f', 'subs r11, r11, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', 'b 15b',
  '16:', 'tst r12, #2', 'beq 14b', 'b 99f')
c('H: everything is live, the counter is pushed (two words)')
a('23:', 'push {{r0, r1}}', 'mov.w r0, #16777216',
  '25:', 'tst lr, #8', 'beq 26f', 'subs r0, r0, #1', 'beq 99f', 'ldr lr, [r4, #0x18]', 'b 25b',
  '26:', 'pop {{r0, r1}}', 'tst lr, #2', 'beq 24b', 'b 99f')
c('PRF: lr counts, the CR value is re-made')
a('33:', 'mov.w lr, #16777216',
  '35:', 'tst r12, #8', 'beq 36f', 'subs lr, lr, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', 'b 35b',
  '36:', 'movw lr, #0x4', 'movt lr, #0x6', 'tst r12, #2', 'beq 34b', 'b 99f')
a('99:', 'bl {fault}', '98:', 'add sp, sp, #276', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}', '.size '+F+', . - '+F)
print('\n'.join(('    '+l) if l.startswith('// ') else '    "'+l+'",' for l in L))
