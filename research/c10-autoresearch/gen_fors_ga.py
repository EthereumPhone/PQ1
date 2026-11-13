# Generates the global_asm! text for pq1_v1_fors_sub_z (round 10, E10).
L=[]
def a(*xs):
    for x in xs: L.append(x)
def c(t): L.append('// '+t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #-8]')
def ladder(hit, cnt_lbl):
    # straight polls, then a 2^24-guarded loop counting in r0 (dead before the HR read)
    a('.rept 16', 'ldr r12, [r4, #0x18]', 'lsls r12, r12, #30', f'bmi {hit}f', '.endr',
      'mov.w r0, #16777216',
      f'{cnt_lbl}:', 'ldr r12, [r4, #0x18]', 'lsls r12, r12, #30', f'bmi {hit}f', 'subs r0, r0, #1', f'bne {cnt_lbl}b', 'b 99f')
def hr_clear_busy(slow):
    a('ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]')
def busy_check(slow):
    a('ldr r12, [r4, #0x18]', 'tst r12, #10', f'bne {slow}f')
def busy_slow(slow, back, l1, l2):
    # BUSY still set, or a stale DCIS: HR words and preloads are live; count in lr, re-make CR
    a(f'{slow}:', 'mov.w lr, #16777216',
      f'{l1}:', 'tst r12, #8', f'beq {l2}f', 'subs lr, lr, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', f'b {l1}b',
      f'{l2}:', 'movw lr, #0x24', 'movt lr, #0x6', 'tst r12, #2', f'beq {back}b', 'b 99f')
F='pq1_v1_fors_sub_z'
a('.syntax unified', '.section .text.'+F+',\\"ax\\",%progbits', '.p2align 2', '.global '+F, '.type '+F+',%function', '.thumb_func', F+':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #196')
c('frame: 0 L0..L6, 28 N0..N6, 56 t0 t1 t2, 68 rev(j+1), 72 rev(j), 76 rev(h+1), 80 rev(j>>(h+1)),')
c('84 sk_seed, 88 j, 92 k, 96 depth, 100 h, 104 left ptr, 108 ctx, 112 node stack (5 x 16)')
a('str r0, [sp, #108]', 'mov r12, r0', 'mov lr, sp',
  'ldm r12!, {{r0, r1, r2, r3, r5, r6, r7}}', 'stm lr!, {{r0, r1, r2, r3, r5, r6, r7}}',
  'ldm r12!, {{r0, r1, r2, r3, r5, r6, r7}}', 'stm lr!, {{r0, r1, r2, r3, r5, r6, r7}}',
  'ldm r12!, {{r0, r1, r2, r5, r6}}', 'stm lr!, {{r0, r1, r2}}',
  'str r5, [sp, #84]', 'str r6, [sp, #88]',
  'movs r0, #0', 'str r0, [sp, #92]', 'str r0, [sp, #96]',
  'rev r1, r6', 'str r1, [sp, #72]', 'adds r1, r6, #1', 'rev r1, r1', 'str r1, [sp, #68]',
  'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}', 'movw lr, #0x24', 'movt lr, #0x6')
c('first PRF (leaf j0), issued here so the caller never holds sk_seed words: idle and no stale')
c('DCIS (as gather_init), STR 0, INIT, sk_seed (single loads, registers only), tail, be32(j0), DCAL')
a('ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 50f',
  '51:', 'movs r0, #0', 'str r0, [r4, #-4]', 'str lr, [r4, #-12]', 'ldr r12, [sp, #84]',
  'ldr r0, [r12]', 'ldr r1, [r12, #4]', 'ldr r2, [r12, #8]', 'ldr r3, [r12, #12]')
din('r0','r1','r2','r3')
a('ldr r0, [r12, #16]', 'ldr r1, [r12, #20]', 'ldr r2, [r12, #24]', 'ldr r3, [r12, #28]')
din('r0','r1','r2','r3')
a('ldr r0, [sp, #56]', 'ldr r1, [sp, #60]', 'ldr r2, [sp, #64]', 'ldr r3, [sp, #72]')
din('r0','r1','r2','r3')
a('mov.w r0, #256', 'str r0, [r4, #-4]',
  'mov r12, sp', 'ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}', 'b 10f')
c('BUSY still set, or a stale DCIS, before the first INIT')
a('50:', 'mov.w r0, #16777216',
  '52:', 'tst r12, #8', 'beq 53f', 'subs r0, r0, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', 'b 52b',
  '53:', 'tst r12, #2', 'beq 51b', 'b 99f')
c('==== LEAF (the PRF digest in flight; leaf constants in r5..r11) ====')
a('10:')
ladder(11, 12)
a('11:')
hr_clear_busy(13)
a('rev r0, r0')
busy_check(13)
a('14:', 'str lr, [r4, #-12]', 'ldr r12, [sp, #72]', 'movs.w lr, #0')
din('r5','r6','r7','r8','lr','lr','lr','lr','lr','lr','r9','r10','r11','lr','lr','r12','r0')
c('block-0 window')
a('rev r1, r1', 'rev r2, r2', 'rev r3, r3', 'mov.w r12, #256')
din('r1','r2','r3','lr','lr','lr','lr')
a('str r12, [r4, #-4]', 'movw lr, #0x24', 'movt lr, #0x6',
  'ldr r0, [sp, #92]', 'tst r0, #1', 'bne 20f', 'b 30f')
busy_slow(13, 14, 15, 16)
c('==== NODE (the right child in flight) ====')
a('20:', 'movs r0, #0', 'str r0, [sp, #100]')
a('21:', 'add r12, sp, #28', 'ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}',
  'ldr r0, [sp, #100]', 'adds r1, r0, #1', 'rev r2, r1', 'str r2, [sp, #76]',
  'ldr r2, [sp, #88]', 'lsrs r2, r2, r1', 'rev r2, r2', 'str r2, [sp, #80]',
  'ldr r0, [sp, #96]', 'subs r0, r0, #1', 'str r0, [sp, #96]',
  'add r1, sp, #112', 'add r0, r1, r0, lsl #4', 'str r0, [sp, #104]')
ladder(22, 25)
a('22:')
hr_clear_busy(23)
busy_check(23)
a('24:', 'str lr, [r4, #-12]', 'ldr r12, [sp, #104]', 'movs.w lr, #0')
din('r5','r6','r7','r8')
a('ldr r5, [r12]')
din('lr','lr','lr','lr','lr','lr','r9')
a('ldr r9, [sp, #76]')
din('r10')
a('ldr r10, [sp, #80]')
din('r11','lr','r9','r10','r5')
c('block-0 window')
a('add r12, r12, #4', 'ldm r12, {{r6, r7, r8}}',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3', 'mov.w r12, #256')
din('r6','r7','r8','lr','lr','lr','lr','r0','r1','r2','r3','lr','lr','lr','lr')
a('str r12, [r4, #-4]', 'movw lr, #0x24', 'movt lr, #0x6',
  'ldr r0, [sp, #100]', 'adds r0, r0, #1', 'str r0, [sp, #100]',
  'ldr r1, [sp, #92]', 'lsrs r2, r1, r0', 'tst r2, #1', 'bne 21b',
  'cmp r1, #15', 'beq 40f', 'b 30f')
busy_slow(23, 24, 26, 27)
c('==== PRF of leaf j+1 (the finished leaf/node in flight) ====')
a('30:', 'ldr r12, [sp, #84]',
  'ldr r5, [r12]', 'ldr r6, [r12, #4]', 'ldr r7, [r12, #8]', 'ldr r8, [r12, #12]',
  'ldr r9, [r12, #16]', 'ldr r10, [r12, #20]', 'ldr r11, [r12, #24]')
ladder(32, 35)
a('32:')
hr_clear_busy(33)
busy_check(33)
a('34:', 'str lr, [r4, #-12]', 'ldr r12, [sp, #84]')
din('r5','r6')
a('ldr r12, [r12, #28]')
din('r7','r8','r9','r10','r11')
a('add lr, sp, #56', 'ldm lr, {{r5, r6, r7, r8}}')
din('r12','r5','r6','r7','r8')
a('mov.w r12, #256', 'str r12, [r4, #-4]')
c('PRF window: push the finished node, j += 1, k += 1, leaf constants back')
a('rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'ldr r5, [sp, #96]', 'add r6, sp, #112', 'add r6, r6, r5, lsl #4', 'stm r6, {{r0, r1, r2, r3}}',
  'adds r5, r5, #1', 'str r5, [sp, #96]',
  'ldr r0, [sp, #88]', 'adds r0, r0, #1', 'str r0, [sp, #88]',
  'rev r1, r0', 'str r1, [sp, #72]', 'adds r1, r0, #1', 'rev r1, r1', 'str r1, [sp, #68]',
  'ldr r0, [sp, #92]', 'adds r0, r0, #1', 'str r0, [sp, #92]',
  'mov r12, sp', 'ldm r12, {{r5, r6, r7, r8, r9, r10, r11}}',
  'movw lr, #0x24', 'movt lr, #0x6', 'b 10b')
busy_slow(33, 34, 36, 37)
c('==== root ====')
a('40:')
ladder(41, 43)
a('41:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'ldr r12, [sp, #108]', 'add r12, r12, #76', 'stm r12, {{r0, r1, r2, r3}}', 'b 98f')
a('99:', 'bl {fault}', '98:', 'add sp, sp, #196', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}', '.size '+F+', . - '+F)
out=[]
for l in L:
    if l.startswith('// '): out.append('    '+l)
    else: out.append('    "'+l+'",')
print('\n'.join(out))
