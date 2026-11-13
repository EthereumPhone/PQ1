# Generates the global_asm! text for pq1_v2_key_loop (round 10, E12).
L=[]
def a(*xs): L.extend(xs)
def c(t): L.append('// '+t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #-8]')
def ladder(hit, cnt):
    # polls with dead r0 (scratch) / r1 (counter): r0..r3 are rewritten by the HR read
    a('.rept 16', 'ldr r0, [r4, #0x18]', 'lsls r0, r0, #30', f'bmi {hit}f', '.endr',
      'mov.w r1, #16777216',
      f'{cnt}:', 'ldr r0, [r4, #0x18]', 'lsls r0, r0, #30', f'bmi {hit}f', 'subs r1, r1, #1', f'bne {cnt}b', 'b 99f')
def busy_slow(slow, back, l1, l2):
    a(f'{slow}:', 'mov.w lr, #16777216',
      f'{l1}:', 'tst r12, #8', f'beq {l2}f', 'subs lr, lr, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', f'b {l1}b',
      f'{l2}:', 'movw lr, #0x4', 'movt lr, #0x6', 'tst r12, #2', f'beq {back}b', 'b 99f')
F='pq1_v2_key_loop'
a('.syntax unified', '.section .text.'+F+',\\"ax\\",%progbits', '.p2align 2', '.global '+F, '.type '+F+',%function', '.thumb_func', F+':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #68')
c('frame: 0 a0, 4 end (a1 after the last step), 8 p0, 12 p1|c, 16 a1 base (low24|c), 20 ci, 24 n, 28 steps,')
c('32 sk_seed, 36 out (this chain), 40 S0..S3, 56 p1, 60 low24')
c('ctx: 0 sk_seed, 1 p0, 2 p1, 3..7 S, 7 a0, 8 low24, 9 steps, 10 n, 11 out')
a('ldm r0, {{r1, r2, r3, r5, r6, r7, r8, r9, r10, r11, r12, lr}}',   # 12 words: sk, p0, p1, S0..S3, a0, low24, steps, n, out
  'rev r2, r2', 'rev r3, r3', 'rev r5, r5', 'rev r6, r6', 'rev r7, r7', 'rev r8, r8', 'rev r9, r9', 'rev r10, r10',
  'str r1, [sp, #32]', 'str r2, [sp, #8]', 'str r3, [sp, #56]',
  'str r5, [sp, #40]', 'str r6, [sp, #44]', 'str r7, [sp, #48]', 'str r8, [sp, #52]',
  'str r9, [sp, #0]', 'str r10, [sp, #60]', 'str r11, [sp, #28]', 'str r12, [sp, #24]', 'str lr, [sp, #36]',
  'movs r0, #0', 'str r0, [sp, #20]',
  'str r3, [sp, #12]', 'str r10, [sp, #16]', 'orr r0, r10, r11, lsl #20', 'str r0, [sp, #4]',
  'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}', 'movw lr, #0x4', 'movt lr, #0x6')
c('first PRF: idle and no stale DCIS (as v2_begin), INIT, sk_seed (single loads), p0, p1|c, DCAL')
a('ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 50f',
  '51:', 'str lr, [r4, #-12]', 'ldr r12, [sp, #32]',
  'ldr r0, [r12]', 'ldr r1, [r12, #4]', 'ldr r2, [r12, #8]', 'ldr r3, [r12, #12]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3')
din('r0','r1','r2','r3')
a('ldr r0, [r12, #16]', 'ldr r1, [r12, #20]', 'ldr r2, [r12, #24]', 'ldr r3, [r12, #28]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3')
din('r0','r1','r2','r3')
a('ldrd r0, r1, [sp, #8]')
din('r0','r1')
a('mov.w r12, #280', 'str r12, [r4, #-4]', 'b 32f')
c('==== chain step loop (S in r8..r11, a1 in r5, a0 in r6, the DCAL value in r7) ====')
a('1:', 'add.w r5, r5, #1048576', 'ldr r12, [sp, #4]', 'cmp r5, r12', 'beq 20f',
  'movs r12, #{spin}', '10:', 'subs r12, r12, #1', 'bne 10b',
  'ldr r12, [r4, #0x18]', 'lsls r12, r12, #30', 'bpl 11f',
  '4:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  '3:', 'ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 40f',
  '41:', 'str lr, [r4, #-12]')
din('r8','r9','r10','r11','r0','r1','r2','r3','r6','r5')
a('str r7, [r4, #-4]', 'b 1b',
  '11:', '.rept 7', 'ldr r12, [r4, #0x18]', 'lsls r12, r12, #30', 'bmi 4b', '.endr',
  'mov.w r0, #16777216',
  '12:', 'ldr r12, [r4, #0x18]', 'lsls r12, r12, #30', 'bmi 4b', 'subs r0, r0, #1', 'bne 12b', 'b 99f')
busy_slow(40, 41, 42, 43)
c('==== chain done (its last step in flight): the next chain\'s PRF, or the last read-out ====')
a('20:', 'ldr r0, [sp, #20]', 'adds r0, r0, #1', 'ldr r1, [sp, #24]', 'cmp r0, r1', 'beq 70f',
  'str r0, [sp, #20]', 'lsls r1, r0, #{lsb}', 'lsls r1, r1, #24',
  'ldr r2, [sp, #56]', 'orrs r2, r2, r1', 'str r2, [sp, #12]',
  'ldr r2, [sp, #60]', 'orrs r2, r2, r1', 'str r2, [sp, #16]',
  'ldr r3, [sp, #28]', 'orr r3, r2, r3, lsl #20', 'str r3, [sp, #4]',
  'ldr r1, [sp, #32]',
  'ldr r8, [r1]', 'ldr r9, [r1, #4]', 'ldr r10, [r1, #8]', 'ldr r11, [r1, #12]',
  'ldr r6, [r1, #16]', 'ldr r7, [r1, #20]', 'ldr r5, [r1, #24]',
  'rev r8, r8', 'rev r9, r9', 'rev r10, r10', 'rev r11, r11', 'rev r6, r6', 'rev r7, r7', 'rev r5, r5')
ladder(21, 22)
a('21:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'ldr r12, [r4, #0x18]', 'tst r12, #10', 'bne 23f',
  '24:', 'str lr, [r4, #-12]', 'ldr lr, [sp, #32]')
din('r8','r9')
a('ldr r12, [lr, #28]')
din('r10','r11','r6','r7')
a('rev r12, r12')
din('r5')
a('ldrd r8, r9, [sp, #8]')
din('r12','r8','r9')
a('mov.w r12, #280', 'str r12, [r4, #-4]')
c('PRF window: the finished chain\'s output to out, out += 16')
a('rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'ldr r12, [sp, #36]', 'str r0, [r12]', 'str r1, [r12, #4]', 'str r2, [r12, #8]', 'str r3, [r12, #12]',
  'add r12, r12, #16', 'str r12, [sp, #36]', 'movw lr, #0x4', 'movt lr, #0x6')
c('(the first chain enters here) S back, the chain\'s a1 base, wait for the PRF')
a('32:', 'add r12, sp, #40', 'ldm r12, {{r8, r9, r10, r11}}', 'ldr r5, [sp, #16]',
  'ldr r6, [sp]', 'mov.w r7, #280')
ladder(33, 34)
a('33:', 'b 4b')
busy_slow(23, 24, 25, 26)
c('==== the last chain\'s last step: read, clear, store ====')
a('70:')
ladder(71, 72)
a('71:', 'ldm r4, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x18]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'ldr r12, [sp, #36]', 'str r0, [r12]', 'str r1, [r12, #4]', 'str r2, [r12, #8]', 'str r3, [r12, #12]', 'b 98f')
c('BUSY still set, or a stale DCIS, before the first INIT')
a('50:', 'mov.w r0, #16777216',
  '52:', 'tst r12, #8', 'beq 53f', 'subs r0, r0, #1', 'beq 99f', 'ldr r12, [r4, #0x18]', 'b 52b',
  '53:', 'tst r12, #2', 'beq 51b', 'b 99f')
a('99:', 'bl {fault}', '98:', 'add sp, sp, #68', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}', '.size '+F+', . - '+F)
print('\n'.join(('    '+l) if l.startswith('// ') else '    "'+l+'",' for l in L))
