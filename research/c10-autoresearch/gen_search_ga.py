# Generates the global_asm! text for pq1_v1_search_z (round 10, E11).
L=[]
def a(*xs): L.extend(xs)
def c(t): L.append('// '+t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #4]')
def ladder(hit, cnt):
    a('.rept 16', 'ldr r12, [r4, #0x24]', 'lsls r12, r12, #30', f'bmi {hit}f', '.endr',
      'mov.w r0, #16777216',
      f'{cnt}:', 'ldr r12, [r4, #0x24]', 'lsls r12, r12, #30', f'bmi {hit}f', 'subs r0, r0, #1', f'bne {cnt}b', 'b 99f')
F='pq1_v1_search_z'
a('.syntax unified', '.section .text.pq1_c10_search,\\"ax\\",%progbits', '.p2align 2', '.global '+F, '.type '+F+',%function', '.thumb_func', F+':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #68')
c('frame: 0 d (pred argument, d[0..3] zero), 32 count (try in flight), 36 end, 40 pred, 44 ctx, 48 m0..m3, 64 HR7 temp')
c('ctx: 0..7 words 0..3, 8, 10, 12 (in r5..r11 throughout); 7..11 words 16..19; 11 start; 12 end; 13 pred; 14 c, 15 flag (out)')
a('str r0, [sp, #44]', 'mov r12, r0',
  'ldm r12!, {{r5, r6, r7, r8, r9, r10, r11}}',
  'ldm r12!, {{r0, r1, r2, r3}}', 'add lr, sp, #48', 'stm lr, {{r0, r1, r2, r3}}',
  'ldm r12, {{r0, r1, r2}}', 'str r0, [sp, #32]', 'str r1, [sp, #36]', 'str r2, [sp, #40]',
  'movs r3, #0', 'str r3, [sp]', 'str r3, [sp, #4]', 'str r3, [sp, #8]',
  'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}',
  'adds r0, r0, #1', 'cmp r0, r1', 'beq 50f')
c('==== a try in flight, a next try to issue ====')
a('10:')
ladder(11, 12)
a('11:', 'addw r12, r4, #796', 'ldm r12, {{r0, r1, r2, r3, r12}}',   # HR3..HR7 raw
  'mov.w lr, #1', 'str lr, [r4, #0x24]',
  'ldr lr, [r4, #0x24]', 'tst lr, #10', 'bne 13f',
  '14:', 'movw lr, #0x24', 'movt lr, #0x6', 'str lr, [r4]',      # INIT
  'movs.w lr, #0', 'str r12, [sp, #64]', 'ldr r12, [sp, #48]')
din('r5','r6','r7','r8','lr','lr','lr','lr','r9','lr','r10','lr','r11','lr','lr','lr','r12')
c('block-0 window: the previous try\'s digest words for pred, block-1 words, the count')
a('rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3',
  'str r0, [sp, #12]', 'str r1, [sp, #16]', 'str r2, [sp, #20]', 'str r3, [sp, #24]',
  'ldr r0, [sp, #64]', 'rev r0, r0', 'str r0, [sp, #28]',
  'ldr r3, [sp, #32]', 'adds r3, r3, #1', 'rev r3, r3',
  'ldr r0, [sp, #52]', 'ldr r1, [sp, #56]', 'ldr r2, [sp, #60]', 'mov.w r12, #256')
din('r0','r1','r2')
a('.rept 11', 'str lr, [r4, #4]', '.endr')
din('r3')
a('str r12, [r4, #8]')
c('engine window: pred on the previous try (callee-saved r4..r11 survive the call)')
a('mov r0, sp', 'ldr r12, [sp, #40]', 'blx r12', 'tst r0, #0xFF', 'bne 60f',
  'ldr r0, [sp, #32]', 'adds r0, r0, #1', 'str r0, [sp, #32]',
  'ldr r1, [sp, #36]', 'adds r0, r0, #1', 'cmp r0, r1', 'beq 50f', 'b 10b')
c('BUSY still set, or a stale DCIS (HR words live: the counter is pushed, two words)')
a('13:', 'push {{r0, r1}}', 'mov.w r0, #16777216',
  '15:', 'tst lr, #8', 'beq 16f', 'subs r0, r0, #1', 'beq 99f', 'ldr lr, [r4, #0x24]', 'b 15b',
  '16:', 'pop {{r0, r1}}', 'tst lr, #2', 'beq 14b', 'b 99f')
c('==== the last try in flight: nothing to issue ====')
a('50:')
ladder(51, 52)
a('51:', 'addw r12, r4, #796', 'ldm r12, {{r0, r1, r2, r3, r12}}',
  'mov.w lr, #1', 'str lr, [r4, #0x24]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3', 'rev r12, r12',
  'str r0, [sp, #12]', 'str r1, [sp, #16]', 'str r2, [sp, #20]', 'str r3, [sp, #24]', 'str r12, [sp, #28]',
  'mov r0, sp', 'ldr r12, [sp, #40]', 'blx r12', 'tst r0, #0xFF', 'bne 61f',
  'ldr r0, [sp, #36]', 'movs r1, #0', 'b 70f',
  '60:', 'ldr r0, [sp, #32]', 'movs r1, #1', 'b 70f',
  '61:', 'ldr r0, [sp, #32]', 'movs r1, #2',
  '70:', 'ldr r12, [sp, #44]', 'str r0, [r12, #56]', 'str r1, [r12, #60]', 'b 98f',
  '99:', 'bl {fault}',
  '98:', 'add sp, sp, #68', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}', '.size '+F+', . - '+F)
print('\n'.join(('    '+l) if l.startswith('// ') else '    "'+l+'",' for l in L))
