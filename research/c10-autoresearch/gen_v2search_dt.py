# Generates the global_asm! text for pq1_v2_search_dt (round 11, E17): the v2 WOTS+C count search,
# DATATYPE 00, constants in registers, the digit sum in the engine window.
L=[]
def a(*xs): L.extend(xs)
def c(t): L.append('// '+t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #4]')
def ladder(hit, cnt):
    a('.rept 16', 'ldr r0, [r4, #0x24]', 'lsls r0, r0, #30', f'bmi {hit}f', '.endr',
      'mov.w r1, #16777216',
      f'{cnt}:', 'ldr r0, [r4, #0x24]', 'lsls r0, r0, #30', f'bmi {hit}f', 'subs r1, r1, #1', f'bne {cnt}b', 'b 99f')
def digit_sum(hit, rej, rz):
    # The round-7 v2 fold sum (verbatim registers: w3..w7 in r0, r1, r2, r3, r10; scratch lr, r9,
    # r5, r11, r12), target at [sp, #48]. Falls through to {rej} with no hit; branches to {hit}.
    a('movw lr, #0x71C7', 'movt lr, #0x071C', 'movw r9, #0xF03F', 'movt r9, #0x3F03',
      'and r5, r10, lr', 'and r11, lr, r10, lsr #3', 'add r5, r5, r11',
      'and r11, lr, r3, lsr #1', 'add r5, r5, r11', 'and r11, lr, r3, lsr #4', 'add r5, r5, r11',
      'and r11, lr, r2, lsr #2', 'add r5, r5, r11', 'and r11, lr, r2, lsr #5', 'add r5, r5, r11',
      'and r11, r5, r9', 'and r5, r9, r5, lsr #6', 'add r5, r5, r11',
      'movw r11, #0x1001', 'movt r11, #0x0100', 'mul r5, r5, r11', 'lsr r5, r5, #24',
      'lsr r11, r10, #30', 'bfi r11, r3, #2, #1', 'add r5, r5, r11',
      'lsr r11, r3, #31', 'bfi r11, r2, #1, #2', 'add r5, r5, r11',
      'ldr r12, [sp, #48]', 'add r11, r5, #77', 'cmp r11, r12', f'blo {rej}f',
      'and r11, r1, lr', 'and r12, lr, r1, lsr #3', 'add r11, r11, r12',
      'and r12, r11, r9', 'and r11, r9, r11, lsr #6', 'add r11, r11, r12',
      'movw r12, #0x1001', 'movt r12, #0x0100', 'mul r11, r11, r12', 'add r5, r5, r11, lsr #24',
      'lsr r11, r1, #30', 'bfi r11, r0, #2, #1', 'add r5, r5, r11',
      'ldr r12, [sp, #48]', 'cmp r5, r12', f'beq {hit}f',
      f'{rej}:')
def reload():
    a('mov r12, sp', 'ldm r12, {{r5, r6, r7, r8, r9}}', 'ldr r11, [sp, #20]', 'movw lr, #0x4', 'movt lr, #0x6')
def issue(slow, back):
    # BUSY clear and no stale DCIS, INIT, sm0..sm5 from registers, sm6 sm7 a0 a1 by one ldm, the
    # count (big-endian: the value itself), DCAL (NBLW 24)
    a('ldr r12, [r4, #0x24]', 'tst r12, #10', f'bne {slow}f', f'{back}:', 'str lr, [r4]')
    din('r5','r6','r7','r8','r9','r11')
    a('add r12, sp, #24', 'ldm r12, {{r5, r6, r7, r8}}')
    din('r5','r6')
    a('ldr r9, [sp, #40]')
    din('r9','r7','r8')
    a('mov.w r12, #280', 'str r12, [r4, #8]')
F='pq1_v2_search_dt'
a('.syntax unified', '.section .text.'+F+',\\"ax\\",%progbits', '.p2align 2', '.global '+F, '.type '+F+',%function', '.thumb_func', F+':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #60')
c('frame: 0 sm0..sm7 (big-endian words), 32 a0, 36 a1, 40 the next count to issue, 44 end, 48 target, 52 ctx')
c('ctx: 0..8 sm (big-endian), 8 a0, 9 a1 (big-endian), 10 start, 11 end, 12 target, 13 c, 14 flag (out)')
a('str r0, [sp, #52]', 'mov r12, r0', 'mov lr, sp',
  'ldm r12!, {{r0, r1, r2, r3, r5, r6, r7, r8}}', 'stm lr!, {{r0, r1, r2, r3, r5, r6, r7, r8}}',
  'ldm r12, {{r0, r1, r2, r3, r5}}', 'stm lr!, {{r0, r1}}',
  'str r2, [sp, #40]', 'str r3, [sp, #44]', 'str r5, [sp, #48]',
  'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}')
reload()
c('the first try (start): its own issue, then the next count and the wait loop to use')
issue(80, 81)
reload()
a('ldr r0, [sp, #40]', 'adds r0, r0, #1', 'str r0, [sp, #40]', 'ldr r1, [sp, #44]', 'cmp r0, r1', 'beq 50f')
c('==== a try in flight and another to issue ====')
a('10:')
ladder(11, 12)
a('11:', 'addw r12, r4, #796', 'ldm r12, {{r0, r1, r2, r3, r10}}', 'movs r12, #1', 'str r12, [r4, #0x24]')
issue(13, 14)
c('engine window: the digit sum of the previous try, then the constants back')
digit_sum(60, 15, None)
reload()
a('ldr r0, [sp, #40]', 'adds r0, r0, #1', 'str r0, [sp, #40]', 'ldr r1, [sp, #44]', 'cmp r0, r1', 'beq 50f',
  'b 10b')
c('==== the last try in flight: nothing to issue ====')
a('50:')
ladder(51, 52)
a('51:', 'addw r12, r4, #796', 'ldm r12, {{r0, r1, r2, r3, r10}}', 'movs r12, #1', 'str r12, [r4, #0x24]')
digit_sum(61, 55, None)
a('ldr r0, [sp, #44]', 'movs r1, #0', 'b 70f',
  '60:', 'ldr r0, [sp, #40]', 'subs r0, r0, #1', 'movs r1, #1', 'b 70f',
  '61:', 'ldr r0, [sp, #40]', 'subs r0, r0, #1', 'movs r1, #2',
  '70:', 'ldr r12, [sp, #52]', 'str r0, [r12, #52]', 'str r1, [r12, #56]', 'b 98f')
c('BUSY still set, or a stale DCIS before INIT: lr counts (HR words live), the CR value is re-made')
for slow, back, l1, l2 in ((80, 81, 82, 83), (13, 14, 17, 18)):
    a(f'{slow}:', 'mov.w lr, #16777216',
      f'{l1}:', 'tst r12, #8', f'beq {l2}f', 'subs lr, lr, #1', 'beq 99f', 'ldr r12, [r4, #0x24]', f'b {l1}b',
      f'{l2}:', 'movw lr, #0x4', 'movt lr, #0x6', 'tst r12, #2', f'beq {back}b', 'b 99f')
a('99:', 'bl {fault}', '98:', 'add sp, sp, #60', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}', '.size '+F+', . - '+F)
print('\n'.join(('    '+l) if l.startswith('// ') else '    "'+l+'",' for l in L))
