# Generates the global_asm! text for pq1_v2_t43 (round 12, E18): the T_43 compression of
# `pqsigner_v2_wots_pk16` (712 bytes = 178 words, 12 blocks), DATATYPE 10 (bytes as in memory).
# While a block is in the engine the HASH takes only the next block's first word (the trigger);
# the next store waits for the block. So the feed preloads the following words into registers in
# that window and stores them back to back once the engine is free. 12 data registers + the
# source pointer + the HASH base leave none for a loop counter: the ten middle blocks are unrolled.
L = []
def a(*xs): L.extend(xs)
def c(t): L.append('// ' + t)
def din(*regs):
    for r in regs: a(f'str {r}, [r4, #4]')
F = 'pq1_v2_t43'
R12 = ['r1', 'r2', 'r3', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'lr']
R8 = R12[:8]
R4 = R12[:4]
a('.syntax unified', '.section .text.' + F + ',\\"ax\\",%progbits', '.p2align 2', '.global ' + F,
  '.type ' + F + ',%function', '.thumb_func', F + ':')
a('push {{r4, r5, r6, r7, r8, r9, r10, r11, lr}}', 'sub sp, sp, #4')
c('r0 = the 178 message words (4-aligned), r1 = out (16 bytes), kept at [sp]')
a('str r1, [sp]', 'movw r4, #{hb_lo}', 'movt r4, #{hb_hi}')
c('idle engine and no stale DCIS (else the guarded slow path), STR = 0, INIT with DATATYPE 10')
a('ldr r12, [r4, #0x24]', 'tst r12, #10', 'bne 80f', '81:',
  'movs r12, #0', 'str r12, [r4, #8]', 'movw r12, #0x24', 'movt r12, #0x6', 'str r12, [r4]')
c('block 0: sixteen words into the empty FIFO, then the trigger word (16) into r5')
a('ldm r0!, {{' + ', '.join(R8) + '}}')
din(*R8)
a('ldm r0!, {{' + ', '.join(R8) + '}}')
din(*R8)
a('ldr r5, [r0], #4')
c('blocks 1..10: the trigger starts the previous block; its next 12 words load in the engine window;')
c('the stores resume when the block is done; the last 3 words and the next trigger by one ldm')
for _ in range(10):
    din('r5')
    a('ldm r0!, {{' + ', '.join(R12) + '}}')
    din(*R12)
    a('ldm r0!, {{' + ', '.join(R4) + '}}')
    din('r1', 'r2', 'r3')
c('the trigger (word 176) starts block 10; word 177 waits for it; DCAL (NBLW 0) pads block 11')
din('r5')
a('ldr r1, [r0]')
din('r1')
a('mov.w r12, #256', 'str r12, [r4, #8]')
c('DCIS, guarded (2^24 polls)')
a('.rept 16', 'ldr r12, [r4, #0x24]', 'lsls r12, r12, #30', 'bmi 11f', '.endr',
  'mov.w lr, #16777216',
  '12:', 'ldr r12, [r4, #0x24]', 'lsls r12, r12, #30', 'bmi 11f', 'subs lr, lr, #1', 'bne 12b', 'b 99f')
c('HR0..HR3, clear DCIS, the 16 digest bytes in memory order to out')
a('11:', 'add.w r12, r4, #0x310', 'ldm r12, {{r0, r1, r2, r3}}', 'movs r12, #1', 'str r12, [r4, #0x24]',
  'rev r0, r0', 'rev r1, r1', 'rev r2, r2', 'rev r3, r3', 'ldr r12, [sp]',
  'str r0, [r12]', 'str r1, [r12, #4]', 'str r2, [r12, #8]', 'str r3, [r12, #12]', 'b 98f')
c('BUSY still set, or a stale DCIS before INIT')
a('80:', 'mov.w lr, #16777216',
  '82:', 'tst r12, #8', 'beq 83f', 'subs lr, lr, #1', 'beq 99f', 'ldr r12, [r4, #0x24]', 'b 82b',
  '83:', 'tst r12, #2', 'beq 81b', 'b 99f')
a('99:', 'bl {fault}', '98:', 'add sp, sp, #4', 'pop {{r4, r5, r6, r7, r8, r9, r10, r11, pc}}',
  '.size ' + F + ', . - ' + F)
print('\n'.join(('    ' + l) if l.startswith('// ') else '    "' + l + '",' for l in L))
