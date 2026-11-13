#!/usr/bin/env python3
"""Generate src/compress_asm.s: SHA-512 compression for ARMv8-M Mainline (Thumb-2), fully unrolled.
Frame (sp-relative): V[8] u64 at 0..63 (working variables, slot-rotated by the generator),
W[16] u64 at 64..191, saved state pointer at 192. K pointer in r12 (ldrd post-increment).
u64 in memory little-endian: lo word at +0, hi at +4; ldrd rlo, rhi.
Sigma/sigma: rotr by r<32 per half = (x>>r)^(y<<(32-r)); halves swap for r>=32. OR == XOR for the two
disjoint parts of a rotate, so every term is one eor with a shifted operand."""
V = lambda s: 8 * (s & 7)
W = lambda j: 64 + 8 * (j & 15)
out = []
e = out.append
def sig(dl, dh, l, h, terms_l, terms_h):
    # terms: list of (src, op, sh) with src 'l'/'h'; first term becomes lsr/lsl into dest
    for d, terms in ((dl, terms_l), (dh, terms_h)):
        src, op, sh = terms[0]
        e(f"    {op}.w {d}, {l if src == 'l' else h}, #{sh}")
        for src, op, sh in terms[1:]:
            e(f"    eor.w {d}, {d}, {l if src == 'l' else h}, {op} #{sh}")
def round_(r):
    a, b, c, d, ee, f, g, h = [(i - r) & 7 for i in range(8)]
    j = r & 15
    if False:
        e(f"    @ schedule W[{j}]")
        e(f"    ldrd r2, r3, [sp, #{W(j + 14)}]")
        # sigma1: rotr19, rotr61 (swap+29), shr6
        sig('r4', 'r5', 'r2', 'r3',
            [('l','lsr',19),('h','lsl',13),('h','lsr',29),('l','lsl',3),('l','lsr',6),('h','lsl',26)],
            [('h','lsr',19),('l','lsl',13),('l','lsr',29),('h','lsl',3),('h','lsr',6)])
        e(f"    ldrd r2, r3, [sp, #{W(j + 1)}]")
        # sigma0: rotr1, rotr8, shr7
        sig('r6', 'r7', 'r2', 'r3',
            [('l','lsr',1),('h','lsl',31),('l','lsr',8),('h','lsl',24),('l','lsr',7),('h','lsl',25)],
            [('h','lsr',1),('l','lsl',31),('h','lsr',8),('l','lsl',24),('h','lsr',7)])
        e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
        e(f"    ldrd r6, r7, [sp, #{W(j + 9)}]"); e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
        e(f"    ldrd r6, r7, [sp, #{W(j)}]"); e("    adds r10, r4, r6"); e("    adc r11, r5, r7")
        e(f"    strd r10, r11, [sp, #{W(j)}]")
    else:
        pass  # W[r] is loaded inside the round (post-increment lr)
    e(f"    @ round {r}")
    e(f"    ldrd r2, r3, [sp, #{V(ee)}]")
    e(f"    ldrd r8, r9, [sp, #{V(f)}]")
    e(f"    ldrd r10, r11, [sp, #{V(g)}]")
    sig('r4', 'r5', 'r2', 'r3',
        [('l','lsr',14),('h','lsl',18),('l','lsr',18),('h','lsl',14),('h','lsr',9),('l','lsl',23)],
        [('h','lsr',14),('l','lsl',18),('h','lsr',18),('l','lsl',14),('l','lsr',9),('h','lsl',23)])
    e("    eor.w r8, r8, r10"); e("    and.w r8, r8, r2"); e("    eor.w r8, r8, r10")   # Ch lo
    e("    eor.w r9, r9, r11"); e("    and.w r9, r9, r3"); e("    eor.w r9, r9, r11")   # Ch hi
    e(f"    ldrd r6, r7, [sp, #{V(h)}]")
    e("    adds r4, r4, r8"); e("    adc r5, r5, r9")
    e("    ldrd r8, r9, [r12], #8")
    e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
    e("    ldrd r10, r11, [lr], #8")
    e("    adds r4, r4, r8"); e("    adc r5, r5, r9")
    e(f"    ldrd r6, r7, [sp, #{V(d)}]")
    e("    adds r4, r4, r10"); e("    adc r5, r5, r11")                                   # t1
    e(f"    ldrd r2, r3, [sp, #{V(a)}]")
    e("    adds r6, r6, r4"); e("    adc r7, r7, r5")
    e(f"    strd r6, r7, [sp, #{V(d)}]")                                                    # d += t1
    e(f"    ldrd r8, r9, [sp, #{V(b)}]")
    e(f"    ldrd r10, r11, [sp, #{V(c)}]")
    sig('r6', 'r7', 'r2', 'r3',
        [('l','lsr',28),('h','lsl',4),('h','lsr',2),('l','lsl',30),('h','lsr',7),('l','lsl',25)],
        [('h','lsr',28),('l','lsl',4),('l','lsr',2),('h','lsl',30),('l','lsr',7),('h','lsl',25)])
    e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
    e("    orr.w r6, r2, r8"); e("    and.w r6, r6, r10"); e("    and.w r0, r2, r8"); e("    orr.w r6, r6, r0")
    e("    orr.w r7, r3, r9"); e("    and.w r7, r7, r11"); e("    and.w r0, r3, r9"); e("    orr.w r7, r7, r0")
    e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
    e(f"    strd r4, r5, [sp, #{V(h)}]")                                                    # h = t1 + t2

K = [int(x, 16) for x in open('../../../bip39/src/sha512_fast.rs').read().split('const K: [u64; 80] = [')[1].split('];')[0].replace('\n','').replace(' ','').rstrip(',').split(',')]
assert len(K) == 80

e("    .syntax unified")
e("    .thumb")
e("    .section .text.pqsigner_sha512_compress_m33,\"ax\",%progbits")
e("    .global pqsigner_sha512_compress_m33")
e("    .type pqsigner_sha512_compress_m33,%function")
e("    .p2align 2")
e("    .thumb_func")
e("pqsigner_sha512_compress_m33:")
e("    @ r0 = state *u64[8] (in/out), r1 = block *u64[16]. Frame: V[8] @0, W[80] @64, state ptr @704.")
e("    push {r4-r11, lr}")
e("    sub sp, sp, #712")
e("    str r0, [sp, #704]")
for i in range(8):
    e(f"    ldrd r2, r3, [r0, #{8*i}]"); e(f"    strd r2, r3, [sp, #{8*i}]")
for i in range(16):
    e(f"    ldrd r2, r3, [r1, #{8*i}]"); e(f"    strd r2, r3, [sp, #{64 + 8*i}]")
e("    @ message schedule W[16..80): p = &W[t]")
e("    add lr, sp, #192")
e("    movs r1, #64")
e("    .p2align 2")
e("1:")
e("    ldrd r2, r3, [lr, #-16]")      # W[t-2]
sig('r4', 'r5', 'r2', 'r3',
    [('l','lsr',19),('h','lsl',13),('h','lsr',29),('l','lsl',3),('l','lsr',6),('h','lsl',26)],
    [('h','lsr',19),('l','lsl',13),('l','lsr',29),('h','lsl',3),('h','lsr',6)])
e("    ldrd r2, r3, [lr, #-120]")     # W[t-15]
sig('r6', 'r7', 'r2', 'r3',
    [('l','lsr',1),('h','lsl',31),('l','lsr',8),('h','lsl',24),('l','lsr',7),('h','lsl',25)],
    [('h','lsr',1),('l','lsl',31),('h','lsr',8),('l','lsl',24),('h','lsr',7)])
e("    adds r4, r4, r6"); e("    adc r5, r5, r7")
e("    ldrd r6, r7, [lr, #-56]"); e("    adds r4, r4, r6"); e("    adc r5, r5, r7")    # W[t-7]
e("    ldrd r6, r7, [lr, #-128]"); e("    adds r4, r4, r6"); e("    adc r5, r5, r7")   # W[t-16]
e("    strd r4, r5, [lr], #8")
e("    subs r1, r1, #1")
e("    bne 1b")
e("    @ 80 rounds: an 8-round body (one slot rotation) x 10; K in r12, W in lr, both post-incremented")
e("    movw r12, #:lower16:pqsigner_sha512_k")
e("    movt r12, #:upper16:pqsigner_sha512_k")
e("    add lr, sp, #64")
e("    movs r1, #10")
e("    .p2align 2")
e("2:")
for r in range(8):
    round_(r)
e("    subs r1, r1, #1")
e("    bne 2b")
e("    @ state += V")
e("    ldr r0, [sp, #704]")
for i in range(8):
    e(f"    ldrd r2, r3, [r0, #{8*i}]"); e(f"    ldrd r4, r5, [sp, #{8*i}]")
    e("    adds r2, r2, r4"); e("    adc r3, r3, r5"); e(f"    strd r2, r3, [r0, #{8*i}]")
e("    add sp, sp, #712")
e("    pop {r4-r11, pc}")
e("    .size pqsigner_sha512_compress_m33, .-pqsigner_sha512_compress_m33")
e("    .section .rodata.pqsigner_sha512_k,\"a\",%progbits")
e("    .p2align 3")
e("pqsigner_sha512_k:")
for k in K:
    e(f"    .word 0x{k & 0xffffffff:08x}, 0x{k >> 32:08x}")
open('src/compress_asm.s', 'w').write('\n'.join(out) + '\n')
print(len(out), 'lines')
