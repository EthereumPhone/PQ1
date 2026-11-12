    .syntax unified
    .thumb
    .section .text.pqsigner_sha512_compress_m33,"ax",%progbits
    .global pqsigner_sha512_compress_m33
    .type pqsigner_sha512_compress_m33,%function
    .p2align 2
    .thumb_func
pqsigner_sha512_compress_m33:
    @ r0 = state *u64[8] (in/out), r1 = block *u64[16]. Frame: V[8] @0, W[80] @64, state ptr @704.
    push {r4-r11, lr}
    sub sp, sp, #712
    str r0, [sp, #704]
    ldrd r2, r3, [r0, #0]
    strd r2, r3, [sp, #0]
    ldrd r2, r3, [r0, #8]
    strd r2, r3, [sp, #8]
    ldrd r2, r3, [r0, #16]
    strd r2, r3, [sp, #16]
    ldrd r2, r3, [r0, #24]
    strd r2, r3, [sp, #24]
    ldrd r2, r3, [r0, #32]
    strd r2, r3, [sp, #32]
    ldrd r2, r3, [r0, #40]
    strd r2, r3, [sp, #40]
    ldrd r2, r3, [r0, #48]
    strd r2, r3, [sp, #48]
    ldrd r2, r3, [r0, #56]
    strd r2, r3, [sp, #56]
    ldrd r2, r3, [r1, #0]
    strd r2, r3, [sp, #64]
    ldrd r2, r3, [r1, #8]
    strd r2, r3, [sp, #72]
    ldrd r2, r3, [r1, #16]
    strd r2, r3, [sp, #80]
    ldrd r2, r3, [r1, #24]
    strd r2, r3, [sp, #88]
    ldrd r2, r3, [r1, #32]
    strd r2, r3, [sp, #96]
    ldrd r2, r3, [r1, #40]
    strd r2, r3, [sp, #104]
    ldrd r2, r3, [r1, #48]
    strd r2, r3, [sp, #112]
    ldrd r2, r3, [r1, #56]
    strd r2, r3, [sp, #120]
    ldrd r2, r3, [r1, #64]
    strd r2, r3, [sp, #128]
    ldrd r2, r3, [r1, #72]
    strd r2, r3, [sp, #136]
    ldrd r2, r3, [r1, #80]
    strd r2, r3, [sp, #144]
    ldrd r2, r3, [r1, #88]
    strd r2, r3, [sp, #152]
    ldrd r2, r3, [r1, #96]
    strd r2, r3, [sp, #160]
    ldrd r2, r3, [r1, #104]
    strd r2, r3, [sp, #168]
    ldrd r2, r3, [r1, #112]
    strd r2, r3, [sp, #176]
    ldrd r2, r3, [r1, #120]
    strd r2, r3, [sp, #184]
    @ message schedule W[16..80): p = &W[t]
    add lr, sp, #192
    movs r1, #64
    .p2align 2
1:
    ldrd r2, r3, [lr, #-16]
    lsr.w r4, r2, #19
    eor.w r4, r4, r3, lsl #13
    eor.w r4, r4, r3, lsr #29
    eor.w r4, r4, r2, lsl #3
    eor.w r4, r4, r2, lsr #6
    eor.w r4, r4, r3, lsl #26
    lsr.w r5, r3, #19
    eor.w r5, r5, r2, lsl #13
    eor.w r5, r5, r2, lsr #29
    eor.w r5, r5, r3, lsl #3
    eor.w r5, r5, r3, lsr #6
    ldrd r2, r3, [lr, #-120]
    lsr.w r6, r2, #1
    eor.w r6, r6, r3, lsl #31
    eor.w r6, r6, r2, lsr #8
    eor.w r6, r6, r3, lsl #24
    eor.w r6, r6, r2, lsr #7
    eor.w r6, r6, r3, lsl #25
    lsr.w r7, r3, #1
    eor.w r7, r7, r2, lsl #31
    eor.w r7, r7, r3, lsr #8
    eor.w r7, r7, r2, lsl #24
    eor.w r7, r7, r3, lsr #7
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r6, r7, [lr, #-56]
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r6, r7, [lr, #-128]
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [lr], #8
    subs r1, r1, #1
    bne 1b
    @ 80 rounds: an 8-round body (one slot rotation) x 10; K in r12, W in lr, both post-incremented
    movw r12, #:lower16:pqsigner_sha512_k
    movt r12, #:upper16:pqsigner_sha512_k
    add lr, sp, #64
    movs r1, #10
    .p2align 2
2:
    @ round 0
    ldrd r2, r3, [sp, #32]
    ldrd r8, r9, [sp, #40]
    ldrd r10, r11, [sp, #48]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #56]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #24]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #0]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #24]
    ldrd r8, r9, [sp, #8]
    ldrd r10, r11, [sp, #16]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #56]
    @ round 1
    ldrd r2, r3, [sp, #24]
    ldrd r8, r9, [sp, #32]
    ldrd r10, r11, [sp, #40]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #48]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #16]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #56]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #16]
    ldrd r8, r9, [sp, #0]
    ldrd r10, r11, [sp, #8]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #48]
    @ round 2
    ldrd r2, r3, [sp, #16]
    ldrd r8, r9, [sp, #24]
    ldrd r10, r11, [sp, #32]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #40]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #8]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #48]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #8]
    ldrd r8, r9, [sp, #56]
    ldrd r10, r11, [sp, #0]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #40]
    @ round 3
    ldrd r2, r3, [sp, #8]
    ldrd r8, r9, [sp, #16]
    ldrd r10, r11, [sp, #24]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #32]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #0]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #40]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #0]
    ldrd r8, r9, [sp, #48]
    ldrd r10, r11, [sp, #56]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #32]
    @ round 4
    ldrd r2, r3, [sp, #0]
    ldrd r8, r9, [sp, #8]
    ldrd r10, r11, [sp, #16]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #24]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #56]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #32]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #56]
    ldrd r8, r9, [sp, #40]
    ldrd r10, r11, [sp, #48]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #24]
    @ round 5
    ldrd r2, r3, [sp, #56]
    ldrd r8, r9, [sp, #0]
    ldrd r10, r11, [sp, #8]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #16]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #48]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #24]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #48]
    ldrd r8, r9, [sp, #32]
    ldrd r10, r11, [sp, #40]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #16]
    @ round 6
    ldrd r2, r3, [sp, #48]
    ldrd r8, r9, [sp, #56]
    ldrd r10, r11, [sp, #0]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #8]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #40]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #16]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #40]
    ldrd r8, r9, [sp, #24]
    ldrd r10, r11, [sp, #32]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #8]
    @ round 7
    ldrd r2, r3, [sp, #40]
    ldrd r8, r9, [sp, #48]
    ldrd r10, r11, [sp, #56]
    lsr.w r4, r2, #14
    eor.w r4, r4, r3, lsl #18
    eor.w r4, r4, r2, lsr #18
    eor.w r4, r4, r3, lsl #14
    eor.w r4, r4, r3, lsr #9
    eor.w r4, r4, r2, lsl #23
    lsr.w r5, r3, #14
    eor.w r5, r5, r2, lsl #18
    eor.w r5, r5, r3, lsr #18
    eor.w r5, r5, r2, lsl #14
    eor.w r5, r5, r2, lsr #9
    eor.w r5, r5, r3, lsl #23
    eor.w r8, r8, r10
    and.w r8, r8, r2
    eor.w r8, r8, r10
    eor.w r9, r9, r11
    and.w r9, r9, r3
    eor.w r9, r9, r11
    ldrd r6, r7, [sp, #0]
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r8, r9, [r12], #8
    adds r4, r4, r6
    adc r5, r5, r7
    ldrd r10, r11, [lr], #8
    adds r4, r4, r8
    adc r5, r5, r9
    ldrd r6, r7, [sp, #32]
    adds r4, r4, r10
    adc r5, r5, r11
    ldrd r2, r3, [sp, #8]
    adds r6, r6, r4
    adc r7, r7, r5
    strd r6, r7, [sp, #32]
    ldrd r8, r9, [sp, #16]
    ldrd r10, r11, [sp, #24]
    lsr.w r6, r2, #28
    eor.w r6, r6, r3, lsl #4
    eor.w r6, r6, r3, lsr #2
    eor.w r6, r6, r2, lsl #30
    eor.w r6, r6, r3, lsr #7
    eor.w r6, r6, r2, lsl #25
    lsr.w r7, r3, #28
    eor.w r7, r7, r2, lsl #4
    eor.w r7, r7, r2, lsr #2
    eor.w r7, r7, r3, lsl #30
    eor.w r7, r7, r2, lsr #7
    eor.w r7, r7, r3, lsl #25
    adds r4, r4, r6
    adc r5, r5, r7
    orr.w r6, r2, r8
    and.w r6, r6, r10
    and.w r0, r2, r8
    orr.w r6, r6, r0
    orr.w r7, r3, r9
    and.w r7, r7, r11
    and.w r0, r3, r9
    orr.w r7, r7, r0
    adds r4, r4, r6
    adc r5, r5, r7
    strd r4, r5, [sp, #0]
    subs r1, r1, #1
    bne 2b
    @ state += V
    ldr r0, [sp, #704]
    ldrd r2, r3, [r0, #0]
    ldrd r4, r5, [sp, #0]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #0]
    ldrd r2, r3, [r0, #8]
    ldrd r4, r5, [sp, #8]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #8]
    ldrd r2, r3, [r0, #16]
    ldrd r4, r5, [sp, #16]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #16]
    ldrd r2, r3, [r0, #24]
    ldrd r4, r5, [sp, #24]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #24]
    ldrd r2, r3, [r0, #32]
    ldrd r4, r5, [sp, #32]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #32]
    ldrd r2, r3, [r0, #40]
    ldrd r4, r5, [sp, #40]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #40]
    ldrd r2, r3, [r0, #48]
    ldrd r4, r5, [sp, #48]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #48]
    ldrd r2, r3, [r0, #56]
    ldrd r4, r5, [sp, #56]
    adds r2, r2, r4
    adc r3, r3, r5
    strd r2, r3, [r0, #56]
    add sp, sp, #712
    pop {r4-r11, pc}
    .size pqsigner_sha512_compress_m33, .-pqsigner_sha512_compress_m33
    .section .rodata.pqsigner_sha512_k,"a",%progbits
    .p2align 3
pqsigner_sha512_k:
    .word 0xd728ae22, 0x428a2f98
    .word 0x23ef65cd, 0x71374491
    .word 0xec4d3b2f, 0xb5c0fbcf
    .word 0x8189dbbc, 0xe9b5dba5
    .word 0xf348b538, 0x3956c25b
    .word 0xb605d019, 0x59f111f1
    .word 0xaf194f9b, 0x923f82a4
    .word 0xda6d8118, 0xab1c5ed5
    .word 0xa3030242, 0xd807aa98
    .word 0x45706fbe, 0x12835b01
    .word 0x4ee4b28c, 0x243185be
    .word 0xd5ffb4e2, 0x550c7dc3
    .word 0xf27b896f, 0x72be5d74
    .word 0x3b1696b1, 0x80deb1fe
    .word 0x25c71235, 0x9bdc06a7
    .word 0xcf692694, 0xc19bf174
    .word 0x9ef14ad2, 0xe49b69c1
    .word 0x384f25e3, 0xefbe4786
    .word 0x8b8cd5b5, 0x0fc19dc6
    .word 0x77ac9c65, 0x240ca1cc
    .word 0x592b0275, 0x2de92c6f
    .word 0x6ea6e483, 0x4a7484aa
    .word 0xbd41fbd4, 0x5cb0a9dc
    .word 0x831153b5, 0x76f988da
    .word 0xee66dfab, 0x983e5152
    .word 0x2db43210, 0xa831c66d
    .word 0x98fb213f, 0xb00327c8
    .word 0xbeef0ee4, 0xbf597fc7
    .word 0x3da88fc2, 0xc6e00bf3
    .word 0x930aa725, 0xd5a79147
    .word 0xe003826f, 0x06ca6351
    .word 0x0a0e6e70, 0x14292967
    .word 0x46d22ffc, 0x27b70a85
    .word 0x5c26c926, 0x2e1b2138
    .word 0x5ac42aed, 0x4d2c6dfc
    .word 0x9d95b3df, 0x53380d13
    .word 0x8baf63de, 0x650a7354
    .word 0x3c77b2a8, 0x766a0abb
    .word 0x47edaee6, 0x81c2c92e
    .word 0x1482353b, 0x92722c85
    .word 0x4cf10364, 0xa2bfe8a1
    .word 0xbc423001, 0xa81a664b
    .word 0xd0f89791, 0xc24b8b70
    .word 0x0654be30, 0xc76c51a3
    .word 0xd6ef5218, 0xd192e819
    .word 0x5565a910, 0xd6990624
    .word 0x5771202a, 0xf40e3585
    .word 0x32bbd1b8, 0x106aa070
    .word 0xb8d2d0c8, 0x19a4c116
    .word 0x5141ab53, 0x1e376c08
    .word 0xdf8eeb99, 0x2748774c
    .word 0xe19b48a8, 0x34b0bcb5
    .word 0xc5c95a63, 0x391c0cb3
    .word 0xe3418acb, 0x4ed8aa4a
    .word 0x7763e373, 0x5b9cca4f
    .word 0xd6b2b8a3, 0x682e6ff3
    .word 0x5defb2fc, 0x748f82ee
    .word 0x43172f60, 0x78a5636f
    .word 0xa1f0ab72, 0x84c87814
    .word 0x1a6439ec, 0x8cc70208
    .word 0x23631e28, 0x90befffa
    .word 0xde82bde9, 0xa4506ceb
    .word 0xb2c67915, 0xbef9a3f7
    .word 0xe372532b, 0xc67178f2
    .word 0xea26619c, 0xca273ece
    .word 0x21c0c207, 0xd186b8c7
    .word 0xcde0eb1e, 0xeada7dd6
    .word 0xee6ed178, 0xf57d4f7f
    .word 0x72176fba, 0x06f067aa
    .word 0xa2c898a6, 0x0a637dc5
    .word 0xbef90dae, 0x113f9804
    .word 0x131c471b, 0x1b710b35
    .word 0x23047d84, 0x28db77f5
    .word 0x40c72493, 0x32caab7b
    .word 0x15c9bebc, 0x3c9ebe0a
    .word 0x9c100d4c, 0x431d67c4
    .word 0xcb3e42b6, 0x4cc5d4be
    .word 0xfc657e2a, 0x597f299c
    .word 0x3ad6faec, 0x5fcb6fab
    .word 0x4a475817, 0x6c44198c
