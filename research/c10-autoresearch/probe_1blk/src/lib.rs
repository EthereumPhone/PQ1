//! Probe (not an evaluator; NOT the frozen format): cost per chain step of today's 2-block th preimage
//! (96 B = 24 words) against a hypothetical 1-block one (52 B = 13 words: seed16 | compact adrs 20 | value16),
//! both in the same tight loop (INIT, feed, DCAL, DCIS poll, HR0..3, DCIS clear), 4,096 steps each.
//! OUT[2] = 2-block cycles/step, OUT[3] = 1-block cycles/step, OUT[4] = 2-block with HR via HRA ldm.
#![no_std]
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
#[used] #[no_mangle] pub static mut SIG0: [u8; 4008] = [0; 4008];
#[used] #[no_mangle] pub static mut SIG1: [u8; 4008] = [0; 4008];
extern "C" { fn bench_halt(code: u32) -> !; }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0xF0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0xF1) } }
#[inline(always)] fn cyc() -> u32 { unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) } }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
const HB: usize = 0x520C_0400;
#[inline(always)] fn wr(off: usize, v: u32) { unsafe { core::ptr::write_volatile((HB + off) as *mut u32, v) } }
#[inline(always)] fn rd(off: usize) -> u32 { unsafe { core::ptr::read_volatile((HB + off) as *const u32) } }
const CR_GO: u32 = (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2);
#[inline(always)]
fn step(words: &[u32], v: &mut [u32; 4], hra: bool) {
    while rd(0x24) & 8 != 0 {}
    wr(0x00, CR_GO);
    for w in words { wr(0x04, *w); }
    wr(0x04, v[0]); wr(0x04, v[1]); wr(0x04, v[2]); wr(0x04, v[3]);
    wr(0x08, 1 << 8);
    while rd(0x24) & 2 == 0 {}
    if hra {
        let (a, b, c, d): (u32, u32, u32, u32);
        unsafe { core::arch::asm!("ldm {p}, {{r0, r1, r2, r3}}", p = in(reg) (HB + 0x0C) as u32,
            out("r0") a, out("r1") b, out("r2") c, out("r3") d, options(nostack, readonly)) };
        *v = [a.swap_bytes(), b.swap_bytes(), c.swap_bytes(), d.swap_bytes()];
    } else {
        *v = [rd(0x310).swap_bytes(), rd(0x314).swap_bytes(), rd(0x318).swap_bytes(), rd(0x31C).swap_bytes()];
    }
    wr(0x24, 1);
}
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3031);
    unsafe { pqsigner_hw::hash::init_clock() };
    wr(0x08, 0);
    // 2-block: 16 fixed words + 4 value + 4 zero = 24 words; 1-block: 9 fixed words + 4 value = 13 words
    let two: [u32; 20] = core::array::from_fn(|i| if i < 16 { 0x1111_1111u32.wrapping_mul(i as u32 + 1) } else { 0 });
    let one: [u32; 9] = core::array::from_fn(|i| 0x2222_2222u32.wrapping_mul(i as u32 + 1));
    let mut v = [1u32, 2, 3, 4];
    // two-block: fixed words, then value, then 4 zero words (the step() appends value after `words`;
    // reorder: write 16 fixed, value, 4 zeros)
    let mut v2 = v;
    let t = cyc();
    for _ in 0..4096 {
        while rd(0x24) & 8 != 0 {}
        wr(0x00, CR_GO);
        for w in &two[..16] { wr(0x04, *w); }
        wr(0x04, v2[0]); wr(0x04, v2[1]); wr(0x04, v2[2]); wr(0x04, v2[3]);
        wr(0x04, 0); wr(0x04, 0); wr(0x04, 0); wr(0x04, 0);
        wr(0x08, 1 << 8);
        while rd(0x24) & 2 == 0 {}
        v2 = [rd(0x310).swap_bytes(), rd(0x314).swap_bytes(), rd(0x318).swap_bytes(), rd(0x31C).swap_bytes()];
        wr(0x24, 1);
    }
    out(2, cyc().wrapping_sub(t) / 4096);
    let t = cyc();
    for _ in 0..4096 { step(&one, &mut v, false); }
    out(3, cyc().wrapping_sub(t) / 4096);
    // 2-block with HRA ldm read-out
    let mut v3 = [1u32, 2, 3, 4];
    let t = cyc();
    for _ in 0..4096 {
        while rd(0x24) & 8 != 0 {}
        wr(0x00, CR_GO);
        for w in &two[..16] { wr(0x04, *w); }
        wr(0x04, v3[0]); wr(0x04, v3[1]); wr(0x04, v3[2]); wr(0x04, v3[3]);
        wr(0x04, 0); wr(0x04, 0); wr(0x04, 0); wr(0x04, 0);
        wr(0x08, 1 << 8);
        while rd(0x24) & 2 == 0 {}
        let (a, b, c, d): (u32, u32, u32, u32);
        unsafe { core::arch::asm!("ldm {p}, {{r0, r1, r2, r3}}", p = in(reg) (HB + 0x0C) as u32,
            out("r0") a, out("r1") b, out("r2") c, out("r3") d, options(nostack, readonly)) };
        v3 = [a.swap_bytes(), b.swap_bytes(), c.swap_bytes(), d.swap_bytes()];
        wr(0x24, 1);
    }
    out(4, cyc().wrapping_sub(t) / 4096);
    out(5, (v2 == v3) as u32); // HRA read-out gives the same chain values
    out(6, v[0]);
    out(1, 8);
}
