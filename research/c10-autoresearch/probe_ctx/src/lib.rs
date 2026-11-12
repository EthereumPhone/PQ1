//! Probe (not an evaluator): HASH context save/restore as a SHA-256 midstate.
//! OUT[2] = normal 128-B digest cycles; [3] = restore cycles with str loop; [4] = restore with ldm/stm bursts;
//! [5] = full resumed digest (burst restore + 15 words + DCAL + wait + 8 HR); [6] = digest-match bitmask
//! (bit0 loop-restore digest == reference, bit1 burst-restore == reference); [7] = save cycles.
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
const CR: usize = 0x00; const DIN: usize = 0x04; const STR: usize = 0x08; const IMR: usize = 0x20; const SR: usize = 0x24;
const CSR0: usize = 0xF8; const HR: usize = 0x310;
const CR_GO: u32 = (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2);
fn wait_dcis_read() -> [u32; 8] {
    while rd(SR) & 2 == 0 {}
    let d = core::array::from_fn(|k| rd(HR + 4 * k));
    wr(SR, 1);
    d
}
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3050);
    unsafe { pqsigner_hw::hash::init_clock() };
    let msg: [u32; 32] = core::array::from_fn(|i| 0x6A09_E667u32.wrapping_mul(i as u32 + 3) ^ 0x5bd1_e995);
    // reference digest, plain feed
    while rd(SR) & 8 != 0 {}
    let t = cyc();
    wr(STR, 0); wr(CR, CR_GO);
    for w in msg { wr(DIN, w); }
    wr(STR, 1 << 8);
    let reference = wait_dcis_read();
    out(2, cyc().wrapping_sub(t));
    // save the context after 17 words (block 1 processed, word 17 in the FIFO)
    while rd(SR) & 8 != 0 {}
    wr(STR, 0); wr(CR, CR_GO);
    for w in &msg[..17] { wr(DIN, *w); }
    let t = cyc();
    while rd(SR) & 8 != 0 {}
    while rd(SR) & 1 == 0 {}
    let mut ctx = [0u32; 41];
    ctx[0] = rd(IMR); ctx[1] = rd(STR); ctx[2] = rd(CR);
    for k in 0..38 { ctx[3 + k] = rd(CSR0 + 4 * k); }
    out(7, cyc().wrapping_sub(t));
    // abandon this message
    wr(CR, CR_GO);
    let mut ok = 0u32;
    // resume A: plain str loop restore
    while rd(SR) & 8 != 0 {}
    let t = cyc();
    wr(IMR, ctx[0]); wr(STR, ctx[1]); wr(CR, ctx[2]); wr(CR, ctx[2] | (1 << 2));
    for k in 0..38 { wr(CSR0 + 4 * k, ctx[3 + k]); }
    out(3, cyc().wrapping_sub(t));
    for w in &msg[17..] { wr(DIN, *w); }
    wr(STR, 1 << 8);
    if wait_dcis_read() == reference { ok |= 1; }
    // resume B: ldm/stm bursts
    while rd(SR) & 8 != 0 {}
    let t0 = cyc();
    wr(IMR, ctx[0]); wr(STR, ctx[1]); wr(CR, ctx[2]); wr(CR, ctx[2] | (1 << 2));
    unsafe {
        core::arch::asm!(
            "ldm {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}", "stm {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "ldm {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}", "stm {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "ldm {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}", "stm {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "ldm {s}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}", "stm {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
            "ldm {s}!, {{r0, r1, r2, r3, r4, r5}}", "stm {d}!, {{r0, r1, r2, r3, r4, r5}}",
            s = inout(reg) ctx.as_ptr().add(3) => _, d = inout(reg) (HB + CSR0) as u32 => _,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _, out("r8") _, out("r9") _,
            options(nostack));
    }
    let t1 = cyc();
    out(4, t1.wrapping_sub(t0));
    for w in &msg[17..] { wr(DIN, *w); }
    wr(STR, 1 << 8);
    let d = wait_dcis_read();
    out(5, cyc().wrapping_sub(t0));
    if d == reference { ok |= 2; }
    out(6, ok);
    out(1, 8);
}
