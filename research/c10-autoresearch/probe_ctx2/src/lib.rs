//! Probe (not an evaluator): which HASH context registers carry state after one block, and does a
//! SPARSE restore (INIT + only the CSRs that differ from the post-INIT context) reproduce the digest?
//! OUT[2..3]  = CSR index mask differing between post-INIT and after-block-1 of message X (bits 0..37)
//! OUT[4..5]  = mask differing between X and Y after block 1
//! OUT[6]     = number of CSRs in the sparse set (union of the two masks)
//! OUT[7]     = sparse-restore digests correct (bitmask over 8 trials; 0xFF = all)
//! OUT[8]     = cycles of one sparse restore (CR + n CSR writes); OUT[9] = full 128-B digest (plain feed);
//! OUT[10]    = resumed digest total (sparse restore + 15 words + DCAL + wait + 8 HR)
//! SIG0: CSR dumps (post-INIT, X, Y) for inspection.
#![no_std]
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
#[used] #[no_mangle] pub static mut SIG0: [u32; 1002] = [0; 1002];
#[used] #[no_mangle] pub static mut SIG1: [u8; 4008] = [0; 4008];
extern "C" { fn bench_halt(code: u32) -> !; }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0xF0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0xF1) } }
#[inline(always)] fn cyc() -> u32 { unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) } }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
const HB: usize = 0x520C_0400;
#[inline(always)] fn wr(off: usize, v: u32) { unsafe { core::ptr::write_volatile((HB + off) as *mut u32, v) } }
#[inline(always)] fn rd(off: usize) -> u32 { unsafe { core::ptr::read_volatile((HB + off) as *const u32) } }
const CR: usize = 0x00; const DIN: usize = 0x04; const STR: usize = 0x08; const SR: usize = 0x24;
const CSR0: usize = 0xF8; const HR: usize = 0x310;
const CR_GO: u32 = (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2);
fn idle() { while rd(SR) & 8 != 0 {} }
fn digest_plain(m: &[u32; 32]) -> [u32; 8] {
    idle(); wr(STR, 0); wr(CR, CR_GO);
    for w in m { wr(DIN, *w); }
    wr(STR, 1 << 8);
    while rd(SR) & 2 == 0 {}
    let d = core::array::from_fn(|k| rd(HR + 4 * k)); wr(SR, 1); d
}
fn save_after(m: Option<&[u32; 32]>) -> [u32; 38] {
    idle(); wr(STR, 0); wr(CR, CR_GO);
    if let Some(m) = m { for w in &m[..17] { wr(DIN, *w); } }
    idle(); while rd(SR) & 1 == 0 {}
    let c = core::array::from_fn(|k| rd(CSR0 + 4 * k));
    wr(CR, CR_GO); c
}
fn msg(seed: u32) -> [u32; 32] { core::array::from_fn(|i| (seed ^ 0x9E37_79B9).wrapping_mul(i as u32 * 2 + 1).rotate_left(i as u32)) }
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3051);
    unsafe { pqsigner_hw::hash::init_clock() };
    let x = msg(1); let y = msg(2);
    let s0 = save_after(None);
    let sx = save_after(Some(&x));
    let sy = save_after(Some(&y));
    unsafe {
        let p = core::ptr::addr_of_mut!(SIG0).cast::<u32>();
        for k in 0..38 { *p.add(k) = s0[k]; *p.add(40 + k) = sx[k]; *p.add(80 + k) = sy[k]; }
    }
    let (mut m0, mut m1) = (0u64, 0u64);
    for k in 0..38 { if s0[k] != sx[k] { m0 |= 1 << k; } if sx[k] != sy[k] { m1 |= 1 << k; } }
    out(2, m0 as u32); out(3, (m0 >> 32) as u32); out(4, m1 as u32); out(5, (m1 >> 32) as u32);
    let set = m0 | m1;
    out(6, set.count_ones());
    // sparse restore: for 8 messages sharing block 1 + word 17 of x, vary words 18..32 (the grind shape)
    let mut ok = 0u32; let mut t_restore = 0u32; let mut t_total = 0u32;
    let t = cyc(); let _ = digest_plain(&x); out(9, cyc().wrapping_sub(t));
    let ctx = save_after(Some(&x));
    for trial in 0..8u32 {
        let mut m = x; m[31] = trial.wrapping_mul(0x0101_0101) ^ 0x55; m[25] ^= trial;
        let reference = digest_plain(&m);
        idle();
        let t0 = cyc();
        wr(STR, 0); wr(CR, CR_GO);
        for k in 0..38 { if set & (1 << k) != 0 { wr(CSR0 + 4 * k, ctx[k]); } }
        let t1 = cyc();
        for w in &m[17..] { wr(DIN, *w); }
        wr(STR, 1 << 8);
        while rd(SR) & 2 == 0 {}
        let d: [u32; 8] = core::array::from_fn(|k| rd(HR + 4 * k)); wr(SR, 1);
        let t2 = cyc();
        if d == reference { ok |= 1 << trial; }
        t_restore += t1.wrapping_sub(t0); t_total += t2.wrapping_sub(t0);
    }
    out(7, ok); out(8, t_restore / 8); out(10, t_total / 8);
    out(1, 8);
}
