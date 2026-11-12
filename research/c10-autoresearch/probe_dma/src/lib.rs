//! Probe (not an evaluator): GPDMA1 channel 12 feeding HASH_DIN (software request, 4-word bursts) vs the CPU.
//! OUT[2] = CPU-fed 96-B digest (INIT..HR read), OUT[3] = DMA-fed 96-B digest (INIT, DMA, wait TC, DCAL, HR),
//! OUT[4] = DMA enable -> TCF, OUT[5] = digests equal (1), OUT[6] = GPDMA CxSR at the end (error flags),
//! OUT[7] = variant with DMA setup regs pre-written (only BR1 + CR.EN per digest).
#![no_std]
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
#[used] #[no_mangle] pub static mut SIG0: [u8; 4008] = [0; 4008];
#[used] #[no_mangle] pub static mut SIG1: [u8; 4008] = [0; 4008];
extern "C" { fn bench_halt(code: u32) -> !; }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0xF0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0xF1) } }
#[inline(always)] fn cyc() -> u32 { unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) } }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
#[inline(always)] fn w32(a: usize, v: u32) { unsafe { core::ptr::write_volatile(a as *mut u32, v) } }
#[inline(always)] fn r32(a: usize) -> u32 { unsafe { core::ptr::read_volatile(a as *const u32) } }
const HB: usize = 0x520C_0400;
const CR: usize = HB; const DIN: usize = HB + 4; const STR: usize = HB + 8; const SR: usize = HB + 0x24; const HR: usize = HB + 0x310;
const CR_GO: u32 = (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2);
const DMA: usize = 0x5002_0000;
const CH: usize = DMA + 0x50 + 0x80 * 12;
const C_FCR: usize = CH + 0x0C; const C_SR: usize = CH + 0x10; const C_CR: usize = CH + 0x14;
const C_TR1: usize = CH + 0x40; const C_TR2: usize = CH + 0x44; const C_BR1: usize = CH + 0x48;
const C_SAR: usize = CH + 0x4C; const C_DAR: usize = CH + 0x50;
fn finish() -> [u32; 4] {
    w32(STR, 1 << 8);
    while r32(SR) & 2 == 0 {}
    let d = [r32(HR), r32(HR + 4), r32(HR + 8), r32(HR + 12)];
    w32(SR, 1);
    d
}
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3044);
    unsafe { pqsigner_hw::hash::init_clock() };
    w32(0x5602_0C00 + 0x88, r32(0x5602_0C00 + 0x88) | 1); // RCC_AHB1ENR1.GPDMA1EN
    let _ = r32(0x5602_0C00 + 0x88);
    w32(DMA + 0x00, r32(DMA + 0x00) | (1 << 12)); // SECCFGR: channel 12 secure
    w32(DMA + 0x04, r32(DMA + 0x04) | (1 << 12)); // PRIVCFGR: channel 12 privileged
    let buf: [u32; 24] = core::array::from_fn(|i| 0x9E37_79B9u32.wrapping_mul(i as u32 + 7));
    // CPU-fed reference
    while r32(SR) & 8 != 0 {}
    let t = cyc();
    w32(STR, 0); w32(CR, CR_GO);
    for w in buf { w32(DIN, w); }
    let d_cpu = finish();
    out(2, cyc().wrapping_sub(t));
    // DMA-fed
    let tr1: u32 = 2 | (1 << 3) | (3 << 4) | (1 << 15) | (2 << 16) | (3 << 20) | (1 << 31); // word, SINC, SBL 4, SSEC, word, DBL 4, DSEC
    let mut best = u32::MAX; let mut tc = 0u32; let mut d_dma = [0u32; 4];
    for _ in 0..16 {
        while r32(SR) & 8 != 0 {}
        let t0 = cyc();
        w32(STR, 0); w32(CR, CR_GO);
        w32(C_CR, 0); w32(C_FCR, 0x7F00);
        w32(C_TR1, tr1); w32(C_TR2, 1 << 9); w32(C_BR1, 96);
        w32(C_SAR, buf.as_ptr() as u32); w32(C_DAR, DIN as u32);
        w32(C_CR, 1);
        let t1 = cyc();
        while r32(C_SR) & (1 << 8) == 0 { if r32(C_SR) & 0x7F00 & !(1 << 8) != 0 { break; } }
        let t2 = cyc();
        out(8, r32(SR));                       // HASH_SR right after TC (NBWP bits 13:9, DINNE 15)
        let mut spins = 0u32;
        while (r32(SR) >> 9) & 0x1F != 8 && spins < 1000 { spins += 1; }   // wait: 8 words pending in block 2
        out(9, spins); out(10, r32(SR));
        d_dma = finish();
        out(11, d_dma[0]); out(12, d_cpu[0]);
        let t3 = cyc();
        if t3.wrapping_sub(t0) < best { best = t3.wrapping_sub(t0); tc = t2.wrapping_sub(t1); }
    }
    out(3, best); out(4, tc); out(5, (d_dma == d_cpu) as u32); out(6, r32(C_SR));
    // pre-written setup: only BR1 + EN per digest
    let mut best2 = u32::MAX;
    for _ in 0..16 {
        while r32(SR) & 8 != 0 {}
        w32(C_FCR, 0x7F00);
        let t0 = cyc();
        w32(STR, 0); w32(CR, CR_GO);
        w32(C_BR1, 96); w32(C_SAR, buf.as_ptr() as u32);
        w32(C_CR, 1);
        while r32(C_SR) & (1 << 8) == 0 { if r32(C_SR) & 0x7E00 != 0 { break; } }
        while (r32(SR) >> 9) & 0x1F != 8 {}
        let d = finish();
        let t1 = cyc();
        if d != d_cpu { out(5, 0); }
        if t1.wrapping_sub(t0) < best2 { best2 = t1.wrapping_sub(t0); }
    }
    out(7, best2);
    w32(C_CR, 0);
    w32(DMA + 0x00, r32(DMA + 0x00) & !(1 << 12));
    w32(DMA + 0x04, r32(DMA + 0x04) & !(1 << 12));
    out(1, 8);
}
