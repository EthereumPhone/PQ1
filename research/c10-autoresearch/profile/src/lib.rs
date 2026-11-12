//! Diagnostic profile (NOT the evaluator): where do the cycles of one digest go?
#![no_std]
use sphincs_c10::sim_internals as si;
include!("../../inputs.rs");
const OUT: *mut u32 = 0x3000_0100 as *mut u32;
extern "C" { fn bench_halt(code: u32) -> !; fn pqsigner_sha256_oneshot(p: *const u8, n: usize, o: *mut u8); }
#[used] #[no_mangle] pub static mut SIG0: [u8; 4008] = [0; 4008];
#[used] #[no_mangle] pub static mut SIG1: [u8; 4008] = [0; 4008];
#[inline(always)] fn cyc() -> u32 { unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) } }
#[inline(always)] fn out(i: usize, v: u32) { unsafe { core::ptr::write_volatile(OUT.add(i), v) } }
#[no_mangle] pub extern "C" fn pqsigner_hash_fault() -> ! { unsafe { bench_halt(0xF0) } }
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { bench_halt(0xF1) } }
const HB: usize = 0x520C_0400;
#[inline(always)] fn wr(off: usize, v: u32) { unsafe { core::ptr::write_volatile((HB + off) as *mut u32, v) } }
#[inline(always)] fn rd(off: usize) -> u32 { unsafe { core::ptr::read_volatile((HB + off) as *const u32) } }
const NREP: u32 = 4096;

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 { out(i, 0); }
    out(0, 0x4331_3042);
    unsafe { pqsigner_hw::hash::init_clock() };
    let seed = si::pad16(&PK_SEED);
    let adrs = si::make_adrs(0, 5, 0, 7, 3, 0, 0);
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(&SK_SEED);
    let mut d = [0u8; 32];
    // 2: oneshot(96 B) back to back
    let t = cyc();
    for i in 0..NREP { buf[95] = i as u8; unsafe { pqsigner_sha256_oneshot(buf.as_ptr(), 96, d.as_mut_ptr()) }; }
    out(2, cyc().wrapping_sub(t) / NREP);
    // 3: th()
    let mut v = [0u8; 32];
    let t = cyc();
    for _ in 0..NREP { let r = si::th(&seed, &adrs, &v); v[..16].copy_from_slice(&r); }
    out(3, cyc().wrapping_sub(t) / NREP);
    // 4: chain_hash, 7 steps, per step
    let mut val = [0u8; 16];
    let t = cyc();
    for _ in 0..(NREP / 7) { val = si::chain_hash(&seed, &adrs, &val, 0, 7); }
    out(4, cyc().wrapping_sub(t) / ((NREP / 7) * 7));
    // 5: wots_secret
    let t = cyc();
    for i in 0..NREP { let r = si::wots_secret(&SK_SEED, 0, 5, i, 3); val[0] ^= r[0]; }
    out(5, cyc().wrapping_sub(t) / NREP);
    // 6: fors_secret
    let t = cyc();
    for i in 0..NREP { let r = si::fors_secret(&SK_SEED, 77, 3, i); val[0] ^= r[0]; }
    out(6, cyc().wrapping_sub(t) / NREP);
    // Register-level anatomy of one 96-B digest (sum over NREP):
    // 7: INIT write..last DIN write (24 words) ; 8: STR writes ; 9: DCAL..DCIS ; 10: HR read 8 + DCIS clear
    let (mut a7, mut a8, mut a9, mut a10) = (0u32, 0u32, 0u32, 0u32);
    let words: [u32; 24] = core::array::from_fn(|i| 0x0101_0101u32.wrapping_mul(i as u32 + 1));
    for i in 0..NREP {
        while rd(0x24) & 8 != 0 {}
        let t0 = cyc();
        wr(0x08, 0);
        wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        for w in 0..24 { wr(0x04, words[w] ^ i); }
        let t1 = cyc();
        wr(0x08, 0);
        wr(0x08, 1 << 8);
        let t2 = cyc();
        while rd(0x24) & 2 == 0 {}
        let t3 = cyc();
        let mut acc = 0u32;
        for k in 0..8 { acc ^= unsafe { core::ptr::read_volatile((HB + 0x310 + 4 * k) as *const u32) }; }
        wr(0x24, rd(0x24) & !2);
        let t4 = cyc();
        val[1] ^= acc as u8;
        a7 += t1 - t0; a8 += t2 - t1; a9 += t3 - t2; a10 += t4 - t3;
    }
    out(7, a7 / NREP); out(8, a8 / NREP); out(9, a9 / NREP); out(10, a10 / NREP);
    // 11: same but 16 words only (1 block + pad) to get engine per block
    let mut a11 = 0u32;
    for i in 0..NREP {
        while rd(0x24) & 8 != 0 {}
        wr(0x08, 0);
        wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        for w in 0..16 { wr(0x04, words[w] ^ i); }
        // wait for engine to drain block 1 (BUSY clear), then time a 2nd 16-word block's processing
        while rd(0x24) & 8 != 0 {}
        let t0 = cyc();
        for w in 0..16 { wr(0x04, words[w] ^ i); }
        wr(0x04, 0); // 33rd word forces processing of block 2
        while rd(0x24) & 8 != 0 {}
        a11 += cyc() - t0;
        wr(0x08, 0); wr(0x08, 1 << 8);
        while rd(0x24) & 2 == 0 {}
        wr(0x24, rd(0x24) & !2);
    }
    out(11, a11 / NREP);
    // 15..: per-access latency (dsb after each group so posted writes are counted)
    macro_rules! dsb { () => { unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) } } }
    let mut acc = [0u32; 8]; let mut a_poll = 0u32;
    for i in 0..NREP {
        while rd(0x24) & 8 != 0 {}
        wr(0x08, 0);
        let t0 = cyc(); wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2)); dsb!(); let t1 = cyc();
        wr(0x04, i); dsb!(); let t2 = cyc();
        for w in 0..4 { wr(0x04, words[w]); } dsb!(); let t3 = cyc();
        for w in 4..12 { wr(0x04, words[w]); } dsb!(); let t4 = cyc();
        for w in 12..15 { wr(0x04, words[w]); } dsb!(); let t5 = cyc();   // 16 words in: engine starts block 1
        let mut x = 0; for _ in 0..8 { x ^= rd(0x24); } let t6 = cyc();   // 8 SR reads
        for w in 0..8 { wr(0x04, words[w]); } dsb!(); let t7 = cyc();     // 8 more DIN while block 1 runs
        wr(0x08, 1 << 8); dsb!(); let t8 = cyc();
        while rd(0x24) & 2 == 0 {}
        let t9 = cyc();
        for k in 0..4 { x ^= unsafe { core::ptr::read_volatile((HB + 0x310 + 4 * k) as *const u32) }; }
        let t10 = cyc();
        wr(0x24, !2u32); dsb!(); let t11 = cyc();
        val[2] ^= x as u8;
        acc[0] += t1 - t0; acc[1] += t2 - t1; acc[2] += t3 - t2; acc[3] += t4 - t3;
        acc[4] += t6 - t5; acc[5] += t7 - t6; acc[6] += t10 - t9; acc[7] += t11 - t10; a_poll += t9 - t8;
        let _ = t5 - t4;
    }
    for k in 0..8 { out(15 + k, acc[k] / NREP); }
    out(23, a_poll / NREP);
    // 24..: bus probes. 24 = 8 DIN writes from registers (straight-line str), 25 = 8 CSR0 writes (same
    // peripheral, not the FIFO), 26 = 8 SRAM stores, 27 = 8 DIN writes + dsb. All with the engine idle and
    // a fresh INIT so the FIFO is empty.
    let mut b = [0u32; 4];
    let mut sram = [0u32; 8];
    for i in 0..NREP {
        while rd(0x24) & 8 != 0 {}
        wr(0x08, 0); wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        let t0 = cyc();
        unsafe { core::arch::asm!(
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "dsb sy",
            a = in(reg) (HB + 0x04) as u32, v = in(reg) i, options(nostack)) };
        let t1 = cyc();
        b[0] += t1 - t0;
        // finish this message cleanly
        for _ in 0..8 { wr(0x04, 0); }
        wr(0x08, 1 << 8); while rd(0x24) & 2 == 0 {} wr(0x24, !2u32);
        while rd(0x24) & 8 != 0 {}
        let t2 = cyc();
        unsafe { core::arch::asm!(
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "dsb sy",
            a = in(reg) (HB + 0x0F8) as u32, v = in(reg) i, options(nostack)) };   // HASH_CSR0
        let t3 = cyc();
        b[1] += t3 - t2;
        let t4 = cyc();
        unsafe { core::arch::asm!(
            "str {v}, [{a}]", "str {v}, [{a}, #4]", "str {v}, [{a}, #8]", "str {v}, [{a}, #12]",
            "str {v}, [{a}, #16]", "str {v}, [{a}, #20]", "str {v}, [{a}, #24]", "str {v}, [{a}, #28]", "dsb sy",
            a = in(reg) sram.as_mut_ptr(), v = in(reg) i, options(nostack)) };
        let t5 = cyc();
        b[2] += t5 - t4;
        let t6 = cyc();
        let mut x = 0u32;
        unsafe { core::arch::asm!(
            "ldr {x}, [{a}]", "ldr {x}, [{a}]", "ldr {x}, [{a}]", "ldr {x}, [{a}]",
            "ldr {x}, [{a}]", "ldr {x}, [{a}]", "ldr {x}, [{a}]", "ldr {x}, [{a}]",
            a = in(reg) (HB + 0x24) as u32, x = out(reg) x, options(nostack)) };
        let t7 = cyc();
        b[3] += t7 - t6; val[3] ^= x as u8;
    }
    for k in 0..4 { out(24 + k, b[k] / NREP); }
    wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));  // INIT: discard the CSR scribble
    // 28: full 96-B digest, straight-line: CR=INIT, 24 str DIN, STR=DCAL, poll DCIS, 4 ldr HR, clear.
    // 29: time from the 16th DIN write to BUSY clear (one block of engine time).
    // 30: time from DCAL to DCIS in that full digest.
    let (mut f, mut g, mut h) = (0u32, 0u32, 0u32);
    for i in 0..NREP {
        while rd(0x24) & 8 != 0 {}
        let t0 = cyc();
        wr(0x08, 0);
        wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        unsafe { core::arch::asm!(
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            a = in(reg) (HB + 0x04) as u32, v = in(reg) i, options(nostack)) };
        wr(0x08, 1 << 8);
        let t1 = cyc();
        while rd(0x24) & 2 == 0 {}
        let t2 = cyc();
        let mut x = 0u32;
        for k in 0..4 { x ^= unsafe { core::ptr::read_volatile((HB + 0x310 + 4 * k) as *const u32) }; }
        wr(0x24, !2u32);
        let t3 = cyc();
        f += t3 - t0; h += t2 - t1; val[4] ^= x as u8;
        // engine time for one block
        while rd(0x24) & 8 != 0 {}
        wr(0x08, 0);
        wr(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        unsafe { core::arch::asm!(
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            "str {v}, [{a}]", "str {v}, [{a}]", "str {v}, [{a}]",
            a = in(reg) (HB + 0x04) as u32, v = in(reg) i, options(nostack)) };
        let t4 = cyc();
        unsafe { core::arch::asm!("str {v}, [{a}]", "dsb sy", a = in(reg) (HB + 0x04) as u32, v = in(reg) i, options(nostack)) };
        while rd(0x24) & 8 != 0 {}
        let t5 = cyc();
        g += t5 - t4;
        wr(0x08, 1 << 8); while rd(0x24) & 2 == 0 {} wr(0x24, !2u32);
    }
    out(28, f / NREP); out(29, g / NREP); out(30, h / NREP);
    // 12: grind_r once (cycles) ; 13: sign_fors_tree once
    let t = cyc();
    let (_r, dg) = si::grind_r(&SK_SEED, &PK_SEED, &[0u8; 16], &MSG0, Some(&OPT_RAND));
    out(12, cyc().wrapping_sub(t));
    let t = cyc();
    let (sec, _auth) = si::sign_fors_tree(&seed, &SK_SEED, 77, 3, 1234);
    out(13, cyc().wrapping_sub(t));
    // 31: find_count on m0 for layer 0 (cycles), 15: its count (tries = count + 1)
    let t = cyc();
    let (cnt, _d, _dig) = si::find_count(&seed, 0, 3, 5, &MSG0);
    out(31, cyc().wrapping_sub(t));
    out(15, cnt);
    // 16: compute_fors_root cycles
    let t = cyc();
    let fr = si::compute_fors_root(&seed, &SK_SEED, 77, 12);
    out(16, cyc().wrapping_sub(t));
    val[5] ^= fr[0];
    out(14, (dg[0] ^ sec[0] ^ val[0] ^ val[1] ^ d[0]) as u32);
    out(1, 8);
}
