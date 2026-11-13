// Round 6 "test zero": DWT cycles per digest of each fused v2 driver entry,
// in isolation, on fixed inputs. Not a gate (bench_v2drv checks the bytes).
// Result window (0x3000_0100): 0 magic 'MCR2', 1 stage (100 = done), then
// pairs (cycles, digests) per measurement from word 2.
#![no_std]

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
extern "C" {
    fn bench_halt(code: u32) -> !;
    fn pqsigner_v2_chain16(seed: *const u8, val: *mut u8, a0: u32, low24: u32, start: u32, steps: u32);
    fn pqsigner_v2_node16(seed: *const u8, l: *const u8, r: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_wots_chains16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_wots_pk16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, k0: u32, k1: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_fors_subtree16(sk: *const u8, seed: *const u8, p0: u32, p1: u32, a0: u32, a1: u32, j0: u32, h: u32, out: *mut u8);
    fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32;
}
#[no_mangle]
pub static mut SIG0: [u8; 4008] = [0; 4008];
#[no_mangle]
pub static mut SIG1: [u8; 4008] = [0; 4008];
#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F0) }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F1) }
}
#[inline(always)]
fn out(i: usize, v: u32) {
    // SAFETY: the harness's result window.
    unsafe { core::ptr::write_volatile(OUT.add(i), v) }
}
#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: DWT_CYCCNT, enabled by the harness.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}

// Round 7 raw probes (Fable list 6, "microbench first"): HASH registers, secure alias.
const HB: u32 = 0x520C_0400;
#[inline(always)]
unsafe fn hw(off: u32, v: u32) {
    unsafe { core::ptr::write_volatile((HB + off) as *mut u32, v) }
}
#[inline(always)]
unsafe fn hr(off: u32) -> u32 {
    unsafe { core::ptr::read_volatile((HB + off) as *const u32) }
}
#[inline(always)]
fn spin(n: u32) {
    if n != 0 {
        // SAFETY: register-only countdown.
        unsafe { core::arch::asm!("1:", "subs {0}, #1", "bne 1b", inout(reg) n => _, options(nomem, nostack)) }
    }
}
/// Idle engine, INIT, 10 DIN words: the chain-step message shape.
#[inline(always)]
unsafe fn feed10() {
    unsafe {
        while hr(0x24) & 8 != 0 {}
        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        for i in 0..10u32 {
            hw(0x04, i.wrapping_mul(0x0101_0101));
        }
    }
}
#[inline(always)]
unsafe fn drain() {
    unsafe {
        while hr(0x24) & 2 == 0 {}
        let _ = hr(0x310);
        hw(0x24, 1);
    }
}

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x4D43_5232);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let s = [0x5Au8; 16];
    let sk = [0xA5u8; 32];
    let mut v = [0x11u8; 16];
    let mut o = [0u8; 688];
    let mut k = 2usize;
    let mut rec = |c: u32, d: u32| {
        out(k, c);
        out(k + 1, d);
        k += 2;
    };
    // SAFETY (all calls): the buffers above are large enough; arguments in range.
    unsafe {
        // 1. chain16, 15 steps per call (amortizes the entry), 2,000 calls.
        let t = cyc();
        for _ in 0..2000 {
            pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), 0x0102_0304, 0x0000_0500, 0, 15);
        }
        rec(cyc().wrapping_sub(t), 30_000);
        // 2. chain16, 1 step per call (entry + one digest), 5,000 calls.
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), 0x0102_0304, 0x0000_0500, 3, 1);
        }
        rec(cyc().wrapping_sub(t), 5_000);
        // 3. node16 (55 bytes), 5,000 calls.
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_v2_node16(s.as_ptr(), v.as_ptr(), s.as_ptr(), 0x0102_0304, 0x0000_2500, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 5_000);
        // 4. wots_chains16, steps 7 (keygen shape): 43 x 8 digests per call, 200 calls.
        let t = cyc();
        for _ in 0..200 {
            pqsigner_v2_wots_chains16(sk.as_ptr(), 0x0102_0304, 0, s.as_ptr(), 0x0102_0305, 0, 7, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 200 * 344);
        // 5. wots_pk16 (chains + T_43), 200 calls.
        let t = cyc();
        for _ in 0..200 {
            pqsigner_v2_wots_pk16(sk.as_ptr(), 0x0102_0304, 0, s.as_ptr(), 0x0102_0305, 0, 0x0102_0306, 0, 7, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 200 * 345);
        // 6. fors_subtree16, h = 11 (6,143 digests), 4 calls.
        let t = cyc();
        for _ in 0..4 {
            pqsigner_v2_fors_subtree16(sk.as_ptr(), s.as_ptr(), 0x0102_0304, 0, 0x0102_0305, 0, 0, 11, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 4 * 6143);
        // 7. search43_target, impossible target: 20,000 tries.
        let mut d = [0u8; 32];
        let mut sm = [0x33u8; 32];
        sm[0] = 1;
        let t = cyc();
        let _ = pqsigner_v2_search43_target(sm.as_ptr(), 0x0102_0307, 0, 0, 20_000, 400, d.as_mut_ptr());
        rec(cyc().wrapping_sub(t), 20_000);
        // 8. Engine floor, tight poll: STR(DCAL) .. DCIS seen, 1,000 trials: (min, sum).
        let (mut mn, mut sum) = (u32::MAX, 0u32);
        for _ in 0..1000 {
            feed10();
            let t = cyc();
            hw(0x08, 24 | 1 << 8);
            while hr(0x24) & 2 == 0 {}
            let c = cyc().wrapping_sub(t);
            hw(0x24, 1);
            mn = mn.min(c);
            sum += c;
        }
        rec(mn, sum);
        // 9. Engine floor, delay sweep: the smallest spin count d with DCIS set on all 64
        //    trials of one SR read after STR(DCAL) + spin(d); then cycles per 1,000 spins.
        let mut dstar = 0xFFFF;
        for d in 0..80u32 {
            let mut all = true;
            for _ in 0..64 {
                feed10();
                hw(0x08, 24 | 1 << 8);
                spin(d);
                let hit = hr(0x24) & 2 != 0;
                drain();
                all &= hit;
            }
            if all {
                dstar = d;
                break;
            }
        }
        let t = cyc();
        spin(1000);
        rec(dstar, cyc().wrapping_sub(t));
        // 10. Unrolled asm: K back-to-back DIN stores after INIT (engine idle), 256 reps;
        //     then K back-to-back SR loads and K HR0 loads. Words: (st2, st14), (sr2, sr14), (hr2, hr14).
        macro_rules! timed {
            ($k:literal, $ins:literal, $off:expr, $init:expr) => {{
                let mut tot = 0u32;
                for _ in 0..256 {
                    if $init {
                        while hr(0x24) & 8 != 0 {}
                        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
                        let _ = hr(0x24);
                    }
                    let t = cyc();
                    core::arch::asm!(concat!(".rept ", $k), $ins, ".endr", a = in(reg) HB + $off, v = inout(reg) 0x1234_5678u32 => _, options(nostack));
                    tot += cyc().wrapping_sub(t);
                }
                tot
            }};
        }
        let a = timed!(2, "str {v}, [{a}]", 4, true);
        let b = timed!(14, "str {v}, [{a}]", 4, true);
        rec(a, b);
        let a = timed!(2, "ldr {v}, [{a}]", 0x24, false);
        let b = timed!(14, "ldr {v}, [{a}]", 0x24, false);
        rec(a, b);
        let a = timed!(2, "ldr {v}, [{a}]", 0x310, false);
        let b = timed!(14, "ldr {v}, [{a}]", 0x310, false);
        rec(a, b);
        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        // 12. DCAL -> DCIS seen and DCAL -> BUSY clear (after DCIS), 1,000 trials: sums.
        let (mut sd, mut sb) = (0u32, 0u32);
        for _ in 0..1000 {
            feed10();
            let t = cyc();
            hw(0x08, 24 | 1 << 8);
            while hr(0x24) & 2 == 0 {}
            let c1 = cyc().wrapping_sub(t);
            while hr(0x24) & 8 != 0 {}
            let c2 = cyc().wrapping_sub(t);
            hw(0x24, 1);
            sd += c1;
            sb += c2;
        }
        rec(sd, sb);
        // 13. A tight, real-shaped step: INIT, 10 DIN (asm), DCAL; t1 after DCAL is issued,
        //     t2 at DCIS seen, t3 at BUSY clear after the HR read + SR clear. Sums over 1,000;
        //     plus the same with a 40-cycle gap between INIT and the first DIN (t2 only).
        let (mut s1, mut s2, mut s3, mut s4) = (0u32, 0u32, 0u32, 0u32);
        for gap in [false, true] {
            for _ in 0..1000 {
                while hr(0x24) & 8 != 0 {}
                let t0 = cyc();
                hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
                if gap {
                    spin(13);
                }
                core::arch::asm!(".rept 10", "str {v}, [{a}]", ".endr", a = in(reg) HB + 4, v = in(reg) 0x1234_5678u32, options(nostack));
                hw(0x08, 24 | 1 << 8);
                let t1 = cyc();
                while hr(0x24) & 2 == 0 {}
                let t2 = cyc();
                let _ = hr(0x310);
                hw(0x24, 1);
                while hr(0x24) & 8 != 0 {}
                let t3 = cyc();
                if gap {
                    s4 += t2.wrapping_sub(t0);
                } else {
                    s1 += t1.wrapping_sub(t0);
                    s2 += t2.wrapping_sub(t0);
                    s3 += t3.wrapping_sub(t0);
                }
            }
        }
        rec(s1, s2);
        rec(s3, s4);
        // 11. search43 with the real target 205: 16 searches, (cycles, tries).
        let (mut cy, mut tries) = (0u32, 0u32);
        for m in 0..16u8 {
            sm[1] = m;
            let t = cyc();
            let r = pqsigner_v2_search43_target(sm.as_ptr(), 0x0102_0307, 0, 0, 1 << 22, 205, d.as_mut_ptr());
            cy = cy.wrapping_add(cyc().wrapping_sub(t));
            tries += r + 1;
        }
        rec(cy, tries);
    }
    out(1, 100);
}
