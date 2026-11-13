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
    fn pqsigner_sha256_chain16(buf: *mut u8, start_pos: u32, steps: u32);
    fn pqsigner_wots_chains16(sk: *const u8, prf_tail: *const u8, seed_adrs: *const u8, order: *const u8, digits: *const u8, fixed_steps: u32, n: u32, out: *mut u8);
    fn pqsigner_sha256_search128(buf: *const u8, start: u32, n: u32, pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8) -> u32;
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
        // 10. A v1-shaped two-block step (96-byte message, NBLW = 0): t1 after 16 stores,
        //     t2 after the 17th, t3 after 24 stores + DCAL, t4 at DCIS seen. Sums over 256.
        let (mut s1, mut s2, mut s3, mut s4) = (0u32, 0u32, 0u32, 0u32);
        for _ in 0..256 {
            while hr(0x24) & 8 != 0 {}
            hw(0x08, 0);
            let t0 = cyc();
            hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
            core::arch::asm!(".rept 16", "str {v}, [{a}]", ".endr", a = in(reg) HB + 4, v = in(reg) 0x1234_5678u32, options(nostack));
            let t1 = cyc();
            core::arch::asm!("str {v}, [{a}]", a = in(reg) HB + 4, v = in(reg) 0x1234_5678u32, options(nostack));
            let t2 = cyc();
            core::arch::asm!(".rept 7", "str {v}, [{a}]", ".endr", a = in(reg) HB + 4, v = in(reg) 0u32, options(nostack));
            hw(0x08, 1 << 8);
            let t3 = cyc();
            while hr(0x24) & 2 == 0 {}
            let t4 = cyc();
            let _ = hr(0x310);
            hw(0x24, 1);
            s1 += t1.wrapping_sub(t0);
            s2 += t2.wrapping_sub(t0);
            s3 += t3.wrapping_sub(t0);
            s4 += t4.wrapping_sub(t0);
        }
        rec(s1, s2);
        rec(s3, s4);
        rec(0, 0);
        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
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
        // 12. v1 (deployed format): chain16 over seed ‖ adrs(WOTS, zero words) ‖ pad16(v),
        //     15 steps per call, 2,000 calls; and search128 with a never-true predicate.
        let mut b = [0u8; 96];
        b[..16].copy_from_slice(&[0x5A; 16]);
        b[32..44].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        b[48..52].copy_from_slice(&[0, 0, 0, 7]);
        b[64..80].copy_from_slice(&[0x11; 16]);
        let t = cyc();
        for _ in 0..2000 {
            pqsigner_sha256_chain16(b.as_mut_ptr(), 0, 15);
        }
        rec(cyc().wrapping_sub(t), 30_000);
        // v1 wots_chains16 (keygen shape: 43 chains x (PRF + 7 steps)), 50 keys.
        let tail = [0x22u8; 48];
        let mut sa = [0u8; 64];
        sa[..16].copy_from_slice(&[0x5A; 16]);
        sa[32..44].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let t = cyc();
        for _ in 0..50 {
            pqsigner_wots_chains16(sk.as_ptr(), tail.as_ptr(), sa.as_ptr(), core::ptr::null(), core::ptr::null(), 7, 43, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 50 * 43 * 8);
        let _ = (never as unsafe extern "C" fn(*const u8) -> bool, pqsigner_sha256_search128 as unsafe extern "C" fn(*const u8, u32, u32, unsafe extern "C" fn(*const u8) -> bool, *mut u8) -> u32);
    }
    out(1, 100);
}

unsafe extern "C" fn never(p: *const u8) -> bool {
    // A digit-sum-shaped predicate that never holds (sum of the 43 low digits is at most 301).
    let mut s = 0u32;
    for i in 0..16 {
        // SAFETY: the driver passes 32 readable bytes.
        let b = unsafe { *p.add(16 + i) };
        s += u32::from(b & 7) + u32::from((b >> 3) & 7) + u32::from(b >> 6);
    }
    s == 1000
}
