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

/// Round 11 probe: one digest of `msg` with DATATYPE 00 (32-bit words, no swap): each DIN word is
/// the big-endian value of four message bytes, the last partial word holds its bytes in the top
/// bits, and NBLW = 8 x (len % 4) is written before DCAL (then NBLW | DCAL, as the driver does).
/// Returns the eight HR words as digest bytes.
#[cfg(any(feature = "nblw32", feature = "t43"))]
fn dt32_digest(msg: &[u8]) -> [u8; 32] {
    unsafe {
        while hr(0x24) & 8 != 0 {}
        hw(0x08, 0);
        hw(0x00, (0b00 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        let full = msg.len() / 4;
        for k in 0..full {
            hw(0x04, u32::from_be_bytes([msg[4 * k], msg[4 * k + 1], msg[4 * k + 2], msg[4 * k + 3]]));
        }
        let r = msg.len() % 4;
        if r != 0 {
            let mut b = [0u8; 4];
            b[..r].copy_from_slice(&msg[4 * full..]);
            hw(0x04, u32::from_be_bytes(b));
        }
        let nblw = 8 * r as u32;
        hw(0x08, nblw);
        hw(0x08, nblw | 1 << 8);
        while hr(0x24) & 2 == 0 {}
        let mut d = [0u8; 32];
        for k in 0..8u32 {
            d[4 * k as usize..4 * k as usize + 4].copy_from_slice(&hr(0x310 + 4 * k).to_be_bytes());
        }
        hw(0x24, 1);
        d
    }
}

#[cfg(feature = "nblw32")]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    use sha2::{Digest, Sha256};
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x4E42_4C57);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let mut x: u32 = 0x2545_F491;
    let mut rnd = || { x ^= x << 13; x ^= x >> 17; x ^= x << 5; x as u8 };
    // [2..10): (checks, fails) per NBLW 0, 8, 16, 24; every length 0..=160, 4 messages each,
    // then 400 messages of each v2 shape (39, 43, 55 bytes).
    let mut cnt = [[0u32; 2]; 4];
    let mut msg = [0u8; 160];
    for len in 0..=160usize {
        for _ in 0..4 {
            for b in msg[..len].iter_mut() { *b = rnd(); }
            let want: [u8; 32] = Sha256::digest(&msg[..len]).into();
            let got = dt32_digest(&msg[..len]);
            let c = len % 4;
            cnt[c][0] += 1;
            if got != want { cnt[c][1] += 1; }
        }
    }
    for len in [39usize, 43, 55] {
        for _ in 0..400 {
            for b in msg[..len].iter_mut() { *b = rnd(); }
            let want: [u8; 32] = Sha256::digest(&msg[..len]).into();
            let got = dt32_digest(&msg[..len]);
            cnt[3][0] += 1;
            if got != want { cnt[3][1] += 1; }
        }
    }
    for (k, c) in cnt.iter().enumerate() {
        out(2 + 2 * k, c[0]);
        out(3 + 2 * k, c[1]);
    }
    // [10, 11]: a byte-data (DATATYPE 10) one-shot right after, against software (the per-digest
    // CR write must leave no 32-bit mode behind).
    let mut fails = 0u32;
    for len in [0usize, 39, 64, 96, 128, 155] {
        for b in msg[..len].iter_mut() { *b = rnd(); }
        let want: [u8; 32] = Sha256::digest(&msg[..len]).into();
        let _ = dt32_digest(&msg[..39]);
        let mut d = [0u8; 32];
        // SAFETY: `len` readable, 32 writable bytes.
        unsafe { pqsigner_sha256_oneshot_ext(msg.as_ptr(), len, d.as_mut_ptr()) };
        if d != want { fails += 1; }
    }
    out(10, 6);
    out(11, fails);
    out(1, 100);
}

#[cfg(feature = "nblw32")]
extern "C" {
    #[link_name = "pqsigner_sha256_oneshot"]
    fn pqsigner_sha256_oneshot_ext(p: *const u8, n: usize, out: *mut u8);
}

#[cfg(not(any(feature = "nblw32", feature = "t43")))]
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

// Round 12: the T_43 one-shot (wots_pk16's 712-byte compression) — timing of the current
// `oneshot16` call against tight feeds in DATATYPE 10 (memory words as loaded) and 00 (each word
// byte-swapped), all compared with `oneshot16`'s 16 bytes; then the multi-block DATATYPE 00 probe
// (every length 640..=776, i.e. every NBLW across the 712-byte shape's block boundaries, and 200
// random 712-byte messages) against software SHA-256, each followed by a byte-data one-shot.
// Result window: 2 cycles/call oneshot16, 3 feed10, 4 feed00, 5 feed00 with `rev` in the store
// (as an asm feed would), 6 mismatches of the three feeds vs oneshot16, [8..16) (checks, fails)
// per NBLW 0/8/16/24, 16 (checks, 17 fails) of the byte one-shot after a 32-bit digest.
#[cfg(feature = "t43")]
extern "C" {
    #[link_name = "pqsigner_sha256_oneshot16"]
    fn oneshot16_ext(p: *const u8, n: usize, out: *mut u8);
}
#[cfg(feature = "t43")]
#[inline(always)]
unsafe fn t43_feed<const SWAP: bool>(words: &[u32; 178]) -> [u32; 4] {
    unsafe {
        while hr(0x24) & 8 != 0 {}
        if hr(0x24) & 2 != 0 {
            bench_halt(0x00F2);
        }
        hw(0x08, 0);
        hw(0x00, if SWAP { 0 } else { 0b10 << 4 } | (1 << 17) | (1 << 18) | (1 << 2));
        for w in words.iter() {
            hw(0x04, if SWAP { w.swap_bytes() } else { *w });
        }
        hw(0x08, 1 << 8);
        while hr(0x24) & 2 == 0 {}
        let r = [hr(0x310), hr(0x314), hr(0x318), hr(0x31C)];
        hw(0x24, 1);
        r
    }
}
#[cfg(feature = "t43")]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    use sha2::{Digest, Sha256};
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x5434_3332);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let mut x: u32 = 0x2545_F491;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let mut buf = [0u32; 178];
    for w in buf.iter_mut() {
        *w = rnd();
    }
    let bytes = |b: &[u32; 178]| -> [u8; 712] {
        let mut o = [0u8; 712];
        for (k, w) in b.iter().enumerate() {
            o[4 * k..4 * k + 4].copy_from_slice(&w.to_le_bytes());
        }
        o
    };
    let mut d16 = [0u8; 16];
    const N: u32 = 2000;
    // SAFETY: 712 readable, 16 writable bytes.
    let t = cyc();
    for _ in 0..N {
        unsafe { oneshot16_ext(buf.as_ptr().cast::<u8>(), 712, d16.as_mut_ptr()) };
    }
    out(2, cyc().wrapping_sub(t) / N);
    let want: [u8; 16] = Sha256::digest(bytes(&buf))[..16].try_into().unwrap();
    let mut bad = u32::from(d16 != want);
    let as16 = |r: [u32; 4]| -> [u8; 16] {
        let mut o = [0u8; 16];
        for (k, w) in r.iter().enumerate() {
            o[4 * k..4 * k + 4].copy_from_slice(&w.to_be_bytes());
        }
        o
    };
    let mut r = [0u32; 4];
    let t = cyc();
    for _ in 0..N {
        r = unsafe { t43_feed::<false>(&buf) };
    }
    out(3, cyc().wrapping_sub(t) / N);
    bad += u32::from(as16(r) != want) << 1;
    let t = cyc();
    for _ in 0..N {
        r = unsafe { t43_feed::<true>(&buf) };
    }
    out(4, cyc().wrapping_sub(t) / N);
    bad += u32::from(as16(r) != want) << 2;
    out(5, 0);
    out(6, bad);
    // The multi-block DATATYPE 00 probe.
    let mut cnt = [[0u32; 2]; 4];
    let mut msg = [0u8; 776];
    for len in 640..=776usize {
        for _ in 0..2 {
            for b in msg[..len].iter_mut() {
                *b = rnd() as u8;
            }
            let want: [u8; 32] = Sha256::digest(&msg[..len]).into();
            let c = len % 4;
            cnt[c][0] += 1;
            if dt32_digest(&msg[..len]) != want {
                cnt[c][1] += 1;
            }
        }
    }
    for _ in 0..200 {
        for b in msg[..712].iter_mut() {
            *b = rnd() as u8;
        }
        let want: [u8; 32] = Sha256::digest(&msg[..712]).into();
        cnt[0][0] += 1;
        if dt32_digest(&msg[..712]) != want {
            cnt[0][1] += 1;
        }
    }
    for (k, c) in cnt.iter().enumerate() {
        out(8 + 2 * k, c[0]);
        out(9 + 2 * k, c[1]);
    }
    let mut fails = 0u32;
    for len in [0usize, 55, 64, 712, 713, 776] {
        for b in msg[..len].iter_mut() {
            *b = rnd() as u8;
        }
        let want: [u8; 16] = Sha256::digest(&msg[..len])[..16].try_into().unwrap();
        let _ = dt32_digest(&msg[..701]);
        let mut d = [0u8; 16];
        // SAFETY: `len` readable, 16 writable bytes.
        unsafe { oneshot16_ext(msg.as_ptr(), len, d.as_mut_ptr()) };
        if d != want {
            fails += 1;
        }
    }
    out(16, 6);
    out(17, fails);
    out(1, 100);
}
