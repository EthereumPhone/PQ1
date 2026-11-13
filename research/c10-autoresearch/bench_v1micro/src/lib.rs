// Round 8 "test zero" for v1 (deployed format): DWT cycles of each v1 driver entry
// in isolation, on fixed inputs, plus raw engine floors for 1-, 2- and 3-block
// messages. Not a gate (bytes are checked by the goldens and the kit differential).
// Result window (0x3000_0100): 0 magic 'MCR1', 1 stage (100 = done), then pairs
// (cycles, count) per measurement from word 2.
#![no_std]

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
extern "C" {
    fn bench_halt(code: u32) -> !;
    fn pqsigner_sha256_chain16(buf: *mut u8, start_pos: u32, steps: u32);
    fn pqsigner_wots_chains16(sk: *const u8, prf_tail: *const u8, seed_adrs: *const u8, order: *const u8, digits: *const u8, fixed_steps: u32, n: u32, out: *mut u8);
    fn pqsigner_fors_subtree16(sk_seed: *const u8, tail: *const u8, leaf_sa: *const u8, node_sa: *const u8, j0: u32, out: *mut u8);
    fn pqsigner_sha256_search128(buf: *const u8, start: u32, n: u32, pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8) -> u32;
    fn pqsigner_th_multi16(seed: *const u8, adrs: *const u8, vals: *const u8, n: u32, out: *mut u8);
    fn pqsigner_sha256_oneshot(ptr: *const u8, len: usize, out: *mut u8);
    fn pqsigner_node16(seed_adrs: *const u8, l: *const u8, r: *const u8, out: *mut u8);
    fn pqsigner_fors_leaf16(sk_seed: *const u8, prf_tail: *const u8, seed_adrs: *const u8, out: *mut u8);
    fn pqsigner_v1_grind_r(sk: *const u8, rand: *const u8, msg: *const u8, seed: *const u8, root: *const u8, max: u32, r_out: *mut u8, d_out: *mut u8) -> u32;
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

const HB: u32 = 0x520C_0400;
#[inline(always)]
unsafe fn hw(off: u32, v: u32) {
    unsafe { core::ptr::write_volatile((HB + off) as *mut u32, v) }
}
#[inline(always)]
unsafe fn hr(off: u32) -> u32 {
    unsafe { core::ptr::read_volatile((HB + off) as *const u32) }
}

/// A tight raw digest of NW whole words (NBLW = 0) with straight-line asm stores of a
/// register constant: BUSY wait, INIT, NW stores, DCAL, tight DCIS poll, HR0..3 (ldm), SR
/// clear. Returns (INIT..DCIS seen).
#[inline(always)]
unsafe fn raw<const NW: usize>(salt: u32) -> u32 {
    unsafe {
        while hr(0x24) & 8 != 0 {}
        hw(0x08, 0);
        let t0 = cyc();
        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        core::arch::asm!(".rept {n}", "str {v}, [{a}]", ".endr", n = const NW, a = in(reg) HB + 4, v = in(reg) salt, options(nostack));
        hw(0x08, 1 << 8);
        while hr(0x24) & 2 == 0 {}
        let t = cyc().wrapping_sub(t0);
        core::arch::asm!("ldm {p}, {{r0, r1, r2, r3}}", p = in(reg) HB + 0x0C, out("r0") _, out("r1") _, out("r2") _, out("r3") _, options(nostack, readonly));
        hw(0x24, 1);
        t
    }
}

/// v1 grind predicate shape (`wots::digit_sum(d) == target`), copied from the signer.
#[inline(always)]
fn digit_sum(digest: &[u8; 32]) -> u32 {
    let mut sum = 0u32;
    for g in 0..5 {
        let lo = 31 - 3 * g;
        let v = digest[lo] as u32 | (digest[lo - 1] as u32) << 8 | (digest[lo - 2] as u32) << 16;
        let s1 = (v & 0o07070707) + ((v >> 3) & 0o07070707);
        let s2 = s1 + (s1 >> 12);
        sum += (s2 & 0o77) + ((s2 >> 6) & 0o77);
    }
    let v = digest[16] as u32 | ((digest[15] & 1) as u32) << 8;
    sum + (v & 7) + ((v >> 3) & 7) + ((v >> 6) & 7)
}
unsafe extern "C" fn pred_false(_p: *const u8) -> bool {
    false
}
unsafe extern "C" fn pred_never(p: *const u8) -> bool {
    // SAFETY: the driver passes 32 readable bytes.
    digit_sum(unsafe { &*p.cast::<[u8; 32]>() }) == 1000
}
unsafe extern "C" fn pred_205(p: *const u8) -> bool {
    // SAFETY: the driver passes 32 readable bytes.
    digit_sum(unsafe { &*p.cast::<[u8; 32]>() }) == 205
}

/// Block-0 window probe: INIT, 16 stores, the 17th (block 0 starts), N dependent ALU ops,
/// then the remaining NW - 17 stores, DCAL, tight DCIS poll. Returns INIT..DCIS.
#[inline(always)]
unsafe fn win<const NW: usize, const N: usize>(salt: u32) -> u32 {
    unsafe {
        while hr(0x24) & 8 != 0 {}
        hw(0x08, 0);
        let t0 = cyc();
        hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
        core::arch::asm!(".rept 17", "str {v}, [{a}]", ".endr",
            ".rept {n}", "add {x}, {x}, #1", ".endr",
            ".rept {m}", "str {v}, [{a}]", ".endr",
            n = const N, m = const NW - 17, a = in(reg) HB + 4, v = in(reg) salt, x = inout(reg) salt => _, options(nostack));
        hw(0x08, 1 << 8);
        while hr(0x24) & 2 == 0 {}
        let t = cyc().wrapping_sub(t0);
        core::arch::asm!("ldm {p}, {{r0, r1, r2, r3}}", p = in(reg) HB + 0x0C, out("r0") _, out("r1") _, out("r2") _, out("r3") _, options(nostack, readonly));
        hw(0x24, 1);
        t
    }
}

macro_rules! winsweep {
    ($nw:literal, $($n:literal),*) => {{
        let mut k = 2usize;
        $(
            let mut s = 0u32;
            for i in 0..256u32 { s += unsafe { win::<$nw, $n>(i) }; }
            out(k, s / 256);
            k += 1;
        )*
        let _ = k;
    }};
}

/// About 1 in 64, and only when the unread head d[0..12] is zero (as the driver passes it).
unsafe extern "C" fn pred64z(p: *const u8) -> bool {
    // SAFETY: the driver passes 32 readable bytes.
    let d = unsafe { &*p.cast::<[u8; 32]>() };
    d[..12].iter().all(|&b| b == 0) && d[31] & 0x3F == 0
}
fn search_check() -> (u32, u32) {
    let mut mb = [0u8; 129];
    for i in 0..16 { mb[1 + i] = (i as u8).wrapping_mul(41) ^ 0xC3; }
    for i in 32..64 { mb[1 + i] = (i as u8).wrapping_mul(23) ^ 0x18; }
    for i in 64..80 { mb[1 + i] = (i as u8).wrapping_mul(71) ^ 0x9E; }
    let b = |mb: &[u8; 129]| -> [u8; 128] { let mut x = [0u8; 128]; x.copy_from_slice(&mb[1..]); x };
    let plain = |c: u32| -> [u8; 32] {
        let mut x = b(&mb);
        x[124..128].copy_from_slice(&c.to_be_bytes());
        let mut d = [0u8; 32];
        // SAFETY: 128 readable, 32 writable bytes.
        unsafe { pqsigner_sha256_oneshot(x.as_ptr(), 128, d.as_mut_ptr()) };
        d
    };
    // Reference: the first hits from 0 (pred64 on the full digest).
    let mut hits = [0u32; 6];
    let (mut k, mut c) = (0usize, 0u32);
    while k < 6 { if plain(c)[31] & 0x3F == 0 { hits[k] = c; k += 1; } c += 1; }
    let reff = |start: u32, n: u32| -> (u32, [u8; 32]) {
        for &h in hits.iter() { if h >= start && h < start + n { return (h, plain(h)); } }
        (start + n, [0u8; 32])
    };
    let (mut checks, mut fails) = (0u32, 0u32);
    let cases: [(u32, u32); 12] = [(hits[0], 1), (hits[0], 2), (hits[0] + 1, 1), (hits[0] + 1, 2), (hits[0] + 1, 3),
        (0, 1 << 16), (hits[1], 1), (hits[1] - 1, 2), (hits[1] - 2, 2), (hits[2] + 1, hits[3] - hits[2] - 1),
        (hits[2] + 1, hits[3] - hits[2]), (hits[4] - 5, 200)];
    for &(start, n) in cases.iter() {
        let (wc, wd) = reff(start, n);
        let mut d = [0u8; 32];
        // SAFETY: 128 readable bytes at an odd address, 32 writable.
        let r = unsafe { pqsigner_sha256_search128(mb.as_ptr().add(1), start, n, pred64z, d.as_mut_ptr()) };
        checks += 1;
        if r != wc || (wc < start + n && d != wd) { fails += 1; }
    }
    (checks, fails)
}

fn grind_check() -> (u32, u32, u32, u32) {
    let (mut checks, mut fails, mut cy, mut nn) = (0u32, 0u32, 0u32, 0u32);
    let mut residue = 0u32;
    for case in 0..4u32 {
        let mut skb = [0u8; 33];
        let mut rb = [0u8; 17];
        let mut mb = [0u8; 33];
        let mut sb = [0u8; 33];
        let mut tb = [0u8; 33];
        for i in 0..32 {
            skb[1 + i] = (i as u8).wrapping_mul(97) ^ case as u8;
            mb[1 + i] = (i as u8).wrapping_mul(31) ^ (3 * case) as u8;
            sb[1 + i] = if i < 16 { (i as u8) ^ 0xA1 } else { 0 };
            tb[1 + i] = if i < 16 { (i as u8).wrapping_mul(5) ^ 0x3E } else { 0 };
        }
        for i in 0..16 { rb[1 + i] = (i as u8).wrapping_mul(13) ^ 0x77 ^ case as u8; }
        let with_rand = case & 1 == 0;
        // Reference: the sign path's own loop through the generic one-shot.
        let mut prf = [0u8; 119];
        prf[..32].copy_from_slice(&skb[1..33]);
        prf[32..39].copy_from_slice(b"R_grind");
        let mut off = 39;
        if with_rand { prf[off..off + 16].copy_from_slice(&rb[1..17]); off += 16; }
        prf[off..off + 32].copy_from_slice(&mb[1..33]);
        off += 32;
        let plen = off + 32;
        let mut hm = [0u8; 160];
        hm[..32].copy_from_slice(&sb[1..33]);
        hm[32..64].copy_from_slice(&tb[1..33]);
        hm[96..128].copy_from_slice(&mb[1..33]);
        hm[128..160].copy_from_slice(&[0xFF; 32]);
        let (mut wn, mut wr, mut wd) = (0u32, [0u8; 16], [0u8; 32]);
        for nonce in 0..100_000u32 {
            prf[off + 28..off + 32].copy_from_slice(&nonce.to_be_bytes());
            let mut r = [0u8; 32];
            // SAFETY: valid buffers.
            unsafe { pqsigner_sha256_oneshot(prf.as_ptr(), plen, r.as_mut_ptr()) };
            hm[64..80].copy_from_slice(&r[..16]);
            let mut d = [0u8; 32];
            // SAFETY: valid buffers.
            unsafe { pqsigner_sha256_oneshot(hm.as_ptr(), 160, d.as_mut_ptr()) };
            let v = u32::from(d[15]) | u32::from(d[14]) << 8;
            if (v >> 4) & 0x7FF == 0 { wn = nonce; wr.copy_from_slice(&r[..16]); wd = d; break; }
        }
        let mut ro = [0u8; 17];
        let mut dout = [0u8; 33];
        // Clear the dead stack first, so the scan below sees only the grind call's residue.
        {
            let sp: usize;
            // SAFETY: reads sp only.
            unsafe { core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
            for a in (sp - 2048)..(sp - 64) {
                // SAFETY: secure SRAM below the live stack, below this frame's own use (64-byte margin).
                unsafe { core::ptr::write_volatile(a as *mut u8, 0) };
            }
        }
        let t = cyc();
        // SAFETY: valid buffers at odd addresses.
        let n = unsafe {
            pqsigner_v1_grind_r(skb.as_ptr().add(1), if with_rand { rb.as_ptr().add(1) } else { core::ptr::null() }, mb.as_ptr().add(1),
                sb.as_ptr().add(1), tb.as_ptr().add(1), 100_000, ro.as_mut_ptr().add(1), dout.as_mut_ptr().add(1))
        };
        cy = cy.wrapping_add(cyc().wrapping_sub(t));
        nn += n + 1;
        checks += 1;
        if n != wn || ro[1..17] != wr || dout[1..33] != wd { fails += 1; }
        // Residue: any 4-byte window of rand or sk_seed in the dead stack below sp (the
        // callee's frame) after the call counts as a failure (one per call at most).
        let sp: usize;
        // SAFETY: reads sp only.
        unsafe { core::arch::asm!("mov {0}, sp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
        let (mut lr_, mut ls_) = (false, false);
        for a in (sp - 2048)..(sp - 4) {
            // SAFETY: secure SRAM below the live stack (bench stack, no interrupts).
            let w: [u8; 4] = unsafe { core::array::from_fn(|i| core::ptr::read_volatile((a + i) as *const u8)) };
            for k in 0..13 {
                if with_rand && w == rb[1 + k..5 + k] { lr_ = true; }
            }
            for k in 0..29 {
                if w == skb[1 + k..5 + k] { ls_ = true; }
            }
        }
        if lr_ { residue |= 1 << case; }
        if ls_ { residue |= 1 << (4 + case); }
        if lr_ || ls_ { fails += 1; }
    }
    (checks, fails, cy, (nn & 0xFF_FFFF) | (residue & 0xFF) << 24)
}

#[cfg(feature = "win")]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x4D43_5257);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    winsweep!(24, 0, 8, 16, 24, 32, 40, 44, 48, 52, 56, 64, 72);
    // 3-block: words 14.. of the window
    {
        let mut k = 14usize;
        for (n, v) in [(0u32, 0u32)].iter() { let _ = (n, v); }
        macro_rules! w3 { ($($n:literal),*) => { $( { let mut s = 0u32; for i in 0..256u32 { s += unsafe { win::<32, $n>(i) }; } out(k, s / 256); k += 1; } )* }; }
        w3!(0, 16, 32, 40, 48, 52, 56, 64);
        let _ = k;
    }
    out(1, 100);
}

#[cfg(not(feature = "win"))]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x4D43_5231);
    // SAFETY: single-threaded; keeps the runner's symbols.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let sk = [0xA5u8; 32];
    let tail = [0x22u8; 48];
    #[cfg(feature = "stale")]
    {
        out(1, 300);
        let mut sa = [0u8; 64];
        sa[..16].copy_from_slice(&[0x5A; 16]);
        let mut o = [0u8; 688];
        // SAFETY: raw secure HASH registers; one 12-word message left uncleared (stale DCIS).
        unsafe {
            while hr(0x24) & 8 != 0 {}
            hw(0x08, 0);
            hw(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
            for i in 0..12u32 {
                hw(0x04, i);
            }
            hw(0x08, 1 << 8);
            while hr(0x24) & 2 == 0 {}
            #[cfg(feature = "stale-positive")]
            hw(0x24, 1);
            #[cfg(feature = "stale-search")]
            {
                let mut sb = [0u8; 128];
                sb[..16].copy_from_slice(&[0x5A; 16]);
                sb[64..80].copy_from_slice(&[0x77; 16]);
                let _ = pqsigner_sha256_search128(sb.as_ptr(), 0, 100, pred_never, o.as_mut_ptr());
            }
            #[cfg(not(any(feature = "stale-fors", feature = "stale-search")))]
            pqsigner_wots_chains16(sk.as_ptr(), tail.as_ptr(), sa.as_ptr(), core::ptr::null(), core::ptr::null(), 7, 43, o.as_mut_ptr());
            #[cfg(feature = "stale-fors")]
            pqsigner_fors_subtree16(sk.as_ptr(), tail.as_ptr(), sa.as_ptr(), sa.as_ptr(), 32, o.as_mut_ptr());
        }
        out(1, 301);
        return;
    }
    let mut sa = [0u8; 64];
    sa[..16].copy_from_slice(&[0x5A; 16]);
    sa[32..44].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    let mut na = sa;
    na[44..48].copy_from_slice(&[0, 0, 0, 3]);
    let mut o = [0u8; 688];
    let mut k = 2usize;
    let mut rec = |c: u32, d: u32| {
        out(k, c);
        out(k + 1, d);
        k += 2;
    };
    // SAFETY (all calls): the buffers above are large enough; arguments in range.
    unsafe {
        // [2,3] wots_chains16 keygen shape: 43 x (PRF + 7 steps), 50 keys -> per digest.
        let t = cyc();
        for _ in 0..50 {
            pqsigner_wots_chains16(sk.as_ptr(), tail.as_ptr(), sa.as_ptr(), core::ptr::null(), core::ptr::null(), 7, 43, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 50 * 43 * 8);
        // [4,5] v1 R grind entry against a one-shot loop, with and without rand, odd addresses:
        // (grinds checked, failures); [18,19] its (cycles, nonces).
        let (gc, gf, gcy, gn) = grind_check();
        rec(gc, gf);
        // [6,7] chain16, 15 steps per call, 2,000 calls.
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
        // [8,9] fors_subtree16, 200 calls -> (cycles, calls); 47 digests per call.
        let ftail = [0x33u8; 16];
        let t = cyc();
        for i in 0..200u32 {
            pqsigner_fors_subtree16(sk.as_ptr(), ftail.as_ptr(), sa.as_ptr(), na.as_ptr(), 16 * i, o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 200);
        // [10,11] search128 correctness on the WOTS shape (odd-address buffer) against a
        // one-shot loop: (checks, failures).
        let (nc, nf) = search_check();
        rec(nc, nf);
        // WOTS-shaped search buffer: seed (zero half), adrs, 16-byte node, zeros.
        let mut sb = [0u8; 128];
        sb[..64].copy_from_slice(&sa);
        sb[64..80].copy_from_slice(&[0x77; 16]);
        let mut d = [0u8; 32];
        let _ = pred_false;
        // [12,13] search128, digit-sum predicate that never holds: 20,000 tries.
        let t = cyc();
        let _ = pqsigner_sha256_search128(sb.as_ptr(), 0, 20_000, pred_never, d.as_mut_ptr());
        rec(cyc().wrapping_sub(t), 20_000);
        // [14,15] search128 with the real target 205: 8 searches, (cycles, tries).
        let (mut cy, mut tries) = (0u32, 0u32);
        for m in 0..8u8 {
            sb[70] = m;
            let t = cyc();
            let r = pqsigner_sha256_search128(sb.as_ptr(), 0, 1 << 22, pred_205, d.as_mut_ptr());
            cy = cy.wrapping_add(cyc().wrapping_sub(t));
            tries += r + 1;
        }
        rec(cy, tries);
        // [16,17] th_multi16 n = 43 (WOTS pk compress), 500 calls.
        let t = cyc();
        for _ in 0..500 {
            pqsigner_th_multi16(sa.as_ptr(), sa.as_ptr().add(32), o.as_ptr(), 43, d.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 500);
        rec(gcy, gn);
        let mut ob = [0x44u8; 160];
        // [20,21] oneshot 160 B (h_msg shape), 2,000 calls.
        let t = cyc();
        for i in 0..2000u32 {
            ob[70] = i as u8;
            pqsigner_sha256_oneshot(ob.as_ptr(), 160, d.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 2000);
        // [22,23] node16, 5,000 calls; [24,25] fors_leaf16, 5,000 calls.
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_node16(na.as_ptr(), o.as_ptr(), o.as_ptr().add(16), o.as_mut_ptr().add(32));
        }
        rec(cyc().wrapping_sub(t), 5000);
        let t = cyc();
        for _ in 0..5000 {
            pqsigner_fors_leaf16(sk.as_ptr(), ftail.as_ptr(), sa.as_ptr(), o.as_mut_ptr());
        }
        rec(cyc().wrapping_sub(t), 5000);
        // [26..31] raw floors, 2,000 digests each: (whole loop cycles, sum INIT..DCIS) for
        // 12 words (1 block), 24 words (2 blocks), 32 words (3 blocks incl. the pad block).
        // [26,27] correctness: wots_chains16 keygen shape (43 chains, steps 1..7) with sk_seed,
        // tail, seed_adrs and out at odd addresses, against software SHA-256: (keys checked,
        // mismatching keys).
        let (mut nk, mut bad) = (0u32, 0u32);
        for steps in 1..8u32 {
            let mut skb = [0u8; 33];
            let mut tb = [0u8; 49];
            let mut sab = [0u8; 65];
            for i in 0..32 { skb[1 + i] = (i as u8).wrapping_mul(29) ^ (steps as u8); }
            for i in 0..48 { tb[1 + i] = (i as u8).wrapping_mul(13) ^ 0x3C; }
            sab[1..17].copy_from_slice(&[0x5A ^ steps as u8; 16]);
            for i in 0..12 { sab[33 + i] = i as u8 + steps as u8; }
            sab[33 + 20..33 + 24].copy_from_slice(&[0, 0, 1, 2]);
            let mut ob = [0u8; 16 * 43 + 1];
            pqsigner_wots_chains16(skb.as_ptr().add(1), tb.as_ptr().add(1), sab.as_ptr().add(1), core::ptr::null(), core::ptr::null(), steps, 43, ob.as_mut_ptr().add(1));
            let mut ok = true;
            for i in 0..43u32 {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(&skb[1..33]);
                h.update(&tb[1..45]);
                h.update(i.to_be_bytes());
                let d = h.finalize();
                let mut v = [0u8; 16];
                v.copy_from_slice(&d[..16]);
                let mut c = [0u8; 64];
                c.copy_from_slice(&sab[1..65]);
                c[52..56].copy_from_slice(&i.to_be_bytes());
                for pos in 0..steps {
                    c[56..60].copy_from_slice(&pos.to_be_bytes());
                    let mut h = Sha256::new();
                    h.update(c);
                    h.update(v);
                    h.update([0u8; 16]);
                    let d = h.finalize();
                    v.copy_from_slice(&d[..16]);
                }
                if ob[1 + 16 * i as usize..1 + 16 * i as usize + 16] != v { ok = false; }
            }
            nk += 1;
            if !ok { bad += 1; }
        }
        // Aliased case (out == sk_seed, n = 2, steps 1): the Rust loop's order (chain 0's output
        // overwrites sk_seed[0..16] before chain 1's PRF) must hold.
        {
            use sha2::{Digest, Sha256};
            let mut kb = [0u8; 33];
            for i in 0..32 { kb[1 + i] = (i as u8) ^ 0x93; }
            let tb = [0x4Bu8; 48];
            let mut sab = [0u8; 64];
            sab[..16].copy_from_slice(&[0x21; 16]);
            let mut refk = [0u8; 32];
            refk.copy_from_slice(&kb[1..33]);
            let mut want = [0u8; 32];
            for i in 0..2u32 {
                let mut h = Sha256::new();
                h.update(refk);
                h.update(&tb[..44]);
                h.update(i.to_be_bytes());
                let d = h.finalize();
                let mut c = sab;
                c[52..56].copy_from_slice(&i.to_be_bytes());
                let mut h = Sha256::new();
                h.update(c);
                h.update(&d[..16]);
                h.update([0u8; 16]);
                let d = h.finalize();
                want[16 * i as usize..16 * i as usize + 16].copy_from_slice(&d[..16]);
                refk[16 * i as usize..16 * i as usize + 16].copy_from_slice(&d[..16]);
            }
            let p = kb.as_mut_ptr().add(1);
            pqsigner_wots_chains16(p, tb.as_ptr(), sab.as_ptr(), core::ptr::null(), core::ptr::null(), 1, 2, p);
            nk += 1;
            if kb[1..33] != want { bad += 1; }
        }
        rec(nk, bad);
        // [28,29] correctness: fors_subtree16 with sk_seed, tail, leaf_sa, node_sa and out at odd
        // addresses, against software SHA-256: (subtrees checked, mismatching subtrees).
        let (mut ns, mut bad) = (0u32, 0u32);
        for case in 0..4u32 {
            use sha2::{Digest, Sha256};
            let mut skb = [0u8; 33];
            let mut tb = [0u8; 17];
            let mut lab = [0u8; 65];
            let mut nab = [0u8; 65];
            for i in 0..32 { skb[1 + i] = (i as u8).wrapping_mul(53) ^ case as u8; }
            for i in 0..12 { tb[1 + i] = (i as u8).wrapping_mul(7) ^ 0x66; }
            for i in 0..60 { lab[1 + i] = (i as u8).wrapping_mul(11) ^ case as u8; }
            for i in 0..56 { nab[1 + i] = (i as u8).wrapping_mul(19) ^ 0x2D; }
            let j0 = 16 * (case * 37 + 3);
            let mut ob = [0u8; 17];
            pqsigner_fors_subtree16(skb.as_ptr().add(1), tb.as_ptr().add(1), lab.as_ptr().add(1), nab.as_ptr().add(1), j0, ob.as_mut_ptr().add(1));
            let mut st = [[0u8; 16]; 5];
            let mut hs = [0u32; 5];
            let mut sp = 0usize;
            for j in j0..j0 + 16 {
                let mut h = Sha256::new();
                h.update(&skb[1..33]);
                h.update(&tb[1..13]);
                h.update(j.to_be_bytes());
                let sec = h.finalize();
                let mut h = Sha256::new();
                h.update(&lab[1..61]);
                h.update(j.to_be_bytes());
                h.update(&sec[..16]);
                h.update([0u8; 16]);
                let d = h.finalize();
                let mut node = [0u8; 16];
                node.copy_from_slice(&d[..16]);
                let mut ht = 0u32;
                while sp > 0 && hs[sp - 1] == ht {
                    sp -= 1;
                    let mut h = Sha256::new();
                    h.update(&nab[1..57]);
                    h.update((ht + 1).to_be_bytes());
                    h.update((j >> (ht + 1)).to_be_bytes());
                    h.update(st[sp]);
                    h.update([0u8; 16]);
                    h.update(node);
                    h.update([0u8; 16]);
                    let d = h.finalize();
                    node.copy_from_slice(&d[..16]);
                    ht += 1;
                }
                st[sp] = node;
                hs[sp] = ht;
                sp += 1;
            }
            ns += 1;
            if ob[1..17] != st[0] { bad += 1; }
        }
        rec(ns, bad);
        let mut s = 0u32;
        let t = cyc();
        for i in 0..2000u32 { s += raw::<32>(i); }
        rec(cyc().wrapping_sub(t), s);
    }
    out(1, 100);
}
