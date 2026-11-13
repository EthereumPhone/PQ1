// GATE 5 (#1155, spec §7): every fused v2 driver entry against software SHA-256
// on the kit, with a v1 digest (NBLW = 0) interleaved between every v2 call so a
// stale NBLW = 24, or any other state left in the HASH peripheral, shows up as a
// wrong v1 digest. Preimages are rebuilt here from the spec (A7 as an integer,
// §1; byte layouts, §2), not from v2hash.rs or the driver.
//
// Result window (32 words at 0x3000_0100): 0 magic 'DRV2', 1 stage (100 = done),
// 2 checks run, 3 checks failed, 4..14 failures per group, 15 first failing
// group, 16 its case index, 17 v1 probes.
#![no_std]
use sha2::{Digest, Sha256};

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
const MAGIC: u32 = 0x4452_5632; // 'DRV2'

extern "C" {
    fn bench_halt(code: u32) -> !;
    fn pqsigner_sha256_oneshot(p: *const u8, n: usize, out: *mut u8);
    fn pqsigner_sha256_init();
    fn pqsigner_sha256_update(p: *const u8, n: usize);
    fn pqsigner_sha256_final(out: *mut u8);
    fn pqsigner_v2_chain16(seed: *const u8, val: *mut u8, a0: u32, low24: u32, start: u32, steps: u32);
    fn pqsigner_v2_prf_chain16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_node16(seed: *const u8, l: *const u8, r: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_fors_leaf16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, a1: u32, out: *mut u8);
    fn pqsigner_v2_wots_chains16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_wots_pk16(sk: *const u8, p0: u32, p1: u32, seed: *const u8, a0: u32, low24: u32, k0: u32, k1: u32, steps: u32, out: *mut u8);
    fn pqsigner_v2_grind_r(prf: *const u8, len: u32, hm: *const u8, start: u32, n: u32, out_r: *mut u8, out_d: *mut u8) -> u32;
    fn pqsigner_v2_fors_subtree16(sk: *const u8, seed: *const u8, p0: u32, p1: u32, a0: u32, a1: u32, j0: u32, h: u32, out: *mut u8);
    fn pqsigner_sha256_chain16(buf: *mut u8, start_pos: u32, steps: u32);
    fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32;
    // v1 entries for the round-11 "v1 entry right after a v2 one" control.
    fn pqsigner_wots_chains16(sk: *const u8, prf_tail: *const u8, seed_adrs: *const u8, order: *const u8, digits: *const u8, fixed_steps: u32, n: u32, out: *mut u8);
    fn pqsigner_fors_subtree16(sk_seed: *const u8, tail: *const u8, leaf_sa: *const u8, node_sa: *const u8, j0: u32, out: *mut u8);
    fn pqsigner_sha256_search128(buf: *const u8, start: u32, n: u32, pred: unsafe extern "C" fn(*const u8) -> bool, out: *mut u8) -> u32;
}

#[inline(always)]
fn out(i: usize, v: u32) {
    // SAFETY: the harness's result window (32 words at OUT).
    unsafe { core::ptr::write_volatile(OUT.add(i), v) }
}
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
// The runner reads these symbols (it refuses an image without them).
#[no_mangle]
pub static mut SIG0: [u8; 4008] = [0; 4008];
#[no_mangle]
pub static mut SIG1: [u8; 4008] = [0; 4008];

struct Rng(u64);
impl Rng {
    fn u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
    fn below(&mut self, n: u32) -> u32 {
        self.u32() % n
    }
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.u32() as u8;
        }
    }
}

struct Tally {
    run: u32,
    fail: u32,
    per: [u32; 11],
}
impl Tally {
    fn check(&mut self, group: usize, case: u32, ok: bool) {
        self.run += 1;
        if !ok {
            if self.fail == 0 {
                out(15, group as u32);
                out(16, case);
            }
            self.fail += 1;
            self.per[group] += 1;
        }
    }
}

// ---- spec model ----------------------------------------------------------------

/// A7 field layout (spec §1). RESEARCH variant `split810`: kp 10 bits at
/// 32..23, ci at 22..17 (format-options check, 2026-11-13).
#[cfg(not(feature = "split810"))]
const KP_BITS: u32 = 9;
#[cfg(feature = "split810")]
const KP_BITS: u32 = 10;
const KP_SHIFT: u32 = 33 - KP_BITS;
const CI_SHIFT: u32 = KP_SHIFT - 6;
/// Random `kp` values cover the whole field.
const KP_RANGE: u32 = 1 << KP_BITS;

/// A7 (spec §1) as an integer; widths checked.
fn a7(ty: u64, layer: u64, tree: u64, kp: u64, ci: u64, cp: u64, ha: u64) -> u64 {
    assert!(ty < 16 && layer < 2 && tree < 1 << 18 && kp < 1 << KP_BITS && ci < 1 << 6 && cp < 16 && ha < 1 << 11);
    ty << 52 | layer << 51 | tree << 33 | kp << KP_SHIFT | ci << CI_SHIFT | cp << 12 | ha << 1
}
fn a7b(a: u64) -> [u8; 7] {
    core::array::from_fn(|k| (a >> (8 * (6 - k))) as u8)
}
/// The two DIN words of A7 in memory order: bytes 0..3, then 4..6 and a zero.
fn words(a: u64) -> (u32, u32) {
    let b = a7b(a);
    (u32::from_le_bytes([b[0], b[1], b[2], b[3]]), u32::from_le_bytes([b[4], b[5], b[6], 0]))
}
fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
fn f(s: &[u8; 16], v: &[u8; 16], a: u64) -> [u8; 16] {
    sha(&[s, v, &a7b(a)])[..16].try_into().unwrap()
}
fn hh(s: &[u8; 16], l: &[u8; 16], r: &[u8; 16], a: u64) -> [u8; 16] {
    sha(&[s, l, r, &a7b(a)])[..16].try_into().unwrap()
}
fn prf(sk: &[u8; 32], a: u64) -> [u8; 16] {
    #[cfg(not(feature = "prf2"))]
    return sha(&[sk, &a7b(a)])[..16].try_into().unwrap();
    // RESEARCH variant `prf2`: the digest over the even index carries index
    // 2j (bytes 0..16) and 2j + 1 (bytes 16..32); the pair bit is ci's LSB for
    // WOTS_PRF (type 5) and ha's LSB for FORS_PRF (type 6).
    #[cfg(feature = "prf2")]
    {
        let bit = match a >> 52 {
            5 => CI_SHIFT,
            6 => 1,
            t => panic!("prf on A7 type {t}"),
        };
        let half = (a >> bit & 1) as usize;
        sha(&[sk, &a7b(a & !(1u64 << bit))])[16 * half..16 * half + 16].try_into().unwrap()
    }
}
fn wd(sm: &[u8; 32], count: u32, a: u64) -> [u8; 32] {
    sha(&[sm, &count.to_be_bytes(), &a7b(a)])
}
/// Σ (D >> 3i) & 7, i < 43, D big-endian (spec 0.3: the low 129 bits).
fn digit_sum(d: &[u8; 32]) -> u32 {
    let bit = |k: usize| u32::from((d[31 - k / 8] >> (k % 8)) & 1);
    (0..43).map(|i| bit(3 * i) | bit(3 * i + 1) << 1 | bit(3 * i + 2) << 2).sum()
}
/// FORS subtree root by recursion (the driver iterates with a stack).
fn subtree(sk: &[u8; 32], s: &[u8; 16], ht: u64, t: u64, j0: u32, h: u32) -> [u8; 16] {
    if h == 0 {
        let x = prf(sk, a7(6, 0, ht, t, 0, 0, u64::from(j0)));
        return f(s, &x, a7(3, 0, ht, t, 0, 0, u64::from(j0)));
    }
    let l = subtree(sk, s, ht, t, j0, h - 1);
    let r = subtree(sk, s, ht, t, j0 + (1 << (h - 1)), h - 1);
    hh(s, &l, &r, a7(3, 0, ht, t, 0, u64::from(h), u64::from(j0 >> h)))
}


include!("../../residue.rs");

/// Round 9 standing gate, v2 side (round-7 asm entries): secrets' patterns first, a cleared
/// dead stack, the call, the scan. Returns (cases, bitmask of cases with residue). Bits:
/// 0 wots_chains16, 1 wots_pk16, 2 prf_chain16, 3 fors_leaf16, 4 fors_subtree16 h=4,
/// 5 fors_subtree16 h=7, 6 chain16 from a secret, 7 grind_r 119 B, 8 grind_r 103 B.
#[cfg(feature = "residue")]
fn residue_suite(rng: &mut Rng) -> (u32, u32) {
    let mut mask = 0u32;
    let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
    rng.fill(&mut sk);
    rng.fill(&mut s);
    let (layer, tree, kp) = (1u64, 0x2_3456u64, u64::from(rng.below(KP_RANGE)));
    let ((p0, p1), (a0, a1), (k0, k1)) =
        (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)), words(a7(1, layer, tree, kp, 0, 0, 0)));
    let mut o = [0u8; 688];
    let key_pats = || {
        res_reset();
        res_add(&sk);
        for ci in 0..43u64 {
            let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
            res_add(&v);
            if ci < 8 {
                for p in 0..6u64 {
                    v = f(&s, &v, a7(0, layer, tree, kp, ci, p, 0));
                    res_add(&v);
                }
            }
        }
    };
    // SAFETY (all calls): valid buffers of the documented sizes; arguments in range.
    unsafe {
        key_pats();
        res_clear();
        pqsigner_v2_wots_chains16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, 7, o.as_mut_ptr());
        if res_found() { mask |= 1 << 0; }
        key_pats();
        res_clear();
        pqsigner_v2_wots_pk16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, k0, k1, 7, o.as_mut_ptr());
        if res_found() { mask |= 1 << 1; }
        // prf_chain16, chain 5, 6 steps.
        let (q0, q1) = words(a7(5, layer, tree, kp, 5, 0, 0));
        let (b0, b1) = words(a7(0, layer, tree, kp, 5, 0, 0));
        res_reset();
        res_add(&sk);
        let mut v = prf(&sk, a7(5, layer, tree, kp, 5, 0, 0));
        res_add(&v);
        for p in 0..5u64 {
            v = f(&s, &v, a7(0, layer, tree, kp, 5, p, 0));
            res_add(&v);
        }
        res_clear();
        pqsigner_v2_prf_chain16(sk.as_ptr(), q0, q1, s.as_ptr(), b0, b1, 6, o.as_mut_ptr());
        if res_found() { mask |= 1 << 2; }
        // FORS: leaf, subtrees of height 4 and 7.
        let (ht, tt) = (0x1_2345u64, 7u64);
        let j = 1234u64;
        let ((f0, f1), (l0, l1)) = (words(a7(6, 0, ht, tt, 0, 0, j)), words(a7(3, 0, ht, tt, 0, 0, j)));
        res_reset();
        res_add(&sk);
        res_add(&prf(&sk, a7(6, 0, ht, tt, 0, 0, j)));
        res_clear();
        pqsigner_v2_fors_leaf16(sk.as_ptr(), f0, f1, s.as_ptr(), l0, l1, o.as_mut_ptr());
        if res_found() { mask |= 1 << 3; }
        let ((g0, g1), (m0, m1)) = (words(a7(6, 0, ht, tt, 0, 0, 0)), words(a7(3, 0, ht, tt, 0, 0, 0)));
        for (bit, h, j0) in [(4u32, 4u32, 16 * 21u32), (5, 7, 128 * 5)] {
            res_reset();
            res_add(&sk);
            for jj in j0..j0 + (1 << h) {
                res_add(&prf(&sk, a7(6, 0, ht, tt, 0, 0, u64::from(jj))));
            }
            res_clear();
            pqsigner_v2_fors_subtree16(sk.as_ptr(), s.as_ptr(), g0, g1, m0, m1, j0, h, o.as_mut_ptr());
            if res_found() { mask |= 1 << bit; }
        }
        // chain16 from a secret start (chain 9), 6 steps.
        let base = a7(0, layer, tree, kp, 9, 0, 0);
        let (c0, c1) = words(base);
        let mut v = prf(&sk, a7(5, layer, tree, kp, 9, 0, 0));
        res_reset();
        let mut w = v;
        res_add(&w);
        for p in 0..5u64 {
            w = f(&s, &w, base | p << 12);
            res_add(&w);
        }
        res_clear();
        pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), c0, c1, 0, 6);
        if res_found() { mask |= 1 << 6; }
        // grind_r: the PRF preimage's sk_seed bytes (0..32) and, at 119 B, rand (39..55).
        for (bit, len) in [(7u32, 119usize), (8, 103)] {
            let (mut pb, mut hb) = ([0u8; 119], [0u8; 87]);
            rng.fill(&mut pb);
            rng.fill(&mut hb);
            pb[..32].copy_from_slice(&sk);
            res_reset();
            res_add(&pb[..32]);
            if len == 119 { res_add(&pb[39..55]); }
            res_clear();
            let (mut gr, mut gd) = ([0u8; 16], [0u8; 32]);
            let _ = pqsigner_v2_grind_r(pb.as_ptr(), len as u32, hb.as_ptr(), 0, 3000, gr.as_mut_ptr(), gd.as_mut_ptr());
            if res_found() { mask |= 1 << bit; }
        }
    }
    (9, mask)
}

/// The v1 count-search predicate for the control: about 1 in 64 (the digest's last byte only).
unsafe extern "C" fn pred_lo6(p: *const u8) -> bool {
    // SAFETY: the driver passes 32 readable bytes.
    unsafe { *p.add(31) & 0x3F == 0 }
}

/// Round 11 control (the coordinator's "a v1 entry right after a v2 one"): run right after every
/// call to the DATATYPE-00 v2 functions (FORS subtree, count search, whole-key loop, pk16). One of
/// the v1 global_asm entries (rotating: whole-key loop, FORS subtree, count search), with input in
/// the shape that selects its asm path, against software SHA-256 from the v1 spec (the
/// bench_v1micro references). A DATATYPE 00, or any other state the v2 asm leaves behind, shows up
/// here as a wrong v1 result. Returns pass/fail.
fn v1_entry_probe(rng: &mut Rng, case: u32) -> bool {
    match case % 3 {
        0 => {
            // v1-asm-key-ga: seed_adrs words 4..7, 11 and 15 zero; fixed steps; no order/digits.
            let (mut sk, mut tail, mut sa) = ([0u8; 32], [0u8; 48], [0u8; 64]);
            rng.fill(&mut sk);
            rng.fill(&mut tail);
            rng.fill(&mut sa);
            for w in [4usize, 5, 6, 7, 11, 15] {
                sa[4 * w..4 * w + 4].fill(0);
            }
            let (steps, n) = (1 + rng.below(7), 3u32);
            let mut o = [0u8; 48];
            // SAFETY: 32, 48 and 64 readable, 48 writable (disjoint from sk); null order/digits.
            unsafe { pqsigner_wots_chains16(sk.as_ptr(), tail.as_ptr(), sa.as_ptr(), core::ptr::null(), core::ptr::null(), steps, n, o.as_mut_ptr()) };
            let mut ok = true;
            for i in 0..n {
                let mut v: [u8; 16] = sha(&[&sk, &tail[..44], &i.to_be_bytes()])[..16].try_into().unwrap();
                let mut c = sa;
                c[52..56].copy_from_slice(&i.to_be_bytes());
                for pos in 0..steps {
                    c[56..60].copy_from_slice(&pos.to_be_bytes());
                    v = sha(&[&c, &v, &[0u8; 16]])[..16].try_into().unwrap();
                }
                ok &= o[16 * i as usize..16 * i as usize + 16] == v;
            }
            ok
        }
        1 => {
            // v1-asm-fors-ga: leaf address words 4..9, 13, 14 zero; node address 4..9, 13 zero.
            let (mut sk, mut tail, mut la, mut na) = ([0u8; 32], [0u8; 16], [0u8; 64], [0u8; 64]);
            rng.fill(&mut sk);
            rng.fill(&mut tail);
            rng.fill(&mut la);
            rng.fill(&mut na);
            for w in [4usize, 5, 6, 7, 8, 9, 13, 14] {
                la[4 * w..4 * w + 4].fill(0);
            }
            for w in [4usize, 5, 6, 7, 8, 9, 13] {
                na[4 * w..4 * w + 4].fill(0);
            }
            let j0 = 16 * rng.below(64);
            let mut o = [0u8; 16];
            // SAFETY: 32, 16, 64 and 64 readable, 16 writable; j0 a multiple of 16.
            unsafe { pqsigner_fors_subtree16(sk.as_ptr(), tail.as_ptr(), la.as_ptr(), na.as_ptr(), j0, o.as_mut_ptr()) };
            let mut st = [[0u8; 16]; 5];
            let mut hs = [0u32; 5];
            let mut sp = 0usize;
            for j in j0..j0 + 16 {
                let sec = sha(&[&sk, &tail[..12], &j.to_be_bytes()]);
                let mut node: [u8; 16] = sha(&[&la[..60], &j.to_be_bytes(), &sec[..16], &[0u8; 16]])[..16].try_into().unwrap();
                let mut ht = 0u32;
                while sp > 0 && hs[sp - 1] == ht {
                    sp -= 1;
                    node = sha(&[&na[..56], &(ht + 1).to_be_bytes(), &(j >> (ht + 1)).to_be_bytes(), &st[sp], &[0u8; 16], &node, &[0u8; 16]])[..16]
                        .try_into()
                        .unwrap();
                    ht += 1;
                }
                st[sp] = node;
                hs[sp] = ht;
                sp += 1;
            }
            o == st[0]
        }
        _ => {
            // v1-asm-search-ga: words 4..7, 9, 11, 13..15 and 20..30 zero; the count is word 31.
            let mut b = [0u8; 128];
            for w in [0usize, 1, 2, 3, 8, 10, 12, 16, 17, 18, 19] {
                let x = rng.u32().to_le_bytes();
                b[4 * w..4 * w + 4].copy_from_slice(&x);
            }
            let start = rng.u32() >> 2;
            let n = if case % 2 == 0 { 100 } else { 5 };
            let mut want = (start + n, [0u8; 32]);
            let mut x = b;
            for c in start..start + n {
                x[124..128].copy_from_slice(&c.to_be_bytes());
                let d = sha(&[&x]);
                if d[31] & 0x3F == 0 {
                    want = (c, d);
                    break;
                }
            }
            let mut d = [0u8; 32];
            // SAFETY: 128 readable, 32 writable bytes.
            let r = unsafe { pqsigner_sha256_search128(b.as_ptr(), start, n, pred_lo6, d.as_mut_ptr()) };
            r == want.0 && (r == start + n || d == want.1)
        }
    }
}

/// A v1-shaped digest (NBLW = 0 for multiples of 4, any length) between v2 calls.
fn v1_probe(rng: &mut Rng, t: &mut Tally, case: u32) {
    let mut buf = [0u8; 200];
    let n = rng.below(201) as usize;
    rng.fill(&mut buf[..n]);
    let mut got = [0u8; 32];
    // SAFETY: `n` readable bytes, 32 writable.
    unsafe { pqsigner_sha256_oneshot(buf.as_ptr(), n, got.as_mut_ptr()) };
    t.check(0, case, got == sha(&[&buf[..n]]));
    if case % 4 == 0 {
        // The streaming API too, in random chunks.
        let mut got = [0u8; 32];
        // SAFETY: as above; chunks stay inside `buf[..n]`.
        unsafe {
            pqsigner_sha256_init();
            let mut o = 0;
            while o < n {
                let k = (rng.below(70) as usize + 1).min(n - o);
                pqsigner_sha256_update(buf.as_ptr().add(o), k);
                o += k;
            }
            pqsigner_sha256_final(got.as_mut_ptr());
        }
        t.check(7, case, got == sha(&[&buf[..n]]));
    }
}

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, MAGIC);
    // SAFETY: single-threaded; keeps the runner's SIG0/SIG1 symbols in the image.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
    }
    // SAFETY: first HASH use; the harness raised the clock.
    unsafe { pqsigner_hw::hash::init_clock() };
    out(1, 1);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    #[cfg(feature = "residue")]
    {
        out(1, 400);
        let (c, m) = residue_suite(&mut rng);
        out(2, c);
        out(3, m);
        out(1, 401);
        return;
    }
    #[allow(unreachable_code)]
    let mut t = Tally { run: 0, fail: 0, per: [0; 11] };
    let mut probe = 0u32;
    macro_rules! between {
        () => {{
            v1_probe(&mut rng, &mut t, probe);
            probe += 1;
        }};
    }
    // Round 11: groups 5..8 (the DATATYPE-00 functions) run a v1 entry first.
    let (mut v1e, mut v1e_fail) = (0u32, 0u32);
    macro_rules! between_e {
        () => {{
            let ok = v1_entry_probe(&mut rng, v1e);
            t.check(0, v1e, ok);
            if !ok {
                v1e_fail += 1;
            }
            v1e += 1;
            between!();
        }};
    }

    // 1. chain16: positions start..start+steps <= 15 (cp is 4 bits; C10 uses < 7).
    out(1, 2);
    for c in 0..200u32 {
        let (mut s, mut v) = ([0u8; 16], [0u8; 16]);
        rng.fill(&mut s);
        rng.fill(&mut v);
        let (layer, tree, kp, ci) = (rng.below(2), rng.below(512), rng.below(KP_RANGE), rng.below(43));
        let start = rng.below(16);
        let steps = rng.below(16 - start + 1);
        let base = a7(0, layer.into(), tree.into(), kp.into(), ci.into(), 0, 0);
        let mut want = v;
        for p in start..start + steps {
            want = f(&s, &want, base | u64::from(p) << 12);
        }
        let (a0, a1) = words(base);
        between!();
        // SAFETY: 16 readable, 16 readable and writable.
        unsafe { pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), a0, a1, start, steps) };
        t.check(1, c, v == want);
    }

    // 2. prf_chain16: secret then its chain from 0.
    out(1, 3);
    for c in 0..100u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (layer, tree, kp, ci) = (u64::from(rng.below(2)), u64::from(rng.below(512)), u64::from(rng.below(KP_RANGE)), u64::from(rng.below(43)));
        let steps = rng.below(8);
        let pa = a7(5, layer, tree, kp, ci, 0, 0);
        let base = a7(0, layer, tree, kp, ci, 0, 0);
        let mut want = prf(&sk, pa);
        for p in 0..steps {
            want = f(&s, &want, base | u64::from(p) << 12);
        }
        let ((p0, p1), (a0, a1)) = (words(pa), words(base));
        let mut got = [0u8; 16];
        between!();
        // SAFETY: 32 and 16 readable, 16 writable.
        unsafe { pqsigner_v2_prf_chain16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, steps, got.as_mut_ptr()) };
        t.check(2, c, got == want);
    }

    // 3. node16 (H): every cp, ha over the whole range, both node types.
    out(1, 4);
    for c in 0..200u32 {
        let (mut s, mut l, mut r) = ([0u8; 16], [0u8; 16], [0u8; 16]);
        rng.fill(&mut s);
        rng.fill(&mut l);
        rng.fill(&mut r);
        let ha = match c % 4 { 0 => 0, 1 => 2047, _ => rng.below(2048) };
        let a = if c % 2 == 0 {
            a7(2, rng.below(2).into(), rng.below(512).into(), 0, 0, u64::from(c % 16), ha.into())
        } else {
            a7(3, 0, rng.below(1 << 18).into(), rng.below(13).into(), 0, u64::from(c % 16), ha.into())
        };
        let (a0, a1) = words(a);
        let mut got = [0u8; 16];
        between!();
        // SAFETY: 16 readable each, 16 writable.
        unsafe { pqsigner_v2_node16(s.as_ptr(), l.as_ptr(), r.as_ptr(), a0, a1, got.as_mut_ptr()) };
        t.check(3, c, got == hh(&s, &l, &r, a));
    }

    // 4. fors_leaf16.
    out(1, 5);
    for c in 0..200u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (ht, tt) = (u64::from(rng.below(1 << 18)), u64::from(rng.below(13)));
        let j = u64::from(match c % 4 { 0 => 0, 1 => 2047, _ => rng.below(2048) });
        let (pa, la) = (a7(6, 0, ht, tt, 0, 0, j), a7(3, 0, ht, tt, 0, 0, j));
        let ((p0, p1), (a0, a1)) = (words(pa), words(la));
        let mut got = [0u8; 16];
        between!();
        // SAFETY: 32 and 16 readable, 16 writable.
        unsafe { pqsigner_v2_fors_leaf16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, got.as_mut_ptr()) };
        t.check(4, c, got == f(&s, &prf(&sk, pa), la));
    }

    // 5. fors_subtree16: every height 0..=11, at the first, the last and a
    //    random aligned position.
    out(1, 6);
    let mut c = 0u32;
    for h in 0..=11u32 {
        let last = 2048 - (1 << h);
        for j0 in [0, last, rng.below(2048 >> h) << h] {
            let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
            rng.fill(&mut sk);
            rng.fill(&mut s);
            let (ht, tt) = (u64::from(rng.below(1 << 18)), u64::from(rng.below(13)));
            let ((p0, p1), (a0, a1)) = (words(a7(6, 0, ht, tt, 0, 0, 0)), words(a7(3, 0, ht, tt, 0, 0, 0)));
            let want = subtree(&sk, &s, ht, tt, j0, h);
            let mut got = [0u8; 16];
            between_e!();
            // SAFETY: 32 and 16 readable, 16 writable; h <= 11, j0 aligned, in range.
            unsafe { pqsigner_v2_fors_subtree16(sk.as_ptr(), s.as_ptr(), p0, p1, a0, a1, j0, h, got.as_mut_ptr()) };
            t.check(5, c, got == want);
            c += 1;
        }
    }

    // 6. search43_target: n = 0; a hit on the first try; a hit on the last of
    //    six with no earlier hit; exhaustion; a start next to u32::MAX.
    out(1, 7);
    let mut c = 0u32;
    for _ in 0..20 {
        let mut sm = [0u8; 32];
        rng.fill(&mut sm);
        let a = a7(7, rng.below(2).into(), rng.below(512).into(), rng.below(KP_RANGE).into(), 0, 0, 0);
        let (a0, a1) = words(a);
        let start = rng.u32() >> 1;
        let mut d = [0xEEu8; 32];
        between_e!();
        // SAFETY: 32 readable, 32 writable; start + n does not overflow.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 0, 205, d.as_mut_ptr()) };
        t.check(6, c, r == start && d == [0xEE; 32]);
        c += 1;

        let w0 = wd(&sm, start, a);
        between_e!();
        // SAFETY: as above.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 9, digit_sum(&w0), d.as_mut_ptr()) };
        t.check(6, c, r == start && d == w0);
        c += 1;

        let sums: [u32; 6] = core::array::from_fn(|i| digit_sum(&wd(&sm, start + i as u32, a)));
        if !sums[..5].contains(&sums[5]) {
            between_e!();
            // SAFETY: as above.
            let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 6, sums[5], d.as_mut_ptr()) };
            t.check(6, c, r == start + 5 && d == wd(&sm, start + 5, a));
            c += 1;
        }

        between_e!();
        // SAFETY: as above (301 = 43 x 7 is the largest digit sum).
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 7, 302, d.as_mut_ptr()) };
        t.check(6, c, r == start + 7);
        c += 1;

        // The real target (205) over a long run, against a software search:
        // exercises the early reject on real digests, not only at the extremes.
        if c < 12 {
            let s0 = rng.u32() >> 2;
            let mut want = None;
            for k in s0..s0 + 150_000 {
                let w = wd(&sm, k, a);
                if digit_sum(&w) == 205 {
                    want = Some((k, w));
                    break;
                }
            }
            if let Some((k, w)) = want {
                between_e!();
                // SAFETY: as above.
                let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, s0, k - s0 + 10, 205, d.as_mut_ptr()) };
                t.check(6, 1000 + c, r == k && d == w);
            }
        }

        let hi = u32::MAX - 16;
        let wh = wd(&sm, hi, a);
        between_e!();
        // SAFETY: as above; hi + 16 does not overflow.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, hi, 16, digit_sum(&wh), d.as_mut_ptr()) };
        t.check(6, c, r == hi && d == wh);
        c += 1;
    }
    between_e!();

    // 6b. Round 7: dense digit-sum sweep, driver search vs software, 96 tries per call.
    //     Targets 140..160 sit near the mean (hits dense, the full-sum path); 180..200
    //     straddle s4 + 77 (both sides of the early reject).
    for _ in 0..6 {
        let mut sm = [0u8; 32];
        rng.fill(&mut sm);
        let a = a7(7, rng.below(2).into(), rng.below(512).into(), rng.below(KP_RANGE).into(), 0, 0, 0);
        let (a0, a1) = words(a);
        let start = rng.u32() >> 1;
        let sums: [u32; 96] = core::array::from_fn(|i| digit_sum(&wd(&sm, start + i as u32, a)));
        for target in (140..=160u32).chain((180..=200u32).step_by(2)) {
            let want = sums.iter().position(|&x| x == target).map_or(start + 96, |i| start + i as u32);
            let mut d = [0xEEu8; 32];
            between_e!();
            // SAFETY: 32 readable, 32 writable; start + 96 does not overflow.
            // `sm` at an odd address: the driver contract is "32 readable bytes", no alignment.
            let mut smo = [0u8; 40];
            smo[1..33].copy_from_slice(&sm);
            // SAFETY: smo[1..33] is readable.
            let r = unsafe { pqsigner_v2_search43_target(smo.as_ptr().add(1), a0, a1, start, 96, target, d.as_mut_ptr()) };
            t.check(6, c, r == want && (r == start + 96 || d == wd(&sm, r, a)));
            c += 1;
        }
    }

    // 7. wots_chains16: a whole key's 43 chains (PRF then `steps` steps each).
    out(1, 8);
    for c in 0..40u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (layer, tree, kp) = (u64::from(rng.below(2)), u64::from(rng.below(1 << 18)), u64::from(rng.below(KP_RANGE)));
        let steps = if c % 2 == 0 { 7 } else { rng.below(16) };
        let mut got = [0u8; 688];
        let ((p0, p1), (a0, a1)) = (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)));
        between_e!();
        // SAFETY: 32 and 16 readable, 688 writable; steps <= 15.
        unsafe { pqsigner_v2_wots_chains16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, steps, got.as_mut_ptr()) };
        let mut ok = true;
        for ci in 0..43u64 {
            let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
            for p in 0..u64::from(steps) {
                v = f(&s, &v, a7(0, layer, tree, kp, ci, p, 0));
            }
            ok &= got[16 * ci as usize..16 * ci as usize + 16] == v;
        }
        t.check(8, c, ok);
    }
    // Round 11: `out == sk_seed` (aliased). The Rust loop's order: chain k's output lands in the
    // buffer before chain k + 1's PRF reads `sk_seed`. Sequential software reference.
    {
        let mut buf = [0u8; 688];
        rng.fill(&mut buf[..32]);
        let mut s = [0u8; 16];
        rng.fill(&mut s);
        let (layer, tree, kp) = (1u64, 0x1_2345u64, u64::from(rng.below(KP_RANGE)));
        let mut want = buf;
        for ci in 0..43u64 {
            let sk: [u8; 32] = want[..32].try_into().unwrap();
            let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
            for p in 0..3u64 {
                v = f(&s, &v, a7(0, layer, tree, kp, ci, p, 0));
            }
            want[16 * ci as usize..16 * ci as usize + 16].copy_from_slice(&v);
        }
        let ((p0, p1), (a0, a1)) = (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)));
        between_e!();
        let bp = buf.as_mut_ptr();
        // SAFETY: one 688-byte buffer serves as `sk_seed` (its first 32 bytes) and as `out`.
        unsafe { pqsigner_v2_wots_chains16(bp, p0, p1, s.as_ptr(), a0, a1, 3, bp) };
        t.check(8, 40, buf == want);
    }
    between_e!();

    // 8. wots_pk16: the whole key, T_43 = S || A7(WOTS_PK) || 0x00 || v_0..v_42.
    out(1, 9);
    for c in 0..40u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (layer, tree, kp) = (u64::from(rng.below(2)), u64::from(rng.below(1 << 18)), u64::from(rng.below(KP_RANGE)));
        let ((p0, p1), (a0, a1), (k0, k1)) =
            (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)), words(a7(1, layer, tree, kp, 0, 0, 0)));
        let mut got = [0u8; 16];
        between_e!();
        // SAFETY: 32 and 16 readable, 16 writable; steps = 7.
        unsafe { pqsigner_v2_wots_pk16(sk.as_ptr(), p0, p1, s.as_ptr(), a0, a1, k0, k1, 7, got.as_mut_ptr()) };
        let mut h = Sha256::new();
        h.update(s);
        h.update(a7b(a7(1, layer, tree, kp, 0, 0, 0)));
        h.update([0u8]);
        for ci in 0..43u64 {
            let mut v = prf(&sk, a7(5, layer, tree, kp, ci, 0, 0));
            for p in 0..7 {
                v = f(&s, &v, a7(0, layer, tree, kp, ci, p, 0));
            }
            h.update(v);
        }
        let want: [u8; 32] = h.finalize().into();
        t.check(9, c, got[..] == want[..16]);
    }
    between_e!();

    // 9. grind_r: the first nonce whose last FORS index is 0, found in software;
    //    a run that stops one try short must report exhaustion.
    out(1, 10);
    let mut c = 0u32;
    for k in 0..6u32 {
        let len = if k % 2 == 0 { 103usize } else { 119 };
        let (mut p, mut h) = ([0u8; 119], [0u8; 87]);
        rng.fill(&mut p);
        rng.fill(&mut h);
        let start = rng.below(1 << 20);
        let sw_try = |nonce: u32, p: &mut [u8; 119], h: &mut [u8; 87]| -> ([u8; 16], [u8; 32]) {
            p[len - 4..len].copy_from_slice(&nonce.to_be_bytes());
            let r: [u8; 16] = sha(&[&p[..len]])[..16].try_into().unwrap();
            h[64..80].copy_from_slice(&r);
            (r, sha(&[&h[..]]))
        };
        let mut hit = None;
        for nonce in start..start + 40_000 {
            let (r, d) = sw_try(nonce, &mut p, &mut h);
            if ((u32::from(d[14]) << 8 | u32::from(d[15])) >> 4) & 0x7FF == 0 {
                hit = Some((nonce, r, d));
                break;
            }
        }
        let Some((nonce, r, d)) = hit else { continue };
        let (mut gr, mut gd) = ([0u8; 16], [0u8; 32]);
        between!();
        // SAFETY: `len` and 87 readable, 16 and 32 writable; no overflow.
        let got = unsafe { pqsigner_v2_grind_r(p.as_ptr(), len as u32, h.as_ptr(), start, nonce - start + 3, gr.as_mut_ptr(), gd.as_mut_ptr()) };
        t.check(10, c, got == nonce && gr == r && gd == d);
        c += 1;
        if nonce > start {
            between!();
            // SAFETY: as above.
            let got = unsafe { pqsigner_v2_grind_r(p.as_ptr(), len as u32, h.as_ptr(), start, nonce - start, gr.as_mut_ptr(), gd.as_mut_ptr()) };
            t.check(10, c, got == nonce);
            c += 1;
        }
    }
    between!();

    out(2, t.run);
    out(3, t.fail);
    for (i, x) in t.per.iter().enumerate() {
        out(4 + i, *x);
    }
    out(17, probe);
    out(18, v1e);
    out(19, v1e_fail);
    out(1, 100);

    #[cfg(feature = "stale")]
    {
        // Round 7 control: a completed digest left uncleared (stale DCIS). The next
        // chain step must refuse it and halt through `pqsigner_hash_fault`.
        out(1, 300);
        // SAFETY: raw secure HASH registers (CR, DIN, STR, SR); one 10-word message.
        unsafe {
            let r = |o: u32| core::ptr::read_volatile((0x520C_0400 + o) as *const u32);
            let w = |o: u32, v: u32| core::ptr::write_volatile((0x520C_0400 + o) as *mut u32, v);
            while r(0x24) & 8 != 0 {}
            w(0x00, (0b10 << 4) | (1 << 17) | (1 << 18) | (1 << 2));
            for i in 0..10u32 {
                w(0x04, i);
            }
            w(0x08, 24 | 1 << 8);
            while r(0x24) & 2 == 0 {}
            #[cfg(feature = "stale-positive")]
            w(0x24, 1);
        }
        let s = [0x5Au8; 16];
        let mut v = [0x11u8; 16];
        #[cfg(not(any(feature = "stale-search", feature = "stale-v1", feature = "stale-v2key", feature = "stale-v2fors", feature = "stale-v2t43")))]
        // SAFETY: valid buffers.
        unsafe { pqsigner_v2_chain16(s.as_ptr(), v.as_mut_ptr(), 0x0102_0304, 0x0000_0500, 0, 3) };
        #[cfg(feature = "stale-v2t43")]
        {
            // Round 12: the T_43 feed's own check before INIT (called directly: in `wots_pk16` the
            // key loop's check would fire first).
            extern "C" {
                fn pq1_v2_t43(src: *const u32, out: *mut u8);
            }
            let m = [0x2D2D_2D2Du32; 178];
            let mut o = [0u8; 16];
            let _ = (&s, &mut v);
            // SAFETY: 178 readable aligned words, 16 writable bytes.
            unsafe { pq1_v2_t43(m.as_ptr(), o.as_mut_ptr()) };
        }
        #[cfg(feature = "stale-v2fors")]
        {
            // Round 11: the v2 subtree's own first-PRF check (its Rust entry waits for BUSY only).
            let sk = [0x6Bu8; 32];
            let mut o = [0u8; 16];
            let _ = &mut v;
            // SAFETY: valid buffers; h = 4, j0 = 16 (aligned, in range).
            unsafe { pqsigner_v2_fors_subtree16(sk.as_ptr(), s.as_ptr(), 0x0102_0304, 0, 0x0102_0305, 0, 16, 4, o.as_mut_ptr()) };
        }
        #[cfg(feature = "stale-v2key")]
        {
            // Round 10: the whole-key loop's own first-PRF check (its Rust entry waits for BUSY only).
            let sk = [0x6Bu8; 32];
            let mut o = [0u8; 688];
            let _ = &mut v;
            // SAFETY: valid buffers.
            unsafe { pqsigner_v2_wots_chains16(sk.as_ptr(), 0x0102_0304, 0, s.as_ptr(), 0x0102_0305, 0, 7, o.as_mut_ptr()) };
        }
        #[cfg(feature = "stale-v1")]
        {
            // v1 WOTS-shaped buffer (the zero words of `chain_core`'s Z path).
            let mut b = [0u8; 96];
            b[..16].copy_from_slice(&[0x5A; 16]);
            b[32..44].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            // SAFETY: 96 readable and writable bytes.
            unsafe { pqsigner_sha256_chain16(b.as_mut_ptr(), 0, 3) };
        }
        #[cfg(feature = "stale-search")]
        {
            let sm = [0x33u8; 32];
            let mut d = [0u8; 32];
            let _ = (&s, &mut v);
            // SAFETY: valid buffers.
            let _ = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), 0x0102_0307, 0, 0, 100, 205, d.as_mut_ptr()) };
        }
        out(1, 301);
    }

    #[cfg(feature = "guard")]
    {
        // Misaligned j0: the driver must halt through `pqsigner_hash_fault`.
        out(1, 200);
        let mut got = [0u8; 16];
        let z = [0u8; 32];
        // SAFETY: valid buffers; the arguments break only the alignment rule.
        unsafe { pqsigner_v2_fors_subtree16(z.as_ptr(), z.as_ptr(), 0, 0, 0, 0, 1, 1, got.as_mut_ptr()) };
        out(1, 201);
    }
}
