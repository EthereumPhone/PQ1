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
    fn pqsigner_v2_search43_target(sm: *const u8, a0: u32, a1: u32, start: u32, n: u32, target: u32, out: *mut u8) -> u32;
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

/// A7 (spec §1) as an integer; widths checked.
fn a7(ty: u64, layer: u64, tree: u64, kp: u64, ci: u64, cp: u64, ha: u64) -> u64 {
    assert!(ty < 16 && layer < 2 && tree < 1 << 18 && kp < 1 << 9 && ci < 1 << 6 && cp < 16 && ha < 1 << 11);
    ty << 52 | layer << 51 | tree << 33 | kp << 24 | ci << 18 | cp << 12 | ha << 1
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
    sha(&[sk, &a7b(a)])[..16].try_into().unwrap()
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
    let mut t = Tally { run: 0, fail: 0, per: [0; 11] };
    let mut probe = 0u32;
    macro_rules! between {
        () => {{
            v1_probe(&mut rng, &mut t, probe);
            probe += 1;
        }};
    }

    // 1. chain16: positions start..start+steps <= 15 (cp is 4 bits; C10 uses < 7).
    out(1, 2);
    for c in 0..200u32 {
        let (mut s, mut v) = ([0u8; 16], [0u8; 16]);
        rng.fill(&mut s);
        rng.fill(&mut v);
        let (layer, tree, kp, ci) = (rng.below(2), rng.below(512), rng.below(512), rng.below(43));
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
        let (layer, tree, kp, ci) = (u64::from(rng.below(2)), u64::from(rng.below(512)), u64::from(rng.below(512)), u64::from(rng.below(43)));
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
            between!();
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
        let a = a7(7, rng.below(2).into(), rng.below(512).into(), rng.below(512).into(), 0, 0, 0);
        let (a0, a1) = words(a);
        let start = rng.u32() >> 1;
        let mut d = [0xEEu8; 32];
        between!();
        // SAFETY: 32 readable, 32 writable; start + n does not overflow.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 0, 205, d.as_mut_ptr()) };
        t.check(6, c, r == start && d == [0xEE; 32]);
        c += 1;

        let w0 = wd(&sm, start, a);
        between!();
        // SAFETY: as above.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 9, digit_sum(&w0), d.as_mut_ptr()) };
        t.check(6, c, r == start && d == w0);
        c += 1;

        let sums: [u32; 6] = core::array::from_fn(|i| digit_sum(&wd(&sm, start + i as u32, a)));
        if !sums[..5].contains(&sums[5]) {
            between!();
            // SAFETY: as above.
            let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, start, 6, sums[5], d.as_mut_ptr()) };
            t.check(6, c, r == start + 5 && d == wd(&sm, start + 5, a));
            c += 1;
        }

        between!();
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
                between!();
                // SAFETY: as above.
                let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, s0, k - s0 + 10, 205, d.as_mut_ptr()) };
                t.check(6, 1000 + c, r == k && d == w);
            }
        }

        let hi = u32::MAX - 16;
        let wh = wd(&sm, hi, a);
        between!();
        // SAFETY: as above; hi + 16 does not overflow.
        let r = unsafe { pqsigner_v2_search43_target(sm.as_ptr(), a0, a1, hi, 16, digit_sum(&wh), d.as_mut_ptr()) };
        t.check(6, c, r == hi && d == wh);
        c += 1;
    }
    between!();

    // 7. wots_chains16: a whole key's 43 chains (PRF then `steps` steps each).
    out(1, 8);
    for c in 0..40u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (layer, tree, kp) = (u64::from(rng.below(2)), u64::from(rng.below(1 << 18)), u64::from(rng.below(512)));
        let steps = if c % 2 == 0 { 7 } else { rng.below(16) };
        let mut got = [0u8; 688];
        let ((p0, p1), (a0, a1)) = (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)));
        between!();
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
    between!();

    // 8. wots_pk16: the whole key, T_43 = S || A7(WOTS_PK) || 0x00 || v_0..v_42.
    out(1, 9);
    for c in 0..40u32 {
        let (mut sk, mut s) = ([0u8; 32], [0u8; 16]);
        rng.fill(&mut sk);
        rng.fill(&mut s);
        let (layer, tree, kp) = (u64::from(rng.below(2)), u64::from(rng.below(1 << 18)), u64::from(rng.below(512)));
        let ((p0, p1), (a0, a1), (k0, k1)) =
            (words(a7(5, layer, tree, kp, 0, 0, 0)), words(a7(0, layer, tree, kp, 0, 0, 0)), words(a7(1, layer, tree, kp, 0, 0, 0)));
        let mut got = [0u8; 16];
        between!();
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
    between!();

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
    out(1, 100);

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
