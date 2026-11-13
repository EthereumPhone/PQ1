// Round 13: product sign-chain attribution. A step-for-step mirror of the secure world's
// `c10_sign_verified_with_progress_inner` (secure/src/crypto.rs) — CFI counter, OptRand,
// shuffle seeds, sign A, random delay, sign B, constant-time compare, random delay, verify
// behind the sentinel check, the CFI check, the release copy — with a DWT stamp after each
// phase, averaged over NMSG messages (grind luck). Measurement only: the chain's own verify
// checks every signature, and the result bytes are not otherwise compared.
//
// Not kit-measurable, so stubbed: the OptRand and shuffle-seed draws (`rng_strong::fill`, the
// OPTIGA + SE050 I2C draws; the kit has no secure elements) take fixed bytes; the UI progress
// sink and `ChipWaitTicks` / `busy_poll` are no-ops (the progress calls are counted); the
// random-delay byte comes from an xorshift instead of the TRNG-seeded delay pool.
//
// Result window (32 words at 0x3000_0100): 0 magic 'CHN1', 1 stage (100 = done), 2 keygen
// cycles (the slot-cache miss), 3 chains that returned Ok, 4..16 the mean cycles per chain of
// phases 0..12 (see PHASES), 17 the mean chain total, 18 progress calls per chain, 19 hash
// ticks per chain (tick builds), 20 random-delay iterations per chain.
#![no_std]
use sphincs_c10::{params::SIGNATURE_LEN, shuffle::ShuffleSeed, SigningKey};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

include!("../../inputs.rs");

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
const MAGIC: u32 = 0x4348_4E31; // 'CHN1'
const NMSG: u32 = 16;
const NPH: usize = 13;
// Phases: 0 rate step + CFI, 1 OptRand (stub draw, zero check), 2 shuffle seeds (stub draws,
// zero checks, ShuffleSeed, wipes), 3 sign A, 4 random delay, 5 sign B, 6 ct_eq of the two
// signatures, 7 random delay, 8 verify, 9 the verify sentinel check (two evaluations and a
// delay), 10 the CFI check (sentinel check, delay), 11 delay-source check and OptRand wipe,
// 12 the release copy of the signature out of the chain.

#[no_mangle]
pub static mut SIG0: [u8; SIGNATURE_LEN] = [0; SIGNATURE_LEN];
#[no_mangle]
pub static mut SIG1: [u8; SIGNATURE_LEN] = [0; SIGNATURE_LEN];

extern "C" {
    fn bench_halt(code: u32) -> !;
}
#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: DWT_CYCCNT, enabled by the harness.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
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

static mut TICKS: u32 = 0;
static mut PROGRESS: u32 = 0;
static mut DELAY_ITERS: u32 = 0;

// bench_avg_v1's stubs of the secure world's `pqsigner_hash_tick` -> `film_tick_hash` (ui/px/lcd.rs)
// with a film live; the time-paced frame draw is not modelled.
#[cfg(feature = "tick")]
mod tick {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    static FILM_LIVE: AtomicBool = AtomicBool::new(true);
    static FILM_HASHES: AtomicU32 = AtomicU32::new(0);
    #[inline(never)]
    fn film_tick_paced() {
        core::hint::black_box(());
    }
    #[no_mangle]
    pub extern "C" fn pqsigner_hash_tick() {
        // SAFETY: single-threaded bench counter.
        unsafe { super::TICKS = super::TICKS.wrapping_add(1) };
        if !FILM_LIVE.load(Ordering::Relaxed) {
            return;
        }
        let n = FILM_HASHES.load(Ordering::Relaxed).wrapping_add(1);
        FILM_HASHES.store(n, Ordering::Relaxed);
        if n % 64 == 0 {
            film_tick_paced();
        }
    }
    #[no_mangle]
    pub extern "C" fn pqsigner_hash_tick_n(k: u32) {
        // SAFETY: single-threaded bench counter.
        unsafe { super::TICKS = super::TICKS.wrapping_add(1) };
        if !FILM_LIVE.load(Ordering::Relaxed) {
            return;
        }
        let o = FILM_HASHES.load(Ordering::Relaxed);
        let n = o.wrapping_add(k);
        FILM_HASHES.store(n, Ordering::Relaxed);
        if n / 64 != o / 64 {
            film_tick_paced();
        }
    }
}

// The product passes `progress_halves!(sink)`: two `fn(u8)` items that scale and forward to the
// UI sink. Here the sink only counts.
#[inline(never)]
fn sink(pct: u8) {
    core::hint::black_box(pct);
    // SAFETY: single-threaded bench counter.
    unsafe { PROGRESS = PROGRESS.wrapping_add(1) };
}
fn first_half(pct: u8) {
    sink(pct / 2);
}
fn second_half(pct: u8) {
    sink(50 + pct / 2);
}

// The delay byte (product: the TRNG-seeded delay pool; here an xorshift).
static mut XS: u32 = 0x9E37_79B9;
fn rng_byte() -> u8 {
    // SAFETY: single-threaded bench state.
    unsafe {
        XS ^= XS << 13;
        XS ^= XS >> 17;
        XS ^= XS << 5;
        DELAY_ITERS = DELAY_ITERS.wrapping_add(XS & 0xFF);
        (XS & 0xFF) as u8
    }
}
fn wait_random() {
    let b = rng_byte();
    pqsigner_fi::wait_random_loop(|| b);
}
#[inline(never)]
fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}
#[inline(always)]
fn zeroize_barrier() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cortex_m_dsb();
}
#[inline(always)]
fn cortex_m_dsb() {
    // SAFETY: a barrier only.
    unsafe { core::arch::asm!("dsb sy", options(nomem, nostack, preserves_flags)) };
}

// secure/src/fi.rs `CfiCounter`, verbatim in behaviour.
struct CfiCounter {
    accum: u32,
}
impl CfiCounter {
    const INIT_VALUE: u32 = 0x1357_2468;
    const fn new() -> Self {
        Self { accum: Self::INIT_VALUE }
    }
    #[inline(never)]
    fn bump(&mut self, magic: u32) {
        // SAFETY: a field of `self`.
        unsafe {
            let cur = core::ptr::read_volatile(&self.accum);
            core::ptr::write_volatile(&mut self.accum, cur.wrapping_add(magic));
        }
    }
    #[inline(never)]
    fn check_into_sentinel(&self, expected: u32) -> u32 {
        // SAFETY: a field of `self`.
        let cur = unsafe { core::ptr::read_volatile(&self.accum) };
        check_true_into_sentinel(|| cur == expected)
    }
}
const OK: u32 = pqsigner_fi::OK_SENTINEL;
const S_RATE: u32 = 0x0101_0001;
const S_OPT: u32 = 0x0202_0002;
const S_SHUF: u32 = 0x0303_0003;
const S_SA: u32 = 0x0404_0004;
const S_SB: u32 = 0x0505_0005;
const S_EQ: u32 = 0x0606_0006;
const S_VG: u32 = 0x0707_0007;
const CFI_EXPECTED: u32 = CfiCounter::INIT_VALUE
    .wrapping_add(S_RATE)
    .wrapping_add(S_OPT)
    .wrapping_add(S_SHUF)
    .wrapping_add(S_SA)
    .wrapping_add(S_SB)
    .wrapping_add(S_EQ)
    .wrapping_add(S_VG);

#[inline(never)]
fn chain(sk: &SigningKey, msg_hash: &[u8; 32], seeds: ([u8; 32], [u8; 32]), ph: &mut [u32; NPH]) -> Result<[u8; SIGNATURE_LEN], ()> {
    let mut t = cyc();
    let mut stamp = |k: usize| {
        let n = cyc();
        ph[k] = ph[k].wrapping_add(n.wrapping_sub(t));
        t = n;
    };
    let mut cfi = CfiCounter::new();
    let charge = OK;
    if check_true_into_sentinel(|| core::hint::black_box(charge) == OK) != OK {
        return Err(());
    }
    cfi.bump(S_RATE);
    stamp(0);

    let mut opt_rand_buf = [0u8; sphincs_c10::params::N];
    opt_rand_buf.copy_from_slice(&core::hint::black_box(OPT_RAND));
    let mut acc: u8 = 0;
    for &b in opt_rand_buf.iter() {
        acc |= b;
    }
    if acc == 0 {
        opt_rand_buf.zeroize();
        zeroize_barrier();
        return Err(());
    }
    let opt_rand = Some(&opt_rand_buf);
    cfi.bump(S_OPT);
    stamp(1);

    let mut shuffle_seed_a = core::hint::black_box(seeds.0);
    let mut shuffle_seed_b = core::hint::black_box(seeds.1);
    let (mut acc_a, mut acc_b) = (0u8, 0u8);
    for i in 0..32 {
        acc_a |= shuffle_seed_a[i];
        acc_b |= shuffle_seed_b[i];
    }
    if acc_a == 0 || acc_b == 0 {
        return Err(());
    }
    let shuffle_a = ShuffleSeed(shuffle_seed_a);
    let shuffle_b = ShuffleSeed(shuffle_seed_b);
    shuffle_seed_a.zeroize();
    shuffle_seed_b.zeroize();
    zeroize_barrier();
    cfi.bump(S_SHUF);
    stamp(2);

    let sig_a = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_a, first_half);
    cfi.bump(S_SA);
    stamp(3);
    wait_random();
    stamp(4);
    let sig_b = sk.sign_with_shuffle(msg_hash, opt_rand, &shuffle_b, second_half);
    cfi.bump(S_SB);
    stamp(5);

    if !bool::from(sig_a[..].ct_eq(&sig_b[..])) {
        return Err(());
    }
    cfi.bump(S_EQ);
    stamp(6);
    wait_random();
    stamp(7);
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a);
    stamp(8);
    if check_true_into_sentinel(|| core::hint::black_box(v)) != OK {
        return Err(());
    }
    cfi.bump(S_VG);
    stamp(9);
    if cfi.check_into_sentinel(CFI_EXPECTED) != OK {
        return Err(());
    }
    stamp(10);
    if core::hint::black_box(false) {
        return Err(());
    }
    opt_rand_buf.zeroize();
    zeroize_barrier();
    stamp(11);
    Ok(sig_a)
}

#[cfg(not(feature = "residue"))]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, MAGIC);
    // SAFETY: first HASH use; the harness raised the clock.
    unsafe { pqsigner_hw::hash::init_clock() };
    out(1, 1);
    let t = cyc();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    out(2, cyc().wrapping_sub(t));
    // SAFETY: single-threaded bench counters, reset after keygen.
    unsafe {
        TICKS = 0;
        PROGRESS = 0;
        DELAY_ITERS = 0;
    }
    let mut ph = [0u32; NPH];
    let (mut ok, mut total) = (0u32, 0u64);
    for i in 0..NMSG {
        let mut m = MSG0;
        m[0..4].copy_from_slice(&i.to_le_bytes());
        m[4] ^= 0xA5;
        let mut sa = SHUFFLE_A;
        let mut sb = SHUFFLE_B;
        sa[0] ^= i as u8;
        sb[1] ^= i as u8;
        let t0 = cyc();
        let r = chain(&sk, &m, (sa, sb), &mut ph);
        let t1 = cyc();
        let s = match r {
            Ok(s) => {
                ok += 1;
                s
            }
            Err(()) => [0u8; SIGNATURE_LEN],
        };
        ph[12] = ph[12].wrapping_add(cyc().wrapping_sub(t1));
        total += u64::from(cyc().wrapping_sub(t0));
        // SAFETY: single-threaded; read by the runner after the halt.
        unsafe {
            if i == 0 {
                core::ptr::addr_of_mut!(SIG1).write_volatile(s);
            }
            core::ptr::addr_of_mut!(SIG0).write_volatile(s);
        }
        out(1, 2 + i);
    }
    out(3, ok);
    for (k, v) in ph.iter().enumerate() {
        out(4 + k, v / NMSG);
    }
    out(17, (total / u64::from(NMSG)) as u32);
    // SAFETY: single-threaded bench counters.
    unsafe {
        out(18, PROGRESS / NMSG);
        out(19, TICKS / NMSG);
        out(20, DELAY_ITERS / NMSG);
    }
    out(1, 100);
}

// Round 13 residue mode (`--features residue`): the round-9 dead-stack scan (residue.rs) around the
// product driver entries with secret preimages, as the signer calls them: 0 `oneshot16` on the
// 80-byte `wots_secret` preimage (sk_seed first), 1 `oneshot` on an 80-byte secret-PRF preimage,
// 2 the streaming init / update / final with the key in its own update. Patterns: the secret and
// the digest (a first call gives it), then a second call on a cleared dead stack and the scan.
// The secret buffers are statics, so the scanner never sees them in place. Result: 0 'RES1',
// 1 stage 401, 2 cases, 3 the mask of cases with residue.
#[cfg(feature = "residue")]
include!("../../residue.rs");
#[cfg(feature = "residue")]
extern "C" {
    fn pqsigner_sha256_oneshot16(p: *const u8, n: usize, out: *mut u8);
    fn pqsigner_sha256_oneshot(p: *const u8, n: usize, out: *mut u8);
    fn pqsigner_sha256_init();
    fn pqsigner_sha256_update(p: *const u8, n: usize);
    fn pqsigner_sha256_final(out: *mut u8);
}
/// `res_clear` leaves the 64 bytes just below sp alone, but `res_found` scans them: the bench's own
/// `res_add` frame can leave pattern words there that a shallow driver call never overwrites.
/// Zero them too (interrupts are masked; nothing below sp is live).
#[cfg(feature = "residue")]
#[inline(always)]
fn res_clear_margin() {
    let sp = res_sp();
    let mut a = (sp - 64) & !3;
    while a < sp {
        // SAFETY: secure SRAM below the live stack (bench: interrupts masked).
        unsafe { core::ptr::write_volatile(a as *mut u32, 0) };
        a += 4;
    }
}
/// Diagnostic: the lowest-offset hit, as (sp - address, word).
#[cfg(feature = "residue")]
#[inline(always)]
fn res_first_hit() -> (usize, u32) {
    let sp = res_sp();
    // SAFETY: as `res_found`.
    let n = unsafe { core::ptr::addr_of!(RES_N).read_volatile() };
    // SAFETY: as `res_found`.
    let pats = unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(RES_PATS).cast::<u32>(), n) };
    let mut a = sp - 4;
    while a > sp - RES_DEPTH {
        // SAFETY: as `res_found`.
        let w = u32::from_le_bytes(unsafe { core::ptr::read_volatile(a as *const [u8; 4]) });
        if w != 0 && pats.contains(&w) {
            return (sp - a, w);
        }
        a -= 1;
    }
    (0, 0)
}
/// Positive control (`residue-control`, case 3): copies the key into its own frame and returns,
/// so its dead frame holds the secret: the scan must flag it.
#[cfg(feature = "residue")]
#[inline(never)]
unsafe fn leak(buf: *const u8, d: *mut u8) {
    let mut f = [0u8; 48];
    for (k, b) in f.iter_mut().enumerate() {
        // SAFETY: `buf` names 80 readable bytes.
        *b = unsafe { buf.add(k % 32).read_volatile() };
    }
    // SAFETY: `d` names 32 writable bytes.
    unsafe { d.write_volatile(core::hint::black_box(&f)[0]) };
}
#[cfg(feature = "residue")]
static mut RBUF: [u8; 80] = [0; 80];
#[cfg(feature = "residue")]
static mut RD: [u8; 32] = [0; 32];
#[cfg(feature = "residue")]
#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, 0x5245_5331);
    // SAFETY: single-threaded; keeps the runner's SIG0/SIG1 symbols in the image. First HASH use.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).cast::<u8>().write_volatile(0);
        core::ptr::addr_of_mut!(SIG1).cast::<u8>().write_volatile(0);
        pqsigner_hw::hash::init_clock();
    }
    let mut mask = 0u32;
    let mut sk = [0u8; 32];
    for (i, b) in sk.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(151) ^ 0x6D;
    }
    let ncase = if cfg!(feature = "residue-control") { 4u32 } else { 3 };
    // SAFETY (all calls): the statics are valid for the lengths given; single-threaded bench.
    unsafe {
        let buf = core::ptr::addr_of_mut!(RBUF).cast::<u8>();
        let d = core::ptr::addr_of_mut!(RD).cast::<u8>();
        for case in 0..ncase {
            for k in 0..80 {
                buf.add(k).write_volatile(if k < 32 { sk[k] } else { (k as u8).wrapping_mul(29) ^ case as u8 });
            }
            if case == 0 {
                // wots_secret: sk_seed || "wots" || layer || to_b32(tree) || kp || ci
                for (k, b) in b"wots".iter().enumerate() {
                    buf.add(32 + k).write_volatile(*b);
                }
            }
            let run = || match case {
                0 => pqsigner_sha256_oneshot16(buf, 80, d),
                1 => pqsigner_sha256_oneshot(buf, 80, d),
                3 => leak(buf, d),
                _ => {
                    pqsigner_sha256_init();
                    pqsigner_sha256_update(buf, 32);
                    pqsigner_sha256_update(buf.add(32), 48);
                    pqsigner_sha256_final(d);
                }
            };
            run();
            let mut dig = [0u8; 32];
            for (k, b) in dig.iter_mut().enumerate() {
                *b = d.add(k).read_volatile();
            }
            res_reset();
            res_add(&sk);
            res_add(&dig[..if case == 0 { 16 } else { 32 }]);
            res_clear();
            res_clear_margin();
            run();
            if res_found() {
                mask |= 1 << case;
                if case < 3 {
                    let (off, w) = res_first_hit();
                    out(4 + 2 * case as usize, off as u32);
                    out(5 + 2 * case as usize, w);
                }
            }
        }
    }
    out(2, ncase);
    out(3, mask);
    out(1, 401);
}
