//! On-core timing bench (`sign-timing` feature, DVT rows 16.4 and 16.6).
//!
//! Runs once at boot right after `hw::rng::init`, then never returns. Nothing
//! is printed: the host reads the result statics over SWD
//! (`tools/dvt/sign_timing.py`), so the image needs no debugger while it runs.
//!
//! Phase 1 (16.4) is a dudect-style fixed-vs-random Welch test on the core,
//! with interrupts masked and the DWT cycle counter as the clock. Each
//! measurement draws its class from the TRNG; class 0 uses a fixed secret
//! input, class 1 a fresh TRNG one, and every public input is the same in
//! both classes:
//!   0 `fors_secret`, 1 `wots_secret`  (the C10 PRF over `sk_seed`)
//!   2 `pqsigner_domain::slot_entropy` (SHA-256 KDF over the slot master)
//!   3 `hmac_sha512_bytes`             (the BIP-39 → master HMAC, secret msg)
//!   4 `subtle::ct_eq` over 4,008 B    (class 0 equal, class 1 differing)
//!
//! Phase 2 (16.6) times whole `sign_with_shuffle_silent` calls with fresh
//! TRNG `opt_rand`, shuffle and message. Class 0 signs under one fixed key,
//! class 1 under a fresh TRNG `sk_seed` per sign. Keys come from
//! `SigningKey::from_parts` with a TRNG `pk_root`: the signatures do not
//! verify, but every hash has the same length and count as a real sign. Each
//! record carries the cycle count, both layers' WOTS counts read from the
//! signature, and the sign's inputs (test key, message, `opt_rand`) plus the
//! signature's R, so the host can recompute the R-grind iteration count (it
//! is not in the signature) and check it against R.
//!
//! Bench only: random test keys sit in SRAM and timing results are exposed
//! over SWD. No flash, OTP, option-byte or SE access. Never ship.

use core::hint::black_box;
use core::sync::atomic::{AtomicU32, Ordering};

use sphincs_c10::params::{L, N, SIGNATURE_LEN, SIG_FORS_TOTAL, SIG_HT_LAYER};
use sphincs_c10::shuffle::ShuffleSeed;
use sphincs_c10::sim_internals::{fors_secret, wots_secret};
use sphincs_c10::SigningKey;
use subtle::ConstantTimeEq;

pub const PRIMS: usize = 5;
pub const PRIM_ITERS: u32 = 100_000;
pub const MAX_SIGNS: usize = 512;
pub const REC_WORDS: usize = 40;

/// Per primitive, per class: `[n, sum_lo, sum_hi, sumsq_lo, sumsq_hi, min, max, _]`.
/// Plain integer sums so the host computes the statistics exactly.
#[used]
#[no_mangle]
pub static mut SIGN_TIMING_PRIM: [[[u32; 8]; 2]; PRIMS] = [[[0; 8]; 2]; PRIMS];

/// One record per sign. Words: `0` class, `1` cycles, `2`/`3` WOTS count of
/// layer 0/1; then bytes (little-endian words) `sk_seed[32] pk_seed[16]
/// pk_root[16] msg[32] opt_rand[16] R[16]`, then padding.
#[used]
#[no_mangle]
pub static mut SIGN_TIMING_REC: [[u32; REC_WORDS]; MAX_SIGNS] = [[0; REC_WORDS]; MAX_SIGNS];

/// 1 while phase 1 runs, 2 once it is done; the host may read `SIGN_TIMING_PRIM` then.
#[used]
#[no_mangle]
pub static SIGN_TIMING_PHASE: AtomicU32 = AtomicU32::new(0);
/// Signs completed (records valid below this index).
#[used]
#[no_mangle]
pub static SIGN_TIMING_SIGNS: AtomicU32 = AtomicU32::new(0);
/// `rng::fill` calls that returned `Err` (retried, never served).
#[used]
#[no_mangle]
pub static SIGN_TIMING_RNG_ERRS: AtomicU32 = AtomicU32::new(0);

const DEMCR: u32 = 0xE000_EDFC;
const DWT_CTRL: u32 = 0xE000_1000;
const DWT_CYCCNT: u32 = 0xE000_1004;
const DWT_LAR: u32 = 0xE000_1FB0;

fn trng(buf: &mut [u8]) {
    while crate::rng::fill(buf).is_err() {
        SIGN_TIMING_RNG_ERRS.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline(always)]
fn cyccnt() -> u32 {
    // SAFETY: DWT_CYCCNT is a read-only use of the architectural counter;
    // this bench image owns the DWT for its whole run.
    unsafe { crate::hw::mmio::Reg32::new(DWT_CYCCNT) }.read()
}

fn dwt_start() {
    // SAFETY: architectural debug registers; the bench owns them exclusively.
    unsafe {
        crate::hw::mmio::Reg32::new(DEMCR).set_bits(1 << 24); // TRCENA
        crate::hw::mmio::Reg32::new(DWT_LAR).write(0xC5AC_CE55);
        crate::hw::mmio::Reg32::new(DWT_CYCCNT).write(0);
        crate::hw::mmio::Reg32::new(DWT_CTRL).set_bits(1); // CYCCNTENA
    }
}

fn record(prim: usize, class: usize, dt: u32) {
    // SAFETY: single-threaded boot context; the host reads only after PHASE == 2.
    let s = unsafe { &mut (*core::ptr::addr_of_mut!(SIGN_TIMING_PRIM))[prim][class] };
    if s[0] == 0 {
        s[5] = u32::MAX;
    }
    s[0] += 1;
    let sum = (u64::from(s[2]) << 32 | u64::from(s[1])) + u64::from(dt);
    s[1] = sum as u32;
    s[2] = (sum >> 32) as u32;
    let sq = (u64::from(s[4]) << 32 | u64::from(s[3])) + u64::from(dt) * u64::from(dt);
    s[3] = sq as u32;
    s[4] = (sq >> 32) as u32;
    s[5] = s[5].min(dt);
    s[6] = s[6].max(dt);
}

/// Time `f` once with interrupts masked.
#[inline(always)]
fn timed(f: impl FnOnce()) -> u32 {
    cortex_m::interrupt::free(|_| {
        let t0 = cyccnt();
        f();
        cyccnt().wrapping_sub(t0)
    })
}

fn phase1() {
    let mut fixed = [0u8; 64];
    trng(&mut fixed);
    let mut classes = [0u8; 256];
    let mut a = [0u8; SIGNATURE_LEN];
    trng(&mut a);
    let mut b = [0u8; SIGNATURE_LEN];
    for prim in 0..PRIMS {
        let mut i = 0u32;
        while i < PRIM_ITERS {
            if i % 2048 == 0 {
                trng(&mut classes);
            }
            let class = usize::from((classes[(i as usize / 8) % 256] >> (i % 8)) & 1);
            // Both classes run the same code before the timed call: the TRNG
            // fill happens every time and only a constant-time select picks
            // the input. A fill in class 1 only evicts I-cache lines and
            // reads as a class-dependent difference (first run, 10-18).
            let mut fresh = [0u8; 64];
            trng(&mut fresh);
            let mask = 0u8.wrapping_sub(class as u8);
            let mut x = [0u8; 64];
            for k in 0..64 {
                x[k] = (fixed[k] & !mask) | (fresh[k] & mask);
            }
            let flip = black_box(x[2] | 1) & mask;
            let dt = match prim {
                0 => {
                    let sk: [u8; 32] = x[..32].try_into().unwrap();
                    timed(|| {
                        black_box(fors_secret(black_box(&sk), 7, 3, 1234));
                    })
                }
                1 => {
                    let sk: [u8; 32] = x[..32].try_into().unwrap();
                    timed(|| {
                        black_box(wots_secret(black_box(&sk), 1, 0x2A, 77, 9));
                    })
                }
                2 => {
                    let m: [u8; 32] = x[..32].try_into().unwrap();
                    timed(|| {
                        black_box(pqsigner_domain::slot_entropy(black_box(&m), 8453, 3));
                    })
                }
                3 => timed(|| {
                    black_box(pqsigner_domain::hmac_sha512_bytes(b"sphincs-c6-v1", black_box(&x)));
                }),
                _ => {
                    b.copy_from_slice(&a);
                    // Class 1 differs at a TRNG-chosen position (so an early
                    // exit would show); class 0 runs the same xor with 0.
                    let p = usize::from(u16::from_le_bytes([fresh[0], fresh[1]])) % SIGNATURE_LEN;
                    b[p] ^= flip;
                    timed(|| {
                        black_box(black_box(&a[..]).ct_eq(black_box(&b[..])));
                    })
                }
            };
            record(prim, class, dt);
            i += 1;
        }
    }
}

fn wots_count(sig: &[u8; SIGNATURE_LEN], layer: usize) -> u32 {
    let o = SIG_FORS_TOTAL + layer * SIG_HT_LAYER + L * N;
    u32::from_be_bytes([sig[o], sig[o + 1], sig[o + 2], sig[o + 3]])
}

fn phase2() -> ! {
    let mut fixed = [0u8; 32 + 2 * N];
    trng(&mut fixed);
    let mut pk_seed = [0u8; N];
    trng(&mut pk_seed);
    let mut n = 0usize;
    loop {
        let mut cls = [0u8; 1];
        trng(&mut cls);
        let class = u32::from(cls[0] & 1);
        let mut rnd = [0u8; 32 + 2 * N];
        trng(&mut rnd);
        let mask = 0u8.wrapping_sub(class as u8);
        let mut parts = [0u8; 32 + 2 * N];
        for k in 0..parts.len() {
            parts[k] = (fixed[k] & !mask) | (rnd[k] & mask);
        }
        let sk_seed: [u8; 32] = parts[..32].try_into().unwrap();
        let pk_root: [u8; N] = parts[32..32 + N].try_into().unwrap();
        let key = SigningKey::from_parts(sk_seed, pk_seed, pk_root);
        let mut fresh = [0u8; 32 + N + 32];
        trng(&mut fresh);
        let msg: [u8; 32] = fresh[..32].try_into().unwrap();
        let opt: [u8; N] = fresh[32..32 + N].try_into().unwrap();
        let shuffle = ShuffleSeed(fresh[32 + N..].try_into().unwrap());

        let mut sig = [0u8; SIGNATURE_LEN];
        let dt = timed(|| {
            sig = key.sign_with_shuffle_silent(&msg, Some(&opt), &shuffle);
        });
        let mut rec = [0u32; REC_WORDS];
        rec[0] = class;
        rec[1] = dt;
        rec[2] = wots_count(&sig, 0);
        rec[3] = wots_count(&sig, 1);
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&sk_seed);
        bytes[32..48].copy_from_slice(&pk_seed);
        bytes[48..64].copy_from_slice(&pk_root);
        bytes[64..96].copy_from_slice(&msg);
        bytes[96..112].copy_from_slice(&opt);
        bytes[112..128].copy_from_slice(&sig[..N]);
        for (w, c) in rec[4..36].iter_mut().zip(bytes.chunks_exact(4)) {
            *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        // SAFETY: single-threaded; the host reads records below SIGN_TIMING_SIGNS.
        unsafe {
            (*core::ptr::addr_of_mut!(SIGN_TIMING_REC))[n % MAX_SIGNS] = rec;
        }
        n += 1;
        SIGN_TIMING_SIGNS.store(n as u32, Ordering::Release);
    }
}

pub fn run_and_halt() -> ! {
    dwt_start();
    SIGN_TIMING_PHASE.store(1, Ordering::Release);
    phase1();
    SIGN_TIMING_PHASE.store(2, Ordering::Release);
    phase2()
}
