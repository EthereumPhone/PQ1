//! Masked-SHA-256 overhead bench (`bench-masked-sha` feature).
//!
//! Answers the §18 SHAKE-vs-SHA2 question's #2 measurement: "how much
//! slower is a first-order-masked SHA-256 than the STM32U585 HASH
//! peripheral?" Per the advisor-reviewed plan we DON'T build a full
//! masked SHA-256 (correctness-risk + code volume); instead we measure
//! the two masked gates that dominate the cost and project the
//! per-block number from SHA-256's fixed structure
//! (`masked_sha2::{ADDS_PER_BLOCK, ANDS_PER_BLOCK}`).
//!
//! Runs once at boot under DWT cycle counting, streams results over
//! semihosting, then halts. Build + run via `make bench-masked-sha-hw`.
//!
//! Each masked gate is measured TWO ways:
//!   * **TRNG-inline** — fresh randomness drawn from the hardware TRNG
//!     inside the timed loop. The conservative production number IF
//!     masks come straight from the TRNG.
//!   * **rand-pre-drawn** — randomness drawn once outside the loop and
//!     reused (NOT cryptographically valid — measures pure gate logic).
//!     A lower bound for a DRBG-fed production variant (Trezor's
//!     ChaCha-DRBG pattern), where per-call RNG cost is ~free.
//!
//! The two bracket the real cost depending on the RNG strategy; the
//! standalone TRNG-draw measurement shows how much of the gap is RNG.

use cortex_m_semihosting::hprintln;
use masked_sha2::{
    mask, sec_add, sec_and, Share, ADDS_PER_BLOCK, ANDS_PER_BLOCK, SEC_ADD_RANDS,
};

// Cortex-M33 DWT / DEMCR registers (core debug block, always accessible
// to secure code). The production main() enables these right before NS
// boot; this bench short-circuits earlier so it arms them itself.
const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;
const DWT_LAR: *mut u32 = 0xE000_1FB0 as *mut u32;

const CPU_HZ: u32 = 160_000_000;
const ITERS: u32 = 20_000;

#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: plain read of the free-running DWT cycle counter.
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

unsafe fn enable_dwt() {
    // TRCENA in DEMCR enables the trace/DWT unit; DWT_LAR unlocks write
    // access on TrustZone parts; reset + enable the free-running counter.
    core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | (1 << 24));
    core::ptr::write_volatile(DWT_LAR, 0xC5AC_CE55);
    core::ptr::write_volatile(DWT_CYCCNT, 0);
    core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 1);
}

/// Draw one TRNG word (4 bytes). Falls back to a fixed value on RNG
/// fault — a bench, not a security path.
#[inline(always)]
fn rng_word() -> u32 {
    let mut b = [0u8; 4];
    let _ = crate::rng::fill(&mut b);
    u32::from_le_bytes(b)
}

#[inline(always)]
fn rng_add_rands() -> [u32; SEC_ADD_RANDS] {
    let mut r = [0u32; SEC_ADD_RANDS];
    for w in r.iter_mut() {
        *w = rng_word();
    }
    r
}

/// `(end − start) / ITERS`, the per-iteration cycle cost.
#[inline]
fn per_iter(start: u32, end: u32) -> u32 {
    end.wrapping_sub(start) / ITERS
}

pub fn run_and_halt() -> ! {
    // SAFETY: arming the core DWT counter — plain MMIO writes to the
    // debug block, single-threaded boot context.
    unsafe {
        enable_dwt();
    }

    hprintln!(
        "[BENCH] masked-sha2 overhead @ {} MHz, {} iters/measurement",
        CPU_HZ / 1_000_000,
        ITERS
    );

    // ---- Baseline 1: HASH peripheral, exactly ONE compression --------
    // A 55-byte input is the largest that hashes in a single 512-bit
    // block (55 + 1 padding byte + 8 length bytes = 64), so this is one
    // compression — apples-to-apples with the per-block projection.
    let input = [0xA5u8; 55];
    let mut out = [0u8; 32];
    let t0 = cyc();
    for _ in 0..ITERS {
        // SAFETY: category-3 FFI symbols; single SHA-256 stream in
        // flight, init→update→final ordering respected.
        unsafe {
            crate::hw::hash::pqsigner_sha256_init();
            crate::hw::hash::pqsigner_sha256_update(input.as_ptr(), input.len());
            crate::hw::hash::pqsigner_sha256_final(out.as_mut_ptr());
        }
        core::hint::black_box(&out);
    }
    let hw_block = per_iter(t0, cyc());
    hprintln!("[BENCH] HASH peripheral  1-block : {} cyc", hw_block);

    // ---- Baseline 2: sha2 software, exactly ONE compression ----------
    let t0 = cyc();
    for _ in 0..ITERS {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(core::hint::black_box(&input));
        core::hint::black_box(&d);
    }
    let sw_block = per_iter(t0, cyc());
    hprintln!("[BENCH] sha2 software    1-block : {} cyc", sw_block);

    // ---- TRNG draw cost (to separate RNG from gate logic) ------------
    let t0 = cyc();
    for _ in 0..ITERS {
        core::hint::black_box(rng_word());
    }
    let trng_word = per_iter(t0, cyc());
    hprintln!("[BENCH] TRNG draw        1 word  : {} cyc", trng_word);

    // ---- sec_and: TRNG-inline (conservative) -------------------------
    let a: Share = mask(core::hint::black_box(0x1234_5678), rng_word());
    let b: Share = mask(core::hint::black_box(0x9ABC_DEF0), rng_word());
    let mut acc: Share = [0, 0];
    let t0 = cyc();
    for _ in 0..ITERS {
        let r = rng_word();
        acc = sec_and(core::hint::black_box(a), core::hint::black_box(b), r);
    }
    core::hint::black_box(&acc);
    let and_trng = per_iter(t0, cyc());

    // ---- sec_and: rand pre-drawn (gate logic / DRBG lower bound) -----
    let r_fixed = rng_word();
    let t0 = cyc();
    for _ in 0..ITERS {
        acc = sec_and(core::hint::black_box(a), core::hint::black_box(b), r_fixed);
    }
    core::hint::black_box(&acc);
    let and_pure = per_iter(t0, cyc());
    hprintln!(
        "[BENCH] sec_and  TRNG-inline: {} cyc | gate-only: {} cyc",
        and_trng, and_pure
    );

    // ---- sec_add: TRNG-inline (conservative) -------------------------
    let t0 = cyc();
    for _ in 0..ITERS {
        let rs = rng_add_rands();
        acc = sec_add(core::hint::black_box(a), core::hint::black_box(b), &rs);
    }
    core::hint::black_box(&acc);
    let add_trng = per_iter(t0, cyc());

    // ---- sec_add: rand pre-drawn (gate logic / DRBG lower bound) -----
    let rs_fixed = rng_add_rands();
    let t0 = cyc();
    for _ in 0..ITERS {
        acc = sec_add(core::hint::black_box(a), core::hint::black_box(b), &rs_fixed);
    }
    core::hint::black_box(&acc);
    let add_pure = per_iter(t0, cyc());
    hprintln!(
        "[BENCH] sec_add  TRNG-inline: {} cyc | gate-only: {} cyc",
        add_trng, add_pure
    );

    // ---- Projection --------------------------------------------------
    // projected masked-SHA-256 block ≈ ADDS_PER_BLOCK × sec_add
    //                                 + ANDS_PER_BLOCK × sec_and.
    // The σ/Σ rotate-mix + message-schedule XOR work is excluded, so
    // this is a LOWER BOUND on the masked block cost (the real number is
    // a bit higher, dominated by these same two gates).
    let proj_trng = ADDS_PER_BLOCK
        .saturating_mul(add_trng)
        .saturating_add(ANDS_PER_BLOCK.saturating_mul(and_trng));
    let proj_pure = ADDS_PER_BLOCK
        .saturating_mul(add_pure)
        .saturating_add(ANDS_PER_BLOCK.saturating_mul(and_pure));

    hprintln!("[BENCH] ---- projection (lower bound) ----");
    hprintln!(
        "[BENCH]   {} adds + {} ands per block",
        ADDS_PER_BLOCK, ANDS_PER_BLOCK
    );
    hprintln!(
        "[BENCH]   masked block TRNG-inline : {} cyc  (~{} us)",
        proj_trng,
        proj_trng / (CPU_HZ / 1_000_000)
    );
    hprintln!(
        "[BENCH]   masked block gate-only   : {} cyc  (~{} us)",
        proj_pure,
        proj_pure / (CPU_HZ / 1_000_000)
    );

    // ---- Ratios (the headline numbers) -------------------------------
    // Integer ×100 ratio so we don't need float formatting.
    let ratio = |num: u32, den: u32| -> u32 {
        if den == 0 {
            0
        } else {
            num.saturating_mul(100) / den
        }
    };
    hprintln!("[BENCH] ---- slowdown vs baselines (x100) ----");
    hprintln!(
        "[BENCH]   masked/HW-peripheral : TRNG {}x100 | gate {}x100",
        ratio(proj_trng, hw_block),
        ratio(proj_pure, hw_block)
    );
    hprintln!(
        "[BENCH]   masked/sha2-software : TRNG {}x100 | gate {}x100",
        ratio(proj_trng, sw_block),
        ratio(proj_pure, sw_block)
    );

    hprintln!("[BENCH] === masked-sha2 bench complete ===");

    // Clean SYS_EXIT so probe-rs / QEMU sees success and detaches.
    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    loop {
        cortex_m::asm::wfe();
    }
}
