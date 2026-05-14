//! Multi-source strong RNG. Mirrors Trezor's
//! `core/embed/sec/rng/rng_strong.c` design: fill from the platform
//! TRNG (STM32 hardware RNG on real silicon; semihosting `/dev/urandom`
//! on QEMU), then XOR-mix per-block from each available secure-element
//! TRNG.
//!
//! **Security argument.** XOR over independent random sources preserves
//! entropy from any unbroken source. If `n-1` of the `n` contributing
//! TRNGs are compromised / biased / stuck, the remaining one carries
//! full entropy into the output. This defends:
//!
//!   - **STM32U585 RNG seed-error / clock-error** (latched SEIS/CEIS):
//!     compromised silicon RNG → SE-side bytes still random.
//!   - **OPTIGA Trust M TRNG fault** (chip-side glitch): STM32 + SE050
//!     still contribute.
//!   - **SE050 TRNG fault**: STM32 + OPTIGA still contribute.
//!   - **Single-fault FI on one source's read path**: the other two
//!     reach the XOR-fold unfaulted.
//!
//! **What we do NOT defend** with the XOR alone:
//!
//!   - A single-fault that clamps the **buffer** (not the source) to
//!     all-zeros after the fold. The post-fill non-zero acceptance
//!     gate catches this: an all-zero N-byte buffer is diagnostic of
//!     a stuck-at-0 fault (legitimate randoms collide with all-zero
//!     at probability `2^-(8·N)` — for N=16, that's 2^-128).
//!   - A coordinated fault that mutates all three sources identically.
//!     Out of scope for our threat model (single-fault assumption).
//!
//! Consumed by `crate::crypto::c10_sign_verified_with_progress` to
//! draw a fresh `opt_rand` per signing call (F-13 follow-up; aligned
//! with `docs/work-todo.md` §10 "Multi-Source RNG").

use zeroize::Zeroize;

/// Fill `buf` with strong random bytes: platform TRNG XOR'd with the
/// active SE backend's `random()` (which itself XOR-mixes all
/// available SE-side sources for multi-SE backends like
/// `DualSecureElement`).
///
/// Returns `Err(())` if:
///   - the platform TRNG fails (STM32 RNG peripheral seed/clock error
///     on hardware, or semihosting `/dev/urandom` unavailable on QEMU),
///     or
///   - the resulting buffer is all-zero after the fold (stuck-at-0
///     fault diagnostic — fail-closed).
///
/// SE-side failure is **not** propagated: a broken SE TRNG falls
/// through to the next source. The platform TRNG is always present, so
/// we always have at least one contribution.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    if buf.is_empty() {
        return Ok(());
    }

    // ── Step 1: platform TRNG (STM32 or QEMU /dev/urandom) ──────────
    // Always available. Establishes the baseline; XOR layers below
    // strictly improve entropy.
    crate::rng::fill(buf)?;

    // ── Step 2: XOR-mix per-block from the SE backend ────────────────
    // For multi-SE backends the trait impl already XOR-folds the
    // per-source contributions internally (see
    // `DualSecureElement::random`). Block-by-block matches Trezor's
    // pattern and keeps the SE TLV body small.
    let mut block = [0u8; 32];
    let mut off = 0;
    while off < buf.len() {
        let len = (buf.len() - off).min(block.len());
        // SAFETY: the caller (sign path) has unlocked the SE, so the
        // global SE handle is initialised. `se_random` returns Err
        // when the active backend has no TRNG (the mock backend) —
        // we fall through and the platform TRNG is the sole
        // contributor for that backend.
        #[cfg(not(test))]
        if unsafe { crate::se_random(&mut block[..len]) }.is_ok() {
            for i in 0..len {
                buf[off + i] ^= block[i];
            }
        }
        off += len;
    }
    block.zeroize();

    // ── Step 3: fail-closed non-zero acceptance gate ────────────────
    // An all-zero buffer is a strong signal of a stuck-at-0 fault
    // somewhere on the fill path. For any reasonable buffer length
    // (the typical caller uses 16 B for SPHINCS+C10 OptRand) the
    // legitimate collision probability with all-zero is 2^-(8·N),
    // which is negligible. Refuse rather than silently emit a
    // predictable random.
    let mut acc: u8 = 0;
    for &b in buf.iter() {
        acc |= b;
    }
    if acc == 0 {
        return Err(());
    }

    Ok(())
}
