//! Multi-source strong RNG. Mirrors Trezor's
//! `core/embed/sec/rng/rng_strong.c` design: fill from the platform
//! TRNG (STM32 hardware RNG on real silicon; semihosting `/dev/urandom`
//! on QEMU), then XOR-mix per-block from both mandatory secure-element
//! TRNGs in hardware builds.
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
//! **Failure semantics — strict, no silent fall-through.** Any configured
//! source that fails to deliver entropy aborts the call. The production path
//! obtains OPTIGA and SE050 bytes through separate methods and requires an
//! independent success/nonzero receipt for each before either is mixed.
//! Refusing the call is the loud failure mode — under EMFI / I2C
//! glitching, silently degrading to fewer sources would let an
//! attacker reduce entropy without anything noticing.
//!
//! Under `feature = "mock-se"` only (dev/QEMU builds), the SE contributions
//! are absent because the mock backend has no TRNG. Compile-time and final-ELF
//! gates require `mock-se` off and all three hardware backends for production.
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
//! with `docs/archive/work-todo-retired-2026-07-19.md` §10 "Multi-Source RNG").

use crate::rng_strong_fold::{
    fold_se_sources, verify_nonzero_output_twice_into, SeSource, SourceRepeatState,
    MIN_SOURCE_BLOCK,
};
use crate::secure_element::WalletStore;
use core::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

/// Serialize the shared physical-source continuous-repetition history.
/// Strong-RNG users run in secure thread mode, but an immediate-fail guard is
/// still safer than relying on every future caller to preserve that invariant.
static STRONG_RNG_BUSY: AtomicBool = AtomicBool::new(false);
static mut SOURCE_REPEAT_STATE: SourceRepeatState = SourceRepeatState::new();

struct StrongRngGuard;

impl StrongRngGuard {
    fn try_acquire() -> Result<Self, ()> {
        STRONG_RNG_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| ())
    }
}

impl Drop for StrongRngGuard {
    fn drop(&mut self) {
        STRONG_RNG_BUSY.store(false, Ordering::Release);
    }
}

/// Common strict three-source composition for callers that already hold the
/// active secure-element handle. Keeping this alongside [`fill`] prevents
/// those callers from hand-rolling an optional-SE fallback or aliasing the
/// global backend through the source-specific global accessors.
pub(crate) fn fill_with_source_draw(
    buf: &mut [u8],
    source_draw: impl FnMut(SeSource, &mut [u8]) -> bool,
) -> Result<(), ()> {
    if buf.is_empty() {
        return Ok(());
    }
    if buf.len() < MIN_SOURCE_BLOCK {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    let _guard = match StrongRngGuard::try_acquire() {
        Ok(guard) => guard,
        Err(()) => {
            buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
    };
    // SAFETY: `_guard` serializes every access for the full platform + SE
    // draw, fold, history publication, and final-output verification.
    let source_history = unsafe { &mut *core::ptr::addr_of_mut!(SOURCE_REPEAT_STATE) };

    // Fail-initialize the platform buffer before the call. If the call itself
    // or an outer Result branch is fault-skipped, stale caller bytes cannot be
    // mistaken for an STM32 contribution.
    buf.zeroize();
    crate::fi::zeroize_barrier();
    let platform_result = crate::rng::fill(buf);
    #[cfg(feature = "rng-xor-probe")]
    crate::rng_xor_probe::record_platform(buf);
    let mut platform_nonzero = 0u8;
    for &byte in buf.iter() {
        platform_nonzero |= byte;
    }
    let mut platform_receipt = crate::fi::FAIL_SENTINEL;
    let checked_platform =
        crate::fi::check_true_into_sentinel(|| platform_result.is_ok() && platform_nonzero != 0);
    // SAFETY: unique stack receipt. Two volatile gates below prevent one
    // skipped/inverted ordinary Result branch from accepting an error-wiped
    // zero baseline.
    unsafe {
        core::ptr::write_volatile(&mut platform_receipt, checked_platform);
    }
    if unsafe { core::ptr::read_volatile(&platform_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&platform_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }

    // Apply each SE contribution exactly once. The fold owns promotion of the
    // fail-initialized receipt: only its unconditional all-chunks-success exit
    // writes OK, while every failed source path wipes `buf`. Keeping the
    // promotion inside the fold prevents a skipped/inverted caller-side bool
    // promotion from accepting the untouched STM32-only baseline.
    let mut fold_receipt = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique stack local. Volatile fail-initialization makes a skipped
    // stateful fold leave an explicit failure receipt instead of stale truth.
    unsafe {
        core::ptr::write_volatile(&mut fold_receipt, crate::fi::FAIL_SENTINEL);
    }
    fold_se_sources(buf, source_draw, source_history, &mut fold_receipt);
    let se_ok = crate::fi::check_true_into_sentinel(|| {
        // SAFETY: repeated read of the live stack receipt for FI checking.
        unsafe { core::ptr::read_volatile(&fold_receipt) == crate::fi::OK_SENTINEL }
    });
    if se_ok != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }

    let mut output_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut output_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_nonzero_output_twice_into(buf, &mut output_receipt);
    if unsafe { core::ptr::read_volatile(&output_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&output_receipt) } != crate::fi::OK_SENTINEL {
        buf.zeroize();
        crate::fi::zeroize_barrier();
        return Err(());
    }
    Ok(())
}

/// Strict three-source fill for a caller that already owns the active wallet
/// backend. The two chip methods are deliberately separate so a nonzero
/// OPTIGA result cannot mask a skipped/zero SE050 result (or vice versa).
pub(crate) fn fill_with_store(buf: &mut [u8], store: &mut impl WalletStore) -> Result<(), ()> {
    // The trait defaults fail. Only a backend that explicitly exposes both
    // physical chips can pass this path; production is additionally compile-
    // fenced to `DualSecureElement`.
    fill_with_source_draw(buf, |source, block| match source {
        SeSource::Optiga => store.random_optiga(block).is_ok(),
        SeSource::Se050 => store.random_se050(block).is_ok(),
    })
}

/// Fill `buf` with strong random bytes from three independently checked
/// sources: the platform TRNG, OPTIGA TRNG, and SE050 TRNG. Each secure-
/// element source is folded into the platform bytes exactly once.
///
/// Returns `Err(())` if:
///   - the platform TRNG fails (STM32 RNG peripheral seed/clock error
///     on hardware, or semihosting `/dev/urandom` unavailable on QEMU),
///   - the SE-side TRNG fails on a production backend (for
///     `DualSecureElement` this means either OPTIGA or SE050 failed),
///   - the resulting buffer is all-zero after the fold (stuck-at-0
///     fault diagnostic — fail-closed).
///
/// Under `feature = "mock-se"` the SE call is allowed to fail (the
/// mock backend has no TRNG); under any production backend
/// (`optiga-trust-m`, `se050`, `dual-se`) a missing SE
/// contribution is fatal.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    #[cfg(all(not(test), not(feature = "mock-se")))]
    {
        return fill_with_source_draw(buf, |source, block| match source {
            SeSource::Optiga => unsafe { crate::se_random_optiga(block) }.is_ok(),
            SeSource::Se050 => unsafe { crate::se_random_se050(block) }.is_ok(),
        });
    }

    // Dev/QEMU (`mock-se`): the mock backend has no TRNG, so an absent
    // SE contribution is tolerated. CI gates production firmware on
    // `mock-se` OFF.
    #[cfg(all(not(test), feature = "mock-se"))]
    {
        if buf.is_empty() {
            return Ok(());
        }
        if crate::rng::fill(buf).is_err() {
            buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
        let mut output_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut output_receipt, crate::fi::FAIL_SENTINEL);
        }
        verify_nonzero_output_twice_into(buf, &mut output_receipt);
        if unsafe { core::ptr::read_volatile(&output_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&output_receipt) } != crate::fi::OK_SENTINEL {
            buf.zeroize();
            crate::fi::zeroize_barrier();
            return Err(());
        }
        return Ok(());
    }
}
