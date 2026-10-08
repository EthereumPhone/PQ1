//! Platform-agnostic RNG facade.
//!
//! On QEMU: delegates to `host_rng` (semihosting /dev/urandom).
//! On STM32U585: delegates to `hw::rng` (hardware TRNG peripheral).

#[cfg(not(feature = "stm32u585"))]
use crate::host_rng;
#[cfg(feature = "stm32u585")]
use crate::hw::rng as hw_rng;

// Final-artifact receipt for the backend selected by the SAME cfg predicate
// as `fill`/`byte` below.  `scripts/prod_symbol_audit.sh` requires the hardware
// value and rejects the host value in every candidate production ELF.  This
// closes the source-vs-linked-artifact gap that made the Coldcard Yasmarang
// fallback possible: reviewing a hardware driver is not evidence that the
// final image actually selected it.
#[cfg(feature = "stm32u585")]
#[used]
#[no_mangle]
#[link_section = ".pqsigner.rng_backend"]
pub static PQSIGNER_RNG_BACKEND: [u8; b"PQ1_RNG_BACKEND=STM32U585_TRNG\0".len()] =
    *b"PQ1_RNG_BACKEND=STM32U585_TRNG\0";

#[cfg(not(feature = "stm32u585"))]
#[used]
#[no_mangle]
#[link_section = ".pqsigner.rng_backend"]
pub static PQSIGNER_RNG_BACKEND: [u8; b"PQ1_RNG_BACKEND=HOST_URANDOM\0".len()] =
    *b"PQ1_RNG_BACKEND=HOST_URANDOM\0";

// Final-artifact receipt for the complete strong-RNG source set. Runtime
// contribution checks still live in `rng_strong`; this marker proves that the
// linked image selected all three physical backends rather than a reduced
// development configuration.
#[cfg(all(
    feature = "stm32u585",
    feature = "dual-se",
    feature = "optiga-trust-m",
    feature = "se050",
    not(feature = "mock-se"),
))]
#[used]
#[no_mangle]
#[link_section = ".pqsigner.rng_backend"]
pub static PQSIGNER_STRONG_RNG_SOURCES: [u8;
    b"PQ1_STRONG_RNG_SOURCES=STM32U585+OPTIGA_TRUST_M+SE050\0".len()] =
    *b"PQ1_STRONG_RNG_SOURCES=STM32U585+OPTIGA_TRUST_M+SE050\0";

#[cfg(not(all(
    feature = "stm32u585",
    feature = "dual-se",
    feature = "optiga-trust-m",
    feature = "se050",
    not(feature = "mock-se"),
)))]
#[used]
#[no_mangle]
#[link_section = ".pqsigner.rng_backend"]
pub static PQSIGNER_STRONG_RNG_SOURCES: [u8;
    b"PQ1_STRONG_RNG_SOURCES=DEVELOPMENT_OR_INCOMPLETE\0".len()] =
    *b"PQ1_STRONG_RNG_SOURCES=DEVELOPMENT_OR_INCOMPLETE\0";

/// Keep the cfg-coupled backend receipt live through linker section-GC.
///
/// `#[used]` forces object emission but GNU ld may still garbage-collect an
/// unreferenced custom section. The volatile load creates a reachable runtime
/// edge from `main`; the artifact audit can therefore require the full marker.
#[inline(never)]
pub fn retain_backend_receipt() {
    // SAFETY: points to the first byte of an immutable static allocation.
    let first = unsafe { core::ptr::read_volatile(PQSIGNER_RNG_BACKEND.as_ptr()) };
    let strong_first = unsafe { core::ptr::read_volatile(PQSIGNER_STRONG_RNG_SOURCES.as_ptr()) };
    if first != b'P' || strong_first != b'P' {
        panic!("RNG backend receipt corrupted");
    }
}

/// Fill from the selected platform backend.
///
/// The contents of `buf` are unspecified on `Err`; callers must discard them.
/// Security-critical consumers use `rng_strong`, which pre-zeroes and wipes
/// its authoritative typed slice on every platform-source failure.
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::fill(buf) }
    #[cfg(feature = "stm32u585")]
    { hw_rng::fill(buf) }
}

pub fn byte() -> u8 {
    #[cfg(not(feature = "stm32u585"))]
    { host_rng::byte() }
    #[cfg(feature = "stm32u585")]
    { hw_rng::byte() }
}

/// One TRNG byte for **NON-SECRET** uses, returning `fallback` instead of
/// panicking if the peripheral reports a transient seed/clock error or
/// times out.
///
/// `byte()` deliberately `.expect()`s on TRNG failure so a secret-consuming
/// caller (SE handshake, nonce, key material) can never silently proceed
/// on a deterministic stream — see the `negative_rng_byte_helper_panics_*`
/// pin. But the FI-delay loop length in [`crate::fi::wait_random`] is
/// explicitly non-secret (it only sets the *duration* of a timing delay and
/// leaks nothing — see `fi.rs` rationale), and it is read thousands of times
/// per signature. Routing that path through a fatal `.expect()` means a
/// single transient STM32U5 TRNG seed-error during any of those reads panics
/// the secure world mid-sign and hangs the device until a power cycle. This
/// helper degrades that non-secret path gracefully.
///
/// **Do NOT use for key/nonce/handshake material** — a `fallback` is a
/// fixed byte, so anything that needs unpredictability must use `byte()` /
/// `fill()` (which fail loudly).
pub fn byte_nonsecret(fallback: u8) -> u8 {
    let mut b = [0u8; 1];
    match fill(&mut b) {
        Ok(()) => {
            #[cfg(feature = "ui-px-frametime")]
            nonsecret_tally(false);
            b[0]
        }
        Err(()) => {
            #[cfg(feature = "ui-px-frametime")]
            nonsecret_tally(true);
            fallback
        }
    }
}

/// How often `byte_nonsecret` returned the FALLBACK instead of a fresh TRNG
/// byte. Bench instrumentation only (`ui-px-frametime`, in `PROD_FORBIDDEN`).
///
/// WHY THIS IS COUNTED (#805 condition (d)). `fi::wait_random` draws its delay
/// length here, and the fill that serves it *itself* contains 17
/// `fi::wait_random()` call sites (`hw/rng.rs`, several inside loops). Because
/// `DriverGuard::try_acquire()?` is the FIRST statement of `fill_bound`, every
/// one of those inner calls loses the non-blocking race and returns `Err`
/// before reaching a `wait_random` of its own. The recursion is therefore
/// bounded at depth 2 — a one-level fan-out, not a 28-deep nest as #802 and an
/// earlier version of this comment both said — and one top-level delay costs
/// `1 + K` calls with `K` fallbacks, where `K` is the number of inner sites
/// actually reached.
///
/// So the shape of the claim is right (one fresh length, many replays of
/// `FI_DELAY_LAST_GOOD`) but the arithmetic was INFERRED, never measured, and
/// the #802 fix changed the contention pattern by removing the 1 kHz SysTick
/// caller. `CLAUDE.md`'s carve-out for countermeasure timing requires the
/// degraded path to be "bounded, loud, documented, and NOT the dominant path,
/// with a MEASURED fallback rate" — so it has to be measured, not asserted,
/// before any DRBG is built on the argument.
///
/// Two numbers, and they cross-check each other. The bench's boot-time
/// one-shot gives `K` structurally, with a clean guard and nothing else
/// running. The running rate averages steady state, and must converge to
/// `K / (K + 1)`; anything ABOVE that is a genuine TRNG seed/clock error
/// (`SECS`/`CECS`) rather than guard contention, which is the one failure the
/// structural read cannot predict.
#[cfg(feature = "ui-px-frametime")]
pub static NONSECRET_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ui-px-frametime")]
pub static NONSECRET_FALLBACKS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

#[cfg(feature = "ui-px-frametime")]
#[inline]
fn nonsecret_tally(fell_back: bool) {
    use core::sync::atomic::Ordering::Relaxed;
    NONSECRET_CALLS.fetch_add(1, Relaxed);
    if fell_back {
        NONSECRET_FALLBACKS.fetch_add(1, Relaxed);
    }
}
