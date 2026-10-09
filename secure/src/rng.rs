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
///
/// MEASURED on the enclosed EVT screen unit, 2026-10-09, `evt-images/px805fb`
/// (`mock-se,dev-testkey,ui-lcd,stm32u585,board-pq1,debug-log,ui-px,ui-px-dma,
/// ui-px-frametime,ui-px-bench`), read off the glass:
///
/// ```text
///   one top-level fi::wait_random()  ->  32 calls, 31 fallbacks
///   running rate                     ->  96 %  == floor(100*31/32)
/// ```
///
/// So `K = 31`, not the 27 asserted on #802, and the running rate lands
/// exactly on the structural prediction.
///
/// WHAT THIS DOES AND DOES NOT SETTLE. The one success in that one-shot IS the
/// top-level draw: the caller's delay got a fresh TRNG byte and the 31 replays
/// all fell inside the extent of that one fill. By COUNT the fallback is the
/// dominant path, 31:1; by ROLE it is confined to delays that harden the RNG
/// driver itself. `CLAUDE.md` condition (d) says "NOT the dominant path"
/// without saying which, so this measurement satisfies it on one reading and
/// fails it on the other — an ambiguity in text written on 2026-10-08, to be
/// resolved by the owner, not silently here.
///
/// WHO ACTUALLY LOSES THE GUARD. Not a thread-mode signing/auth/gateway
/// delay: this is a single core and `DriverGuard` is released by `Drop` before
/// any holder returns, so thread mode can only find `DRIVER_BUSY` set when
/// thread mode is itself the holder — i.e. this very fan-out. The loser is
/// always the PREEMPTING context, and it loses for its whole duration, because
/// a handler that fires while thread mode is inside `fill_bound` finds the
/// guard held until it returns. Two consequences, neither measured here:
///
///   * `consumption_mask::randomize()` runs from SysTick and once per ~1 s
///     calls `rng::fill` to re-seed the sca-1 xorshift, FAIL-OPEN. Preempting
///     a thread-mode fill silently skips that reseed — plausibly correlated
///     with signing, which is when the PWM trace is worth collecting. That
///     feature is production-forced and was ABSENT from the image above, so
///     the agreement with `100*31/32` was guaranteed by the configuration.
///   * The PendSV re-unlock runs `enter_pin` in exception context
///     (`main.rs`), so a thread-mode fill in flight makes every delay on that
///     PIN path replay and every `rng::fill` it attempts return `Err`.
///
/// Separating them needs fallbacks split by `IPSR != 0`; thread-mode
/// fallbacks per fill should be exactly 31, and anything in exception context
/// is the real contention. The bench cannot produce a production-shaped number
/// on its own because it never signs.
///
/// WHAT THE REPLAYS ACTUALLY LEAK. `fi::rng_byte` passes `FI_DELAY_LAST_GOOD`
/// as the fallback and stores the result only AFTER `fill` returns, so all 31
/// inner delays of fill `N` use `b_{N-1}` — the fresh length of the PREVIOUS
/// top-level delay, which an attacker watching the trace has already measured.
/// They are not low-entropy, they are a deterministic function of an observed
/// quantity.
#[cfg(feature = "ui-px-frametime")]
pub static NONSECRET_CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "ui-px-frametime")]
pub static NONSECRET_FALLBACKS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Fallbacks taken in EXCEPTION context (`IPSR != 0`).
///
/// This is the discriminating counter. A thread-mode fallback is the known
/// fan-out — bounded, structural, 31 per fill. A fallback with `IPSR != 0` is a
/// handler that preempted a thread-mode fill and lost the guard for its whole
/// duration, which is the only way a delay OUTSIDE this driver ever replays.
/// `consumption_mask::randomize()`'s fail-open sca-1 reseed and the PendSV
/// `enter_pin` path are both in that class.
#[cfg(feature = "ui-px-frametime")]
pub static NONSECRET_FALLBACKS_ISR: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Non-zero inside any exception handler. ARMv7-M/ARMv8-M B1.4.2: IPSR holds
/// the active exception number, and 0 means thread mode.
#[cfg(all(feature = "ui-px-frametime", target_arch = "arm"))]
#[inline]
fn in_exception() -> bool {
    let ipsr: u32;
    // SAFETY: `mrs` from IPSR is an unprivileged-safe status read with no
    // side effects and no memory access.
    unsafe {
        core::arch::asm!("mrs {}, ipsr", out(reg) ipsr, options(nomem, nostack, preserves_flags));
    }
    ipsr != 0
}

#[cfg(all(feature = "ui-px-frametime", not(target_arch = "arm")))]
#[inline]
fn in_exception() -> bool {
    false
}

#[cfg(feature = "ui-px-frametime")]
#[inline]
fn nonsecret_tally(fell_back: bool) {
    use core::sync::atomic::Ordering::Relaxed;
    NONSECRET_CALLS.fetch_add(1, Relaxed);
    if fell_back {
        NONSECRET_FALLBACKS.fetch_add(1, Relaxed);
        if in_exception() {
            NONSECRET_FALLBACKS_ISR.fetch_add(1, Relaxed);
        }
    }
}
