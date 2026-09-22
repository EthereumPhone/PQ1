//! Hardware True Random Number Generator driver for STM32U585.
//!
//! Uses the RNG peripheral at 0x520C0800 (secure alias).
//! Requires HSI48 enabled and RNG clock selected (done by rcc::init).

use crate::hw::mmio::{Reg32, RoReg32};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// RNG register base (SECURE alias — AHB2 bus). With TZEN=1 the GTZC
// secures the RNG peripheral by default; NS-alias accesses (0x420C_0800)
// are rejected by the bus fabric (reads return 0, writes are dropped)
// even from the secure master, which was the root cause of first-boot
// "rng::fill FAILED". Talk to the peripheral from the secure world
// via 0x52xx... instead.
const RNG: u32 = 0x520C_0800;

struct RngRegs {
    cr: Reg32,
    sr: Reg32,
    dr: RoReg32,
    /// Noise source control (offset 0x0C). Present on U575/U585; the parts
    /// without it (U535/U545) are also the ones with a different HTCR value.
    nscr: Reg32,
    htcr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register owned by the
// secure RNG driver. Callers may include SysTick; DRIVER_BUSY serializes the
// entire CR/SR/DR state machine and PREVIOUS_WORD holds the software CRNGT.
const REG: RngRegs = unsafe {
    RngRegs {
        cr: Reg32::new(RNG + 0x00),
        sr: Reg32::new(RNG + 0x04),
        dr: RoReg32::new(RNG + 0x08),
        nscr: Reg32::new(RNG + 0x0C),
        htcr: Reg32::new(RNG + 0x10),
    }
};

// CR bits
const RNGEN: u32 = 1 << 2;
// CONFIGLOCK (bit 31). RM0456 §48.7.1: with it set, writes to RNG_NSCR,
// RNG_HTCR and RNG_CR bits [29:4] are ignored until the next RNG reset, and it
// can only be cleared by resetting the peripheral.
//
// Two reasons this is set rather than left clear, beyond matching the ESV
// certificate (E11 Table 2 gives RNG_CR = 0x80F00DXX):
//
//  1. RM0456 §48.3.4: "When the RNG peripheral is reset through RCC (hardware
//     reset), the RNG configuration for optimal randomness is lost ... Software
//     reset with CONFIGLOCK set PRESERVES the RNG configuration." Our
//     seed-error recovery is exactly such a software reset.
//  2. It stops any later code — including a compromised path — from silently
//     re-pointing the noise source. The entropy configuration becomes
//     immutable for the life of the power cycle.
//
// It does NOT interfere with recovery: CONDRST is bit 30 and RNGEN is bit 2,
// both outside the locked [29:4] window, so the conditioning soft reset and
// enable/disable still work. Set LAST, after every read-back has passed, so a
// partially-failed init can never lock a wrong configuration in place.
const CONFIGLOCK: u32 = 1 << 31;
// CONDRST lives at bit 30 on STM32U5, not bit 6 (bit 6 is part of CONFIG1).
const CONDRST: u32 = 1 << 30;

// SR bits
const DRDY: u32 = 1 << 0;
const CECS: u32 = 1 << 1;
const SECS: u32 = 1 << 2;
const CEIS: u32 = 1 << 5;
const SEIS: u32 = 1 << 6;
const ERROR_FLAGS: u32 = SEIS | SECS | CEIS | CECS;

/// Bounded polling budget for conditioning reset and data-ready waits.
const POLL_LIMIT: u32 = 1_000_000;

// RNG_CR — ST's AN4230 value for THIS part.
//
// `stm32u585xx.h` (CMSIS 1.4.x) ships the per-product AN4230 values under the
// heading "RNG Nist Compliance Values", and ST's own HAL writes them with the
// comment "Recommended value for NIST compliance, refer to application note
// AN4230" (`stm32u5xx_hal_rng.c`). They are:
//
//     RNG_CR   0x00F00D00      <- this constant, already correct
//     RNG_HTCR 0xA2B0          <- see below
//     RNG_NSCR 0x17CBB         <- see below
//
// Field decode (bit positions from the same header, NOT guessed): CONFIG1
// (25:20) = 0x0F, CONFIG2 (15:13) = 0x0, CONFIG3 (11:8) = 0xD, NISTC (bit 12)
// = 0, CED (bit 5) = 0, CLKDIV = 0 — with rng_clk = 48 MHz from HSI48, which
// is RM0456 §48.6.2's validation condition.
//
// An earlier comment here called it "CONFIG3=0x0F, CONFIG1=0x34"; the value
// never said that. Using the wrong CR layout here is what caused the
// first-boot wizard to see `rng::fill FAILED`.
const RNG_CR_NIST_DEFAULT: u32 = 0x00F0_0D00;

// RNG_HTCR — health-test config, AN4230 value for U575/U585 (#704).
//
// This was `0xAAC7`, taken from RM0456 Table 464's generic configuration-C row
// on the strength of note 4 ("can be fixed in the RNG driver, it does not
// depend upon the STM32 product"). That note does not hold across this family:
// `0xAAC7` is what `stm32u535xx.h` / `stm32u545xx.h` define — the two parts
// that have **no RNG_NSCR register at all** — while U575/U585, which do have
// one, define `0xA2B0`. The health-test thresholds are matched to the noise
// source, so borrowing the value from a part with different noise hardware
// runs our health tests against thresholds meant for a different topology.
//
// The driver previously never wrote HTCR at all, so the CR bits ran against
// the RESET thresholds (0x0000_72AC, §48.7.5). On pq1 that surfaced as a
// latched seed error (SR=0x41) before the first draw after nearly every idle
// gap (#698). HTCR is only taken into account while CONDRST=1 (§48.7.5), so it
// is written inside the conditioning-reset window in `init_locked`.
const RNG_HTCR_AN4230: u32 = 0x0000_A2B0;

// RNG_NSCR — noise source control, AN4230 value for U575/U585 (#704).
//
// Never written before: the register was not even mapped, so the noise source
// ran at its reset value rather than ST's validated one. NSCR's `EN_OSC1..6`
// fields select which noise oscillators run, so this is not a cosmetic
// difference — it is *which* entropy hardware is enabled. Like HTCR it is only
// taken into account while CONDRST=1.
const RNG_NSCR_AN4230: u32 = 0x0001_7CBB;

/// Last accepted 32-bit word for a continuous repetition test. Zero is the
/// initial sentinel and cannot collide with a valid observation because an
/// all-zero word is rejected independently.
static PREVIOUS_WORD: AtomicU32 = AtomicU32::new(0);

/// Serializes CR/SR/DR state transitions across thread mode and SysTick.
/// Contention fails immediately instead of spinning in an interrupt.
static DRIVER_BUSY: AtomicBool = AtomicBool::new(false);

struct DriverGuard;

impl DriverGuard {
    fn try_acquire() -> Result<Self, ()> {
        DRIVER_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| ())
    }
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        DRIVER_BUSY.store(false, Ordering::Release);
    }
}

#[inline]
fn status_is_clean(sr: u32) -> bool {
    sr & ERROR_FLAGS == 0
}

/// Publish success only for a nonempty word fragment bounded by both the
/// four-byte source word and the remaining destination.
///
/// This is intentionally independent of `min(4, remaining)`: optimized ARM
/// implements that clamp with one conditional move. If that instruction is
/// omitted, a caller-owned failed receipt must reject before either slice is
/// formed, rather than treating adjacent stack state as RNG bytes.
#[inline(never)]
fn validate_word_take_into(remaining: usize, take: usize, receipt: &mut u32) {
    // SAFETY: unique caller-owned receipt. A skipped validator stays failed.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    let remaining_a = unsafe { core::ptr::read_volatile(&remaining) };
    let take_a = unsafe { core::ptr::read_volatile(&take) };
    if take_a == 0 || take_a > 4 || take_a > remaining_a {
        return;
    }
    crate::fi::wait_random();
    let remaining_b = unsafe { core::ptr::read_volatile(&remaining) };
    let take_b = unsafe { core::ptr::read_volatile(&take) };
    if take_b == 0 || take_b > 4 || take_b > remaining_b {
        return;
    }
    // SAFETY: both independent bounds observations passed; sole success store.
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Prove that one copied output fragment is the current pair of healthy DR
/// words, not merely bytes from whatever pointer reached the exact copier.
///
/// Pointer publication alone is insufficient for a stack-local source: LLVM
/// can materialize that local's address once and reuse the same register for
/// both the publication and copy calls. A skipped address materialization can
/// then make both pointers agree on unrelated static memory. This independent
/// postcondition recomputes the expected bytes from the two hardware words and
/// scans the caller output twice before publishing success.
#[inline(never)]
fn verify_current_word_fragment_into(
    destination_base: *const u8,
    destination_offset: usize,
    word_a: u32,
    word_b: u32,
    take: usize,
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }
    if take == 0 || take > 4 || word_a == 0 || word_b == 0 || word_a == word_b {
        return;
    }
    let expected_word_a = word_a ^ word_b;
    if expected_word_a == 0 {
        return;
    }
    let destination = destination_base.wrapping_add(destination_offset);
    let expected_a = expected_word_a.to_le_bytes();
    let mut processed_a = 0usize;
    let mut diff_a = 0u8;
    for i in 0..take {
        diff_a |= unsafe { core::ptr::read_volatile(destination.add(i)) } ^ expected_a[i];
        unsafe {
            core::ptr::write_volatile(&mut processed_a, i + 1);
        }
    }
    if unsafe { core::ptr::read_volatile(&processed_a) } != take || diff_a != 0 {
        return;
    }

    crate::fi::wait_random();

    let word_a_b = unsafe { core::ptr::read_volatile(&word_a) };
    let word_b_b = unsafe { core::ptr::read_volatile(&word_b) };
    if word_a_b == 0 || word_b_b == 0 || word_a_b == word_b_b {
        return;
    }
    let expected_word_b = word_a_b ^ word_b_b;
    if expected_word_b == 0 || expected_word_b != expected_word_a {
        return;
    }
    let expected_b = expected_word_b.to_le_bytes();
    let mut processed_b = 0usize;
    let mut diff_b = 0u8;
    for i in 0..take {
        diff_b |= unsafe { core::ptr::read_volatile(destination.add(i)) } ^ expected_b[i];
        unsafe {
            core::ptr::write_volatile(&mut processed_b, i + 1);
        }
    }
    if unsafe { core::ptr::read_volatile(&processed_b) } != take || diff_b != 0 {
        return;
    }

    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Bind the live destination region to the independently duplicated entry
/// arguments supplied by [`fill`].
///
/// The public wrapper passes the incoming slice pointer/length in both ARM
/// argument pairs (`r0/r1` and `r2/r3`). Keeping this check out of line stops
/// one omitted callee-side capture from making every later destination use
/// agree on the same stale register. Both observations must agree twice before
/// the first hardware word is drawn.
#[inline(never)]
fn verify_fill_region_binding_into(
    live_base: *mut u8,
    live_len: usize,
    expected_base: *mut u8,
    expected_len: usize,
    receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::FAIL_SENTINEL);
    }

    let live_base_a = unsafe { core::ptr::read_volatile(&live_base) };
    let live_len_a = unsafe { core::ptr::read_volatile(&live_len) };
    let expected_base_a = unsafe { core::ptr::read_volatile(&expected_base) };
    let expected_len_a = unsafe { core::ptr::read_volatile(&expected_len) };
    if live_base_a != expected_base_a
        || live_len_a != expected_len_a
        || live_base_a.is_null()
    {
        return;
    }

    crate::fi::wait_random();

    let live_base_b = unsafe { core::ptr::read_volatile(&live_base) };
    let live_len_b = unsafe { core::ptr::read_volatile(&live_len) };
    let expected_base_b = unsafe { core::ptr::read_volatile(&expected_base) };
    let expected_len_b = unsafe { core::ptr::read_volatile(&expected_len) };
    if live_base_b != live_base_a
        || live_len_b != live_len_a
        || expected_base_b != expected_base_a
        || expected_len_b != expected_len_a
        || live_base_b != expected_base_b
        || live_len_b != expected_len_b
        || live_base_b.is_null()
    {
        return;
    }

    unsafe {
        core::ptr::write_volatile(receipt, crate::fi::OK_SENTINEL);
    }
}

/// Advance the sole platform-fill cursor only after one exact word-fragment
/// copy.  Binding the claimed `current` offset to the canonical volatile
/// completion state prevents a skipped cursor load/initialization from
/// starting at a stale prior-frame prefix.  The exact word shape is checked
/// twice, then the next value is published twice and read back twice.
#[inline(never)]
fn publish_verified_word_progress_into(
    completed_bytes: &mut usize,
    current: usize,
    take: usize,
    total: usize,
    progress_receipt: &mut u32,
) {
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::FAIL_SENTINEL);
    }

    let completed_a = unsafe { core::ptr::read_volatile(completed_bytes) };
    let current_a = unsafe { core::ptr::read_volatile(&current) };
    let take_a = unsafe { core::ptr::read_volatile(&take) };
    let total_a = unsafe { core::ptr::read_volatile(&total) };
    if completed_a != current_a || current_a >= total_a {
        return;
    }
    let remaining_a = total_a - current_a;
    let expected_take_a = core::cmp::min(4, remaining_a);
    if take_a != expected_take_a {
        return;
    }
    let next_a = match current_a.checked_add(take_a) {
        Some(next) if next <= total_a => next,
        _ => return,
    };

    crate::fi::wait_random();

    let completed_b = unsafe { core::ptr::read_volatile(completed_bytes) };
    let current_b = unsafe { core::ptr::read_volatile(&current) };
    let take_b = unsafe { core::ptr::read_volatile(&take) };
    let total_b = unsafe { core::ptr::read_volatile(&total) };
    if completed_b != current_b || current_b >= total_b {
        return;
    }
    let remaining_b = total_b - current_b;
    let expected_take_b = core::cmp::min(4, remaining_b);
    if take_b != expected_take_b {
        return;
    }
    let next_b = match current_b.checked_add(take_b) {
        Some(next) if next <= total_b => next,
        _ => return,
    };
    if next_b != next_a {
        return;
    }

    unsafe {
        core::ptr::write_volatile(completed_bytes, next_a);
        core::ptr::write_volatile(completed_bytes, next_b);
    }
    if unsafe { core::ptr::read_volatile(completed_bytes) } != next_a {
        return;
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(completed_bytes) } != next_b {
        return;
    }
    unsafe {
        core::ptr::write_volatile(progress_receipt, crate::fi::OK_SENTINEL);
    }
}

/// Wait until the hardware acknowledges that conditioning reset completed.
fn wait_for_conditioning_reset() -> Result<(), ()> {
    let mut timeout = 0u32;
    while REG.cr.read() & CONDRST != 0 {
        timeout = timeout.wrapping_add(1);
        if timeout >= POLL_LIMIT {
            secure_log!("[S] rng: CONDRST completion timeout");
            return Err(());
        }
    }
    Ok(())
}

/// Read one word and publish it only after the CubeU5-required post-DR status
/// check plus software zero/repetition health tests.
///
/// Both outputs are fail-initialized in this non-inlined callee. Callers also
/// fail-initialize and check `read_receipt` twice, so skipping the call cannot
/// reinterpret stale ABI return registers as a successful hardware sample.
#[inline(never)]
fn read_healthy_word_into(word_out: &mut u32, read_receipt: &mut u32) {
    // SAFETY: unique caller-owned output slots. Zero is never an accepted RNG
    // word and the Hamming-distant failure sentinel is never success.
    unsafe {
        core::ptr::write_volatile(word_out, 0);
        core::ptr::write_volatile(read_receipt, crate::fi::FAIL_SENTINEL);
    }
    let mut timeout = 0u32;
    loop {
        let sr = REG.sr.read();
        if !status_is_clean(sr) {
            secure_log!("[S] rng: error before DR read SR=0x{:08x}", sr);
            return;
        }
        if sr & DRDY != 0 {
            break;
        }
        timeout = timeout.wrapping_add(1);
        if timeout >= POLL_LIMIT {
            let sr_end = REG.sr.read();
            let cr_end = REG.cr.read();
            secure_log!(
                "[S] rng: DRDY timeout CR=0x{:08x} SR=0x{:08x}",
                cr_end,
                sr_end
            );
            return;
        }
    }

    let word = REG.dr.read();

    // RM0456 / CubeU5: a seed error may assert concurrently with the DR read.
    // Such a word may not have enough entropy, so sample SR again BEFORE any
    // byte reaches the caller.
    let sr_after = REG.sr.read();
    let status_clean = status_is_clean(sr_after);

    // Atomically install the new CRNGT state. If SysTick accepted another
    // word between our load and compare-exchange, re-evaluate against that
    // newer predecessor before committing.
    let mut previous = PREVIOUS_WORD.load(Ordering::Relaxed);
    loop {
        let mut health_receipt = crate::fi::FAIL_SENTINEL;
        let checked_health = crate::fi::check_true_into_sentinel(|| {
            crate::rng_health::word_is_acceptable(status_clean, word, previous)
        });
        // SAFETY: unique stack receipt. Two caller-visible volatile gates make
        // a skipped zero/repetition/status branch reject rather than release.
        unsafe {
            core::ptr::write_volatile(&mut health_receipt, checked_health);
        }
        if unsafe { core::ptr::read_volatile(&health_receipt) } != crate::fi::OK_SENTINEL {
            secure_log!(
                "[S] rng: rejected word (status=0x{:08x}, zero={}, repeat={})",
                sr_after,
                word == 0,
                word == previous
            );
            return;
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&health_receipt) } != crate::fi::OK_SENTINEL {
            return;
        }
        match PREVIOUS_WORD.compare_exchange_weak(
            previous,
            word,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                // SAFETY: publish data before the success receipt. A skipped
                // data store leaves `word_out == 0`; callers require both
                // independently drawn words to be nonzero before combining.
                unsafe {
                    core::ptr::write_volatile(word_out, word);
                }
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                unsafe {
                    core::ptr::write_volatile(read_receipt, crate::fi::OK_SENTINEL);
                }
                return;
            }
            Err(observed) => previous = observed,
        }
    }
}

/// Initialize the RNG peripheral. Must be called after `rcc::init()`.
/// Returns `Err(())` unless conditioning reset completes and one healthy
/// warm-up word is observed and discarded.
fn init_locked() -> Result<(), ()> {
    // 1. Enter config mode with the NIST-compliant CR value.
    REG.cr.write(RNG_CR_NIST_DEFAULT | CONDRST);
    // 1b. Health-test thresholds matching the CR configuration. Must happen
    //     while CONDRST=1 or the write is ignored; read back and fail closed
    //     if it did not take (e.g. CONFIGLOCK set, or a wrong register map).
    // Order matches ST's HAL (`stm32u5xx_hal_rng.c`): CR|CONDRST, then HTCR,
    // then NSCR, then clear CONDRST.
    let htcr_before = REG.htcr.read();
    REG.htcr.write(RNG_HTCR_AN4230);
    let htcr_after = REG.htcr.read();
    secure_log!(
        "[S] rng: HTCR 0x{:08x} -> 0x{:08x} (AN4230 U585 wants 0x{:08x})",
        htcr_before,
        htcr_after,
        RNG_HTCR_AN4230
    );
    // Only consumed by `secure_log!`, which is empty without `debug-log`.
    let _ = htcr_before;
    if htcr_after != RNG_HTCR_AN4230 {
        return Err(());
    }
    // 1c. Noise source control. Same CONDRST-window rule and the same
    //     fail-closed read-back: a silently-ignored NSCR write would leave the
    //     noise oscillators at reset while everything downstream assumed ST's
    //     validated set.
    let nscr_before = REG.nscr.read();
    REG.nscr.write(RNG_NSCR_AN4230);
    let nscr_after = REG.nscr.read();
    secure_log!(
        "[S] rng: NSCR 0x{:08x} -> 0x{:08x} (AN4230 U585 wants 0x{:08x})",
        nscr_before,
        nscr_after,
        RNG_NSCR_AN4230
    );
    let _ = nscr_before;
    if nscr_after != RNG_NSCR_AN4230 {
        return Err(());
    }
    // 2. Leave config mode (clear CONDRST) while keeping the config bits.
    REG.cr.write(RNG_CR_NIST_DEFAULT);
    wait_for_conditioning_reset()?;
    // 3. Clear any latched seed / clock error interrupts from pre-init.
    let sr = REG.sr.read();
    REG.sr.write(sr & !(SEIS | CEIS));
    // 4. Enable the RNG and lock the configuration. E11 Table 2's CR is
    //    0x80F00DXX, where the low byte is application-dependent (bit 2 = RNGEN
    //    when the peripheral is needed). Locking last means the values just
    //    read back are the ones being frozen.
    REG.cr.write(RNG_CR_NIST_DEFAULT | RNGEN | CONFIGLOCK);
    let cr_locked = REG.cr.read();
    secure_log!("[S] rng: CR after lock = 0x{:08x}", cr_locked);
    if cr_locked & CONFIGLOCK == 0 {
        // On a re-init the bit is already set and this is a no-op; if it reads
        // clear here the lock did not take, so the noise configuration is still
        // mutable and we are not in the certified configuration.
        return Err(());
    }

    // 5. Wait for one fully checked random number and discard it. Using the
    // same read path pins the post-warm-up SEIS/SECS/CEIS/CECS assertion and
    // seeds the continuous repetition test for the first returned word. The
    // caller-owned receipt prevents a skipped call from waiving warm-up.
    let mut warmup_word = 0u32;
    let mut warmup_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut warmup_word, 0);
        core::ptr::write_volatile(&mut warmup_receipt, crate::fi::FAIL_SENTINEL);
    }
    read_healthy_word_into(&mut warmup_word, &mut warmup_receipt);
    if unsafe { core::ptr::read_volatile(&warmup_receipt) } != crate::fi::OK_SENTINEL
        || unsafe { core::ptr::read_volatile(&warmup_word) } == 0
    {
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&warmup_receipt) } != crate::fi::OK_SENTINEL
        || unsafe { core::ptr::read_volatile(&warmup_word) } == 0
    {
        return Err(());
    }
    Ok(())
}

/// Initialize the peripheral while excluding concurrent SysTick reads.
pub fn init() -> Result<(), ()> {
    let _guard = DriverGuard::try_acquire()?;
    init_locked()
}

/// Fill `buf` with random bytes from the hardware TRNG.
/// Returns `Err(())` if the RNG reports a seed or clock error.
/// A rejection before the duplicated entry binding completes does not touch
/// the destination; a later error may leave a random prefix. Callers must
/// discard the entire buffer on `Err` and security-critical callers own the
/// authoritative typed wipe (the strong three-source facade does both).
///
/// The immediate four-argument call is deliberate. On ARM, the live slice is
/// already in `r0/r1`; duplicating it into `r2/r3` before the out-of-line body
/// gives the body two independently captured roots. The production symbol
/// audit and optimized-ELF review pin this boundary.
#[inline(never)]
pub fn fill(buf: &mut [u8]) -> Result<(), ()> {
    // SAFETY: both raw regions are the same live, uniquely borrowed slice.
    // `fill_bound` checks the duplicated pointer/length before any access.
    unsafe {
        fill_bound(
            buf.as_mut_ptr(),
            buf.len(),
            buf.as_mut_ptr(),
            buf.len(),
        )
    }
}

#[inline(never)]
#[export_name = "pqsigner_hw_rng_fill_bound"]
unsafe fn fill_bound(
    destination_base: *mut u8,
    destination_len: usize,
    expected_destination_base: *mut u8,
    expected_destination_len: usize,
) -> Result<(), ()> {
    // SysTick periodically reseeds the non-secret PWM mask through this same
    // driver. Never let it interleave an SR/DR read with thread-mode entropy
    // or a conditioning reset; the ISR retries after a busy error. Contention
    // returns before any raw destination is constructed or touched.
    let _guard = DriverGuard::try_acquire()?;

    let mut fill_binding_receipt = crate::fi::FAIL_SENTINEL;
    unsafe {
        core::ptr::write_volatile(&mut fill_binding_receipt, crate::fi::FAIL_SENTINEL);
    }
    verify_fill_region_binding_into(
        destination_base,
        destination_len,
        expected_destination_base,
        expected_destination_len,
        &mut fill_binding_receipt,
    );
    if unsafe { core::ptr::read_volatile(&fill_binding_receipt) } != crate::fi::OK_SENTINEL {
        return Err(());
    }
    crate::fi::wait_random();
    if unsafe { core::ptr::read_volatile(&fill_binding_receipt) } != crate::fi::OK_SENTINEL {
        return Err(());
    }

    // SAFETY: `fill` supplies its live exclusive slice, and both independent
    // pointer/length observations matched twice. Before this point no slice
    // was constructed and no rejection path dereferenced either raw region.
    let buf = unsafe { core::slice::from_raw_parts_mut(destination_base, destination_len) };
    let result = (|| -> Result<(), ()> {

        let sr0 = REG.sr.read();
        let cr0 = REG.cr.read();
        secure_log!("[S] rng::fill entry: CR=0x{:08x} SR=0x{:08x}", cr0, sr0);

        // If any current or latched seed/clock error is visible, RM0456 requires
        // a conditioning reset. Recovery is attempted once and its Result is
        // propagated; there is no best-effort continuation on a failed reset.
        if sr0 & ERROR_FLAGS != 0 {
            secure_log!("[S] rng::fill: seed/clock error — recovering");
            init_locked()?;
            let sr1 = REG.sr.read();
            let cr1 = REG.cr.read();
            secure_log!(
                "[S] rng::fill after recover: CR=0x{:08x} SR=0x{:08x}",
                cr1,
                sr1
            );
        }

        let mut completed_bytes = usize::MAX;
        let mut progress_init_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut progress_init_receipt, crate::fi::FAIL_SENTINEL);
        }
        crate::rng_exact::initialize_exact_progress_into(
            &mut completed_bytes,
            &mut progress_init_receipt,
        );
        if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
            return Err(());
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&progress_init_receipt) } != crate::fi::OK_SENTINEL {
            return Err(());
        }
        loop {
            let i = unsafe { core::ptr::read_volatile(&completed_bytes) };
            if i >= buf.len() {
                break;
            }
            // Draw two independently receipted words and XOR them. Besides
            // preserving the STM32 TRNG's entropy, this means one skipped DR
            // load still leaves a fresh hardware sample in every output word.
            // Whole-call skips are caught by the caller-owned fail receipts.
            let mut word_a = 0u32;
            let mut word_b = 0u32;
            let mut read_receipt_a = crate::fi::FAIL_SENTINEL;
            let mut read_receipt_b = crate::fi::FAIL_SENTINEL;
            unsafe {
                core::ptr::write_volatile(&mut word_a, 0);
                core::ptr::write_volatile(&mut word_b, 0);
                core::ptr::write_volatile(&mut read_receipt_a, crate::fi::FAIL_SENTINEL);
                core::ptr::write_volatile(&mut read_receipt_b, crate::fi::FAIL_SENTINEL);
            }
            read_healthy_word_into(&mut word_a, &mut read_receipt_a);
            read_healthy_word_into(&mut word_b, &mut read_receipt_b);
            if unsafe { core::ptr::read_volatile(&read_receipt_a) } != crate::fi::OK_SENTINEL
                || unsafe { core::ptr::read_volatile(&read_receipt_b) } != crate::fi::OK_SENTINEL
                || unsafe { core::ptr::read_volatile(&word_a) } == 0
                || unsafe { core::ptr::read_volatile(&word_b) } == 0
            {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&read_receipt_a) } != crate::fi::OK_SENTINEL
                || unsafe { core::ptr::read_volatile(&read_receipt_b) } != crate::fi::OK_SENTINEL
                || unsafe { core::ptr::read_volatile(&word_a) } == 0
                || unsafe { core::ptr::read_volatile(&word_b) } == 0
            {
                return Err(());
            }
            let word =
                unsafe { core::ptr::read_volatile(&word_a) ^ core::ptr::read_volatile(&word_b) };
            if word == 0 {
                return Err(());
            }
            // Publish the combined hardware word twice before the exact copy.
            // `to_le_bytes()` alone compiled to one stack `str`; skipping that
            // instruction made the exact copier faithfully copy stale stack
            // data. Two volatile stores mean one omitted publication still
            // leaves the independently drawn STM32 word as the copy source.
            let mut word_storage = 0u32;
            unsafe {
                core::ptr::write_volatile(&mut word_storage, word.to_le());
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            unsafe {
                core::ptr::write_volatile(&mut word_storage, word.to_le());
            }
            // SAFETY: `word_storage` is an aligned live u32 and STM32U585 is
            // little-endian. The slice is read-only and lasts only through the
            // exact copy below.
            let word_bytes = unsafe {
                core::slice::from_raw_parts((&word_storage as *const u32).cast::<u8>(), 4)
            };
            let remaining = buf.len() - i;
            let take = core::cmp::min(word_bytes.len(), remaining);
            let mut take_receipt = crate::fi::FAIL_SENTINEL;
            unsafe {
                core::ptr::write_volatile(&mut take_receipt, crate::fi::FAIL_SENTINEL);
            }
            validate_word_take_into(remaining, take, &mut take_receipt);
            if unsafe { core::ptr::read_volatile(&take_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&take_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
            let mut copy_receipt = crate::fi::FAIL_SENTINEL;
            unsafe {
                core::ptr::write_volatile(&mut copy_receipt, crate::fi::FAIL_SENTINEL);
            }
            let mut published_source = core::ptr::null();
            let mut source_publication_receipt = crate::fi::FAIL_SENTINEL;
            crate::rng_exact::publish_region_pointer_into(
                word_bytes.as_ptr(),
                &mut published_source,
                &mut source_publication_receipt,
            );
            if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&source_publication_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            let mut published_destination = core::ptr::null();
            let mut destination_publication_receipt = crate::fi::FAIL_SENTINEL;
            crate::rng_exact::publish_region_pointer_into(
                unsafe { buf.as_ptr().add(i) },
                &mut published_destination,
                &mut destination_publication_receipt,
            );
            if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&destination_publication_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            crate::rng_exact::copy_exact_into(
                word_bytes.as_ptr(),
                core::ptr::addr_of!(published_source),
                take,
                buf.as_mut_ptr(),
                i,
                core::ptr::addr_of!(published_destination),
                take,
                &mut copy_receipt,
            );
            if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&copy_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
            let mut word_relation_receipt = crate::fi::FAIL_SENTINEL;
            unsafe {
                core::ptr::write_volatile(
                    &mut word_relation_receipt,
                    crate::fi::FAIL_SENTINEL,
                );
            }
            verify_current_word_fragment_into(
                buf.as_ptr(),
                i,
                unsafe { core::ptr::read_volatile(&word_a) },
                unsafe { core::ptr::read_volatile(&word_b) },
                take,
                &mut word_relation_receipt,
            );
            if unsafe { core::ptr::read_volatile(&word_relation_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&word_relation_receipt) }
                != crate::fi::OK_SENTINEL
            {
                return Err(());
            }
            let mut progress_receipt = crate::fi::FAIL_SENTINEL;
            unsafe {
                core::ptr::write_volatile(&mut progress_receipt, crate::fi::FAIL_SENTINEL);
            }
            publish_verified_word_progress_into(
                &mut completed_bytes,
                i,
                take,
                buf.len(),
                &mut progress_receipt,
            );
            if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
            crate::fi::wait_random();
            if unsafe { core::ptr::read_volatile(&progress_receipt) } != crate::fi::OK_SENTINEL {
                return Err(());
            }
        }

        // Do not infer success from falling through the loop. A skipped ARM
        // backedge after one 32-bit word must leave a short receipt and fail.
        let mut completion_receipt = crate::fi::FAIL_SENTINEL;
        unsafe {
            core::ptr::write_volatile(&mut completion_receipt, crate::fi::FAIL_SENTINEL);
        }
        crate::rng_exact::verify_exact_progress_into(
            &completed_bytes,
            buf.len(),
            &mut completion_receipt,
        );
        if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
            return Err(());
        }
        crate::fi::wait_random();
        if unsafe { core::ptr::read_volatile(&completion_receipt) } != crate::fi::OK_SENTINEL {
            return Err(());
        }
        Ok(())
    })();

    // Do not clear through the raw entry pointer here. Even after ordinary
    // binding succeeds, a fault in one cleanup-argument materialization could
    // redirect a bulk wipe. The failed receipt/Result is authoritative; every
    // current caller discards the buffer and the strong facade wipes its typed
    // slice. Successful completion still proves every requested byte.
    result
}

/// One-shot single-byte helper (mirrors host_rng::byte API).
pub fn byte() -> u8 {
    let mut b = [0u8; 1];
    fill(&mut b).expect("hw_rng: TRNG read failed");
    b[0]
}
