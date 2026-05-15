//! Power-consumption side-channel mask via TIM2 PWM on PA5.
//!
//! Same threat model as Trezor's `core/embed/sec/consumption_mask/`:
//! long crypto operations (SPHINCS+C10 sign takes ~7 s on STM32U585)
//! produce a characteristic power-draw signature that a correlation
//! power analysis (CPA) attacker with a bench probe can exploit. A
//! PWM output with a randomised duty cycle running in parallel
//! dilutes that signature — power draw on the mask pin varies
//! uncorrelated with the crypto work happening elsewhere in the die.
//!
//! # Simplification vs Trezor
//!
//! Trezor drives TIM2 CCR1 via a GPDMA linked-list block (~100 lines
//! of register-level DMA setup; see
//! `core/embed/sec/consumption_mask/stm32u5/consumption_mask.c`).
//! That achieves zero-CPU-overhead updates. This module takes the
//! simpler path:
//!
//!   * Init configures TIM2 CH1 on PA5 AF1 in PWM Mode 1 with a 10 kHz
//!     period (160 MHz SYSCLK / 16 000).
//!   * `randomize()` is called from the caller's periodic path (e.g.
//!     a 1 ms SysTick handler or inline between signing rounds) and
//!     writes a new pseudo-random CCR1 duty — ~20 CPU cycles per call.
//!
//! The simpler path trades a small CPU cost (~0.02% at 1 ms cadence)
//! for ~400 LOC of linked-list DMA. On C10 sign timing this is
//! invisible. A full DMA port is a follow-up task.
//!
//! # Feature gating
//!
//! Behind `consumption-mask`. Implies `stm32u585` (TIM2 + GPIOA
//! register layouts are U585-specific). When the feature is OFF, the
//! module compiles as a trio of no-op stubs, so adding a call site
//! is safe without the flag.
//!
//! # PA5 choice
//!
//! Trezor convention. On the B-U585I-IOT02A dev board, PA5 is on
//! CN13 pin 11 (Arduino-D13 header-compatible). No PQSigner driver
//! currently claims PA5; enabling the feature is additive.
//!
//! # What this does NOT defend against
//!
//! CPA with electromagnetic probes positioned near the specific
//! crypto peripheral (SAES, PKA) — mask-pin jitter doesn't alter the
//! SAES core's own power draw. Defending against that needs
//! randomised delays (`fi::wait_random`) and masked arithmetic
//! inside the primitive. consumption_mask is one layer of a
//! multi-layer defence, not a standalone fix.

#![allow(dead_code)]

#[cfg(feature = "consumption-mask")]
use core::ptr::{read_volatile, write_volatile};

/// Configure TIM2 CH1 PWM on PA5, start it at 50% duty. Call `randomize()`
/// from a periodic interrupt afterwards to keep the duty jittering.
#[cfg(feature = "consumption-mask")]
pub fn init() {
    // SAFETY: single-threaded boot-time init; register addresses
    // taken from RM0456 Tables 77 (RCC), 80 (GPIOA), 34.4 (TIM2).
    unsafe {
        enable_clocks();
        configure_pa5_af1();
        configure_tim2_pwm();
        // Seed the xorshift PRNG from the hardware TRNG. Single
        // 4-byte TRNG read at boot — the only place this module
        // touches `crate::rng`. Subsequent `randomize()` calls run
        // off the seeded state with zero RNG / semihosting cost.
        seed_prng_from_rng();
        // First duty value so the PWM output isn't stuck at zero
        // before the first SysTick tick lands.
        randomize();
        start_tim2();
    }
}

/// Software xorshift32 PRNG state. Seeded once from the hardware TRNG
/// in [`init`]; advanced by [`randomize`] on every SysTick tick.
///
/// Why not call `rng::byte()` here: SysTick runs at ~1 kHz, so every
/// tick reading from the TRNG would mean 2000 calls/sec into the RNG
/// path. That's tolerable on its own, but `secure/src/hw/rng.rs`
/// emits a `secure_log!` line on entry under `debug-log`, which
/// translates to a semihosting BKPT — at 2000 BKPTs/sec the firmware
/// is choked by host-side roundtrips.
///
/// Cryptographic strength is not required for power masking — the
/// goal is to keep the PWM duty non-static so the power signature
/// uncorrelates from die-internal crypto work. Xorshift32 has period
/// 2^32 - 1 and uniform output distribution; that's plenty.
#[cfg(feature = "consumption-mask")]
static mut PRNG_STATE: u32 = 0;

/// Seed the PRNG from the multi-source strong TRNG. Called once
/// from [`init`].
///
/// Migrated from `crate::rng::byte()` × 4 to `rng_strong::fill` so
/// the PWM-mask seed inherits the same 3-source XOR-mix defense as
/// the signing path's OptRand / shuffle seeds. A predictable mask
/// seed → predictable EM signature → easier for an SCA attacker to
/// subtract the mask and recover the underlying secret. The mask
/// quality matters more than the once-per-init cost (single SE
/// round-trip at boot, no hot-path impact).
#[cfg(feature = "consumption-mask")]
unsafe fn seed_prng_from_rng() {
    let mut seed_bytes = [0u8; 4];
    // Strong fill, with fallback: on early-boot before SE channels
    // are up, `rng_strong::fill` falls through to platform TRNG only
    // (same as the old code). On normal operation it XOR-mixes
    // OPTIGA + SE050.
    let _ = crate::rng_strong::fill(&mut seed_bytes);
    // xorshift32 must not be seeded with 0 (state would stick).
    let mut seed = u32::from_be_bytes(seed_bytes);
    if seed == 0 {
        seed = 0xDEADBEEF;
    }
    PRNG_STATE = seed;
}

/// Write a fresh PRNG-derived duty cycle into TIM2 CCR1. Cost: ~10
/// cycles (xorshift step + modulo + MMIO write) — safe to call from
/// any context including IRQ handlers.
#[cfg(feature = "consumption-mask")]
pub fn randomize() {
    use regs::*;
    // SAFETY: PRNG_STATE is touched only here and from `init`. SysTick
    // is the sole caller in normal operation; if a future user adds an
    // additional caller they must ensure mutual exclusion. A torn
    // read-modify-write would only produce a slightly-less-uniform
    // duty cycle on that one tick — no correctness impact, no panic.
    let mut x = unsafe { PRNG_STATE };
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    unsafe {
        PRNG_STATE = x;
    }
    let duty = x % TIMER_PERIOD;
    // SAFETY: TIM2_CCR1 is a plain MMIO word; concurrent writes from
    // multiple contexts are tolerated — the peripheral re-reads on
    // the next counter-match event.
    unsafe {
        write_volatile(TIM2_CCR1, duty);
    }
}

/// Disable TIM2 output and put PA5 back to analog (reset) mode.
/// Reverses [`init`].
#[cfg(feature = "consumption-mask")]
pub fn stop() {
    use regs::*;
    unsafe {
        // Stop the counter and clear the main output.
        let cr1 = read_volatile(TIM2_CR1);
        write_volatile(TIM2_CR1, cr1 & !TIM_CR1_CEN);
        // CCER.CC1E = 0.
        let ccer = read_volatile(TIM2_CCER);
        write_volatile(TIM2_CCER, ccer & !TIM_CCER_CC1E);
        // PA5 → analog input (device reset state) so the pin stops
        // sourcing from the AF mux.
        let moder = read_volatile(GPIOA_MODER);
        // Clear bits [11:10] → 0b11 (analog).
        let new_moder = (moder & !(0b11 << 10)) | (0b11 << 10);
        write_volatile(GPIOA_MODER, new_moder);
    }
}

#[cfg(not(feature = "consumption-mask"))]
pub fn init() {}

#[cfg(not(feature = "consumption-mask"))]
pub fn randomize() {}

#[cfg(not(feature = "consumption-mask"))]
pub fn stop() {}

#[cfg(feature = "consumption-mask")]
const TIMER_PERIOD: u32 = 16_000;

#[cfg(feature = "consumption-mask")]
mod regs {
    // RCC — APB1 (TIM2) and AHB2 (GPIOA) clock enables, secure alias.
    pub const RCC: u32 = 0x5602_0C00;
    pub const RCC_AHB2ENR1: *mut u32 = (RCC + 0x8C) as *mut u32;
    pub const RCC_APB1ENR1: *mut u32 = (RCC + 0x9C) as *mut u32;

    pub const RCC_AHB2ENR1_GPIOAEN: u32 = 1 << 0;
    pub const RCC_APB1ENR1_TIM2EN: u32 = 1 << 0;

    // GPIOA — secure alias at 0x5202_0000 on STM32U585.
    pub const GPIOA: u32 = 0x5202_0000;
    pub const GPIOA_MODER: *mut u32 = (GPIOA + 0x00) as *mut u32;
    pub const GPIOA_OTYPER: *mut u32 = (GPIOA + 0x04) as *mut u32;
    pub const GPIOA_OSPEEDR: *mut u32 = (GPIOA + 0x08) as *mut u32;
    pub const GPIOA_PUPDR: *mut u32 = (GPIOA + 0x0C) as *mut u32;
    pub const GPIOA_AFRL: *mut u32 = (GPIOA + 0x20) as *mut u32;

    // TIM2 — secure alias at 0x5000_0000.
    pub const TIM2: u32 = 0x5000_0000;
    pub const TIM2_CR1: *mut u32 = (TIM2 + 0x00) as *mut u32;
    pub const TIM2_CR2: *mut u32 = (TIM2 + 0x04) as *mut u32;
    pub const TIM2_SMCR: *mut u32 = (TIM2 + 0x08) as *mut u32;
    pub const TIM2_EGR: *mut u32 = (TIM2 + 0x14) as *mut u32;
    pub const TIM2_CCMR1: *mut u32 = (TIM2 + 0x18) as *mut u32;
    pub const TIM2_CCER: *mut u32 = (TIM2 + 0x20) as *mut u32;
    pub const TIM2_PSC: *mut u32 = (TIM2 + 0x28) as *mut u32;
    pub const TIM2_ARR: *mut u32 = (TIM2 + 0x2C) as *mut u32;
    pub const TIM2_CCR1: *mut u32 = (TIM2 + 0x34) as *mut u32;
    pub const TIM2_BDTR: *mut u32 = (TIM2 + 0x44) as *mut u32;

    pub const TIM_CR1_CEN: u32 = 1 << 0;
    pub const TIM_CCER_CC1E: u32 = 1 << 0;
    pub const TIM_CCMR1_OC1PE: u32 = 1 << 3;
    pub const TIM_CCMR1_OC1M_PWM1: u32 = 0b110 << 4;
    pub const TIM_EGR_UG: u32 = 1 << 0;
}

#[cfg(feature = "consumption-mask")]
unsafe fn enable_clocks() {
    use regs::*;
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | RCC_AHB2ENR1_GPIOAEN);
    let apb1 = read_volatile(RCC_APB1ENR1);
    write_volatile(RCC_APB1ENR1, apb1 | RCC_APB1ENR1_TIM2EN);
}

#[cfg(feature = "consumption-mask")]
unsafe fn configure_pa5_af1() {
    use regs::*;
    // MODER: set PA5 to Alternate Function (0b10 at bits [11:10]).
    let moder = read_volatile(GPIOA_MODER);
    let new_moder = (moder & !(0b11 << 10)) | (0b10 << 10);
    write_volatile(GPIOA_MODER, new_moder);

    // OTYPER: push-pull (0) — reset default, but write explicitly.
    let otyper = read_volatile(GPIOA_OTYPER);
    write_volatile(GPIOA_OTYPER, otyper & !(1 << 5));

    // OSPEEDR: low speed (Trezor matches this — mask doesn't need to
    // be fast, and higher speeds emit more HF noise).
    let ospeedr = read_volatile(GPIOA_OSPEEDR);
    let new_ospeedr = ospeedr & !(0b11 << 10); // low = 0b00
    write_volatile(GPIOA_OSPEEDR, new_ospeedr);

    // PUPDR: pull-up (0b01 at bits [11:10]).
    let pupdr = read_volatile(GPIOA_PUPDR);
    let new_pupdr = (pupdr & !(0b11 << 10)) | (0b01 << 10);
    write_volatile(GPIOA_PUPDR, new_pupdr);

    // AFRL: select AF1 for pin 5 (bits [23:20] = 0b0001).
    let afrl = read_volatile(GPIOA_AFRL);
    let new_afrl = (afrl & !(0b1111 << 20)) | (0b0001 << 20);
    write_volatile(GPIOA_AFRL, new_afrl);
}

#[cfg(feature = "consumption-mask")]
unsafe fn configure_tim2_pwm() {
    use regs::*;
    // Prescaler 0 → counter runs at full APB1 clock (160 MHz on our
    // configuration). Period 16 000 → 10 kHz PWM frequency. Matches
    // Trezor's parameters.
    write_volatile(TIM2_PSC, 0);
    write_volatile(TIM2_ARR, TIMER_PERIOD - 1);

    // CCMR1.OC1M = PWM mode 1 (OC1REF high while CNT < CCR1), OC1PE =
    // preload CCR1 on update event (avoids mid-cycle glitches).
    let ccmr1 = read_volatile(TIM2_CCMR1);
    let new_ccmr1 = (ccmr1 & !(0b111 << 4 | 1 << 3)) | TIM_CCMR1_OC1M_PWM1 | TIM_CCMR1_OC1PE;
    write_volatile(TIM2_CCMR1, new_ccmr1);

    // CCER.CC1E = 1 — output enabled.
    let ccer = read_volatile(TIM2_CCER);
    write_volatile(TIM2_CCER, ccer | TIM_CCER_CC1E);

    // Initial CCR1 = 0; randomize() supplies the first real value.
    write_volatile(TIM2_CCR1, 0);

    // Force an update-event to load PSC/ARR/CCR1 from their preload
    // shadows before the counter starts.
    let egr = read_volatile(TIM2_EGR);
    write_volatile(TIM2_EGR, egr | TIM_EGR_UG);
}

#[cfg(feature = "consumption-mask")]
unsafe fn start_tim2() {
    use regs::*;
    let cr1 = read_volatile(TIM2_CR1);
    write_volatile(TIM2_CR1, cr1 | TIM_CR1_CEN);
}
