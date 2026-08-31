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


// ---------------------------------------------------------------------------
// Board fence — the mask pin is iota2's, and pq1 has no drop-in replacement
// ---------------------------------------------------------------------------
//
// This driver hardcodes TIM2 CH1 on PA5 AF1 and reads no board constant. It is
// the one pin in the whole board port with no `board::` entry, so no
// `const assert!` and no collision guard can see it.
//
// On iota2 PA5 is free and drives an LED — a real load, so the PWM does real
// work on the supply rail. On pq1 PA5 is `LCD_SCK_PIN`, the trusted display's
// SPI clock (see `board/pq1.rs`). Driving it as a 10 kHz PWM would fight the
// display driver for the same pad.
//
// The obvious repoint is NOT available. An earlier version of the production
// fence in `nsc/mod.rs` asserted "PA6 carries AF2 = TIM3_CH1 and is unused
// there", offering it as the fix. PA6 *is* unclaimed — but the vendor pin table
// for this board (`STM32U585CIU6TR Pin Functions.xls`, PIN 16) marks it **NC**,
// and so are pq1's only other free pads: PA10 (PIN 31), PC13 (PIN 2), PB4
// (PIN 40). A mask driving an unconnected pad toggles the GPIO cell but drives
// no external load, so whether it still dilutes the signature enough to satisfy
// the ship-blocker is a bench measurement, not a code review — and moving to
// TIM3 additionally means securing TIM3 (GTZC SECCFGR1 bit 1) in the same
// change, or pq1 ships with an NS-clearable countermeasure, which is precisely
// the hole `SECCFGR1_TIM2_BIT` was added to close.
//
// So: a hard refusal rather than a silently-wrong pin. Production already
// REQUIRES this feature (`nsc/mod.rs`), which means pq1 cannot build a shipping
// image today — that is the honest state, and it was previously hidden by this
// combination compiling cleanly onto the LCD's clock line.
#[cfg(all(feature = "consumption-mask", feature = "board-pq1"))]
compile_error!(
    "`consumption-mask` is not portable to pq1 as written: it drives TIM2 CH1 \
     PWM on PA5, which on that board is SPI1_SCK — the trusted display's clock \
     (board::LCD_SCK_PIN). It would contend with the LCD driver for the pad. \
     There is no drop-in replacement: pq1's only unclaimed pads (PA6, PA10, \
     PC13, PB4) are all NC per the vendor pin table, so a mask there drives no \
     load, and moving to TIM3 also requires adding GTZC SECCFGR1 bit 1 to the \
     secure image. Repointing it is a hardware decision needing a bench \
     measurement. Build with BOARD=iota2, or without `consumption-mask`."
);

#[cfg(feature = "consumption-mask")]
use crate::hw::mmio::Reg32;

/// Configure TIM2 CH1 PWM on PA5, start it at 50% duty. Call `randomize()`
/// from a periodic interrupt afterwards to keep the duty jittering.
#[cfg(feature = "consumption-mask")]
pub fn init() {
    enable_clocks();
    configure_pa5_af1();
    configure_tim2_pwm();
    // SAFETY: seed_prng_from_rng writes the static mut PRNG_STATE; this
    // is the sole pre-`randomize` writer and runs single-threaded at boot.
    unsafe {
        // Seed the xorshift PRNG from the platform hardware TRNG. Single
        // 4-byte TRNG read at boot; subsequent `randomize()` calls run off
        // the seeded state with zero RNG cost between periodic reseeds.
        //
        // Fail closed (finding F12): a failed seed would leave the SCA mask
        // emitting a predictable PWM duty. Panic rather than boot with a
        // deterministic mask — the panic handler zeroizes and halts.
        if seed_prng_from_rng().is_err() {
            panic!("consumption_mask: strong-RNG seed failed; refusing maskless boot");
        }
    }
    // First duty value so the PWM output isn't stuck at zero
    // before the first SysTick tick lands.
    randomize();
    start_tim2();
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

/// sca-1 (Trezor-port): re-seed period, in SysTick ticks (~1 s at 1 kHz).
#[cfg(feature = "consumption-mask")]
const RESEED_PERIOD_TICKS: u32 = 1024;
/// Ticks since the last re-seed. Sole writer is `randomize()` (SysTick).
#[cfg(feature = "consumption-mask")]
static mut RESEED_TICKS: u32 = 0;

/// Seed the non-cryptographic PWM-duty PRNG from the STM32 hardware TRNG.
/// Called once from [`init`].
///
/// This deliberately does not call `rng_strong`: `main` initializes the mask
/// before I2C1 and before any secure-element traffic is allowed. Calling the
/// dual-SE path here violated `se_random`'s initialization precondition and
/// made the canonical production feature set panic before boot. The generated
/// bytes never become a seed, key, nonce, or challenge; they only drive an
/// observable PWM duty cycle. Failure is still fatal, and there is no fixed or
/// software-generated fallback seed.
#[cfg(feature = "consumption-mask")]
unsafe fn seed_prng_from_rng() -> Result<(), ()> {
    let mut seed_bytes = [0u8; 4];
    // Fail closed on RNG error (finding F12): the previous code discarded
    // the `Err` (`let _ =`) leaving `seed_bytes` zero, then substituted a
    // fixed constant seed. That produced a fully deterministic, attacker-
    // predictable PWM-duty sequence — defeating the very randomisation this
    // SCA countermeasure exists to provide. Propagate the failure so the
    // caller refuses to run a maskless boot.
    crate::rng::fill(&mut seed_bytes)?;
    // xorshift32 must not be seeded with 0 (state would stick). An all-zero
    // strong-fill result is itself an RNG fault, so treat it as failure
    // rather than silently substituting a constant.
    let seed = u32::from_be_bytes(seed_bytes);
    if seed == 0 {
        return Err(());
    }
    PRNG_STATE = seed;
    Ok(())
}

/// Write a fresh PRNG-derived duty cycle into TIM2 CCR1. Cost: ~10
/// cycles (xorshift step + modulo + MMIO write) — safe to call from
/// any context including IRQ handlers.
#[cfg(feature = "consumption-mask")]
pub fn randomize() {
    use regs::*;
    // sca-1 (Trezor-port): periodically re-seed the xorshift PRNG. Its output
    // physically drives the observable PA5 PWM duty, so an xorshift32 whose
    // state an SCA attacker recovers (linear, observable) can be modelled and
    // subtracted from the trace; re-seeding every ~1024 ticks (~1 s) expires a
    // recovered state. Seed from the PLATFORM TRNG only (`crate::rng::fill`, a
    // register read) — NOT `rng_strong`: this runs in the SysTick ISR and
    // `rng_strong` does SE I2C round-trips that would race a signing op on the
    // shared bus. Fail-OPEN (unlike boot's fail-closed panic): a transient TRNG
    // error must never kill signing mid-run — keep the current state and retry
    // next window. All-zero result is skipped (xorshift must not seed to 0).
    // SAFETY: single-writer (SysTick), same as PRNG_STATE below.
    unsafe {
        RESEED_TICKS = RESEED_TICKS.wrapping_add(1);
        if RESEED_TICKS >= RESEED_PERIOD_TICKS {
            RESEED_TICKS = 0;
            let mut sb = [0u8; 4];
            if crate::rng::fill(&mut sb).is_ok() {
                let s = u32::from_be_bytes(sb);
                if s != 0 {
                    PRNG_STATE = s;
                }
            }
        }
    }
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
    REG.tim2_ccr1.write(duty);
}

#[cfg(not(feature = "consumption-mask"))]
pub fn init() {}

#[cfg(not(feature = "consumption-mask"))]
pub fn randomize() {}

#[cfg(feature = "consumption-mask")]
const TIMER_PERIOD: u32 = 16_000;

#[cfg(feature = "consumption-mask")]
mod regs {
    use crate::hw::mmio::Reg32;

    // RCC — APB1 (TIM2) and AHB2 (GPIOA) clock enables, secure alias.
    pub const RCC: u32 = 0x5602_0C00;
    // GPIOA — secure alias at 0x5202_0000 on STM32U585.
    pub const GPIOA: u32 = 0x5202_0000;
    // TIM2 — secure alias at 0x5000_0000.
    pub const TIM2: u32 = 0x5000_0000;

    pub const RCC_AHB2ENR1_GPIOAEN: u32 = 1 << 0;
    pub const RCC_APB1ENR1_TIM2EN: u32 = 1 << 0;
    pub const TIM_CR1_CEN: u32 = 1 << 0;
    pub const TIM_CCER_CC1E: u32 = 1 << 0;
    pub const TIM_CCMR1_OC1PE: u32 = 1 << 3;
    pub const TIM_CCMR1_OC1M_PWM1: u32 = 0b110 << 4;
    pub const TIM_EGR_UG: u32 = 1 << 0;

    pub struct Regs {
        pub rcc_ahb2enr1: Reg32,
        pub rcc_apb1enr1: Reg32,
        pub gpioa_moder: Reg32,
        pub gpioa_otyper: Reg32,
        pub gpioa_ospeedr: Reg32,
        pub gpioa_pupdr: Reg32,
        pub gpioa_afrl: Reg32,
        pub tim2_cr1: Reg32,
        pub tim2_egr: Reg32,
        pub tim2_ccmr1: Reg32,
        pub tim2_ccer: Reg32,
        pub tim2_psc: Reg32,
        pub tim2_arr: Reg32,
        pub tim2_ccr1: Reg32,
    }

    // SAFETY: each address is a real, 4-byte-aligned MMIO register owned
    // by this consumption-mask driver in the single-threaded secure world.
    // Shared GPIOA / RCC registers are accessed by other drivers via
    // disjoint-bit RMW; this is safe under the secure-world's
    // non-preemptive execution model.
    pub const REG: Regs = unsafe {
        Regs {
            rcc_ahb2enr1: Reg32::new(RCC + 0x8C),
            rcc_apb1enr1: Reg32::new(RCC + 0x9C),
            gpioa_moder: Reg32::new(GPIOA + 0x00),
            gpioa_otyper: Reg32::new(GPIOA + 0x04),
            gpioa_ospeedr: Reg32::new(GPIOA + 0x08),
            gpioa_pupdr: Reg32::new(GPIOA + 0x0C),
            gpioa_afrl: Reg32::new(GPIOA + 0x20),
            tim2_cr1: Reg32::new(TIM2 + 0x00),
            tim2_egr: Reg32::new(TIM2 + 0x14),
            tim2_ccmr1: Reg32::new(TIM2 + 0x18),
            tim2_ccer: Reg32::new(TIM2 + 0x20),
            tim2_psc: Reg32::new(TIM2 + 0x28),
            tim2_arr: Reg32::new(TIM2 + 0x2C),
            tim2_ccr1: Reg32::new(TIM2 + 0x34),
        }
    };
}

#[cfg(feature = "consumption-mask")]
fn enable_clocks() {
    use regs::*;
    REG.rcc_ahb2enr1.set_bits(RCC_AHB2ENR1_GPIOAEN);
    REG.rcc_apb1enr1.set_bits(RCC_APB1ENR1_TIM2EN);
}

#[cfg(feature = "consumption-mask")]
fn configure_pa5_af1() {
    use regs::*;
    // MODER: set PA5 to Alternate Function (0b10 at bits [11:10]).
    REG.gpioa_moder.modify(|v| (v & !(0b11 << 10)) | (0b10 << 10));

    // OTYPER: push-pull (0) — reset default, but write explicitly.
    REG.gpioa_otyper.clear_bits(1 << 5);

    // OSPEEDR: low speed (Trezor matches this — mask doesn't need to
    // be fast, and higher speeds emit more HF noise). Low = 0b00.
    REG.gpioa_ospeedr.clear_bits(0b11 << 10);

    // PUPDR: pull-up (0b01 at bits [11:10]).
    REG.gpioa_pupdr.modify(|v| (v & !(0b11 << 10)) | (0b01 << 10));

    // AFRL: select AF1 for pin 5 (bits [23:20] = 0b0001).
    REG.gpioa_afrl.modify(|v| (v & !(0b1111 << 20)) | (0b0001 << 20));
}

#[cfg(feature = "consumption-mask")]
fn configure_tim2_pwm() {
    use regs::*;
    // Prescaler 0 → counter runs at full APB1 clock (160 MHz on our
    // configuration). Period 16 000 → 10 kHz PWM frequency. Matches
    // Trezor's parameters.
    REG.tim2_psc.write(0);
    REG.tim2_arr.write(TIMER_PERIOD - 1);

    // CCMR1.OC1M = PWM mode 1 (OC1REF high while CNT < CCR1), OC1PE =
    // preload CCR1 on update event (avoids mid-cycle glitches).
    REG.tim2_ccmr1.modify(|v| {
        (v & !(0b111 << 4 | 1 << 3)) | TIM_CCMR1_OC1M_PWM1 | TIM_CCMR1_OC1PE
    });

    // CCER.CC1E = 1 — output enabled.
    REG.tim2_ccer.set_bits(TIM_CCER_CC1E);

    // Initial CCR1 = 0; randomize() supplies the first real value.
    REG.tim2_ccr1.write(0);

    // Force an update-event to load PSC/ARR/CCR1 from their preload
    // shadows before the counter starts.
    REG.tim2_egr.set_bits(TIM_EGR_UG);
}

#[cfg(feature = "consumption-mask")]
fn start_tim2() {
    use regs::*;
    REG.tim2_cr1.set_bits(TIM_CR1_CEN);
}
