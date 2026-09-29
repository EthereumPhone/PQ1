//! Power-consumption side-channel mask: a randomised-duty PWM on a
//! board-selected timer channel.
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
//! Trezor drives the CCR1 register via a GPDMA linked-list block (~100
//! lines of register-level DMA setup). This module takes the simpler
//! path: `init` configures the channel in PWM Mode 1 at 10 kHz
//! (160 MHz SYSCLK / 16 000) and `randomize()` writes a new
//! pseudo-random duty (~20 CPU cycles) from the caller's periodic
//! path. ~0.02% CPU at a 1 ms cadence, invisible on C10 sign timing.
//! A full DMA port is a follow-up.
//!
//! # Feature gating
//!
//! Behind `consumption-mask`. Implies `stm32u585`. When the feature is
//! OFF the module compiles as no-op stubs, so adding a call site is
//! safe without the flag.
//!
//! # Pin and timer come from the board
//!
//!   `iota2`  PA5, TIM2_CH1, AF1   — Trezor convention, unchanged.
//!   `pq1`    PA6, TIM3_CH1, AF2   — TIM2_CH1's pins are all taken there
//!                                    (PA0 LEFT KEY, PA5 the LCD's SCK,
//!                                    PA15 SE_RST), so the mask moves to
//!                                    TIM3. `sau::configure_gtzc` secures
//!                                    both timers so NS cannot stop either.
//!
//! This was the one pin in the board port with no `board::` entry, so no
//! `const assert!` and no collision guard could see it — and it pointed
//! straight at pq1's display clock.
//!
//! # What "unloaded" means here, honestly
//!
//! Neither board drives a load from this pin: iota2's PA5 was picked because
//! no driver claimed it, and pq1's PA6 is `NC` in the vendor pin table. A
//! randomised DUTY CYCLE only modulates power draw across a resistive load;
//! into a bare pad, switching current is set by frequency, not duty. So how
//! much this actually dilutes the die's signature is **unmeasured on either
//! board** — `docs/hardware/evt-silicon-validation.md` records it as an open
//! bench item ("must sit near/across the die supply to matter", §9). Moving
//! the pin on pq1 changes nothing about that; it does not make it worse, and
//! it does not make it work.
//!
//! [`selftest_pin_toggles`] at least catches the failure mode below it: a
//! wrong AF number, where the timer runs but never reaches the pad.
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
use crate::hw::mmio::Reg32;

/// Configure TIM2 CH1 PWM on PA5, start it at 50% duty. Call `randomize()`
/// from a periodic interrupt afterwards to keep the duty jittering.
#[cfg(feature = "consumption-mask")]
pub fn init() {
    enable_clocks();
    configure_mask_pin_af();
    configure_tim_pwm();
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
    start_tim();

    // Report whether the PWM actually reaches the pad. Logged rather than
    // fatal: on a board whose mask pin is `NC` this is the only observable
    // evidence the alternate-function mapping is right, and a false negative
    // (e.g. a duty that lands at an extreme) must not brick a boot.
    #[cfg(feature = "debug-log")]
    {
        if selftest_pin_toggles() {
            secure_log!(
                "[S][mask] PWM reaches the pad (port 0x{:08x} pin {} AF{})",
                regs::PORT,
                regs::PIN,
                regs::AF
            );
        } else {
            secure_log!(
                "[S][mask] WARNING: pin {} never toggled — AF{} is probably not \
                 this pin's timer channel; the mask is a no-op",
                regs::PIN,
                regs::AF
            );
        }
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
    REG.tim_ccr1.write(duty);
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

    use crate::board;

    // Every address and bit below comes from the board map. The mask used to
    // hardcode TIM2/PA5/AF1 — the one pin in the whole board port with no
    // `board::` entry, so no `const assert!` and no collision guard could see
    // it. On pq1 PA5 is the trusted display's SPI clock.
    pub const RCC: u32 = board::RCC_S;
    pub const PORT: u32 = board::MASK_PWM_PORT;
    pub const PIN: u32 = board::MASK_PWM_PIN;
    pub const AF: u32 = board::MASK_PWM_AF;
    pub const TIM: u32 = board::MASK_TIM_BASE;

    pub const RCC_GPIO_EN: u32 = board::gpio_rcc_bit(PORT);
    pub const RCC_APB1ENR1_TIMEN: u32 = board::MASK_TIM_RCC_EN_BIT;

    pub const TIM_CR1_CEN: u32 = 1 << 0;
    pub const TIM_CCER_CC1E: u32 = 1 << 0;
    pub const TIM_CCMR1_OC1PE: u32 = 1 << 3;
    pub const TIM_CCMR1_OC1M_PWM1: u32 = 0b110 << 4;
    pub const TIM_EGR_UG: u32 = 1 << 0;

    pub struct Regs {
        pub rcc_ahb2enr1: Reg32,
        pub rcc_apb1enr1: Reg32,
        pub gpio_moder: Reg32,
        pub gpio_otyper: Reg32,
        pub gpio_ospeedr: Reg32,
        pub gpio_pupdr: Reg32,
        pub gpio_afr: Reg32,
        pub gpio_idr: crate::hw::mmio::RoReg32,
        pub tim_cr1: Reg32,
        pub tim_egr: Reg32,
        pub tim_ccmr1: Reg32,
        pub tim_ccer: Reg32,
        pub tim_psc: Reg32,
        pub tim_arr: Reg32,
        pub tim_ccr1: Reg32,
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
            gpio_moder: Reg32::new(PORT + 0x00),
            gpio_otyper: Reg32::new(PORT + 0x04),
            gpio_ospeedr: Reg32::new(PORT + 0x08),
            gpio_pupdr: Reg32::new(PORT + 0x0C),
            // AFRL for pins 0..7, AFRH for 8..15. Both boards' mask pins are
            // in the low half today; the selection is derived anyway so a
            // future move above pin 7 cannot silently write the wrong word.
            gpio_afr: Reg32::new(PORT + if PIN < 8 { 0x20 } else { 0x24 }),
            gpio_idr: crate::hw::mmio::RoReg32::new(PORT + 0x10),

            tim_cr1: Reg32::new(TIM + 0x00),
            tim_egr: Reg32::new(TIM + 0x14),
            tim_ccmr1: Reg32::new(TIM + 0x18),
            tim_ccer: Reg32::new(TIM + 0x20),
            tim_psc: Reg32::new(TIM + 0x28),
            tim_arr: Reg32::new(TIM + 0x2C),
            tim_ccr1: Reg32::new(TIM + 0x34),
        }
    };
}

#[cfg(feature = "consumption-mask")]
fn enable_clocks() {
    use regs::*;
    REG.rcc_ahb2enr1.set_bits(RCC_GPIO_EN);
    REG.rcc_apb1enr1.set_bits(RCC_APB1ENR1_TIMEN);
}

#[cfg(feature = "consumption-mask")]
/// Confirm the PWM actually reaches the pad.
///
/// The failure this exists for: an alternate-function number that is right for
/// the *peripheral* but wrong for the *pin*. `GPIO_AF2_TIM3` is TIM3's AF
/// everywhere, but which pins expose TIM3_CH1 is a per-pin datasheet table.
/// Get it wrong and everything still "works" — RCC clocks the timer, CR1.CEN
/// sets, CCR1 takes new duties, and no register read anywhere reveals that the
/// pad is disconnected from the output compare. The mask would be a no-op and
/// the only symptom would be a security property silently absent. That is the
/// exact defect class this board port kept producing, so here it is checked.
///
/// `IDR` reflects the pad level even while the pin is in AF mode, so sampling
/// it across more than one PWM period must observe both levels at a duty that
/// is neither 0 nor 100%. Returns false if the pin never moves.
///
/// Cheap and bounded: at 10 kHz a period is 100 us, so a few thousand samples
/// span several periods.
#[cfg(feature = "consumption-mask")]
#[must_use]
pub fn selftest_pin_toggles() -> bool {
    use regs::*;
    let mask = 1u32 << PIN;
    // Park the duty at ~50% so both levels are comfortably wide.
    REG.tim_ccr1.write(TIMER_PERIOD / 2);
    let mut saw_high = false;
    let mut saw_low = false;
    // ~4 PWM periods' worth of samples at 160 MHz, with margin.
    for _ in 0..20_000u32 {
        if REG.gpio_idr.read() & mask == 0 {
            saw_low = true;
        } else {
            saw_high = true;
        }
        if saw_high && saw_low {
            return true;
        }
    }
    false
}

fn configure_mask_pin_af() {
    use regs::*;
    let two = PIN * 2;
    let field = 0b11u32 << two;

    // MODER: alternate function.
    REG.gpio_moder.modify(|v| (v & !field) | (0b10 << two));
    // OTYPER: push-pull (reset default, written explicitly).
    REG.gpio_otyper.clear_bits(1 << PIN);
    // OSPEEDR: low speed — Trezor matches this; the mask does not need to be
    // fast and higher speeds emit more HF noise.
    REG.gpio_ospeedr.clear_bits(field);
    // PUPDR: pull-up.
    REG.gpio_pupdr.modify(|v| (v & !field) | (0b01 << two));
    // AFR nibble for this pin, in whichever half it lives.
    let sh = (PIN % 8) * 4;
    REG.gpio_afr.modify(|v| (v & !(0b1111 << sh)) | (AF << sh));
}

#[cfg(feature = "consumption-mask")]

#[cfg(feature = "consumption-mask")]
fn configure_tim_pwm() {
    use regs::*;
    // Prescaler 0 → counter runs at full APB1 clock (160 MHz on our
    // configuration). Period 16 000 → 10 kHz PWM frequency. Matches
    // Trezor's parameters.
    REG.tim_psc.write(0);
    REG.tim_arr.write(TIMER_PERIOD - 1);

    // CCMR1.OC1M = PWM mode 1 (OC1REF high while CNT < CCR1), OC1PE =
    // preload CCR1 on update event (avoids mid-cycle glitches).
    REG.tim_ccmr1.modify(|v| {
        (v & !(0b111 << 4 | 1 << 3)) | TIM_CCMR1_OC1M_PWM1 | TIM_CCMR1_OC1PE
    });

    // CCER.CC1E = 1 — output enabled.
    REG.tim_ccer.set_bits(TIM_CCER_CC1E);

    // Initial CCR1 = 0; randomize() supplies the first real value.
    REG.tim_ccr1.write(0);

    // Force an update-event to load PSC/ARR/CCR1 from their preload
    // shadows before the counter starts.
    REG.tim_egr.set_bits(TIM_EGR_UG);
}

#[cfg(feature = "consumption-mask")]
fn start_tim() {
    use regs::*;
    REG.tim_cr1.set_bits(TIM_CR1_CEN);
}
