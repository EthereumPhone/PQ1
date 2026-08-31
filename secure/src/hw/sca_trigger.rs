//! `sca-trigger` GPIO instrumentation for on-silicon SCA work.
//!
//! Toggles a GPIO HIGH on entry to a security-critical primitive
//! and LOW on exit, so a ChipWhisperer / NewAE Scaffold / scope rig
//! can sync trace captures to the exact instruction window we want
//! to analyse. The pin is the standard "external sync trigger" input
//! on those rigs (typically an LVCMOS digital input).
//!
//! **Production fence.** This module compiles to a no-op when the
//! `sca-trigger` feature is OFF, AND the production build chain
//! refuses to compile a release that has it ON (see the
//! `compile_error!` in `secure/src/nsc/mod.rs` — `sca-trigger`
//! joins `debug-log` / `uart-console` / `boot-pulse` / etc. in the
//! production-fence allowlist).
//!
//! **Pin choice.** Default: **PD2** (Arduino D4 area on
//! B-U585I-IOT02A — easy header access for a scope probe). If
//! that pin collides with something on your bench setup, change
//! [`TRIG_GPIO_PORT_BASE`] + [`TRIG_PIN`] below. The pin must be
//! free of peripheral muxing (AF=GPIO), in a NS-accessible bank if
//! the post-TZSC build has GPIO security enabled per-pin (it
//! currently doesn't — GPIOA-H bank security is default NS unless
//! `hw::usb_hw::init` flipped specific D+/D- pins).
//!
//! **Where it fires** (when `sca-trigger` is enabled):
//!   - `crypto::c10_sign_verified_with_progress` — wraps the entire
//!     hardened sign call. Captures one full sign window per trace.
//!   - `hw::saes_cmac::cmac_dhuk` — wraps the Tier-1 KDF call.
//!     Captures one full MAC window. NB: cmac_dhuk only fires under
//!     `saes-dhuk`, so the trigger only fires there too.
//!   - `nsc::gated_unlock` — wraps the SE.unlock() call. Captures
//!     one PIN-verify window.
//!
//! **What this enables** that emulation can't:
//!   - Power / EM-channel SCA on real silicon (the F-9 work is
//!     emulation-`mem_address` only — physical-channel leakage
//!     still owed).
//!   - FI campaign with real glitches (voltage / clock / EMFI)
//!     targeting the sync'd window.
//!   - Profiled-DPA template collection with proper alignment.

#![allow(unused)]

/// The trigger pin comes from [`crate::board::SCA_TRIGGER`].
///
/// It used to be hardcoded here as `0x5202_0C00` (GPIOD_S) pin 2 — PD2 — with
/// a comment inviting you to "edit these two constants to relocate the
/// trigger". That was an iota2 fact, and the board port did not carry it
/// across: `board/pq1.rs` moved the trigger to PB3 (port D is not bonded on
/// the 48-pin package at all), but this file kept writing PD2.
///
/// The consequence was worse than a dead trigger. `hw/soft_i2c.rs` builds its
/// bench-OLED collision guard FROM `board::SCA_TRIGGER`, so the guard reasoned
/// about PB3 while the only actual writer touched PD2 — guard and writer
/// looking at different pins, which is the exact shape of the `pin_diag` bug
/// (see `optiga/reset_pin.rs`). Found by GPT-5.6 in the 2026-08-31 review.
///
/// A board with no bonded trigger pin leaves every entry point a no-op rather
/// than writing to a pad that does not exist.
const HAS_TRIG: bool = crate::board::SCA_TRIGGER.is_some();
const TRIG_GPIO_PORT_BASE: u32 = match crate::board::SCA_TRIGGER {
    Some((port, _)) => port,
    None => crate::board::GPIOA_S, // never touched; `HAS_TRIG` gates every use
};
const TRIG_PIN: u8 = match crate::board::SCA_TRIGGER {
    Some((_, pin)) => pin as u8,
    None => 0,
};

const TRIG_BSRR: *mut u32 = (TRIG_GPIO_PORT_BASE + 0x18) as *mut u32;
const TRIG_MODER: *mut u32 = (TRIG_GPIO_PORT_BASE + 0x00) as *mut u32;

const RCC_AHB2ENR1: *mut u32 =
    (crate::board::RCC_S + crate::board::RCC_AHB2ENR1_OFF) as *mut u32;
const TRIG_PORT_EN_BIT: u32 = crate::board::gpio_rcc_bit(TRIG_GPIO_PORT_BASE);

/// One-time GPIO init. Call from boot before any [`trig_high`] /
/// [`trig_low`]. Configures TRIG_PIN as a GPIO output (MODER = 01).
#[cfg(feature = "sca-trigger")]
pub fn init() {
    if !HAS_TRIG {
        return;
    }
    // SAFETY: AHB2ENR1 + the trigger port's MODER are mapped peripheral
    // registers; we're the first writer in boot.
    unsafe {
        // Enable the trigger port's clock.
        let v = core::ptr::read_volatile(RCC_AHB2ENR1);
        core::ptr::write_volatile(RCC_AHB2ENR1, v | TRIG_PORT_EN_BIT);
        cortex_m::asm::dsb();

        // MODER: bits [2n+1:2n] = mode for pin n. 00=input, 01=output,
        // 10=alternate, 11=analog. Clear then set 01 for TRIG_PIN.
        let shift = (TRIG_PIN as u32) * 2;
        let mut moder = core::ptr::read_volatile(TRIG_MODER);
        moder &= !(0b11 << shift);
        moder |= 0b01 << shift;
        core::ptr::write_volatile(TRIG_MODER, moder);
        cortex_m::asm::dsb();
    }
}

/// No-op when sca-trigger is OFF.
#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn init() {}

/// Raise the trigger HIGH. Call at the START of a security-critical
/// primitive. Must be paired with a [`trig_low`] at exit so the scope
/// sees a clean rising/falling edge pair per captured operation.
#[cfg(feature = "sca-trigger")]
#[inline(always)]
pub fn trig_high() {
    // SAFETY: BSRR is a write-only set/reset register; setting a bit
    // in the low half drives the corresponding pin HIGH.
    unsafe {
        core::ptr::write_volatile(TRIG_BSRR, 1 << (TRIG_PIN as u32));
    }
}

/// No-op when sca-trigger is OFF.
#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn trig_high() {}

/// Drive the trigger LOW. Call at the END of a security-critical
/// primitive (paired with [`trig_high`] at entry).
#[cfg(feature = "sca-trigger")]
#[inline(always)]
pub fn trig_low() {
    // SAFETY: BSRR is write-only; setting a bit in the high half
    // drives the corresponding pin LOW.
    unsafe {
        core::ptr::write_volatile(TRIG_BSRR, 1 << ((TRIG_PIN as u32) + 16));
    }
}

/// No-op when sca-trigger is OFF.
#[cfg(not(feature = "sca-trigger"))]
#[inline(always)]
pub fn trig_low() {}

/// RAII guard: trig high on construction, trig low on drop. Useful
/// when an `early-return` path could skip a manual `trig_low` call.
///
/// ```ignore
/// fn c10_sign_verified_with_progress(...) -> Result<...> {
///     let _trig = crate::hw::sca_trigger::Trigger::raise();
///     // ... sign work, possibly with early-return ...
/// }
/// // _trig drops here → trig_low fires.
/// ```
pub struct Trigger;

impl Trigger {
    #[inline(always)]
    pub fn raise() -> Self {
        trig_high();
        Self
    }
}

impl Drop for Trigger {
    #[inline(always)]
    fn drop(&mut self) {
        trig_low();
    }
}
