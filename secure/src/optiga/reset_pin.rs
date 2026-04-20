//! GPIO-driven hard reset of the OPTIGA Trust M via the chip's RST line.
//!
//! On the B-U585I-IOT02A Discovery board the Arduino UNO R3 connector's
//! `D5` pin is wired to STM32U585 pin **PE4** — confirmed empirically by
//! `pin_diag::run()` toggling all four candidates (PA4 / PD5 / PE0 / PE4)
//! with distinct pulse widths and watching the logic-analyzer probe on
//! the physical D5 header: exactly one pulse appeared, at the PE4 width.
//! Prior bring-up iterations of this file targeted PE0, PD5, and PA4 on
//! docs / user reports that didn't match the silkscreen; none of them
//! toggled an electrically-connected pin, so the "hard RST pulse" was
//! effectively a no-op and the chip was only ever being reset via the
//! I²C-level `soft_reset` (REG_SOFT_RESET=0x88). That happened to be
//! enough on a previously-burned bench chip (recovered via SetObject-
//! Protected) but not on pristine silicon.
//!
//! The chip's RST is active-low: driving PE4 low holds the chip in
//! reset, driving high (or floating — chip has an internal pull-up)
//! releases it. We drive the pin explicitly rather than leaving it to
//! the pull-up so that a brownout or glitch on the breadboard rail
//! cannot silently put the chip in reset mid-session.
//!
//! ## Implementation note
//!
//! The init + toggle sequence mirrors the one in `pin_diag::run()` that
//! we empirically know produces a visible PE4 pulse on the logic
//! analyzer. An earlier pure-BSRR implementation in this file did *not*
//! yield a visible edge in the same wiring — something about the write
//! sequencing on this particular silicon revision made the BSRR stores
//! disappear even with DSB barriers. The pattern we now use (OR in the
//! RCC bit, then a full read-modify-write on MODER/OTYPER/OSPEEDR/
//! PUPDR *before* any BSRR store, then 50 ms idle-high settle) is the
//! one that survives that silicon quirk.

#![cfg(feature = "stm32u585")]

use core::ptr::{read_volatile, write_volatile};

const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;
const GPIOE_BASE: u32 = 0x5202_1000;

const RCC_GPIOEEN_BIT: u32 = 4;
const RST_PIN: u32 = 4; // PE4

/// Enable the GPIOE bus clock. Idempotent.
unsafe fn enable_gpioe_clock() {
    let v = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, v | (1 << RCC_GPIOEEN_BIT));
    cortex_m::asm::dsb();
}

/// Configure PE4 as push-pull output driving high, matching the full
/// MODER/OTYPER/OSPEEDR/PUPDR sequence from `pin_diag::config_output_
/// high`.
unsafe fn config_pe4_output_high() {
    let moder = GPIOE_BASE as *mut u32;
    let otyper = (GPIOE_BASE + 0x04) as *mut u32;
    let ospeedr = (GPIOE_BASE + 0x08) as *mut u32;
    let pupdr = (GPIOE_BASE + 0x0C) as *mut u32;
    let bsrr = (GPIOE_BASE + 0x18) as *mut u32;

    // Drive high first so there's no low-glitch when we flip to output.
    write_volatile(bsrr, 1u32 << RST_PIN);

    // MODER[9:8] = 01 (output)
    let mask = 0b11u32 << (2 * RST_PIN);
    let m = read_volatile(moder);
    write_volatile(moder, (m & !mask) | (0b01u32 << (2 * RST_PIN)));

    // OTYPER[4] = 0 (push-pull)
    let o = read_volatile(otyper);
    write_volatile(otyper, o & !(1u32 << RST_PIN));

    // OSPEEDR[9:8] = 01 (medium speed)
    let s = read_volatile(ospeedr);
    write_volatile(ospeedr, (s & !mask) | (0b01u32 << (2 * RST_PIN)));

    // PUPDR[9:8] = 00 (no pull)
    let pu = read_volatile(pupdr);
    write_volatile(pupdr, pu & !mask);
}

/// Configure PE4 as push-pull output, drive high (release chip reset).
///
/// Safe to call multiple times. Only touches bits for pin 4; PE0..PE3
/// and PE5..PE15 are left alone.
pub unsafe fn init() {
    enable_gpioe_clock();
    config_pe4_output_high();
    // 50 ms idle-high settle before the first pulse, matching the lead-
    // in delay in `pin_diag::run`.
    cortex_m::asm::delay(160_000 * 50);
}

/// Pulse PE4 low for ~10 ms, then high, then wait ~50 ms for the chip
/// to finish its internal boot. The 50 ms matches the same settle delay
/// we use in `OptigaTrustM::init` before probing I²C.
pub unsafe fn hard_pulse() {
    let bsrr = (GPIOE_BASE + 0x18) as *mut u32;

    // Re-apply output config defensively in case some later peripheral
    // init reconfigured PE4 between our last `init()` and now.
    config_pe4_output_high();

    // Pulse low for 10 ms.
    write_volatile(bsrr, 1u32 << (16 + RST_PIN));
    cortex_m::asm::delay(1_600_000);

    // Release high.
    write_volatile(bsrr, 1u32 << RST_PIN);

    // Settle 50 ms before the caller probes the chip over I²C.
    cortex_m::asm::delay(8_000_000);
}
