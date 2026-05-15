//! GPIO-driven hard reset of the OPTIGA Trust M via the chip's RST line.
//!
//! On the B-U585I-IOT02A Discovery board the Arduino UNO R3 connector's
//! `D6` pin was empirically confirmed to be STM32U585 pin **PE0** via
//! `pin_diag::run()` + LA capture on 2026-04-23.
//!
//! This disagrees with ST's UM2839 Table 24, which lists `D5 = PE0` and
//! `D6 = PB6`. Earlier on this same board the old "D5 header" also
//! resolved to a different pin than UM2839 claimed (it was PE4, not
//! PE0). The consistent observation is that the silkscreen / Arduino
//! header positions on this specific board are offset by one slot from
//! UM2839's table. When re-targeting the RST pin, ALWAYS use
//! `pin_diag::run()` + LA capture to verify, never the manual.
//!
//! Why we moved the RST wire off D5 (PE4): the OM-SE050ARD shield
//! routes its Arduino `D5` header to the SE050's ENA (enable) line.
//! Driving PE4 low to reset the OPTIGA also powered down the SE050
//! mid-NVM-write, corrupting `ENTROPY_OBJ` and producing the
//! "reconstruction works once, fails after reboot" symptom. D6 on the
//! OM-SE050ARD has no SE050 net, so OPTIGA resets no longer disturb
//! SE050 NVM.
//!
//! The chip's RST is active-low: driving PE0 low holds the chip in
//! reset, driving high (or floating — chip has an internal pull-up)
//! releases it. We drive the pin explicitly rather than leaving it to
//! the pull-up so that a brownout or glitch on the breadboard rail
//! cannot silently put the chip in reset mid-session.
//!
//! ## Implementation note
//!
//! The init + toggle sequence mirrors the one in `pin_diag::run()` that
//! we empirically know produces a visible edge on the logic analyzer
//! (originally validated on PE4; the write-ordering quirk is silicon-
//! level, not pin-level, so the same pattern applies to PE5). An earlier
//! pure-BSRR implementation in this file did *not* yield a visible edge
//! in the same wiring — something about the write sequencing on this
//! particular silicon revision made the BSRR stores disappear even with
//! DSB barriers. The pattern we now use (OR in the RCC bit, then a full
//! read-modify-write on MODER/OTYPER/OSPEEDR/PUPDR *before* any BSRR
//! store, then 50 ms idle-high settle) is the one that survives that
//! silicon quirk.

#![cfg(feature = "stm32u585")]

use core::ptr::{read_volatile, write_volatile};

const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;
const GPIOE_BASE: u32 = 0x5202_1000;

const RCC_GPIOEEN_BIT: u32 = 4;
const RST_PIN: u32 = 0; // PE0 — empirically D6 on this B-U585I-IOT02A
                        // (LA capture 2026-04-23; UM2839 claims PB6
                        // but that mapping is wrong on this board).

/// Enable the GPIOE bus clock. Idempotent.
unsafe fn enable_gpioe_clock() {
    let v = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, v | (1 << RCC_GPIOEEN_BIT));
    cortex_m::asm::dsb();
}

/// Configure the RST pin as push-pull output driving high, matching the
/// full MODER/OTYPER/OSPEEDR/PUPDR sequence from
/// `pin_diag::config_output_high`.
unsafe fn config_rst_output_high() {
    let moder = GPIOE_BASE as *mut u32;
    let otyper = (GPIOE_BASE + 0x04) as *mut u32;
    let ospeedr = (GPIOE_BASE + 0x08) as *mut u32;
    let pupdr = (GPIOE_BASE + 0x0C) as *mut u32;
    let bsrr = (GPIOE_BASE + 0x18) as *mut u32;

    // Drive high first so there's no low-glitch when we flip to output.
    write_volatile(bsrr, 1u32 << RST_PIN);

    // MODER[2*RST_PIN+1 : 2*RST_PIN] = 01 (output)
    let mask = 0b11u32 << (2 * RST_PIN);
    let m = read_volatile(moder);
    write_volatile(moder, (m & !mask) | (0b01u32 << (2 * RST_PIN)));

    // OTYPER[RST_PIN] = 0 (push-pull)
    let o = read_volatile(otyper);
    write_volatile(otyper, o & !(1u32 << RST_PIN));

    // OSPEEDR[2*RST_PIN+1 : 2*RST_PIN] = 01 (medium speed)
    let s = read_volatile(ospeedr);
    write_volatile(ospeedr, (s & !mask) | (0b01u32 << (2 * RST_PIN)));

    // PUPDR[2*RST_PIN+1 : 2*RST_PIN] = 00 (no pull)
    let pu = read_volatile(pupdr);
    write_volatile(pupdr, pu & !mask);
}

/// Configure the RST pin (PE0, Arduino D6 header) as push-pull output,
/// drive high (release chip reset).
///
/// Safe to call multiple times. Only touches bits for `RST_PIN`; the
/// other 15 pins of GPIOE are left alone.
pub unsafe fn init() {
    enable_gpioe_clock();
    config_rst_output_high();
    // 50 ms idle-high settle before the first pulse, matching the lead-
    // in delay in `pin_diag::run`.
    cortex_m::asm::delay(160_000 * 50);
}

