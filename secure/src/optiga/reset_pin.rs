//! GPIO-driven hard reset of the OPTIGA Trust M via the chip's RST line.
//!
//! On the dev setup (B-U585I-IOT02A + OPTIGA MTR Express V3 on a
//! breadboard), the MTR board's `RST` pin is jumpered to Arduino **D5**,
//! which on this board's solder-bridge configuration is STM32 pin
//! **PD5**. (An earlier bring-up iteration used PE0 under a different
//! solder-bridge selection; if a future board variant reroutes D5 back
//! to PE0, update the GPIO-port + pin-number constants below.)
//!
//! The chip's RST is active-low: driving PD5 low holds the chip in
//! reset, driving high (or floating — chip has an internal pull-up)
//! releases it. We drive the pin explicitly rather than leaving it to
//! the pull-up so that a brownout or glitch on the breadboard rail
//! cannot silently put the chip in reset mid-session.
//!
//! A hard pulse clears whatever per-session state has wedged the chip
//! after N successful APDUs (see `project_optiga_reset_oids.md`). Unlike
//! the `soft_reset()` that only toggles IFX I²C layer state, this is a
//! real silicon reset. NV OIDs survive (TA cert stays); volatile session
//! state (strict locks, SEC counter, etc.) resets.

#![cfg(feature = "stm32u585")]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// Register addresses (secure aliases)
// ---------------------------------------------------------------------------

const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;
const GPIOD_MODER:   *mut u32 = 0x5202_0C00 as *mut u32; // +0x00
const GPIOD_OTYPER:  *mut u32 = 0x5202_0C04 as *mut u32; // +0x04
const GPIOD_OSPEEDR: *mut u32 = 0x5202_0C08 as *mut u32; // +0x08
const GPIOD_PUPDR:   *mut u32 = 0x5202_0C0C as *mut u32; // +0x0C
const GPIOD_BSRR:    *mut u32 = 0x5202_0C18 as *mut u32; // +0x18

const RCC_GPIODEN: u32 = 1 << 3;

/// PD5 bit position in BSRR: set bit 5, reset bit (16 + 5) = 21.
const BSRR_PD5_SET:   u32 = 1 << 5;
const BSRR_PD5_RESET: u32 = 1 << 21;

/// Configure PD5 as push-pull output, drive high (release chip reset).
///
/// Safe to call multiple times. Only touches bits for pin 5 so
/// PD0..PD4 / PD6..PD15 are left alone.
pub unsafe fn init() {
    // 1. Enable the GPIOD bus clock. Idempotent — OR in the bit.
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | RCC_GPIODEN);

    // 2. Drive high BEFORE switching to output so there's no low-glitch.
    write_volatile(GPIOD_BSRR, BSRR_PD5_SET);

    // 3. PD5: push-pull output, medium speed, no pull. Each register's
    //    MODER / OSPEEDR / PUPDR field is 2 bits at [11:10] for pin 5;
    //    OTYPER is 1 bit at position 5.
    let moder = read_volatile(GPIOD_MODER);
    write_volatile(GPIOD_MODER, (moder & !0x0000_0C00) | 0x0000_0400);    // 01 = output

    let otyper = read_volatile(GPIOD_OTYPER);
    write_volatile(GPIOD_OTYPER, otyper & !0x0000_0020);                  // 0 = push-pull

    let ospeedr = read_volatile(GPIOD_OSPEEDR);
    write_volatile(GPIOD_OSPEEDR, (ospeedr & !0x0000_0C00) | 0x0000_0400); // 01 = medium

    let pupdr = read_volatile(GPIOD_PUPDR);
    write_volatile(GPIOD_PUPDR, pupdr & !0x0000_0C00);                    // 00 = no pull
}

/// Pulse PD5 low for ~10 ms, then high, then wait ~50 ms for the chip
/// to finish its internal boot. The 50 ms matches the same settle delay
/// we use in `OptigaTrustM::init` before probing I²C.
pub unsafe fn hard_pulse() {
    write_volatile(GPIOD_BSRR, BSRR_PD5_RESET);
    // ~10 ms at 160 MHz = 1.6M cycles. `delay` has a volatile counter so
    // LTO can't elide it.
    cortex_m::asm::delay(1_600_000);
    write_volatile(GPIOD_BSRR, BSRR_PD5_SET);
    // Match the cold-boot settle in `OptigaTrustM::init()`.
    cortex_m::asm::delay(8_000_000);
}
