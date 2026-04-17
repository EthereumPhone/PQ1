//! GPIO-driven hard reset of the OPTIGA Trust M via the chip's RST line.
//!
//! On the dev setup (B-U585I-IOT02A + OPTIGA MTR Express V3 on a
//! breadboard), the MTR board's `RST` pin is jumpered to Arduino **D5**,
//! which on the B-U585I-IOT02A's CN13 header is STM32 pin **PE0**.
//!
//! The chip's RST is active-low: driving PE0 low holds the chip in reset,
//! driving high (or floating — chip has an internal pull-up) releases it.
//! We drive the pin explicitly rather than leaving it to the pull-up so
//! that a brownout or glitch on the breadboard rail cannot silently put
//! the chip in reset mid-session.
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
const GPIOE_MODER:   *mut u32 = 0x5202_1000 as *mut u32; // +0x00
const GPIOE_OTYPER:  *mut u32 = 0x5202_1004 as *mut u32; // +0x04
const GPIOE_OSPEEDR: *mut u32 = 0x5202_1008 as *mut u32; // +0x08
const GPIOE_PUPDR:   *mut u32 = 0x5202_100C as *mut u32; // +0x0C
const GPIOE_BSRR:    *mut u32 = 0x5202_1018 as *mut u32; // +0x18

const RCC_GPIOEEN: u32 = 1 << 4;

/// PE0 bit position in BSRR: set bit 0, reset bit 16.
const BSRR_PE0_SET:   u32 = 1 << 0;
const BSRR_PE0_RESET: u32 = 1 << 16;

/// Configure PE0 as push-pull output, drive high (release chip reset).
///
/// Safe to call multiple times. Does not touch any pin other than PE0
/// and does not disturb pins PE1..PE15 (they remain whatever the rest
/// of the firmware configured them to be).
pub unsafe fn init() {
    // 1. Enable the GPIOE bus clock. Idempotent — OR in the bit.
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | RCC_GPIOEEN);

    // 2. Drive high BEFORE switching to output so there's no low-glitch.
    write_volatile(GPIOE_BSRR, BSRR_PE0_SET);

    // 3. PE0: push-pull output, medium speed, no pull. Only touch bits
    //    [1:0] of each register so PE1..PE15 are left alone.
    let moder = read_volatile(GPIOE_MODER);
    write_volatile(GPIOE_MODER, (moder & !0x0000_0003) | 0x0000_0001);    // 01 = output

    let otyper = read_volatile(GPIOE_OTYPER);
    write_volatile(GPIOE_OTYPER, otyper & !0x0000_0001);                  // 0 = push-pull

    let ospeedr = read_volatile(GPIOE_OSPEEDR);
    write_volatile(GPIOE_OSPEEDR, (ospeedr & !0x0000_0003) | 0x0000_0001); // 01 = medium

    let pupdr = read_volatile(GPIOE_PUPDR);
    write_volatile(GPIOE_PUPDR, pupdr & !0x0000_0003);                    // 00 = no pull
}

/// Pulse PE0 low for ~10 ms, then high, then wait ~50 ms for the chip
/// to finish its internal boot. The 50 ms matches the same settle delay
/// we use in `OptigaTrustM::init` before probing I²C.
pub unsafe fn hard_pulse() {
    write_volatile(GPIOE_BSRR, BSRR_PE0_RESET);
    // ~10 ms at 160 MHz = 1.6M cycles. `delay` has a volatile counter so
    // LTO can't elide it.
    cortex_m::asm::delay(1_600_000);
    write_volatile(GPIOE_BSRR, BSRR_PE0_SET);
    // Match the cold-boot settle in `OptigaTrustM::init()`.
    cortex_m::asm::delay(8_000_000);
}
