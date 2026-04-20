//! GPIO pulse-sequence helper used by the OPTIGA hard-reset path.
//!
//! Originally written as a one-shot D5-pin identification diagnostic:
//! toggles PA4, PD5, PE0, PE4 with distinct pulse widths and observes
//! which one shows up on the logic analyzer probe attached to the
//! Arduino D5 header. That experiment identified PE4 on the B-U585I-
//! IOT02A — see `optiga/reset_pin.rs` for the full write-up.
//!
//! After the identification was done, we found a secondary surprise:
//! a minimal "enable GPIOE clock + pulse PE4 via BSRR" sequence did
//! *not* produce a visible edge on CH2 when invoked from
//! `OptigaTrustM::hard_reset_and_reinit`, while the longer "enable
//! GPIOA/D/E clocks + configure all four pins + 50 ms priming delay"
//! sequence in `run()` below *did*. We haven't fully root-caused the
//! difference — best guess is a silicon / clock-propagation quirk
//! specific to this mask revision plus the `optiga::init` call stack.
//! Until we do, the OPTIGA driver invokes this module's `run()`
//! directly as its hard-reset primitive. The three disconnected
//! candidate pins (PA4, PD5, PE0) are safe to toggle — none of them
//! route to anything on our bring-up setup.
//!
//! Not on the path for non-OPTIGA boards; module is gated on
//! `stm32u585 + optiga-trust-m` in `main.rs`.

#![cfg(feature = "stm32u585")]

use core::ptr::{read_volatile, write_volatile};

const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;

const GPIOA_BASE: u32 = 0x5202_0000;
const GPIOD_BASE: u32 = 0x5202_0C00;
const GPIOE_BASE: u32 = 0x5202_1000;

fn rcc_enable(bit_pos: u32) {
    // SAFETY: read/write of the secure RCC AHB2ENR1 register. Single-
    // threaded boot, no races.
    unsafe {
        let v = read_volatile(RCC_AHB2ENR1);
        write_volatile(RCC_AHB2ENR1, v | (1 << bit_pos));
    }
}

/// Configure `GPIO<port>` pin `p` (0..=15) as push-pull output, initial high.
unsafe fn config_output_high(port_base: u32, p: u32) {
    debug_assert!(p <= 15);
    let moder = port_base as *mut u32; // offset 0x00
    let otyper = (port_base + 0x04) as *mut u32;
    let ospeedr = (port_base + 0x08) as *mut u32;
    let pupdr = (port_base + 0x0C) as *mut u32;
    let bsrr = (port_base + 0x18) as *mut u32;

    // Drive high first (bits 0..15 set, 16..31 reset).
    write_volatile(bsrr, 1u32 << p);

    // MODER[2p+1:2p] = 01 (output)
    let mask = 0b11u32 << (2 * p);
    let m = read_volatile(moder);
    write_volatile(moder, (m & !mask) | (0b01u32 << (2 * p)));

    // OTYPER[p] = 0 (push-pull)
    let o = read_volatile(otyper);
    write_volatile(otyper, o & !(1u32 << p));

    // OSPEEDR[2p+1:2p] = 01 (medium)
    let s = read_volatile(ospeedr);
    write_volatile(ospeedr, (s & !mask) | (0b01u32 << (2 * p)));

    // PUPDR[2p+1:2p] = 00 (no pull)
    let pu = read_volatile(pupdr);
    write_volatile(pupdr, pu & !mask);
}

unsafe fn pulse_low(port_base: u32, p: u32, ms: u32) {
    let bsrr = (port_base + 0x18) as *mut u32;
    // Reset bit: BSRR bit (16 + p)
    write_volatile(bsrr, 1u32 << (16 + p));
    cortex_m::asm::delay(160_000 * ms); // 160 MHz × ms → ms-long delay
    // Set bit
    write_volatile(bsrr, 1u32 << p);
    // Gap high between pulses
    cortex_m::asm::delay(160_000 * 5);
}

/// Enable GPIOA/D/E clocks, configure PA4/PD5/PE0/PE4 as push-pull
/// outputs, then pulse each one low in sequence with a distinct width.
///
/// Historical purpose: identify which STM32 pin was actually wired to
/// the Arduino D5 header on the B-U585I-IOT02A (PE4 for our shield).
/// Current purpose: double as the OPTIGA hard-reset sequence — the
/// PE4 pulse at the end is what actually resets the OPTIGA. See the
/// module-level doc for why this longer sequence is used instead of
/// a minimal BSRR toggle.
pub fn run() {
    // Enable all GPIO clocks we might touch.
    rcc_enable(0);  // GPIOAEN
    rcc_enable(3);  // GPIODEN
    rcc_enable(4);  // GPIOEEN

    unsafe {
        config_output_high(GPIOA_BASE, 4); // PA4
        config_output_high(GPIOD_BASE, 5); // PD5
        config_output_high(GPIOE_BASE, 0); // PE0
        config_output_high(GPIOE_BASE, 4); // PE4 — OPTIGA RST on this board

        // Priming delay before the first pulse; matches the timing
        // profile we empirically confirmed produces a visible edge.
        cortex_m::asm::delay(160_000 * 50);

        pulse_low(GPIOA_BASE, 4,  5); // PA4 (disconnected, harmless)
        pulse_low(GPIOD_BASE, 5, 10); // PD5 (disconnected, harmless)
        pulse_low(GPIOE_BASE, 0, 15); // PE0 (disconnected, harmless)
        pulse_low(GPIOE_BASE, 4, 20); // PE4 — OPTIGA silicon reset

        // Trailing idle high (matches the 50 ms settle in `OptigaTrustM::init`).
        cortex_m::asm::delay(160_000 * 100);
    }
}
