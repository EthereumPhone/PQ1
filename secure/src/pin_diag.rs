//! GPIO pulse-sequence helper used by the OPTIGA hard-reset path, plus
//! an optional broad-sweep Arduino-header identifier.
//!
//! ## Current state (2026-04-23)
//!
//! - `run()` is the minimal OPTIGA RST primitive: pulses PA4 (decoy),
//!   PD5 (decoy), PE0 (Arduino D6 = OPTIGA RST wire) with a 50 ms
//!   priming delay. Invoked by `OptigaTrustM::hard_reset_and_reinit`.
//! - `header_sweep()` (gated on `pin-diag-boot`) pulses every plausible
//!   Arduino digital-header STM32 candidate with a unique width, so a
//!   single LA capture cross-references pin → header position. Used
//!   only during bring-up diagnostics, never in production.
//!
//! ## History (the traps this file exists to avoid)
//!
//! UM2839 Table 24 lists `D5 = PE0` and `D6 = PB6`. Empirical LA
//! captures on this specific B-U585I-IOT02A disagree with both: the
//! old RST wire on "D5" actually drove PE4, and the new RST wire on
//! "D6" actually drives PE0 (confirmed 2026-04-23 via `header_sweep()`
//! + LA CH2 on the physical RST jumper). Cause unknown — either the
//! silkscreen is shifted, the shield re-maps headers, or UM2839's
//! table is for a different board revision. **Always verify with
//! `header_sweep()` before retargeting RST_PIN.**
//!
//! ## Why the minimal `run()` is longer than a single BSRR toggle
//!
//! An earlier "enable GPIOE clock + BSRR toggle PE0" implementation
//! produced *no visible edge* on the LA when invoked from
//! `hard_reset_and_reinit`, while the longer "enable GPIOA/D/E clocks
//! + configure all three pins + 50 ms priming delay + two decoy
//! pulses + real pulse" sequence *did*. Best guess is a silicon /
//! clock-propagation quirk specific to this mask revision plus the
//! `optiga::init` call stack. Not fully root-caused; keep the full
//! sequence until it is.
//!
//! ## Critically NOT pulsed in `run()`
//!
//! `PE4` (the *old* Arduino D5 header) is NEVER pulsed here. That pin
//! routes through the OM-SE050ARD shield to SE050's ENA line. Pulsing
//! PE4 while SE050 is mid-NVM-write corrupted `ENTROPY_OBJ` across
//! reboots — the exact bug this whole wire move was done to fix.
//! `header_sweep()` may pulse PE4 for diagnostic purposes but is
//! explicitly gated out of production builds.
//!
//! Module is gated on `stm32u585 + optiga-trust-m` in `main.rs`.

#![cfg(feature = "stm32u585")]

use core::ptr::{read_volatile, write_volatile};

const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;

const GPIOA_BASE: u32 = 0x5202_0000;
const GPIOB_BASE: u32 = 0x5202_0400;
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

/// OPTIGA hard-reset primitive: configure PE0 (= Arduino D6 header on
/// this B-U585I-IOT02A) as output, plus two disconnected preamble
/// pins, then pulse PA4 / PD5 / PE0 in sequence with a 50 ms priming
/// delay up front.
///
/// The preamble pulses on PA4 and PD5 are *electrically* no-ops (those
/// pins aren't wired to anything on our stack) but functionally load-
/// bearing: an earlier minimal "enable GPIOE clock + BSRR toggle PE0"
/// implementation produced no visible edge on the LA when invoked from
/// `OptigaTrustM::hard_reset_and_reinit`, while this longer init + two
/// decoy pulses + 50 ms priming sequence *did*. The root cause is some
/// silicon / clock-propagation quirk specific to this mask revision —
/// documented but not fully isolated. Keep the full sequence as-is
/// until that is understood.
///
/// Gated on `stm32u585 + optiga-trust-m` in `main.rs`. Pulses only
/// `PA4`, `PD5`, `PE0` — **critically, does NOT touch PE4** (Arduino
/// D5, wired through the OM-SE050ARD shield to SE050's ENA line),
/// which would cause a mid-NVM-write SE050 power cycle. That
/// cross-coupling was the motivation for moving the RST wire off D5
/// in the first place.
pub fn run() {
    rcc_enable(0);  // GPIOAEN
    rcc_enable(3);  // GPIODEN
    rcc_enable(4);  // GPIOEEN

    unsafe {
        config_output_high(GPIOA_BASE, 4); // PA4 (disconnected preamble)
        config_output_high(GPIOD_BASE, 5); // PD5 (disconnected preamble)
        config_output_high(GPIOE_BASE, 0); // PE0 — OPTIGA RST on this board

        // Priming delay matching the timing profile we empirically
        // confirmed produces a visible edge.
        cortex_m::asm::delay(160_000 * 50);

        pulse_low(GPIOA_BASE, 4,  5);  // PA4 (disconnected, harmless)
        pulse_low(GPIOD_BASE, 5, 10);  // PD5 (disconnected, harmless)
        pulse_low(GPIOE_BASE, 0, 20);  // PE0 — OPTIGA silicon reset

        // Trailing idle high (matches the 50 ms settle in `OptigaTrustM::init`).
        cortex_m::asm::delay(160_000 * 100);
    }
}

/// Broad-sweep Arduino-header pin identifier. Pulses every plausible
/// D-header STM32 candidate with a unique width so one LA capture can
/// cross-reference pin → channel.
///
/// Only built when the `pin-diag-boot` feature is on — NOT run during
/// normal OPTIGA operation (pulsing PE4 in normal flow would re-create
/// the SE050 ENA cross-coupling bug).
///
/// Empirical calibration: `cortex_m::asm::delay(160_000 * n)` wall-
/// clocks to ~3·n ms on this target (3-cycle loop body). So each
/// `code_ms` below corresponds to ~3·code_ms actual pulse width.
#[cfg(feature = "pin-diag-boot")]
pub fn header_sweep() {
    rcc_enable(0);  // GPIOAEN
    rcc_enable(1);  // GPIOBEN
    rcc_enable(2);  // GPIOCEN
    rcc_enable(3);  // GPIODEN
    rcc_enable(4);  // GPIOEEN
    rcc_enable(5);  // GPIOFEN

    const GPIOC_BASE: u32 = 0x5202_0800;
    const GPIOF_BASE: u32 = 0x5202_1400;

    unsafe {
        config_output_high(GPIOA_BASE, 4);   // PA4
        config_output_high(GPIOE_BASE, 0);   // PE0  — new empirical D6
        config_output_high(GPIOE_BASE, 4);   // PE4  — old empirical D5
        config_output_high(GPIOB_BASE, 6);   // PB6  — UM2839 D6
        config_output_high(GPIOE_BASE, 5);   // PE5
        config_output_high(GPIOE_BASE, 7);   // PE7  — UM2839 D4
        config_output_high(GPIOF_BASE, 13);  // PF13 — UM2839 D7
        config_output_high(GPIOB_BASE, 2);   // PB2  — UM2839 D3
        config_output_high(GPIOD_BASE, 15);  // PD15 — UM2839 D2
        config_output_high(GPIOC_BASE, 1);   // PC1  — UM2839 D8
        config_output_high(GPIOA_BASE, 8);   // PA8  — UM2839 D9

        cortex_m::asm::delay(160_000 * 50);

        // code_ms → ~3× wall-clock ms.
        pulse_low(GPIOA_BASE, 4,  10);  //  30 ms
        pulse_low(GPIOE_BASE, 0,  20);  //  60 ms — expected D6 winner
        pulse_low(GPIOE_BASE, 4,  30);  //  90 ms — old D5
        pulse_low(GPIOB_BASE, 6,  40);  // 120 ms
        pulse_low(GPIOE_BASE, 5,  50);  // 150 ms
        pulse_low(GPIOE_BASE, 7,  60);  // 180 ms
        pulse_low(GPIOF_BASE, 13, 70);  // 210 ms
        pulse_low(GPIOB_BASE, 2,  80);  // 240 ms
        pulse_low(GPIOD_BASE, 15, 90);  // 270 ms
        pulse_low(GPIOC_BASE, 1,  100); // 300 ms
        pulse_low(GPIOA_BASE, 8,  120); // 360 ms

        cortex_m::asm::delay(160_000 * 100);
    }
}
