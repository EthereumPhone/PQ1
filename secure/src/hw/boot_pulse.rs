//! Early-boot GPIO bisection diagnostic on PE13 (Arduino D13 on the
//! B-U585I-IOT02A — verified via `secure/src/hw/spi_hw.rs`'s SPI1
//! arduino-pinout block; PE13 is the standard SPI1_SCK pin and is
//! free in builds without `spi1-arduino` / `tropic01-se`).
//!
//! Used when stepping to RDP ≥ 1 where neither SWD halt nor USART
//! output works as a diagnostic — wire an LA1010 channel to D5 + GND,
//! count the pulse groups in the trace to identify which boot stage
//! the firmware reached before hanging.
//!
//! ## Silicon quirk: minimal init doesn't drive an edge
//!
//! On this STM32U585 mask revision, a minimal "enable GPIOE clock +
//! configure pin + toggle BSRR" sequence produces no visible LA edge.
//! Documented in `pin_diag.rs::run`'s docstring; the workaround is
//! to also enable GPIOA + GPIOD clocks, configure decoy outputs on
//! PA4 + PD5, and insert a 50 ms priming delay before toggling. The
//! decoy pulses are electrically no-ops (PA4/PD5 aren't wired) but
//! functionally load-bearing — without them the real edge never
//! propagates. Root cause not isolated; preserved here verbatim.
//!
//! ## Pulse encoding
//!
//! Each call to `pulse(N)` emits N short HIGH/LOW pulses with a long
//! LOW gap after the group. Stage encoding:
//!   1 → entered `main` (before `reset_cause`)
//!   2 → after `rcc::init`
//!   3 → after `hash::init_clock`
//!   4 → after `sau::init`
//!   5 → after `rng::init`
//!   6 → in `saes_self_test_and_halt`, just before `uart::init`
//!   7 → after `uart::init` returned
//!
//! If RDP1 trace shows stages 1..K but never K+1, stage K+1 hangs.
//! If RDP1 trace shows nothing at all, the CPU never reached `main` —
//! the hang is inside cortex-m-rt's Reset_Handler (which does .data
//! init, .bss zero, etc.) or the chip's RSS never handed control to
//! firmware at all.

#![cfg(feature = "boot-pulse")]

use core::ptr::{read_volatile, write_volatile};

// Secure RCC alias — under TZEN=1 GPIOA/D/E are secure-by-default and
// AHB2ENR1 GPIO* clock-enable bits must be written via the Secure alias.
const RCC_AHB2ENR1: *mut u32 = 0x5602_0C8C as *mut u32;

// GPIO Secure aliases.
const GPIOA_BASE: u32 = 0x5202_0000;
const GPIOD_BASE: u32 = 0x5202_0C00;
const GPIOE_BASE: u32 = 0x5202_1000;

// PE13 = Arduino D13 on this board (SPI1_SCK in our spi_hw.rs).
// Free in builds without `spi1-arduino` / `tropic01-se`. PE4 (= D5)
// is unusable as a probe target because the OM-SE050ARD shield
// routes it to SE050 ENA, masking GPIO drives.
const TARGET_PIN: u32 = 13;

unsafe fn rcc_enable_gpio(bit: u32) {
    let v = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, v | (1 << bit));
    cortex_m::asm::dsb();
}

/// Configure `GPIO<port>` pin `p` (0..=15) as push-pull output, initial high.
unsafe fn config_output_high(port_base: u32, p: u32) {
    let moder = port_base as *mut u32;
    let otyper = (port_base + 0x04) as *mut u32;
    let ospeedr = (port_base + 0x08) as *mut u32;
    let pupdr = (port_base + 0x0C) as *mut u32;
    let bsrr = (port_base + 0x18) as *mut u32;

    // Drive high first (matches `pin_diag.rs` ordering — set BSRR
    // before reconfiguring MODER so the first edge happens *as* we
    // flip into output mode rather than after a window of analog).
    write_volatile(bsrr, 1u32 << p);

    let mask = 0b11u32 << (2 * p);
    let m = read_volatile(moder);
    write_volatile(moder, (m & !mask) | (0b01u32 << (2 * p)));
    let o = read_volatile(otyper);
    write_volatile(otyper, o & !(1u32 << p));
    let s = read_volatile(ospeedr);
    write_volatile(ospeedr, (s & !mask) | (0b01u32 << (2 * p)));
    let pu = read_volatile(pupdr);
    write_volatile(pupdr, pu & !mask);
}

/// Initialize the boot-pulse pin. Replicates the GPIO-port priming
/// pattern from `pin_diag::run` because a minimal single-port init
/// produces no electrical edge on this silicon (root cause not
/// isolated; documented in `pin_diag::run`).
///
/// # Safety
/// Touches RCC + multiple GPIO ports via Secure aliases. Caller must
/// ensure this runs once early in boot.
pub unsafe fn init() {
    rcc_enable_gpio(0); // GPIOAEN
    rcc_enable_gpio(3); // GPIODEN
    rcc_enable_gpio(4); // GPIOEEN

    // Decoy outputs — electrically no-ops on this stack but
    // functionally load-bearing per `pin_diag::run` docstring.
    config_output_high(GPIOA_BASE, 4);
    config_output_high(GPIOD_BASE, 5);

    // The actual diagnostic pin. Configured as output HIGH initially —
    // the first pulse() call will lower it to mark the start of group 1.
    config_output_high(GPIOE_BASE, TARGET_PIN);

    // Drive LOW so the first HIGH edge is unambiguous in the trace.
    let bsrr = (GPIOE_BASE + 0x18) as *mut u32;
    write_volatile(bsrr, 1u32 << (TARGET_PIN + 16));

    // Priming delay — small in cycle count because we're at MSIS 4 MHz
    // pre-RCC, where each cycle is 40× longer than post-RCC. 10 000
    // cycles = ~2.5 ms at MSIS, ~62 µs at 160 MHz; either is enough
    // for the silicon quirk's settling window per pin_diag::run.
    cortex_m::asm::delay(10_000);

}

/// Emit `count` HIGH/LOW pulses on PE4, then a long LOW gap so the
/// next pulse group is visually distinct in the LA1010 trace.
///
/// # Safety
/// `init()` must have run.
pub unsafe fn pulse(count: u8) {
    let bsrr = (GPIOE_BASE + 0x18) as *mut u32;
    let set: u32 = 1 << TARGET_PIN;
    let reset: u32 = 1 << (TARGET_PIN + 16);

    for _ in 0..count {
        write_volatile(bsrr, set);
        // ~80_000 cycles ≈ 20 ms at MSIS 4 MHz / ~500 µs at 160 MHz.
        // Comfortably visible at 1 MS/s in both clock regimes.
        cortex_m::asm::delay(80_000);
        write_volatile(bsrr, reset);
        cortex_m::asm::delay(80_000);
    }
    // Long LOW gap so consecutive groups are visually distinct.
    cortex_m::asm::delay(800_000);
}
