//! GPIO-driven hard reset of the OPTIGA Trust M via the chip's RST line.
//!
//! The pin comes from [`crate::board::OPTIGA_RST`]:
//!
//! | Board | RST pin | Provenance |
//! |---|---|---|
//! | `iota2` | **PE0** (Arduino `D6`) | empirical — LA capture, see below |
//! | `pq1` | **PA15** (`SE_RST`) | schematic `AL_A66_MB_V10`, sheet 1 |
//!
//! `pq1`'s pin needs none of the archaeology below: it is a named net on a
//! schematic we hold. The dev-board history is kept because the *write
//! ordering* it established is silicon-level rather than pin-level, so it
//! governs both boards.
//!
//! ## Dev-board (`iota2`) history
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
//! The chip's RST is active-low: driving the pin low holds the chip in
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

const RCC_AHB2ENR1: *mut u32 = (crate::board::RCC_S + crate::board::RCC_AHB2ENR1_OFF) as *mut u32;

/// Whether this board drives an OPTIGA reset line at all. A board without
/// one leaves `init`/`pulse` as no-ops rather than writing to a pin that
/// does not exist — on a package that silently accepts such writes, an
/// unconditional store would be an invisible bug.
const HAS_RST: bool = crate::board::OPTIGA_RST.is_some();

/// RST port base, secure alias. Falls back to GPIOA when the board has no
/// reset line; `HAS_RST` gates every use, so the fallback is never touched.
const RST_PORT: u32 = match crate::board::OPTIGA_RST {
    Some((port, _)) => port,
    None => crate::board::GPIOA_S,
};
const RST_PIN: u32 = match crate::board::OPTIGA_RST {
    Some((_, pin)) => pin,
    None => 0,
};

/// `RCC_AHB2ENR1` bit clocking the RST port.
const RST_PORT_RCC_BIT: u32 = crate::board::gpio_rcc_bit(RST_PORT);

/// Enable the RST port's bus clock. Idempotent.
unsafe fn enable_rst_port_clock() {
    // SAFETY: caller contract — `RCC_AHB2ENR1` is the secure-alias RCC
    // register and this is a disjoint-bit read-modify-write.
    unsafe {
        let v = read_volatile(RCC_AHB2ENR1);
        write_volatile(RCC_AHB2ENR1, v | RST_PORT_RCC_BIT);
    }
    cortex_m::asm::dsb();
}

/// Configure the RST pin as push-pull output driving high, matching the
/// full MODER/OTYPER/OSPEEDR/PUPDR sequence from
/// `pin_diag::config_output_high`.
unsafe fn config_rst_output_high() {
    let moder = RST_PORT as *mut u32;
    let otyper = (RST_PORT + 0x04) as *mut u32;
    let ospeedr = (RST_PORT + 0x08) as *mut u32;
    let pupdr = (RST_PORT + 0x0C) as *mut u32;
    let bsrr = (RST_PORT + 0x18) as *mut u32;

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

/// Configure the board's RST pin as a push-pull output and drive it
/// high (releasing chip reset). No-op on a board with no RST line.
///
/// Safe to call multiple times. Only touches bits for `RST_PIN`; the
/// other 15 pins of the port are left alone.
pub unsafe fn init() {
    if !HAS_RST {
        return;
    }
    // SAFETY: caller contract, forwarded to the two helpers.
    unsafe {
        enable_rst_port_clock();
        config_rst_output_high();
    }
    // 50 ms idle-high settle before the first pulse, matching the lead-
    // in delay in `pin_diag::run`.
    cortex_m::asm::delay(160_000 * 50);
}

/// Datasheet-bounded RST low time: 10 us <= t_low <= 2.5 ms (OPTIGA Trust M
/// V3 datasheet v3.70, Table 14). 64_000 cycles is 0.4 ms NOMINAL at 160 MHz
/// but ~1.2 ms wall-clock: `cortex_m::asm::delay` costs about three cycles per
/// iteration. `pin_diag::RST_LOW_CYCLES` documents that calibration and uses
/// the same value; an earlier version of this comment quoted the nominal
/// figure past the source that corrects it. ~1.2 ms is comfortably inside the
/// 10 us..2.5 ms window from both sides.
const RST_LOW_CYCLES: u32 = 64_000;

/// Drive a full LOW->HIGH reset pulse on the board's OPTIGA RST line.
///
/// This is the board-aware equivalent of the reset half of `pin_diag::run`,
/// and it exists because that function is **not** board-aware: it hardcodes
/// the iota2 map (`PA4`/`PD5`/`PE0`) and never reads [`crate::board::
/// OPTIGA_RST`]. On pq1 that would pulse PE0 — a pin the 48-pin package does
/// not bond — leave the real reset (PA15) untouched, and drive PA4, which is
/// `LCD_CS` there, under a comment calling it "disconnected, harmless".
///
/// What is deliberately NOT carried over: pin_diag's two "decoy" pulses on
/// PA4 and PD5. Those are iota2 artifacts from the bring-up sweep that
/// identified which header pin the RST wire was actually on; they are inert
/// on that board because both pads are unconnected there. They are not inert
/// on pq1, so reproducing them would be reproducing the bug.
///
/// Timing matches pin_diag exactly: 50 ms idle-high priming, a 400 us low
/// pulse, then 100 ms trailing idle high before the caller's own settle.
/// No-op on a board with no RST line.
///
/// # Safety
/// Same contract as [`init`]: single-threaded secure-world boot path, and
/// only this pin's bits in the RST port are touched.
pub unsafe fn hard_pulse() {
    if !HAS_RST {
        return;
    }
    // SAFETY: caller contract, forwarded to the helpers; BSRR is a
    // write-only atomic set/reset register so the low/high edges need no RMW.
    unsafe {
        init(); // clock + push-pull output high + 50 ms priming settle

        let bsrr = (RST_PORT + 0x18) as *mut u32;
        write_volatile(bsrr, 1u32 << (RST_PIN + 16)); // reset bit n -> drive LOW
        cortex_m::asm::delay(RST_LOW_CYCLES);
        write_volatile(bsrr, 1u32 << RST_PIN); // set bit n -> release HIGH

        // Trailing idle high, matching `pin_diag::run`'s 100 ms.
        cortex_m::asm::delay(160_000 * 100);
    }
}

