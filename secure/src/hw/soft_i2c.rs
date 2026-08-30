//! Bit-banged I2C master for the bench OLED. **Not for secure elements.**
//!
//! Exists for one reason: the pq1 production board exposes exactly two free
//! GPIOs — `PB3` (the `SWO` pin on the debug header) and `PA3` (the `RX` pad,
//! free because the console is TX-only) — and **no I2C peripheral can reach
//! that pair**. `PB3`'s AF4 is `I2C1_SDA`, but that is the same peripheral the
//! OPTIGA occupies and a peripheral has one SDA pin; `PA3` has no I2C
//! alternate function at all (DS13086 Rev 10, Tables 28/29). PB8/PB9, the
//! natural choice, are not brought out on the board.
//!
//! So: software I2C, at roughly 100 kHz, which an SSD1306 pushing a 16x4
//! character grid does not remotely strain.
//!
//! ## Scope — read before reusing this
//!
//! This drives a **display**. It must never carry secure-element traffic. The
//! secure elements use the hardware peripherals via `hw::i2c_hw`, which gets
//! deterministic timing, hardware ACK detection, proper bus-error and
//! arbitration reporting, and — decisively — is covered by GTZC: I2C1/I2C2/I2C4
//! are marked SECURE in `sau::configure_gtzc`, so the non-secure world is
//! denied access to those buses. **A bit-banged bus has none of that.** It is
//! two GPIO pins; GTZC has no concept of it, so nothing stops NS from driving
//! the same pads if they were ever marked non-secure. That is acceptable for
//! pixels and unacceptable for anything else.
//!
//! Accordingly this module is only compiled under `ui-oled-bench`, which is a
//! bench feature in the Makefile's `PROD_FORBIDDEN` list.
//!
//! ## Electrical
//!
//! Both pins are configured as **open-drain outputs with the internal pull-up
//! enabled**: writing 1 releases the line (it floats up), writing 0 drives it
//! low. That is the correct I2C idiom and it means a slave stretching the
//! clock, or another master, cannot be shorted against. SSD1306 breakout
//! modules carry their own pull-ups (typically 4.7k-10k) to their VCC, which
//! sit in parallel with the internal ones; powering the module from the debug
//! header's 3V3 keeps everything at one rail.
//!
//! `IDR` reflects the pad level even while the pin is an output, which is how
//! the ACK bit is sampled without switching direction.
//!
//! ## What this deliberately does NOT implement
//!
//! Clock stretching is not honoured, multi-master arbitration is not detected,
//! and there is no bus-recovery sequence for a slave that hangs holding SDA
//! low. An SSD1306 does none of those things. If you find yourself wanting
//! them, you want a hardware peripheral, not this file.

#![cfg(all(feature = "ui-oled-bench", feature = "stm32u585"))]

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Compile-time guards
// ---------------------------------------------------------------------------

/// The board must actually name a pin pair for the bench OLED.
const SCL: (u32, u32) = match board::OLED_SCL {
    Some(p) => p,
    None => panic!("this board declares no bench-OLED SCL pin (board::OLED_SCL is None)"),
};
const SDA: (u32, u32) = match board::OLED_SDA {
    Some(p) => p,
    None => panic!("this board declares no bench-OLED SDA pin (board::OLED_SDA is None)"),
};

const _: () = assert!(
    !(SCL.0 == SDA.0 && SCL.1 == SDA.1),
    "the bench OLED's SCL and SDA are the same pin"
);

// PB3 is claimed by BOTH the bench OLED (as SCL) and the side-channel scope
// trigger on pq1. Both are bench-only and neither is load-bearing, but a
// silent double-claim would mean the SCA trigger toggles the display clock
// mid-capture — so it is a build error, not a surprise on the bench.
#[cfg(feature = "sca-trigger")]
const _: () = {
    let t = match board::SCA_TRIGGER {
        Some(p) => p,
        None => (u32::MAX, u32::MAX),
    };
    assert!(
        !(t.0 == SCL.0 && t.1 == SCL.1) && !(t.0 == SDA.0 && t.1 == SDA.1),
        "`ui-oled-bench` and `sca-trigger` both claim the same pin (PB3 on pq1). \
         They are mutually exclusive: the trigger would toggle the display clock \
         during a capture, and the display would corrupt the trigger edge. Pick one."
    );
};

// On iota2 the bench OLED pins ARE the secure-element bus (PB8/PB9). Bit-banging
// them while a real SE backend drives the same pads through the I2C1 peripheral
// is a direct conflict — one wants AF4 open-drain, the other GPIO output. pq1
// does not have this problem (PB3/PA3 are claimed by nothing else).
#[cfg(any(feature = "se050", feature = "optiga-trust-m"))]
const _: () = {
    let mut i = 0;
    while i < board::SE_I2C_BUSES.len() {
        let b = &board::SE_I2C_BUSES[i];
        assert!(
            !(b.port == SCL.0 && (b.scl_pin == SCL.1 || b.sda_pin == SCL.1))
                && !(b.port == SDA.0 && (b.scl_pin == SDA.1 || b.sda_pin == SDA.1)),
            "the bench OLED would bit-bang a pin that a secure element's I2C bus \
             also drives (on iota2 both are PB8/PB9). Build OLED images with \
             `mock-se`, or move the OLED pins."
        );
        i += 1;
    }
};

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Quarter-bit delay. Four of these per clock period puts the bus near
/// 100 kHz at the 160 MHz SYSCLK `hw::rcc::init` establishes.
///
/// `asm::delay` is roughly one iteration per cycle, so 160_000_000 / 100_000
/// = 1600 cycles per period, /4 = 400. Deliberately not calibrated against a
/// possible 16 MHz PLL fallback: running the display 10x slow is harmless,
/// whereas the secure-element buses that DO care about this are on hardware
/// peripherals with a real `TIMINGR`.
const QUARTER: u32 = 400;

fn q() {
    cortex_m::asm::delay(QUARTER);
}

// ---------------------------------------------------------------------------
// Pin primitives
// ---------------------------------------------------------------------------

const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;
const BSRR_OFF: u32 = 0x18;

/// Release a line: open-drain output written high floats, and the pull-ups
/// take it to VCC.
fn release(pin: (u32, u32)) {
    // SAFETY: `pin.0` is a GPIO base from `crate::board`; BSRR is a real
    // write-only register in that block. Writing the low half sets the bit.
    let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
    bsrr.write(1 << pin.1);
}

/// Drive a line low.
fn pull_low(pin: (u32, u32)) {
    // SAFETY: as `release`; the BSRR high half (bit 16+n) resets bit n.
    let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
    bsrr.write(1 << (pin.1 + 16));
}

/// Sample a line's actual level. Valid in output mode — `IDR` reflects the
/// pad, which is how the ACK is read without changing direction.
fn level(pin: (u32, u32)) -> bool {
    // SAFETY: as `release`; IDR is a real read-only register.
    let idr = unsafe { RoReg32::new(pin.0 + IDR_OFF) };
    idr.read() & (1 << pin.1) != 0
}

/// Configure one pin as an open-drain output, initially released.
fn config_open_drain(pin: (u32, u32)) {
    // SAFETY: `pin.0` is a GPIO base from `crate::board`, and every offset is
    // a register within that block. Single-threaded secure world; each field
    // is touched read-modify-write on this pin's bits alone.
    let (moder, otyper, ospeedr, pupdr) = unsafe {
        (
            Reg32::new(pin.0 + MODER_OFF),
            Reg32::new(pin.0 + OTYPER_OFF),
            Reg32::new(pin.0 + OSPEEDR_OFF),
            Reg32::new(pin.0 + PUPDR_OFF),
        )
    };
    let pin2 = pin.1 * 2;
    let field = 0b11u32 << pin2;

    release(pin); // set the latch high BEFORE enabling the output
    otyper.set_bits(1 << pin.1); // open-drain
    pupdr.modify(|v| (v & !field) | (0b01 << pin2)); // internal pull-up
    ospeedr.modify(|v| (v & !field) | (0b01 << pin2)); // medium is plenty at 100 kHz
    moder.modify(|v| (v & !field) | (0b01 << pin2)); // general-purpose output
}

// ---------------------------------------------------------------------------
// Bus primitives
// ---------------------------------------------------------------------------

fn start() {
    release(SDA);
    release(SCL);
    q();
    pull_low(SDA); // SDA falls while SCL is high
    q();
    pull_low(SCL);
    q();
}

fn stop() {
    pull_low(SDA);
    q();
    release(SCL);
    q();
    release(SDA); // SDA rises while SCL is high
    q();
}

/// Clock out one bit.
fn write_bit(bit: bool) {
    if bit {
        release(SDA);
    } else {
        pull_low(SDA);
    }
    q();
    release(SCL);
    q();
    q();
    pull_low(SCL);
    q();
}

/// Clock out a byte, MSB first, and return true if the slave ACKed.
fn write_byte(b: u8) -> bool {
    let mut i = 8;
    while i > 0 {
        i -= 1;
        write_bit(b & (1 << i) != 0);
    }
    // Ninth clock: release SDA and sample what the slave does with it.
    release(SDA);
    q();
    release(SCL);
    q();
    let acked = !level(SDA); // ACK = slave pulls SDA low
    q();
    pull_low(SCL);
    q();
    acked
}

// ---------------------------------------------------------------------------
// Public surface — deliberately identical to the removed `hw::i2c`
// ---------------------------------------------------------------------------

/// Configure both pins. Idempotent; call after `rcc::init()`.
pub fn init() {
    // SAFETY: the secure-alias AHB2ENR1; `gpio_rcc_bit` maps each port base to
    // its own enable bit, so this RMW touches no other driver's bit.
    let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
    enr.set_bits(board::gpio_rcc_bit(SCL.0) | board::gpio_rcc_bit(SDA.0));
    let _ = enr.read(); // propagation barrier — an unclocked port drops writes silently
    cortex_m::asm::dsb();

    config_open_drain(SCL);
    config_open_drain(SDA);
}

/// Write `data` to the 7-bit address `addr`. Returns true if every byte —
/// address included — was acknowledged.
///
/// Signature matches the `hw::i2c::write` this replaces, so the SSD1306 driver
/// needs no transport changes.
pub fn write(addr: u8, data: &[u8]) -> bool {
    start();
    let mut ok = write_byte(addr << 1); // R/W = 0 (write)
    if ok {
        for &b in data {
            if !write_byte(b) {
                ok = false;
                break;
            }
        }
    }
    stop();
    ok
}
