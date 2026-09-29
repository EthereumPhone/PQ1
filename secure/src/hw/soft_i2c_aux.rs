//! Bit-banged I2C master for the pq1 **auxiliary** bus — the two LED-driver
//! ICs on I2C2 (`PB13` = SCL, `PB14` = SDA, AF4), **never** a secure element.
//!
//! ## Why bit-banged, when these are real I2C2 pins
//!
//! Unlike the OLED bus in [`crate::hw::soft_i2c`] (PA2/PA3, where no I2C
//! peripheral can reach the pads at all), PB13/PB14 *are* `I2C2_SCL`/`I2C2_SDA`
//! on AF4, so the hardware peripheral is an option here. It is deliberately not
//! taken:
//!
//! - `hw::i2c_hw` is the **secure-element** bus manager (`board::SE_I2C_BUSES`),
//!   and widening it to a third, non-SE bus invites exactly the kind of
//!   accidental sharing invariant #3 exists to prevent.
//! - A bit-banged master has no kernel-clock dependency, so the same code works
//!   at any `SYSCLK` the boot path happens to have reached — which matters for a
//!   driver that runs from both a prodtest image and (later) the display path.
//! - It is empirically proven on this exact bus: the AW99703 backlight at `0x36`
//!   ACKs a bit-banged write on this board.
//!
//! The peripheral is nonetheless GTZC-SECURE (`sau.rs`, `SECCFGR1` bit 14) and
//! PB12/PB13/PB14 are never handed to the non-secure world, so NS cannot drive
//! these pads either way.
//!
//! ## Scope
//!
//! Same rule as [`crate::hw::soft_i2c`]: this carries brightness values, never
//! secret material. Do not put secure-element traffic on it. Unlike that module
//! it is *not* bench-only — the LED drivers are production parts — so the
//! transport is written to be pin-generic (the bus is a value, not a set of
//! constants) and both LED drivers instantiate it from `board::AUX_I2C_*`
//! rather than growing a private copy each.
//!
//! ## Electrical
//!
//! Both pins are open-drain outputs with the internal pull-up enabled: writing
//! 1 releases the line, 0 drives it low. R128/R129 (4.7 kΩ to 3V3) sit in
//! parallel on the board, next to the AW21036.
#![cfg(all(feature = "stm32u585", feature = "board-pq1"))]

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

/// Quarter-bit delay in core cycles. ≈100 kHz at 160 MHz; slower at any lower
/// `SYSCLK`, which is harmless — I2C has no minimum clock rate.
const QUARTER: u32 = 400;

// GPIO register offsets (RM0456 §12.7).
const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;
const BSRR_OFF: u32 = 0x18;

/// A bit-banged I2C bus on one `(port_base, pin)` pair per line.
pub struct AuxI2c {
    scl: (u32, u32),
    sda: (u32, u32),
}

impl AuxI2c {
    /// Bind the bus to its two pins. Does not touch hardware — call
    /// [`Self::init`] first.
    #[must_use]
    pub const fn new(scl: (u32, u32), sda: (u32, u32)) -> Self {
        Self { scl, sda }
    }

    /// The pq1 auxiliary bus from the board map.
    #[must_use]
    pub const fn board_aux() -> Self {
        Self::new(
            (board::AUX_I2C_PORT, board::AUX_I2C_SCL_PIN),
            (board::AUX_I2C_PORT, board::AUX_I2C_SDA_PIN),
        )
    }

    /// Clock the GPIO port and put both lines in open-drain-with-pull-up, idle
    /// high. Idempotent.
    pub fn init(&self) {
        // SAFETY: the secure-alias RCC AHB2ENR1; `gpio_rcc_bit` maps each port
        // to its own enable bit, so this RMW touches no other driver's bit.
        let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
        enr.set_bits(board::gpio_rcc_bit(self.scl.0) | board::gpio_rcc_bit(self.sda.0));
        let _ = enr.read();
        cortex_m::asm::dsb();
        self.config_open_drain(self.scl);
        self.config_open_drain(self.sda);
    }

    /// Address-only probe: START, address byte, STOP. No register access, so it
    /// is safe on an unknown part.
    ///
    /// Returns `true` if something ACKed `addr7`.
    pub fn probe(&self, addr7: u8) -> bool {
        self.start();
        let acked = self.write_byte(addr7 << 1);
        self.stop();
        acked
    }

    /// Probe every 7-bit address in the I2C-reserved-free range `0x08..=0x77`
    /// into a 128-bit bitmap: address `a` is bit `a % 8` of `bitmap[a / 8]`.
    pub fn scan(&self, bitmap: &mut [u8; 16]) {
        *bitmap = [0u8; 16];
        for addr in 0x08u8..=0x77 {
            if self.probe(addr) {
                bitmap[(addr >> 3) as usize] |= 1 << (addr & 0x07);
            }
        }
    }

    /// Single-register write. Returns `true` if every byte was ACKed.
    pub fn write_reg(&self, addr7: u8, reg: u8, val: u8) -> bool {
        self.start();
        let ok = self.write_byte(addr7 << 1) && self.write_byte(reg) && self.write_byte(val);
        self.stop();
        ok
    }

    /// Single-register read: write the address, repeated START, read one byte
    /// and NACK it (datasheet "read operation" sequence).
    ///
    /// `None` means some byte of the addressing phase was not ACKed — which is
    /// distinguishable from a chip that answers `0x00`, and is the reason this
    /// returns an `Option` rather than a `u8`.
    pub fn read_reg(&self, addr7: u8, reg: u8) -> Option<u8> {
        self.start();
        if !(self.write_byte(addr7 << 1) && self.write_byte(reg)) {
            self.stop();
            return None;
        }
        // Repeated START — no STOP in between, so the register pointer holds.
        self.release(self.sda);
        self.q();
        self.release(self.scl);
        self.q();
        self.pull_low(self.sda);
        self.q();
        self.pull_low(self.scl);
        self.q();
        if !self.write_byte((addr7 << 1) | 1) {
            self.stop();
            return None;
        }
        let val = self.read_byte();
        // NACK the only byte, then STOP: tells the slave to stop driving SDA.
        self.release(self.sda);
        self.q();
        self.release(self.scl);
        self.q();
        self.q();
        self.pull_low(self.scl);
        self.q();
        self.stop();
        Some(val)
    }

    // --- bit-level primitives -------------------------------------------------

    fn q(&self) {
        cortex_m::asm::delay(QUARTER);
    }

    fn release(&self, pin: (u32, u32)) {
        // SAFETY: `pin.0` is a GPIO port base from the board map; BSRR is
        // write-only and a single-bit set touches no other pin.
        let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
        bsrr.write(1 << pin.1);
    }

    fn pull_low(&self, pin: (u32, u32)) {
        // SAFETY: as in `release`; the reset half of BSRR.
        let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
        bsrr.write(1 << (pin.1 + 16));
    }

    fn level(&self, pin: (u32, u32)) -> bool {
        // SAFETY: IDR of a board-map GPIO port; read-only.
        let idr = unsafe { RoReg32::new(pin.0 + IDR_OFF) };
        idr.read() & (1 << pin.1) != 0
    }

    fn config_open_drain(&self, pin: (u32, u32)) {
        // SAFETY: MODER/OTYPER/OSPEEDR/PUPDR of a board-map GPIO port; every
        // RMW below is confined to this pin's own bit field.
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
        self.release(pin); // latch high BEFORE enabling the output
        otyper.set_bits(1 << pin.1); // open-drain
        pupdr.modify(|v| (v & !field) | (0b01 << pin2)); // internal pull-up
        ospeedr.modify(|v| (v & !field) | (0b01 << pin2));
        moder.modify(|v| (v & !field) | (0b01 << pin2)); // general-purpose output
    }

    fn start(&self) {
        self.release(self.sda);
        self.release(self.scl);
        self.q();
        self.pull_low(self.sda);
        self.q();
        self.pull_low(self.scl);
        self.q();
    }

    fn stop(&self) {
        self.pull_low(self.sda);
        self.q();
        self.release(self.scl);
        self.q();
        self.release(self.sda);
        self.q();
    }

    fn write_bit(&self, bit: bool) {
        if bit {
            self.release(self.sda);
        } else {
            self.pull_low(self.sda);
        }
        self.q();
        self.release(self.scl);
        self.q();
        self.q();
        self.pull_low(self.scl);
        self.q();
    }

    fn write_byte(&self, b: u8) -> bool {
        let mut i = 8;
        while i > 0 {
            i -= 1;
            self.write_bit(b & (1 << i) != 0);
        }
        self.release(self.sda); // let the slave drive the ACK bit
        self.q();
        self.release(self.scl);
        self.q();
        let acked = !self.level(self.sda);
        self.q();
        self.pull_low(self.scl);
        self.q();
        acked
    }

    fn read_byte(&self) -> u8 {
        self.release(self.sda); // slave drives SDA for the whole byte
        let mut v = 0u8;
        let mut i = 8;
        while i > 0 {
            i -= 1;
            self.q();
            self.release(self.scl);
            self.q();
            if self.level(self.sda) {
                v |= 1 << i;
            }
            self.q();
            self.pull_low(self.scl);
            self.q();
        }
        v
    }
}

const _: () = assert!(
    !(board::AUX_I2C_SCL_PIN == board::AUX_I2C_SDA_PIN),
    "aux I2C SCL and SDA are the same pin"
);
