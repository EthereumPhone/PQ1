//! I2C hardware initialization for the board's secure elements.
//!
//! Brings up every bus in [`board::SE_I2C_BUSES`]: GPIO pins as open-drain
//! alternate-function, then the I2C peripheral itself at 400 kHz Fast Mode.
//!
//! | Board | Buses |
//! |---|---|
//! | `iota2` | one — I2C1 on PB8/PB9 (AF4), shared by OPTIGA `0x30` and SE050 `0x48` |
//! | `pq1` | two — I2C1 on PB8/PB9 (AF4) for OPTIGA, I2C4 on PB6/PB7 (**AF5**) for SE050 |
//!
//! Making the *set of buses* the board-variable thing — rather than adding
//! a second entry point — is deliberate: it keeps this module down to a
//! single `pub fn init`, which is itself a pinned invariant (a driver that
//! grew a `pub fn write` would be an NS-reachable path onto the SE bus).
//!
//! All configuration runs in the secure world. The I2C peripherals stay
//! secure (no GTZC/SECCFGR changes) — the non-secure world never touches
//! the secure elements directly. Their SECCFGR bits are set once in
//! `sau::configure_gtzc`, which is also where `pq1`'s extra I2C4 bit is
//! accounted for.
//!
//! ## The silent failure to watch for on `pq1`
//!
//! PB6/PB7 are **I2C4 under AF5 and I2C1 under AF4**. Writing AF4 there
//! does not fail — it quietly attaches the SE050's pins to the OPTIGA bus,
//! producing a bus that looks alive and answers for the wrong chip. The
//! alternate function therefore comes from the board table, never from a
//! literal here.

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

/// Register offsets within an I2C block (identical for I2C1/I2C4).
const CR1_OFF: u32 = 0x00;
const CR2_OFF: u32 = 0x04;
const TIMINGR_OFF: u32 = 0x10;
const ISR_OFF: u32 = 0x18;
const ICR_OFF: u32 = 0x1C;
const RXDR_OFF: u32 = 0x24;
const TXDR_OFF: u32 = 0x28;

/// Typed handles onto one I2C peripheral's registers.
///
/// The SE drivers (`se050::i2c`, `optiga::i2c`) build their own instance of
/// this from the base address their board map gives them, so a bus swap is
/// a constant change rather than an edit to the transfer loops.
pub struct I2cRegs {
    pub cr1: Reg32,
    pub cr2: Reg32,
    pub timingr: Reg32,
    pub isr: RoReg32,
    pub icr: Reg32,
    pub rxdr: RoReg32,
    pub txdr: Reg32,
}

impl I2cRegs {
    /// Bind the register block at `base`.
    ///
    /// # Safety
    /// `base` must be the secure-alias base address of a real I2C
    /// peripheral on this part — i.e. one of the values in
    /// `crate::board`'s bus table, not an arbitrary address.
    #[must_use]
    pub const unsafe fn new(base: u32) -> Self {
        // SAFETY: forwarded to the caller's obligation above; each offset
        // is a 4-byte-aligned register inside that peripheral's block.
        unsafe {
            Self {
                cr1: Reg32::new(base + CR1_OFF),
                cr2: Reg32::new(base + CR2_OFF),
                timingr: Reg32::new(base + TIMINGR_OFF),
                isr: RoReg32::new(base + ISR_OFF),
                icr: Reg32::new(base + ICR_OFF),
                rxdr: RoReg32::new(base + RXDR_OFF),
                txdr: Reg32::new(base + TXDR_OFF),
            }
        }
    }
}

/// GPIO register offsets.
const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
/// `AFRL` covers pins 0..7, `AFRH` pins 8..15.
const AFRL_OFF: u32 = 0x20;
const AFRH_OFF: u32 = 0x24;

/// The `GPIOx_AFR[]` half owning `pin`, as a register offset.
///
/// `iota2` uses PB8/PB9 (both in `AFRH`); `pq1` additionally uses PB6/PB7
/// (both in `AFRL`). A fixed `AFRH` — which is what this driver hard-coded
/// before the board split — would silently write I2C4's alternate function
/// into the nibbles belonging to PB14/PB15 instead.
const fn afr_off(pin: u32) -> u32 {
    if pin < 8 {
        AFRL_OFF
    } else {
        AFRH_OFF
    }
}

/// Bit position of `pin`'s 4-bit alternate-function field within that half.
const fn afr_shift(pin: u32) -> u32 {
    (pin % 8) * 4
}

/// Configure one pin as open-drain alternate-function with a pull-up.
///
/// Open-drain is mandatory for I2C. The internal pull-up is additional
/// parallel resistance alongside the board's external pull-ups — it does
/// not replace them, and is not strong enough to drive the bus alone.
fn config_i2c_pin(port: u32, pin: u32, af: u32) {
    // SAFETY: `port` comes from `crate::board`'s bus table and is a real
    // GPIO block in the secure alias; each offset is a register within it.
    // Single-threaded secure world, disjoint-bit read-modify-write so the
    // other pins of this port (and their owning drivers) are untouched.
    let (moder, otyper, ospeedr, pupdr, afr) = unsafe {
        (
            Reg32::new(port + MODER_OFF),
            Reg32::new(port + OTYPER_OFF),
            Reg32::new(port + OSPEEDR_OFF),
            Reg32::new(port + PUPDR_OFF),
            Reg32::new(port + afr_off(pin)),
        )
    };

    let pin2 = pin * 2;
    let field = 0b11u32 << pin2;
    let shift = afr_shift(pin);

    moder.modify(|v| (v & !field) | (0b10 << pin2)); // alternate function
    otyper.set_bits(1 << pin); // open-drain — required for I2C
    ospeedr.modify(|v| (v & !field) | (0b11 << pin2)); // very high speed
    pupdr.modify(|v| (v & !field) | (0b01 << pin2)); // pull-up
    afr.modify(|v| (v & !(0xF << shift)) | (af << shift));
}

/// Bring up one bus: clocks, reset pulse, pins, then the peripheral.
fn init_bus(bus: &board::SeI2cBus) {
    // SAFETY: every address derives from `bus`, which the board map
    // guarantees describes a real peripheral and a real GPIO port; the RCC
    // registers are the secure aliases. Disjoint-bit RMW throughout.
    let (gpio_enr, periph_enr, periph_rstr) = unsafe {
        (
            Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF),
            Reg32::new(board::RCC_S + bus.rcc_enr_off),
            Reg32::new(board::RCC_S + bus.rcc_rstr_off),
        )
    };

    // ---- 1. Enable the GPIO port clock ----
    gpio_enr.set_bits(board::gpio_rcc_bit(bus.port));
    cortex_m::asm::dsb();

    // ---- 2. Enable the I2C peripheral clock ----
    periph_enr.set_bits(bus.rcc_en_bit);
    cortex_m::asm::dsb();

    // ---- 3. Pulse the peripheral reset ----
    periph_rstr.set_bits(bus.rcc_rst_bit);
    cortex_m::asm::dsb();
    periph_rstr.clear_bits(bus.rcc_rst_bit);
    cortex_m::asm::dsb();

    // ---- 4. Configure SCL + SDA ----
    config_i2c_pin(bus.port, bus.scl_pin, bus.af);
    config_i2c_pin(bus.port, bus.sda_pin, bus.af);

    // ---- 5. Configure the peripheral ----
    // SAFETY: `bus.base` is a real I2C peripheral base from the board map.
    let regs = unsafe { I2cRegs::new(bus.base) };

    // PE must be 0 before TIMINGR is written.
    regs.cr1.write(0);
    cortex_m::asm::dsb();

    regs.timingr.write(board::I2C_TIMING_400KHZ);

    // Analog noise filter on (reset default), no digital filter, PE = 1.
    regs.cr1.write(1);
    cortex_m::asm::dsb();
}

/// Initialize every secure-element I2C bus this board has.
///
/// Must be called after `rcc::init()` (clocks at 160 MHz — `TIMINGR`
/// assumes it) and after `se_power::init()`, so the parts on the far end
/// are actually powered before anything addresses them.
pub fn init() {
    for bus in board::SE_I2C_BUSES {
        init_bus(bus);
    }
}
