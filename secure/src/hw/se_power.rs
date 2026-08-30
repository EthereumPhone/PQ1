//! Secure-element power and enable lines.
//!
//! On `iota2` this module does nothing: both secure elements sit on a rail
//! that is live whenever the board is, and neither has an enable pin the
//! MCU drives. Every constant it reads is `None` there, so `init()` folds
//! to an empty function.
//!
//! On `pq1` it is load-bearing and must run **before any I2C traffic**:
//!
//! - **`LDO2_EN` (PA8)** enables `U108`, the `NCP114AMX330TCG` LDO whose
//!   output `VDD1_3V3` is the *only* supply for both the OPTIGA and the
//!   SE050. `R130` is a **10 kΩ pull-down** on that enable node, so at
//!   reset — when PA8 is a high-impedance analog input — the LDO is held
//!   off and both parts are unpowered.
//! - **`SE1_EN` (PB5)** is the SE050's own `ENA` pin.
//! - **`SE_RST` (PA15)** is the OPTIGA's active-low reset, driven by
//!   `optiga::reset_pin` rather than here, because it needs the pulse
//!   sequence that module already owns.
//!
//! ## Why this is worth its own module
//!
//! The failure mode is silent and misleading. With the rail off, every I2C
//! transaction to either chip NACKs or times out, which reads as a *bus*
//! fault — wrong pins, wrong alternate function, wrong `TIMINGR` — and
//! sends you debugging the bus while the actual cause is that the chips
//! have no power. Worse, the dev-board button driver claims PA8 as a
//! *pulled-up input*, which does not switch the rail on either: the
//! internal pull-up against `R130`'s 10 kΩ forms a divider well below the
//! NCP114's enable threshold. (Roughly 0.66 V, taking the pull-up at its
//! ~40 kΩ typical — a computed figure, not a measured one. The conclusion
//! does not depend on the exact value; the margin is large.)
//!
//! `init()` therefore returns what it *observed*, not what it wrote — see
//! [`SePowerState`]. Today its only caller logs that read-back through
//! `secure_log!`, which is gated on `debug-log` — so the failure is visible
//! on a bring-up build and **not** on a `mode-production` one, where the
//! result is currently discarded. Making it fail closed is a policy
//! decision, not part of the pin port; it is deliberately not made here.
//!
//! **What a good read-back still cannot tell you:** `ODR` reflects the
//! output latch, not the pad, and certainly not the LDO's output. A rail
//! that fails to rise (shorted decoupling, a dead LDO, an enable threshold
//! not met) reads exactly like success here. On first bring-up of a new
//! board, meter `VDD1_3V3` rather than trusting this.

#![cfg(feature = "stm32u585")]

use crate::board;
use crate::hw::mmio::Reg32;

/// GPIO register offsets, from RM0456's `GPIO_TypeDef`.
const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;
const ODR_OFF: u32 = 0x14;
const BSRR_OFF: u32 = 0x18;

/// Settle time after asserting the SE supply enable, in milliseconds.
///
/// The NCP114 datasheet gives a typical turn-on in the tens of
/// microseconds; 5 ms is a wide margin that also covers the bulk
/// capacitance on `VDD1_3V3` (`C131`, 4.7 µF) charging, and it costs
/// nothing on a path that runs once per boot.
const RAIL_SETTLE_MS: u32 = 5;

/// Settle time after asserting the SE050 `ENA` line.
const ENABLE_SETTLE_MS: u32 = 1;

/// Settle after releasing the OPTIGA reset. The Trust M needs a start-up
/// window before it answers on the bus; this is a generous floor, and the
/// probe retries on top of it.
const RESET_RELEASE_MS: u32 = 20;

/// Busy-wait milliseconds at the 160 MHz SYSCLK `hw::rcc::init` establishes.
///
/// If the PLL silently fell back to HSI16 this delay is 10x short — one
/// more reason `rcc::init`'s return value is worth checking at boot.
fn delay_ms(ms: u32) {
    cortex_m::asm::delay(160_000 * ms);
}

/// What `init()` actually observed after driving the lines.
///
/// Each field is `None` when the board has no such line (so `iota2` yields
/// all-`None`), and otherwise the **read-back** of that pin's `ODR` bit.
/// `false` where a `true` was expected means the write did not land — most
/// likely an unclocked GPIO port, which on this silicon drops writes
/// silently rather than faulting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SePowerState {
    /// Read-back of the SE supply enable (`LDO2_EN` on `pq1`).
    pub rail_en: Option<bool>,
    /// Read-back of the SE050 enable (`SE1_EN` on `pq1`).
    pub se050_en: Option<bool>,
    /// The OPTIGA reset pin's pad level (`IDR`) sampled **before** we drove
    /// it, or `None` if the board has no such line.
    ///
    /// Worth reporting rather than assuming: the OPTIGA is held in reset
    /// while this is low, and a low reading is the difference between "the
    /// chip is absent" and "the chip was never let out of reset".
    pub optiga_rst_before: Option<bool>,
    /// Read-back of the OPTIGA reset after we drove it high (reset released).
    pub optiga_rst: Option<bool>,
}

impl SePowerState {
    /// True when every line this board *has* read back as asserted.
    ///
    /// Vacuously true on a board with no such lines, which is correct:
    /// `iota2` has nothing to assert and nothing that can fail here.
    #[must_use]
    pub fn all_asserted(self) -> bool {
        self.rail_en.unwrap_or(true)
            && self.se050_en.unwrap_or(true)
            && self.optiga_rst.unwrap_or(true)
    }
}

/// Configure `(port, pin)` as a push-pull output and drive it high.
///
/// Drives the level via `BSRR` *before* switching `MODER` to output, so the
/// pin never presents a low glitch to whatever it enables — the same
/// ordering `optiga::reset_pin` uses, and for the same reason.
fn drive_high(port: u32, pin: u32) {
    // SAFETY: `port` is one of the GPIO base addresses in `crate::board`,
    // all of which are real 4-byte-aligned MMIO blocks, and every offset
    // below is a register within that block. Single-threaded secure world;
    // all shared registers are touched read-modify-write on disjoint bits.
    let (moder, otyper, ospeedr, pupdr, bsrr) = unsafe {
        (
            Reg32::new(port + MODER_OFF),
            Reg32::new(port + OTYPER_OFF),
            Reg32::new(port + OSPEEDR_OFF),
            Reg32::new(port + PUPDR_OFF),
            Reg32::new(port + BSRR_OFF),
        )
    };

    let pin2 = pin * 2;
    let field = 0b11u32 << pin2;

    bsrr.write(1 << pin); // set the level first
    moder.modify(|v| (v & !field) | (0b01 << pin2)); // general-purpose output
    otyper.clear_bits(1 << pin); // push-pull
    ospeedr.modify(|v| (v & !field) | (0b01 << pin2)); // medium speed is plenty
    pupdr.clear_bits(field); // no pull — we drive it
    bsrr.write(1 << pin); // and again, now that it is an output
}

/// Read a pin's actual pad level (`IDR`).
///
/// Unlike `ODR` this reflects the pin, not the output latch, and is valid in
/// every mode except analog — so it can be sampled *before* we drive the pin
/// to see what the board and the option bytes left it at.
fn idr_bit(port: u32, pin: u32) -> bool {
    // SAFETY: as `drive_high` — a real GPIO register in the secure alias.
    let idr = unsafe { Reg32::new(port + IDR_OFF) };
    idr.read() & (1 << pin) != 0
}

/// Read back a pin's output-latch bit.
fn odr_bit(port: u32, pin: u32) -> bool {
    // SAFETY: as `drive_high` — a real GPIO register in the secure alias.
    let odr = unsafe { Reg32::new(port + ODR_OFF) };
    odr.read() & (1 << pin) != 0
}

/// Enable the GPIO port clock for `port`, through the **secure** RCC alias.
///
/// The NS alias silently drops `GPIOxEN` writes at `TZEN=1`, leaving the
/// port unclocked; reads then return bus junk and every write vanishes.
fn enable_port_clock(port: u32) {
    // SAFETY: `RCC_S + RCC_AHB2ENR1_OFF` is the secure-alias AHB2ENR1
    // register; `gpio_rcc_bit` maps a port base to its own enable bit, so
    // this read-modify-write touches no other driver's bit.
    let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
    enr.set_bits(board::gpio_rcc_bit(port));
    // Read back before the barrier, matching `hw::uart::init`. A `dsb` alone
    // orders the store but does not wait for the clock to reach the port, and
    // `drive_high` writes `BSRR` on the very next instruction — on this
    // silicon an unclocked port drops writes silently, which would surface as
    // a `false` in the `ODR` read-back and point at the wrong problem.
    let _ = enr.read();
    cortex_m::asm::dsb();
}

/// Bring up the secure-element supply and enable lines.
///
/// Idempotent. Must run **after** `rcc::init()` (the settle delays assume
/// 160 MHz) and **before** `i2c_hw::init()` and any SE transaction.
///
/// Returns the observed state so the caller can log it; see the module
/// header for what a clean read-back does and does not prove.
pub fn init() -> SePowerState {
    let rail_en = board::SE_RAIL_EN.map(|(port, pin)| {
        enable_port_clock(port);
        drive_high(port, pin);
        // Let the LDO start up and the rail's bulk capacitance charge
        // before anything downstream is enabled or addressed.
        delay_ms(RAIL_SETTLE_MS);
        odr_bit(port, pin)
    });

    let se050_en = board::SE050_EN.map(|(port, pin)| {
        enable_port_clock(port);
        drive_high(port, pin);
        delay_ms(ENABLE_SETTLE_MS);
        odr_bit(port, pin)
    });

    // Release the OPTIGA's active-low reset explicitly.
    //
    // This was previously left undriven on the argument that `PA15_PUPEN=1`
    // in this die's option bytes makes PA15 idle high. That argument was
    // never checked against the pin, so the level is now SAMPLED first and
    // reported — an OPTIGA held in reset NACKs its address exactly like an
    // absent one, and guessing between those two costs a lot of time.
    //
    // Driving a reset line high is "release", i.e. the chip's normal
    // operating state; it is not a lifecycle action. `optiga::reset_pin`
    // still owns the reset *pulse* sequence and its silicon write-ordering
    // quirk — this only establishes the idle level.
    let optiga_rst_before = board::OPTIGA_RST.map(|(port, pin)| {
        enable_port_clock(port);
        idr_bit(port, pin)
    });
    let optiga_rst = board::OPTIGA_RST.map(|(port, pin)| {
        drive_high(port, pin);
        delay_ms(RESET_RELEASE_MS);
        odr_bit(port, pin)
    });

    SePowerState {
        rail_en,
        se050_en,
        optiga_rst_before,
        optiga_rst,
    }
}
