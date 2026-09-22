//! AW99703 backlight boost + LED-sink driver — **pq1 only**.
//!
//! The pq1 panel's backlight is not a GPIO: `LCM_EN` (PB15) is the AW99703's
//! `HWEN`, which only brings the chip out of shutdown into *Standby*. It emits
//! no LED current until `MODE[1:0]` is written to `01` (backlight) over I2C2
//! (PB13/PB14, 4.7 kΩ pull-ups to 3V3 on the RGB-driver side of the bus,
//! 7-bit address `0x36`). Datasheet: AW99703 V1.2 (Dec 2019), register table
//! p.26–28; copy at `evt-images/AW99703-datasheet-v1.2.pdf`.
//!
//! Board facts that fix the register values (schematic sheet 1, "Backlight
//! Driver"): only `LED1` is wired (`LCM_LEDK`), `LED2`/`LED3` float, the `PWM`
//! pin floats, VIN = 3V6, and the boost output capacitor C140 is rated 25 V.
//! Hence: enable channel 1 only, disable PWM-pin dimming, and lower OVP from
//! the 38 V default to 24 V so an open string cannot exceed C140's rating.
//!
//! Transport is a bit-banged I2C master (~100 kHz) on the two GPIOs — this
//! bus carries pixels' worth of brightness, never secure-element traffic, so
//! the reasoning in `soft_i2c` applies unchanged. Write-only: the chip needs
//! no readback to light up.
#![cfg(all(feature = "stm32u585", feature = "ui-lcd", feature = "board-pq1"))]

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

const SCL: (u32, u32) = (board::AUX_I2C_PORT, board::AUX_I2C_SCL_PIN);
const SDA: (u32, u32) = (board::AUX_I2C_PORT, board::AUX_I2C_SDA_PIN);
const ADDR: u8 = board::BACKLIGHT_I2C_ADDR;

const _: () = assert!(
    !(SCL.0 == SDA.0 && SCL.1 == SDA.1),
    "AW99703 SCL and SDA are the same pin"
);

// Register map (datasheet p.26).
const REG_MODE: u8 = 0x02; // [4] PDIS, [2] MAP (1 = linear), [1:0] WORKMODE (01 = backlight)
const REG_LEDCUR: u8 = 0x03; // [7:3] BL_FS = 4.8 mA + code*0.8 mA, [2:0] CH3EN/CH2EN/CH1EN
const REG_BSTCTR1: u8 = 0x04; // [7:6] SF_SFT, [5] SF (1 = 1 MHz), [4:2] OVPSEL, [1:0] OCPSEL
const REG_LEDLSB: u8 = 0x06; // [2:0] brightness LSBs — program BEFORE the MSB
const REG_LEDMSB: u8 = 0x07; // [7:0] brightness MSBs

/// 20 mA full-scale (code 0b10011, the chip default) on channel 1 only.
const LEDCUR_CH1_20MA: u8 = (0b10011 << 3) | 0b001;
/// No frequency shift, 1 MHz switching, **OVP = 24 V** (001), OCP 2.7 A (default).
const BSTCTR1_OVP24V: u8 = (0b00 << 6) | (1 << 5) | (0b001 << 2) | 0b10;
/// PWM-pin dimming disabled (pin floats), linear map, backlight mode.
const MODE_I2C_LINEAR_BACKLIGHT: u8 = (1 << 4) | (1 << 2) | 0b01;
/// Demo brightness: 11-bit code 0x5FF of 0x7FF ≈ 75 % of full scale (linear map).
const BRIGHTNESS_LSB: u8 = 0x07;
const BRIGHTNESS_MSB: u8 = 0xBF;

// --- bit-banged I2C (same idiom as `soft_i2c`, private copy: different pins,
// different cfg gate, and the two must never be silently unified onto one bus) ---
const QUARTER: u32 = 400; // cycles; ≈100 kHz at 160 MHz, slower is fine
const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;
const BSRR_OFF: u32 = 0x18;

fn q() {
    cortex_m::asm::delay(QUARTER);
}
fn release(pin: (u32, u32)) {
    // SAFETY: `pin.0` is a GPIO port base from the board map; BSRR is write-only
    // and a single-bit set touches no other pin.
    let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
    bsrr.write(1 << pin.1);
}
fn pull_low(pin: (u32, u32)) {
    // SAFETY: as in `release`; the reset half of BSRR.
    let bsrr = unsafe { Reg32::new(pin.0 + BSRR_OFF) };
    bsrr.write(1 << (pin.1 + 16));
}
fn level(pin: (u32, u32)) -> bool {
    // SAFETY: IDR of a board-map GPIO port; read-only.
    let idr = unsafe { RoReg32::new(pin.0 + IDR_OFF) };
    idr.read() & (1 << pin.1) != 0
}
fn config_open_drain(pin: (u32, u32)) {
    // SAFETY: MODER/OTYPER/OSPEEDR/PUPDR of a board-map GPIO port; every RMW
    // below is confined to this pin's own bit field.
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
    release(pin); // latch high BEFORE enabling the output
    otyper.set_bits(1 << pin.1); // open-drain
    pupdr.modify(|v| (v & !field) | (0b01 << pin2)); // internal pull-up (parallel to the 4.7 kΩ)
    ospeedr.modify(|v| (v & !field) | (0b01 << pin2));
    moder.modify(|v| (v & !field) | (0b01 << pin2)); // general-purpose output
}
fn start() {
    release(SDA);
    release(SCL);
    q();
    pull_low(SDA);
    q();
    pull_low(SCL);
    q();
}
fn stop() {
    pull_low(SDA);
    q();
    release(SCL);
    q();
    release(SDA);
    q();
}
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
fn write_byte(b: u8) -> bool {
    let mut i = 8;
    while i > 0 {
        i -= 1;
        write_bit(b & (1 << i) != 0);
    }
    release(SDA);
    q();
    release(SCL);
    q();
    let acked = !level(SDA);
    q();
    pull_low(SCL);
    q();
    acked
}
fn write_reg(reg: u8, val: u8) -> bool {
    start();
    let ok = write_byte(ADDR << 1) && write_byte(reg) && write_byte(val);
    stop();
    ok
}

/// Bring the backlight up. Call **after** `LCM_EN`/HWEN has been driven high
/// (the LCD driver does that) — HWEN low resets every register and disables
/// the I2C interface. Returns `true` if the chip ACKed every write.
pub fn init() -> bool {
    // SAFETY: the secure-alias RCC AHB2ENR1; `gpio_rcc_bit` maps the port to
    // its own enable bit, so this RMW touches no other driver's bit.
    let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
    enr.set_bits(board::gpio_rcc_bit(SCL.0) | board::gpio_rcc_bit(SDA.0));
    let _ = enr.read();
    cortex_m::asm::dsb();
    config_open_drain(SCL);
    config_open_drain(SDA);
    // HWEN-high → I2C-ready settle (datasheet t_reset; generous at any SYSCLK).
    cortex_m::asm::delay(800_000);

    let mut ok = true;
    // Order: current/OVP limits first, brightness (LSB then MSB, per datasheet),
    // and only then leave Standby for Backlight mode.
    ok &= write_reg(REG_LEDCUR, LEDCUR_CH1_20MA);
    ok &= write_reg(REG_BSTCTR1, BSTCTR1_OVP24V);
    ok &= write_reg(REG_LEDLSB, BRIGHTNESS_LSB);
    ok &= write_reg(REG_LEDMSB, BRIGHTNESS_MSB);
    ok &= write_reg(REG_MODE, MODE_I2C_LINEAR_BACKLIGHT);
    secure_log!(
        "[S] aw99703: backlight init {}",
        if ok { "ACK" } else { "NACK" }
    );
    ok
}
