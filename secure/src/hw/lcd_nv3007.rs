//! NV3007 SPI LCD driver for the ZT165M017AT module (142×428 TFT,
//! RGB565, 4-line SPI).
//!
//! ## Pin mapping (B-U585I-IOT02A, Arduino R3 headers + `spi1-arduino`)
//!
//! ```text
//!   PE12  CS  (existing `spi_hw` CS pin — D10)
//!   PE13  SCK (existing `spi_hw` SCK   — D13, AF5)
//!   PE15  MOSI (existing `spi_hw` MOSI — D11, AF5)
//!   PE3   DC  (NEW — wire to NV3007 D/CX pin via jumper)
//!   PE1   RES (NEW — wire to NV3007 RES pin via jumper)
//!   3V3   VLED+ (backlight, hard-wired for prototype; PWM-control
//!         possible via a future GPIO if dimming is needed)
//! ```
//!
//! ## Init sequence
//!
//! Ported byte-for-byte from the production `dgen1` Android port's
//! NV3007 driver: `vendor/mediatek/proprietary/bootable/bootloader/
//! lk2/dev/lcm/nv3007_142x428_4line_8bit/nv3007_142x428_4line_8bit.c`
//! (and the matching kernel driver under
//! `kernel-5.10/drivers/sunritel_tools/spi_lcm/`). Both versions
//! match byte-for-byte — that sequence is the canonical one for
//! this exact LCM SKU.
//!
//! The init values are LCM-specific (gamma, GVDD/GVCL, GOA timing).
//! Do not alter without re-validating on real hardware — these are
//! the values the vendor tuned for production panels.
//!
//! ## Coordinate system
//!
//! The native NV3007 RAM is wider than the visible 142-px area; the
//! production driver applies an X offset of 12 in its `BlockWrite`
//! helper. Our [`set_window`] mirrors that — callers pass logical
//! 0..142 / 0..428 coords and the offset is added internally.
//!
//! ## Pixel format
//!
//! 16-bit RGB565 (COLMOD `0x3a` = `0x05`). Full-frame payload:
//! `142 × 428 × 2 = 121,552 bytes`. At STM32U5 SPI1 prescaler ÷32
//! (5 MHz from 160 MHz PCLK) → ~200 ms per full repaint. With the
//! prescaler bumped to ÷8 (20 MHz, still well inside the NV3007's
//! `Tcyc ≥ 10 ns` spec) → ~50 ms per repaint. Partial-area updates
//! of just the 3 secret rows (≈ 5 KB) → ~2-5 ms.
//!
//! ## Phase scope (2026-05-19)
//!
//! - **Phase A (this file)**: command/data send primitives + the
//!   production NV3007 init sequence + `set_window` + `fill_color`
//!   + `write_pixels`. Compiles but unverified — needs real LCD.
//! - **Phase B**: bench-validate on real silicon. Tune SPI baud,
//!   confirm power-on/reset timing.
//! - **Phase C**: implement `ui::Display` trait over the LCD with
//!   `FONT_5X8` scaled up for the higher resolution. Migrate
//!   `flush_with_secret_rows` to the LCD framebuffer.
//! - **Phase D**: re-run `decoy-flicker-test` against the LCD's
//!   slow pixel response (Tr+Tf typ 35 ms max 40 ms per datasheet)
//!   to validate Phase 1 of F-24 stage E.

#![cfg(feature = "ui-lcd")]

use crate::hw::mmio::{Reg32, RoReg32};
use crate::hw::spi_hw::{cs_assert, cs_deassert, SPI_BASE};

// ---------------------------------------------------------------------------
// Display geometry
// ---------------------------------------------------------------------------

/// Visible pixel width (X axis).
pub const FRAME_WIDTH: u16 = 142;
/// Visible pixel height (Y axis).
pub const FRAME_HEIGHT: u16 = 428;

/// X offset applied to all column-address commands. The NV3007's RAM
/// extends past the visible window; the production driver's
/// `BlockWrite()` adds `a=12` to every X coordinate. Replicated here.
pub const X_OFFSET: u16 = 12;
/// Y offset. The production driver uses `b=0`.
pub const Y_OFFSET: u16 = 0;

// ---------------------------------------------------------------------------
// GPIO — DC + RES on GPIOE bits 3 and 1
// ---------------------------------------------------------------------------

/// DC (Data/Command) pin position on GPIOE. Drive HIGH for data,
/// LOW for command. Configured as push-pull output by `init()`.
const DC_PIN: u32 = 3;

/// RES (hardware reset, active-low) pin position on GPIOE. Driven by
/// [`hard_reset`] during init. Push-pull output.
const RES_PIN: u32 = 1;

/// Bit mask in `GPIOE_BSRR` for DC = HIGH (data).
const DC_HIGH_BS: u32 = 1 << DC_PIN;
/// Bit mask in `GPIOE_BSRR` for DC = LOW (command).
const DC_LOW_BR: u32 = 1 << (DC_PIN + 16);

const RES_HIGH_BS: u32 = 1 << RES_PIN;
const RES_LOW_BR: u32 = 1 << (RES_PIN + 16);

// ---------------------------------------------------------------------------
// MMIO handles — GPIOE secure alias (extends what spi_hw already touches)
// ---------------------------------------------------------------------------
//
// `hw::spi_hw::init()` already enables the GPIOE clock and binds PE12-PE15
// (CS, SCK, MISO, MOSI). This module extends the configuration by setting
// PE3 + PE1 as push-pull outputs. We do NOT re-touch PE12-PE15 here.

const GPIOE_S: u32 = 0x5202_1000;

struct LcdRegs {
    gpioe_moder: Reg32,
    gpioe_otyper: Reg32,
    gpioe_ospeedr: Reg32,
    gpioe_pupdr: Reg32,
    gpioe_bsrr: Reg32,

    // SPI peripheral — same base as `spi_hw::SPI_BASE`. We use direct
    // TXDR access for byte sends.
    spi_cr1: Reg32,
    spi_cr2: Reg32,
    spi_cfg1: Reg32,
    spi_sr: RoReg32,
    spi_ifcr: Reg32,
    spi_txdr_addr: u32,
}

// SAFETY: each MMIO address below is a real, 4-byte-aligned register
// on STM32U585. PE3 + PE1 are not claimed by any other secure-world
// driver (verified via grep). The single-threaded secure world doesn't
// race on these; RMW on disjoint bits is fine. The SPI peripheral is
// shared with `hw::spi` (used by Tropic01) — but Tropic01 isn't shipped
// (`project_tropic01_excluded`) and the `ui-lcd` feature is mutually
// exclusive with `tropic01-se` at the Cargo level.
const REG: LcdRegs = unsafe {
    LcdRegs {
        gpioe_moder: Reg32::new(GPIOE_S + 0x00),
        gpioe_otyper: Reg32::new(GPIOE_S + 0x04),
        gpioe_ospeedr: Reg32::new(GPIOE_S + 0x08),
        gpioe_pupdr: Reg32::new(GPIOE_S + 0x0C),
        gpioe_bsrr: Reg32::new(GPIOE_S + 0x18),

        spi_cr1: Reg32::new(SPI_BASE + 0x00),
        spi_cr2: Reg32::new(SPI_BASE + 0x04),
        spi_cfg1: Reg32::new(SPI_BASE + 0x08),
        spi_sr: RoReg32::new(SPI_BASE + 0x14),
        spi_ifcr: Reg32::new(SPI_BASE + 0x18),
        spi_txdr_addr: SPI_BASE + 0x20,
    }
};

// SPI SR bits (STM32U5 SPI v2)
const SR_TXP: u32 = 1 << 1;
const SR_EOT: u32 = 1 << 3;

// CR1 bits
const CR1_SPE: u32 = 1 << 0;
const CR1_CSTART: u32 = 1 << 9;

// ---------------------------------------------------------------------------
// GPIO helpers — DC / RES atomic set/clear via BSRR
// ---------------------------------------------------------------------------

#[inline(always)]
fn dc_low() {
    REG.gpioe_bsrr.write(DC_LOW_BR);
}

#[inline(always)]
fn dc_high() {
    REG.gpioe_bsrr.write(DC_HIGH_BS);
}

#[inline(always)]
fn res_low() {
    REG.gpioe_bsrr.write(RES_LOW_BR);
}

#[inline(always)]
fn res_high() {
    REG.gpioe_bsrr.write(RES_HIGH_BS);
}

/// Configure PE3 (DC) and PE1 (RES) as push-pull outputs at very-high
/// speed. Both start HIGH so RES doesn't accidentally reset the LCD
/// before [`hard_reset`] sequences it.
///
/// Assumes [`hw::spi_hw::init()`] has already enabled the GPIOE clock.
fn init_dc_res_gpios() {
    // MODER: bits [7:6] (PE3) and [3:2] (PE1) → 0b01 (output)
    REG.gpioe_moder.modify(|v| {
        (v & !(0b11 << (DC_PIN * 2)) & !(0b11 << (RES_PIN * 2)))
            | (0b01 << (DC_PIN * 2))
            | (0b01 << (RES_PIN * 2))
    });

    // OTYPER: push-pull (bit = 0)
    REG.gpioe_otyper.clear_bits((1 << DC_PIN) | (1 << RES_PIN));

    // OSPEEDR: bits [7:6] (PE3) and [3:2] (PE1) → 0b11 (very high)
    REG.gpioe_ospeedr.set_bits((0b11 << (DC_PIN * 2)) | (0b11 << (RES_PIN * 2)));

    // PUPDR: no pull-up/down (the LCD pulls these via its own resistors;
    // we drive them push-pull anyway).
    REG.gpioe_pupdr.modify(|v| {
        v & !(0b11 << (DC_PIN * 2)) & !(0b11 << (RES_PIN * 2))
    });

    // Start with both HIGH so RES is deasserted at boot.
    REG.gpioe_bsrr.write(DC_HIGH_BS | RES_HIGH_BS);
}

// ---------------------------------------------------------------------------
// SPI byte send — direct TXDR write
// ---------------------------------------------------------------------------

/// Begin a multi-byte SPI transaction. Sets `TSIZE = 0` (unlimited),
/// enables the peripheral, and starts the transfer. Caller must
/// follow with one or more [`spi_send_byte`] then [`spi_end`].
fn spi_begin() {
    // TSIZE = 0 → free-running mode (the peripheral keeps transferring
    // as long as TXDR has data and SPE is set).
    REG.spi_cr2.write(0);
    REG.spi_cr1.modify(|v| v | CR1_SPE);
    REG.spi_cr1.modify(|v| v | CR1_CSTART);
}

/// Push one byte through TXDR. Blocks until TXP is set (Tx FIFO has
/// space). Discards any incoming RX byte — we don't drive MISO and
/// the LCD doesn't talk back.
fn spi_send_byte(b: u8) {
    while (REG.spi_sr.read() & SR_TXP) == 0 {}
    // 8-bit write to TXDR. Reg32 only supports u32 access; use raw
    // write_volatile here for the byte-wide store the SPI peripheral
    // expects when DSIZE=7.
    // SAFETY: TXDR is a real MMIO register, `cfg1` was set with
    // DSIZE = 7 (8-bit) by spi_hw::init(); byte writes are valid.
    unsafe {
        core::ptr::write_volatile(REG.spi_txdr_addr as *mut u8, b);
    }
}

/// End a multi-byte SPI transaction: wait for the last byte to drain,
/// clear EOT, disable the peripheral.
fn spi_end() {
    // Wait for last byte transmitted. STM32U5 SPI v2: EOT only sets
    // when TSIZE bytes have been transferred OR when SPE is cleared.
    // With TSIZE=0 (unlimited mode) we rely on clearing SPE and
    // letting any TXDR-pending byte drain via the standard procedure.
    // Spin briefly to make sure TXDR-FIFO is empty.
    while (REG.spi_sr.read() & SR_TXP) == 0 {}
    REG.spi_cr1.modify(|v| v & !CR1_SPE);
    REG.spi_ifcr.write(0xFFFF_FFFF); // clear all sticky flags
    let _ = SR_EOT;
}

// ---------------------------------------------------------------------------
// LCD command / data primitives
// ---------------------------------------------------------------------------

/// Send a single command byte (DC=LOW).
pub fn write_cmd(cmd: u8) {
    cs_assert();
    dc_low();
    spi_begin();
    spi_send_byte(cmd);
    spi_end();
    cs_deassert();
}

/// Send a single data byte (DC=HIGH).
pub fn write_data(data: u8) {
    cs_assert();
    dc_high();
    spi_begin();
    spi_send_byte(data);
    spi_end();
    cs_deassert();
}

/// Send a multi-byte data payload in one CS-asserted transaction.
/// Faster than repeated [`write_data`] for bulk pixel writes.
pub fn write_data_bulk(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    cs_assert();
    dc_high();
    spi_begin();
    for &b in data {
        spi_send_byte(b);
    }
    spi_end();
    cs_deassert();
}

// ---------------------------------------------------------------------------
// Hardware reset
// ---------------------------------------------------------------------------

/// Pulse RES per the production NV3007 power-on sequence:
/// `HIGH 10 ms → LOW 200 ms → HIGH 120 ms`.
pub fn hard_reset() {
    res_high();
    delay_ms(10);
    res_low();
    delay_ms(200);
    res_high();
    delay_ms(120);
}

/// Coarse busy-wait — 160 MHz core, ~160k cycles per millisecond.
fn delay_ms(ms: u32) {
    cortex_m::asm::delay(160_000 * ms);
}

// ---------------------------------------------------------------------------
// NV3007 init sequence (ported 1:1 from dgen1 production driver)
// ---------------------------------------------------------------------------

/// Drive the NV3007 init register sequence. **Do not alter values
/// without re-validating on the actual LCM SKU** — these are
/// production-tuned for ZT165M017AT panels (gamma, GVDD/GVCL,
/// GOA timing, frame-rate dividers). Source:
/// `dgen1/.../nv3007_142x428_4line_8bit.c::nv3007_Init_lcm()`.
pub fn run_init_sequence() {
    // ---- Vendor command-mode unlock + analog rail tuning ----
    write_cmd(0xFF); write_data(0xA5);
    write_cmd(0x8F); write_data(0x22); write_data(0x03);
    write_cmd(0x9A); write_data(0x78);
    write_cmd(0x9B); write_data(0x78);
    write_cmd(0x9C); write_data(0xA0);
    write_cmd(0x9D); write_data(0x17); // VGH = +15.5 V
    write_cmd(0x9E); write_data(0xC3); // VGL = -10.5 V
    write_cmd(0x83); write_data(0xA6); // GVCL ADJ -3.87 V
    write_cmd(0x84); write_data(0xC6); // GVDD ADJ +6.0 V
    write_cmd(0x85); write_data(0x62); // GVSP ADJ

    // ---- Gamma (V0/V63 + V1/V62 + V2/V61 + V20/V43 + V4/V59 +
    //              V6/V57 + V13/V50 + V36/V27 — positive + negative) ----
    write_cmd(0x6E); write_data(0x0F);
    write_cmd(0x7E); write_data(0x0F);
    write_cmd(0x60); write_data(0x04);
    write_cmd(0x70); write_data(0x00);
    write_cmd(0x6D); write_data(0x36);
    write_cmd(0x7D); write_data(0x36);
    write_cmd(0x61); write_data(0x05);
    write_cmd(0x71); write_data(0x05);
    write_cmd(0x6C); write_data(0x32);
    write_cmd(0x7C); write_data(0x31);
    write_cmd(0x62); write_data(0x0B);
    write_cmd(0x72); write_data(0x0A);
    write_cmd(0x68); write_data(0x4A);
    write_cmd(0x78); write_data(0x4C);
    write_cmd(0x66); write_data(0x32);
    write_cmd(0x76); write_data(0x30);
    write_cmd(0x6B); write_data(0x13);
    write_cmd(0x7B); write_data(0x12);
    write_cmd(0x63); write_data(0x09);
    write_cmd(0x73); write_data(0x07);
    write_cmd(0x6A); write_data(0x16);
    write_cmd(0x7A); write_data(0x14);
    write_cmd(0x64); write_data(0x08);
    write_cmd(0x74); write_data(0x06);
    write_cmd(0x69); write_data(0x0D);
    write_cmd(0x79); write_data(0x0A);
    write_cmd(0x65); write_data(0x04);
    write_cmd(0x75); write_data(0x03);
    write_cmd(0x67); write_data(0x33);
    write_cmd(0x77); write_data(0x22);
    write_cmd(0x6F); write_data(0x00);
    write_cmd(0x7F); write_data(0x00);

    // ---- GOA (Gate-On Array) timing ----
    write_cmd(0x50); write_data(0x00);
    write_cmd(0x52); write_data(0xD6);
    write_cmd(0x53); write_data(0x04);
    write_cmd(0x54); write_data(0x04);
    write_cmd(0x55); write_data(0x1B);
    write_cmd(0x56); write_data(0x1B);

    write_cmd(0xA0); write_data_bulk(&[0x2A, 0x24, 0x00]);
    write_cmd(0xA1); write_data(0x84);
    write_cmd(0xA2); write_data(0x85);
    write_cmd(0xA8); write_data(0x36);
    write_cmd(0xA9); write_data(0x80);
    write_cmd(0xAA); write_data(0x73);
    write_cmd(0xAB); write_data_bulk(&[0x03, 0x61]);
    write_cmd(0xAC); write_data_bulk(&[0x03, 0x65]);
    write_cmd(0xAD); write_data_bulk(&[0x03, 0x60]);
    write_cmd(0xAE); write_data_bulk(&[0x03, 0x64]);
    write_cmd(0xB9); write_data(0x82);
    write_cmd(0xBA); write_data(0x83);
    write_cmd(0xBB); write_data(0x80);
    write_cmd(0xBC); write_data(0x81);
    write_cmd(0xBD); write_data(0x02);
    write_cmd(0xBE); write_data(0x01);
    write_cmd(0xBF); write_data(0x04);
    write_cmd(0xC0); write_data(0x03);
    write_cmd(0xC4); write_data(0x33);
    write_cmd(0xC5); write_data(0x80);
    write_cmd(0xC6); write_data(0x73);
    write_cmd(0xC7); write_data(0x01);
    write_cmd(0xC8); write_data_bulk(&[0x33, 0x33]);
    write_cmd(0xC9); write_data(0x5B);
    write_cmd(0xCA); write_data(0x5A);
    write_cmd(0xCB); write_data(0x5D);
    write_cmd(0xCC); write_data(0x5C);
    write_cmd(0xCD); write_data_bulk(&[0x33, 0x33]);
    write_cmd(0xCE); write_data(0x5F);
    write_cmd(0xCF); write_data(0x5E);
    write_cmd(0xD0); write_data(0x61);
    write_cmd(0xD1); write_data(0x60);

    // ---- Frame timing / inversion control ----
    write_cmd(0xB0); write_data_bulk(&[0x3A, 0x3A, 0x00, 0x00]);
    write_cmd(0xB6); write_data(0x32);
    write_cmd(0xB7); write_data(0x80);
    write_cmd(0xB8); write_data(0x73);
    write_cmd(0xE0); write_data(0x00);
    write_cmd(0xE1); write_data_bulk(&[0x03, 0x0F]);
    write_cmd(0xE2); write_data(0x04);
    write_cmd(0xE3); write_data(0x01);
    write_cmd(0xE4); write_data(0x0E);
    write_cmd(0xE5); write_data(0x01);
    write_cmd(0xE6); write_data(0x19);
    write_cmd(0xE7); write_data(0x10);
    write_cmd(0xE8); write_data(0x10);
    // 0xE9: inversion mode. 0x21 = dot inversion (default). Other
    // documented values: 0x20 column, 0xA0 2-dot, 0xA1 4-dot.
    write_cmd(0xE9); write_data(0x21);
    write_cmd(0xEA); write_data(0x12);
    write_cmd(0xEB); write_data(0xD0);
    write_cmd(0xEC); write_data(0x04);
    write_cmd(0xED); write_data(0x07);
    write_cmd(0xEE); write_data(0x07);
    write_cmd(0xEF); write_data(0x09);
    write_cmd(0xF0); write_data(0xD0);
    write_cmd(0xF1); write_data(0x0E);
    write_cmd(0xF9); write_data(0x56);
    write_cmd(0xF2); write_data_bulk(&[0x26, 0x1B, 0x0B, 0x20]);
    write_cmd(0xEC); write_data(0x04);

    // 0x35: Tearing Effect Line ON (TE pin). Set to 0x00 = "V-blank only".
    write_cmd(0x35); write_data(0x00);
    // 0x44: tear scanline.
    write_cmd(0x44); write_data_bulk(&[0x00, 0x10]);
    // 0x46: brightness/related.
    write_cmd(0x46); write_data(0x10);

    // Lock vendor command-mode (mirror of the 0xFF/0xA5 unlock at the top).
    write_cmd(0xFF); write_data(0x00);

    // ---- Pixel format: COLMOD (0x3A) = 0x05 → RGB565 16-bit ----
    write_cmd(0x3A); write_data(0x05);

    // ---- Sleep out + display on ----
    write_cmd(0x11);                  // SLPOUT
    delay_ms(200);
    write_cmd(0x29);                  // DISPON
    delay_ms(150);

    // ---- Initial address window: full screen ----
    set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
    delay_ms(20);
}

// ---------------------------------------------------------------------------
// Address window + bulk pixel write
// ---------------------------------------------------------------------------

/// Set the active drawing window. Subsequent [`write_pixels`] /
/// [`write_data_bulk`] data lands inside this rect. The X offset is
/// applied internally per the production driver's `BlockWrite`.
///
/// Coords are inclusive on both ends:
/// `set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1)` selects the
/// entire visible area.
pub fn set_window(x0: u16, y0: u16, x1: u16, y1: u16) {
    let bytes = build_set_window_bytes(x0, y0, x1, y1);
    // CASET (0x2A): 4 bytes
    write_cmd(0x2A);
    write_data_bulk(&bytes.caset);
    // RASET (0x2B): 4 bytes
    write_cmd(0x2B);
    write_data_bulk(&bytes.raset);
    // RAMWR (0x2C): begin RAM-write
    write_cmd(0x2C);
}

/// Pure-logic byte builder for [`set_window`] — host-testable.
fn build_set_window_bytes(x0: u16, y0: u16, x1: u16, y1: u16) -> SetWindowBytes {
    let x0 = x0 + X_OFFSET;
    let x1 = x1 + X_OFFSET;
    let y0 = y0 + Y_OFFSET;
    let y1 = y1 + Y_OFFSET;
    SetWindowBytes {
        caset: [(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8],
        raset: [(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8],
    }
}

struct SetWindowBytes {
    caset: [u8; 4],
    raset: [u8; 4],
}

/// Write `n` pixels of `color` (RGB565) to the current window.
/// Useful for clears or solid-color fills without allocating a buffer.
pub fn write_pixels_solid(color: u16, n: u32) {
    let hi = (color >> 8) as u8;
    let lo = color as u8;
    cs_assert();
    dc_high();
    spi_begin();
    for _ in 0..n {
        spi_send_byte(hi);
        spi_send_byte(lo);
    }
    spi_end();
    cs_deassert();
}

/// Write a slice of RGB565 pixels to the current window. The slice is
/// transmitted big-endian on the wire (NV3007 expects high byte first).
pub fn write_pixels(buf: &[u16]) {
    if buf.is_empty() {
        return;
    }
    cs_assert();
    dc_high();
    spi_begin();
    for &px in buf {
        spi_send_byte((px >> 8) as u8);
        spi_send_byte(px as u8);
    }
    spi_end();
    cs_deassert();
}

/// Fill the entire visible area with `color`. Convenience wrapper.
pub fn fill_screen(color: u16) {
    set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
    write_pixels_solid(color, FRAME_WIDTH as u32 * FRAME_HEIGHT as u32);
}

// ---------------------------------------------------------------------------
// Top-level init
// ---------------------------------------------------------------------------

/// Bring the LCD up. Assumes [`hw::spi_hw::init`] has already
/// configured the SPI peripheral + CS/SCK/MOSI pins. Steps:
///
/// 1. Configure DC + RES GPIOs (PE3 + PE1, push-pull output).
/// 2. Hardware reset pulse.
/// 3. Run the production NV3007 init sequence.
/// 4. Clear the screen to black (RGB565 `0x0000`).
pub fn init() {
    init_dc_res_gpios();
    hard_reset();
    run_init_sequence();
    fill_screen(0x0000);
}

// ---------------------------------------------------------------------------
// Host tests — pure logic only (no MMIO access at test time)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `set_window(0, 0, FRAME_WIDTH-1, FRAME_HEIGHT-1)` should
    /// produce CASET = X_OFFSET..X_OFFSET+FRAME_WIDTH-1 and
    /// RASET = Y_OFFSET..Y_OFFSET+FRAME_HEIGHT-1 — matching the
    /// production `BlockWrite(0, FRAME_WIDTH-1, 0, FRAME_HEIGHT-1)`.
    #[test]
    fn positive_full_screen_window_matches_production_bytes() {
        let bytes = build_set_window_bytes(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
        // X: 0+12 = 12 (0x000C); X1: 141+12 = 153 (0x0099)
        assert_eq!(bytes.caset, [0x00, 0x0C, 0x00, 0x99]);
        // Y: 0; Y1: 427 (0x01AB)
        assert_eq!(bytes.raset, [0x00, 0x00, 0x01, 0xAB]);
    }

    /// Cross-check against the production driver's `nv3007_Init_lcm`
    /// initial CASET/RASET values (the literal bytes the C code
    /// writes after the init sequence). If our builder produces
    /// different bytes, our pixel addressing would be off-by-N from
    /// production, leading to a torn or shifted display.
    #[test]
    fn negative_set_window_offset_matches_dgen1_bootloader_literal() {
        // From nv3007_142x428_4line_8bit.c::nv3007_Init_lcm():
        //   SPI_WriteComm(0x2a);
        //   SPI_WriteData(0x00); SPI_WriteData(0x0c);   // x0 = 12
        //   SPI_WriteData(0x00); SPI_WriteData(0x99);   // x1 = 153
        //   SPI_WriteComm(0x2b);
        //   SPI_WriteData(0x00); SPI_WriteData(0x00);   // y0 = 0
        //   SPI_WriteData(0x01); SPI_WriteData(0xab);   // y1 = 427
        let bytes = build_set_window_bytes(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
        assert_eq!(bytes.caset[0], 0x00);
        assert_eq!(bytes.caset[1], 0x0C);
        assert_eq!(bytes.caset[2], 0x00);
        assert_eq!(bytes.caset[3], 0x99);
        assert_eq!(bytes.raset[0], 0x00);
        assert_eq!(bytes.raset[1], 0x00);
        assert_eq!(bytes.raset[2], 0x01);
        assert_eq!(bytes.raset[3], 0xAB);
    }

    /// A small inner window — e.g. drawing 16×24 starting at (10, 50)
    /// — must apply the X offset but not double-count it. Catches
    /// regressions where set_window forgets to add X_OFFSET to x1.
    #[test]
    fn positive_inner_window_offsets_both_endpoints() {
        let bytes = build_set_window_bytes(10, 50, 25, 73);
        // x0 = 10+12 = 22 (0x0016), x1 = 25+12 = 37 (0x0025)
        assert_eq!(bytes.caset, [0x00, 0x16, 0x00, 0x25]);
        // y0 = 50, y1 = 73
        assert_eq!(bytes.raset, [0x00, 0x32, 0x00, 0x49]);
    }

    /// Frame geometry pins — silent drift in either constant would
    /// invalidate every X/Y address we compute.
    #[test]
    fn negative_frame_geometry_constants_pinned() {
        assert_eq!(FRAME_WIDTH, 142, "ZT165M017AT visible width is 142 px");
        assert_eq!(FRAME_HEIGHT, 428, "ZT165M017AT visible height is 428 px");
        assert_eq!(X_OFFSET, 12, "NV3007 X offset is 12 per production BlockWrite");
        assert_eq!(Y_OFFSET, 0, "NV3007 Y offset is 0 per production BlockWrite");
    }
}
