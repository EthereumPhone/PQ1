//! NV3007 SPI LCD driver for the ZT165M017AT module (142×428 TFT,
//! RGB565, 4-line SPI).
//!
//! ## Pin mapping (B-U585I-IOT02A, Arduino R3 headers + `spi1-arduino`)
//!
//! ```text
//!   PE12  CS  (existing `spi_hw` CS pin — D10 / CN13 pin 3)
//!   PE13  SCK (existing `spi_hw` SCK   — D13 / CN13 pin 6, AF5)
//!   PE15  MOSI (existing `spi_hw` MOSI — D11 / CN13 pin 4, AF5)
//!   PE7   DC  (Arduino D4,  CN14 — wire to NV3007 DC pin via jumper)
//!   PE14  RES (Arduino D12, CN13 pin 5 — wire to NV3007 RES pin via jumper)
//!   3V3   VCC + BLK (backlight, hard-wired for prototype; PWM-control
//!         possible via a future GPIO if dimming is needed)
//!
//! DC/RES were retargeted 2026-06-08 off the Phase-A pins PE3/PE1, which are
//! NOT reachable on this board (PE3 = on-board OCTOSPI PSRAM DQS, no pad;
//! PE1 = camera connector CN7 only). RES first went to PD15/D2 but read flat
//! on the LA at bring-up; moved to PE14 (unused SPI1_MISO = D12, on the solid
//! CN13) which shares GPIOE with the proven-working DC/SPI pins. See
//! `docs/hardware/nv3007-wiring.md`.
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

use crate::board;
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
// GPIO — DC on GPIOE bit 7 (Arduino D4 / PE7), RES on GPIOE bit 14 (Arduino D12 / PE14)
// ---------------------------------------------------------------------------
//
// Retargeted 2026-06-08: Phase-A's PE3 (DC) / PE1 (RES) aren't reachable on
// the B-U585I-IOT02A (PE3 = on-board OCTOSPI PSRAM DQS, no pad; PE1 = camera
// CN7 only). Bench bring-up confirmed DC=PE7 (Arduino D4) works, but the first
// RES choice (PD15, GPIOD, Arduino D2 on CN14) read flat on the LA — so RES
// moved to **PE14** (the unused SPI1_MISO = Arduino **D12 = CN13 pin 5**): same
// GPIOE bank as DC + the SPI pins (proven to drive), on the solid CN13
// connector. The panel is write-only so MISO is free. See docs/hardware/nv3007-wiring.md.

/// DC (Data/Command). HIGH = data, LOW = command. Push-pull output.
/// iota2: PE7 (Arduino D4). pq1: PB0, vendor net "LCM DC".
const DC_PORT: u32 = board::LCD_DC_PORT;
const DC_PIN: u32 = board::LCD_DC_PIN;

/// RES (hardware reset, active-low).
///
/// iota2: PE14 — the panel's reset is strapped to 3V3 there, so this pin is
/// NOT the panel reset; configuring it as an output merely overrides spi_hw's
/// AF5 (SPI1_MISO), which is harmless because the panel is write-only. That
/// board resets via the `SWRESET` command instead. pq1: PB1, vendor net
/// "LCM RST", genuinely driven by the MCU — see [`board::LCD_RST_IS_DRIVABLE`].
const RES_PORT: u32 = board::LCD_RST_PORT;
const RES_PIN: u32 = board::LCD_RST_PIN;

/// Whether the board's reset pin actually reaches the panel. Selects a real
/// reset pulse over the `SWRESET` command in [`init`].
const RES_DRIVABLE: bool = board::LCD_RST_IS_DRIVABLE;

/// BSRR masks for DC.
const DC_HIGH_BS: u32 = 1 << DC_PIN;
const DC_LOW_BR: u32 = 1 << (DC_PIN + 16);

/// BSRR masks for RES.
const RES_HIGH_BS: u32 = 1 << RES_PIN;
const RES_LOW_BR: u32 = 1 << (RES_PIN + 16);

// ---------------------------------------------------------------------------
// MMIO handles — all ports come from the board map
// ---------------------------------------------------------------------------
//
// `hw::spi_hw::init()` enables the clock for the SPI port only. On iota2 the
// DC and RES pins happen to sit on that same port (GPIOE); on pq1 the SPI is
// on port A while DC/RES/backlight are all on port B, so this module enables
// whatever extra port clocks its own pins need.
//
// The previous version hardcoded `GPIOE_S` plus a `GPIOD_S` block for a PD15
// reset that had been abandoned during bring-up — ten dead register handles
// with no consumer anywhere in the file.

struct LcdRegs {
    // DC port.
    dc_moder: Reg32,
    dc_otyper: Reg32,
    dc_ospeedr: Reg32,
    dc_pupdr: Reg32,
    dc_bsrr: Reg32,

    // RES port. The same physical registers as the DC ones when a board puts
    // both pins on one port (iota2 does; pq1 also does, on a different port
    // from the SPI). Aliasing is fine: every write below is a disjoint-bit RMW
    // or a single-bit BSRR store.
    res_moder: Reg32,
    res_otyper: Reg32,
    res_ospeedr: Reg32,
    res_pupdr: Reg32,
    res_bsrr: Reg32,

    // RCC AHB2ENR1 — to clock whatever ports the pins above live on.
    rcc_ahb2enr1: Reg32,

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
// on STM32U585. PE7 (GPIOE) + PD15 (GPIOD) are not claimed by any other
// secure-world driver (verified via grep — they appear only in pin_diag's
// candidate sweep). The single-threaded secure world doesn't
// race on these; RMW on disjoint bits is fine. The SPI peripheral is
// exclusively the LCD's (the TROPIC01 backend that once shared it was
// removed 2026-07-14).
const REG: LcdRegs = unsafe {
    LcdRegs {
        dc_moder: Reg32::new(DC_PORT + 0x00),
        dc_otyper: Reg32::new(DC_PORT + 0x04),
        dc_ospeedr: Reg32::new(DC_PORT + 0x08),
        dc_pupdr: Reg32::new(DC_PORT + 0x0C),
        dc_bsrr: Reg32::new(DC_PORT + 0x18),

        res_moder: Reg32::new(RES_PORT + 0x00),
        res_otyper: Reg32::new(RES_PORT + 0x04),
        res_ospeedr: Reg32::new(RES_PORT + 0x08),
        res_pupdr: Reg32::new(RES_PORT + 0x0C),
        res_bsrr: Reg32::new(RES_PORT + 0x18),

        rcc_ahb2enr1: Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF),

        spi_cr1: Reg32::new(SPI_BASE + 0x00),
        spi_cr2: Reg32::new(SPI_BASE + 0x04),
        spi_cfg1: Reg32::new(SPI_BASE + 0x08),
        spi_sr: RoReg32::new(SPI_BASE + 0x14),
        spi_ifcr: Reg32::new(SPI_BASE + 0x18),
        spi_txdr_addr: SPI_BASE + 0x20,
    }
};

// SPI SR bits (STM32U5 SPI v2, RM0456 §68.8.6)
const SR_TXP: u32 = 1 << 1; // Tx-packet space available (FIFO has room — NOT shifted out)
const SR_EOT: u32 = 1 << 3; // End-of-transfer (sets when TSIZE bytes sent; needs TSIZE > 0)

// CR1 bits (§68.8.1)
const CR1_SPE: u32 = 1 << 0;
const CR1_CSTART: u32 = 1 << 9; // self-clears at EOT; must be re-set per chunk

// IFCR clear-flag bits (§68.8.7) — only named bits are writable
const IFCR_EOTC: u32 = 1 << 3;
const IFCR_TXTFC: u32 = 1 << 4;
const IFCR_OVRC: u32 = 1 << 6;

/// TSIZE is a 16-bit counter (CR2[15:0], §68.8.2). The full RGB565 frame is
/// `142*428*2 = 121,552` bytes, which overflows it, so every bulk transfer is
/// chunked. EVEN bound so an RGB565 pixel is never split across the per-chunk
/// SPE-toggle gap.
const MAX_CHUNK: u16 = 65_534;

// ---------------------------------------------------------------------------
// GPIO helpers — DC / RES atomic set/clear via BSRR
// ---------------------------------------------------------------------------

#[inline(always)]
fn dc_low() {
    REG.dc_bsrr.write(DC_LOW_BR);
}

#[inline(always)]
fn dc_high() {
    REG.dc_bsrr.write(DC_HIGH_BS);
}

#[inline(always)]
fn res_low() {
    REG.res_bsrr.write(RES_LOW_BR);
}

#[inline(always)]
fn res_high() {
    REG.res_bsrr.write(RES_HIGH_BS);
}

/// Configure DC and RES as push-pull outputs at very-high speed, and assert
/// the backlight enable where the board has one.
///
/// Both pins start HIGH so RES does not hold the panel in reset before
/// [`hard_reset`] sequences it.
///
/// `spi_hw::init()` has already clocked the SPI port; this additionally clocks
/// whatever ports DC, RES and the backlight enable live on. On iota2 those are
/// all the SPI port (GPIOE) so the extra enables are same-value writes; on pq1
/// the SPI is on port A and these are on port B.
///
/// RES is configured on BOTH boards even though only pq1 drives a real panel
/// reset: on iota2 the pin is PE14, whose only other role is spi_hw's AF5
/// (SPI1_MISO) on a write-only panel. Keeping the write preserves that board's
/// register sequence exactly.
fn init_dc_res_gpios() {
    // Clock every port this module touches.
    let mut clocks = board::gpio_rcc_bit(DC_PORT) | board::gpio_rcc_bit(RES_PORT);
    if let Some((port, _)) = board::LCD_BACKLIGHT_EN {
        clocks |= board::gpio_rcc_bit(port);
    }
    REG.rcc_ahb2enr1.set_bits(clocks);
    cortex_m::asm::dsb();

    // DC: output, push-pull, very-high speed, no pull.
    let dc2 = DC_PIN * 2;
    let dcf = 0b11u32 << dc2;
    REG.dc_moder.modify(|v| (v & !dcf) | (0b01 << dc2));
    REG.dc_otyper.clear_bits(1 << DC_PIN);
    REG.dc_ospeedr.set_bits(dcf);
    REG.dc_pupdr.modify(|v| v & !dcf);

    // RES: same treatment.
    let res2 = RES_PIN * 2;
    let resf = 0b11u32 << res2;
    REG.res_moder.modify(|v| (v & !resf) | (0b01 << res2));
    REG.res_otyper.clear_bits(1 << RES_PIN);
    REG.res_ospeedr.set_bits(resf);
    REG.res_pupdr.modify(|v| v & !resf);

    // Start both HIGH (RES deasserted, DC = data).
    REG.dc_bsrr.write(DC_HIGH_BS);
    REG.res_bsrr.write(RES_HIGH_BS);

    // Backlight enable, where the board has one (pq1: PB15 = "LCM EN").
    //
    // NOTE: on pq1 this alone may not light the panel. LCM_EN gates an
    // AW99703 LED-driver IC whose brightness is set over I2C2 at 0x36, and
    // there is no driver for that chip in the tree yet. Asserting the enable
    // is necessary, not obviously sufficient — see `board/pq1.rs`.
    if let Some((port, pin)) = board::LCD_BACKLIGHT_EN {
        // SAFETY: `port` is a GPIO base from the board map; these are that
        // block's real MODER/OTYPER/OSPEEDR/BSRR registers, touched with
        // disjoint-bit RMW on this pin alone.
        unsafe {
            let two = pin * 2;
            let field = 0b11u32 << two;
            Reg32::new(port + 0x18).write(1 << pin); // drive high before enabling the output
            Reg32::new(port + 0x00).modify(|v| (v & !field) | (0b01 << two));
            Reg32::new(port + 0x04).clear_bits(1 << pin);
            Reg32::new(port + 0x08).set_bits(field);
            Reg32::new(port + 0x18).write(1 << pin);
        }
    }
}

// ---------------------------------------------------------------------------
// SPI byte send — direct TXDR write
// ---------------------------------------------------------------------------

/// Begin one bounded SPI transfer of exactly `tsize` bytes. TSIZE is loaded
/// into CR2 while SPE = 0 (RM0456 §68.8.2: TSIZE must be changed with the SPI
/// disabled), then SPE + CSTART start the transfer. With TSIZE > 0, EOT fires
/// deterministically when the last byte has shifted out — which is what
/// [`spi_end`] waits on. Caller pushes exactly `tsize` bytes via
/// [`spi_send_byte`], then calls [`spi_end`].
fn spi_begin(tsize: u16) {
    // SPE = 0 so TSIZE is writable (robust even if a prior chunk left it set
    // on an error path).
    REG.spi_cr1.modify(|v| v & !CR1_SPE);
    REG.spi_cr2.write(u32::from(tsize)); // CR2[15:0] = TSIZE; upper bits 0 (no CRC)
    REG.spi_cr1.modify(|v| v | CR1_SPE);
    REG.spi_cr1.modify(|v| v | CR1_CSTART);
}

/// Push one byte through TXDR. Blocks until TXP is set (Tx FIFO has space).
/// Any incoming RX byte is discarded (panel is write-only; MASRX = 0 in
/// `spi_hw::init` means the unread RxFIFO never throttles TX — RM0456 §68.8.1).
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

/// Finish one bounded transfer: wait for EOT (all TSIZE bytes shifted out on
/// the wire), then disable the peripheral and clear the sticky completion
/// flags so the NEXT chunk's EOT-wait doesn't return on a stale flag.
///
/// RM0456 §68.4.13 disable procedure (master, non-receive-only): wait EOT = 1,
/// then SPE = 0. We poll EOT because [`spi_begin`] programs TSIZE > 0, making
/// EOT fire deterministically (§68.4.12). EOT is sticky and is NOT cleared by
/// SPE = 0, so it must be cleared via IFCR.
///
/// The few-cycle delay between the EOT wait and the SPE clear is the ES0499
/// "truncation of SPI output after EOT" erratum mitigation (RM0456 §68.4.13
/// Note): at 5 MHz SPI / 160 MHz core, clearing SPE within ~tens of ns of EOT
/// can produce an asymmetric last SCK pulse and corrupt the final bit. Since
/// every command is now its own TSIZE=1 transfer, that would silently corrupt
/// the LSB of every command byte — so insert the delay.
fn spi_end() {
    while (REG.spi_sr.read() & SR_EOT) == 0 {}
    // ES0499 mitigation: let the last SCK pulse complete symmetrically before
    // dropping SPE. ~16 cycles @160 MHz ≈ 100 ns > one 5 MHz SCK half-period.
    cortex_m::asm::delay(16);
    REG.spi_cr1.modify(|v| v & !CR1_SPE);
    // Clear only the writable, named flags (§68.8.7). EOTC clears EOT for the
    // next chunk; OVRC clears the harmless OVR latched from the undrained
    // RxFIFO on this write-only panel.
    REG.spi_ifcr.write(IFCR_EOTC | IFCR_TXTFC | IFCR_OVRC);
}

// ---------------------------------------------------------------------------
// LCD command / data primitives
// ---------------------------------------------------------------------------

/// Transmit a byte slice as bounded, EOT-terminated chunks (each ≤ TSIZE max).
/// CS and DC are owned by the caller and held across the whole call.
fn spi_transfer(bytes: &[u8]) {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = core::cmp::min(bytes.len() - off, MAX_CHUNK as usize);
        spi_begin(n as u16);
        for &b in &bytes[off..off + n] {
            spi_send_byte(b);
        }
        spi_end();
        off += n;
    }
}

/// Send a command byte (DC = LOW) followed by its parameter bytes (DC = HIGH),
/// all inside ONE CS-low window. NV3007 (Novatek/MIPI-DBI) controllers reset
/// the parameter index on CS rising, so each multi-param command MUST keep CS
/// asserted across the command and every parameter. DC is toggled mid-window;
/// this is safe only because [`spi_end`] waits for EOT before returning, so the
/// command byte is fully shifted out before DC flips to data.
pub fn write_cmd_data(cmd: u8, params: &[u8]) {
    cs_assert();
    dc_low();
    spi_begin(1);
    spi_send_byte(cmd);
    spi_end();
    if !params.is_empty() {
        dc_high();
        spi_transfer(params); // CS still low; chunks ≤ TSIZE max
    }
    cs_deassert();
}

/// Send a single command byte (DC = LOW), no parameters.
pub fn write_cmd(cmd: u8) {
    write_cmd_data(cmd, &[]);
}

/// Send a single data byte (DC = HIGH). Retained for callers that already hold
/// the controller's parameter pointer; prefer [`write_cmd_data`] for new code.
#[allow(dead_code)]
pub fn write_data(data: u8) {
    cs_assert();
    dc_high();
    spi_begin(1);
    spi_send_byte(data);
    spi_end();
    cs_deassert();
}

/// Send a multi-byte data payload in one CS-asserted transaction (chunked).
pub fn write_data_bulk(data: &[u8]) {
    if data.is_empty() {
        return;
    }
    cs_assert();
    dc_high();
    spi_transfer(data);
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
    write_cmd_data(0xFF, &[0xA5]);
    write_cmd_data(0x8F, &[0x22, 0x03]);
    write_cmd_data(0x9A, &[0x78]);
    write_cmd_data(0x9B, &[0x78]);
    write_cmd_data(0x9C, &[0xA0]);
    write_cmd_data(0x9D, &[0x17]); // VGH = +15.5 V
    write_cmd_data(0x9E, &[0xC3]); // VGL = -10.5 V
    write_cmd_data(0x83, &[0xA6]); // GVCL ADJ -3.87 V
    write_cmd_data(0x84, &[0xC6]); // GVDD ADJ +6.0 V
    write_cmd_data(0x85, &[0x62]); // GVSP ADJ

    // ---- Gamma (V0/V63 + V1/V62 + V2/V61 + V20/V43 + V4/V59 +
    //              V6/V57 + V13/V50 + V36/V27 — positive + negative) ----
    write_cmd_data(0x6E, &[0x0F]);
    write_cmd_data(0x7E, &[0x0F]);
    write_cmd_data(0x60, &[0x04]);
    write_cmd_data(0x70, &[0x00]);
    write_cmd_data(0x6D, &[0x36]);
    write_cmd_data(0x7D, &[0x36]);
    write_cmd_data(0x61, &[0x05]);
    write_cmd_data(0x71, &[0x05]);
    write_cmd_data(0x6C, &[0x32]);
    write_cmd_data(0x7C, &[0x31]);
    write_cmd_data(0x62, &[0x0B]);
    write_cmd_data(0x72, &[0x0A]);
    write_cmd_data(0x68, &[0x4A]);
    write_cmd_data(0x78, &[0x4C]);
    write_cmd_data(0x66, &[0x32]);
    write_cmd_data(0x76, &[0x30]);
    write_cmd_data(0x6B, &[0x13]);
    write_cmd_data(0x7B, &[0x12]);
    write_cmd_data(0x63, &[0x09]);
    write_cmd_data(0x73, &[0x07]);
    write_cmd_data(0x6A, &[0x16]);
    write_cmd_data(0x7A, &[0x14]);
    write_cmd_data(0x64, &[0x08]);
    write_cmd_data(0x74, &[0x06]);
    write_cmd_data(0x69, &[0x0D]);
    write_cmd_data(0x79, &[0x0A]);
    write_cmd_data(0x65, &[0x04]);
    write_cmd_data(0x75, &[0x03]);
    write_cmd_data(0x67, &[0x33]);
    write_cmd_data(0x77, &[0x22]);
    write_cmd_data(0x6F, &[0x00]);
    write_cmd_data(0x7F, &[0x00]);

    // ---- GOA (Gate-On Array) timing ----
    write_cmd_data(0x50, &[0x00]);
    write_cmd_data(0x52, &[0xD6]);
    write_cmd_data(0x53, &[0x04]);
    write_cmd_data(0x54, &[0x04]);
    write_cmd_data(0x55, &[0x1B]);
    write_cmd_data(0x56, &[0x1B]);

    write_cmd_data(0xA0, &[0x2A, 0x24, 0x00]);
    write_cmd_data(0xA1, &[0x84]);
    write_cmd_data(0xA2, &[0x85]);
    write_cmd_data(0xA8, &[0x36]);
    write_cmd_data(0xA9, &[0x80]);
    write_cmd_data(0xAA, &[0x73]);
    write_cmd_data(0xAB, &[0x03, 0x61]);
    write_cmd_data(0xAC, &[0x03, 0x65]);
    write_cmd_data(0xAD, &[0x03, 0x60]);
    write_cmd_data(0xAE, &[0x03, 0x64]);
    write_cmd_data(0xB9, &[0x82]);
    write_cmd_data(0xBA, &[0x83]);
    write_cmd_data(0xBB, &[0x80]);
    write_cmd_data(0xBC, &[0x81]);
    write_cmd_data(0xBD, &[0x02]);
    write_cmd_data(0xBE, &[0x01]);
    write_cmd_data(0xBF, &[0x04]);
    write_cmd_data(0xC0, &[0x03]);
    write_cmd_data(0xC4, &[0x33]);
    write_cmd_data(0xC5, &[0x80]);
    write_cmd_data(0xC6, &[0x73]);
    write_cmd_data(0xC7, &[0x01]);
    write_cmd_data(0xC8, &[0x33, 0x33]);
    write_cmd_data(0xC9, &[0x5B]);
    write_cmd_data(0xCA, &[0x5A]);
    write_cmd_data(0xCB, &[0x5D]);
    write_cmd_data(0xCC, &[0x5C]);
    write_cmd_data(0xCD, &[0x33, 0x33]);
    write_cmd_data(0xCE, &[0x5F]);
    write_cmd_data(0xCF, &[0x5E]);
    write_cmd_data(0xD0, &[0x61]);
    write_cmd_data(0xD1, &[0x60]);

    // ---- Frame timing / inversion control ----
    write_cmd_data(0xB0, &[0x3A, 0x3A, 0x00, 0x00]);
    write_cmd_data(0xB6, &[0x32]);
    write_cmd_data(0xB7, &[0x80]);
    write_cmd_data(0xB8, &[0x73]);
    write_cmd_data(0xE0, &[0x00]);
    write_cmd_data(0xE1, &[0x03, 0x0F]);
    write_cmd_data(0xE2, &[0x04]);
    write_cmd_data(0xE3, &[0x01]);
    write_cmd_data(0xE4, &[0x0E]);
    write_cmd_data(0xE5, &[0x01]);
    write_cmd_data(0xE6, &[0x19]);
    write_cmd_data(0xE7, &[0x10]);
    write_cmd_data(0xE8, &[0x10]);
    // 0xE9: inversion mode. 0x21 = dot inversion (default). Other
    // documented values: 0x20 column, 0xA0 2-dot, 0xA1 4-dot.
    write_cmd_data(0xE9, &[0x21]);
    write_cmd_data(0xEA, &[0x12]);
    write_cmd_data(0xEB, &[0xD0]);
    write_cmd_data(0xEC, &[0x04]);
    write_cmd_data(0xED, &[0x07]);
    write_cmd_data(0xEE, &[0x07]);
    write_cmd_data(0xEF, &[0x09]);
    write_cmd_data(0xF0, &[0xD0]);
    write_cmd_data(0xF1, &[0x0E]);
    write_cmd_data(0xF9, &[0x56]);
    write_cmd_data(0xF2, &[0x26, 0x1B, 0x0B, 0x20]);
    write_cmd_data(0xEC, &[0x04]);

    // 0x35: Tearing Effect Line ON (TE pin). Set to 0x00 = "V-blank only".
    write_cmd_data(0x35, &[0x00]);
    // 0x44: tear scanline.
    write_cmd_data(0x44, &[0x00, 0x10]);
    // 0x46: brightness/related.
    write_cmd_data(0x46, &[0x10]);

    // Lock vendor command-mode (mirror of the 0xFF/0xA5 unlock at the top).
    write_cmd_data(0xFF, &[0x00]);

    // ---- Pixel format: COLMOD (0x3A) = 0x05 → RGB565 16-bit ----
    write_cmd_data(0x3A, &[0x05]);

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
    write_cmd_data(0x2A, &bytes.caset); // CASET — single CS window
    write_cmd_data(0x2B, &bytes.raset); // RASET — single CS window
    write_cmd(0x2C); // RAMWR — pixel data follows via write_pixels*
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

/// Write `n` pixels of `color` (RGB565, big-endian on the wire) to the current
/// window. Chunked by pixel count — never builds a 121 KB buffer (no_std,
/// stack-only). CS stays low across all chunks; only SPE toggles per chunk.
pub fn write_pixels_solid(color: u16, n: u32) {
    if n == 0 {
        return;
    }
    let hi = (color >> 8) as u8;
    let lo = color as u8;
    cs_assert();
    dc_high();
    // MAX_CHUNK is even, so MAX_CHUNK/2 pixels = MAX_CHUNK bytes per chunk —
    // a pixel is never split across the SPE-toggle gap.
    let pixels_per_chunk: u32 = u32::from(MAX_CHUNK / 2);
    let mut remaining = n;
    while remaining > 0 {
        let chunk_px = core::cmp::min(remaining, pixels_per_chunk);
        spi_begin((chunk_px * 2) as u16);
        for _ in 0..chunk_px {
            spi_send_byte(hi);
            spi_send_byte(lo);
        }
        spi_end();
        remaining -= chunk_px;
    }
    cs_deassert();
}

/// Write a slice of RGB565 pixels to the current window. Transmitted big-endian
/// (NV3007 expects high byte first). Chunked by pixel count; CS held low across
/// all chunks.
pub fn write_pixels(buf: &[u16]) {
    if buf.is_empty() {
        return;
    }
    cs_assert();
    dc_high();
    let pixels_per_chunk = (MAX_CHUNK / 2) as usize;
    for chunk in buf.chunks(pixels_per_chunk) {
        spi_begin((chunk.len() * 2) as u16);
        for &px in chunk {
            spi_send_byte((px >> 8) as u8);
            spi_send_byte(px as u8);
        }
        spi_end();
    }
    cs_deassert();
}

/// Stream `n` RGB565 pixels into the current window, pulling each from `next`.
/// One continuous transaction — CS held low across the whole run, only SPE
/// toggles per `MAX_CHUNK` chunk (identical framing to [`write_pixels_solid`]).
/// This lets a caller blit a computed full-frame image with a SINGLE
/// `set_window` + RAMWR instead of one window per row, and without ever
/// materialising a 121 KB native framebuffer. Pixels are sent big-endian.
///
/// `#[inline]` so the per-pixel generator closure (and any framebuffer read it
/// performs) folds into a tight loop at the call site rather than an indirect
/// call per pixel — keeps the blit close to the polled-SPI throughput floor.
#[inline]
pub fn write_pixels_with(n: u32, mut next: impl FnMut() -> u16) {
    if n == 0 {
        return;
    }
    cs_assert();
    dc_high();
    let pixels_per_chunk: u32 = u32::from(MAX_CHUNK / 2);
    let mut remaining = n;
    while remaining > 0 {
        let chunk_px = core::cmp::min(remaining, pixels_per_chunk);
        spi_begin((chunk_px * 2) as u16);
        for _ in 0..chunk_px {
            let px = next();
            spi_send_byte((px >> 8) as u8);
            spi_send_byte(px as u8);
        }
        spi_end();
        remaining -= chunk_px;
    }
    cs_deassert();
}

/// Fill the entire visible area with `color`. Convenience wrapper.
pub fn fill_screen(color: u16) {
    set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1);
    write_pixels_solid(color, FRAME_WIDTH as u32 * FRAME_HEIGHT as u32);
}

/// Fill a `w`×`h` rectangle at `(x0, y0)` with `color` — a PARTIAL update.
/// Only the rect's `w*h*2` bytes cross SPI (the controller auto-wraps RAMWR
/// within the CASET/RASET window), so for UI-sized regions this is sub-
/// millisecond versus ~24 ms for a full 142×428 repaint at 40 MHz. This is
/// the primitive the trusted-UI layer uses to keep interactive screens
/// instant — redraw only the changed region (a PIN digit, a text line, the
/// fingerprint words), never the whole frame.
pub fn fill_rect(x0: u16, y0: u16, w: u16, h: u16, color: u16) {
    if w == 0 || h == 0 {
        return;
    }
    set_window(x0, y0, x0 + w - 1, y0 + h - 1);
    write_pixels_solid(color, u32::from(w) * u32::from(h));
}

// ---------------------------------------------------------------------------
// Top-level init
// ---------------------------------------------------------------------------

/// Bring the LCD up. Assumes [`hw::spi_hw::init`] has already
/// configured the SPI peripheral + CS/SCK/MOSI pins. Steps:
///
/// 1. Configure DC + RES GPIOs (PE7 on GPIOE + PD15 on GPIOD, push-pull).
/// 2. Hardware reset pulse.
/// 3. Run the production NV3007 init sequence.
/// 4. Clear the screen to black (RGB565 `0x0000`).
///
/// Assumes [`hw::spi_hw::init()`] has already run (SPI1 + CS/SCK/MOSI).
pub fn init() {
    // main.rs does not init SPI for ui-lcd, so do it here.
    crate::hw::spi_hw::init();
    init_dc_res_gpios();

    // Reset the panel the way this board can. iota2 has its RES strapped to
    // 3V3 (PD15 and PE14 both proved un-drivable during bring-up), so it
    // issues the SWRESET command; pq1 routes LCM_RST to PB1 and gets a real
    // pin pulse, which also resets state SWRESET leaves alone.
    if RES_DRIVABLE {
        hard_reset();
    } else {
        write_cmd(0x01); // SWRESET
    }
    delay_ms(150);
    run_init_sequence();
    fill_screen(0x0000);
}

/// Phase-B bench bring-up (`lcd-test` feature): set up SPI1 + the LCD, then
/// cycle the whole screen **green → red → blue** forever (~1 s each). The
/// first physical confirmation that the wiring + the ported init sequence
/// work on real silicon. Never returns. Run via `make lcd-test-hw`.
#[cfg(feature = "lcd-test")]
pub fn lcd_test_loop() -> ! {
    // RES is tied to 3V3 externally (PD15 and PE14 both proved un-drivable on
    // this board — loaded on-board), so the panel is held OUT of reset and we
    // reset it in software with SWRESET (0x01) instead of a hardware pulse.
    secure_log!("[LCD-TEST] start (RES=3V3, software reset via SWRESET)");
    crate::hw::spi_hw::init();
    secure_log!("[LCD-TEST] spi_hw::init done");
    init_dc_res_gpios(); // DC = PE7 (the PE14/RES config is now unused)
    secure_log!("[LCD-TEST] dc gpio done");
    // Software reset first (RES is tied to 3V3, so no hardware-reset pulse).
    write_cmd(0x01); // SWRESET
    secure_log!("[LCD-TEST] SWRESET sent");
    delay_ms(150);
    // FULL canonical dgen1 init for this exact NV3007 SKU. The earlier minimal
    // init (SWRESET/SLPOUT/COLMOD/DISPON) confirmed the panel is alive after
    // the SPI-transfer fix, but left the pixel format under-configured: solid
    // fills showed fine vertical striping (RGB565 hi/lo bytes split across
    // adjacent columns) because 16-bit mode was never latched — COLMOD 0x05 was
    // sent WITHOUT the vendor unlock (0xFF 0xA5) that gates it, and MADCTL + the
    // GOA timing were skipped, leaving the bottom band unaddressed. The full
    // sequence unlocks vendor regs, sets gamma/GOA/COLMOD in the right order,
    // then SLPOUT + DISPON + full-screen window. Multi-parameter commands now
    // transmit correctly via write_cmd_data, so this runs as the vendor intends.
    run_init_sequence();
    secure_log!("[LCD-TEST] full dgen1 init done — fill loop");

    // One-shot repaint timing via the DWT cycle counter — turns "feels faster"
    // into a real ms/frame number at the current SPI prescaler.
    // SAFETY: TRCENA + DWT_LAR unlock + CYCCNT enable; plain debug-block writes
    // always accessible to secure code (mirrors bench_masked_sha.rs).
    unsafe {
        core::ptr::write_volatile(
            0xE000_EDFC as *mut u32,
            core::ptr::read_volatile(0xE000_EDFC as *mut u32) | (1 << 24),
        ); // DEMCR.TRCENA
        core::ptr::write_volatile(0xE000_1FB0 as *mut u32, 0xC5AC_CE55); // DWT_LAR unlock
        core::ptr::write_volatile(0xE000_1004 as *mut u32, 0); // DWT_CYCCNT = 0
        core::ptr::write_volatile(
            0xE000_1000 as *mut u32,
            core::ptr::read_volatile(0xE000_1000 as *mut u32) | 1,
        ); // DWT_CTRL.CYCCNTENA
    }
    // SAFETY: plain read of the free-running DWT cycle counter.
    let t0 = unsafe { core::ptr::read_volatile(0xE000_1004 as *mut u32) };
    fill_screen(0x07E0); // measured green repaint
    let dt = unsafe { core::ptr::read_volatile(0xE000_1004 as *mut u32) }.wrapping_sub(t0);
    let us = dt / 160; // 160 cycles/µs @160 MHz
    secure_log!(
        "[LCD-TEST] full repaint = {} us ({} cyc) ~ {} fps",
        us,
        dt,
        1_000_000 / us.max(1)
    );
    delay_ms(1000);

    // A couple of full-frame fills so the whole panel is still exercised...
    fill_screen(0xF800); // red
    delay_ms(700);
    fill_screen(0x001F); // blue
    delay_ms(700);

    // ---- Partial-update showcase ----
    // Clear once, then measure ONE small fill_rect: only the box's bytes cross
    // SPI, so it's ~instant compared to a full repaint.
    fill_screen(0x0000);
    let p0 = unsafe { core::ptr::read_volatile(0xE000_1004 as *mut u32) };
    fill_rect(20, 60, 40, 40, 0xFFFF);
    let pdt = unsafe { core::ptr::read_volatile(0xE000_1004 as *mut u32) }.wrapping_sub(p0);
    let pus = pdt / 160;
    secure_log!(
        "[LCD-TEST] partial 40x40 = {} us ({} fps-equiv) vs full-frame {} us",
        pus,
        1_000_000 / pus.max(1),
        us
    );
    fill_rect(20, 60, 40, 40, 0x0000); // erase

    // Moving-box demo (forever), FLICKER-FREE. The naive "draw box → erase whole
    // box → redraw shifted" leaves the box black for ~1 ms/step → visible
    // flicker. Instead we only touch what changes: as the box slides right by
    // STEP, draw a STEP-wide green sliver on the new leading edge and erase a
    // STEP-wide sliver on the vacated trailing edge. The 30 px body is never
    // cleared, so there is no black gap — this is the draw-over technique the
    // real trusted-UI layer uses to repaint a PIN digit / text line without
    // flicker (~180 B/step, far below the bus limit).
    const BOX_W: u16 = 30;
    const STEP: u16 = 3;
    const BOX_Y: u16 = 100;
    let mut x: u16 = 0;
    fill_rect(x, BOX_Y, BOX_W, BOX_W, 0x07E0); // initial solid box
    loop {
        delay_ms(16); // ~60 Hz
        if x + STEP + BOX_W >= FRAME_WIDTH {
            // wrap: clear the box and restart at the left edge
            fill_rect(x, BOX_Y, BOX_W, BOX_W, 0x0000);
            x = 0;
            fill_rect(x, BOX_Y, BOX_W, BOX_W, 0x07E0);
        } else {
            fill_rect(x + BOX_W, BOX_Y, STEP, BOX_W, 0x07E0); // extend leading edge
            fill_rect(x, BOX_Y, STEP, BOX_W, 0x0000); // retract trailing edge
            x += STEP;
        }
    }
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
