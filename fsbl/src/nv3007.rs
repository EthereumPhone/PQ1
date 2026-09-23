//! Minimal NV3007 142×428 SPI LCD driver for the FSBL fingerprint render.
//!
//! Ports the SPI1 + NV3007 bring-up from `secure/src/hw/spi_hw.rs` +
//! `secure/src/hw/lcd_nv3007.rs` + the text-grid blit from
//! `secure/src/ui/lcd.rs`, but — exactly like the now-retired
//! `fsbl/src/oled.rs` did for the SSD1306 — drops every dependency the
//! FSBL doesn't need: no `embedded-graphics`, no semihosting logs, no
//! shared `hw::mmio` typed wrappers, no constant-time secret path (the
//! FSBL only ever renders the PUBLIC firmware fingerprint, never a seed).
//! Raw `read_volatile` / `write_volatile` against the STM32U585
//! secure-alias MMIO addresses, a per-glyph RGB565 scratch cell, and the
//! same 5×8 font in [`crate::glyphs`] the OLED path used.
//!
//! ## Display model — identical 16×4 grid, same words as the secure world
//!
//! Renders the SAME `DISPLAY_COLS=16 × DISPLAY_ROWS=4` char grid as the
//! secure-world `ui-lcd` backend (`secure/src/ui/lcd.rs`), so the FSBL
//! legacy bench-FSBL row and `measured_boot::run`'s advisory row show the same
//! 8 words for the same digest. The eventual trust-root claim additionally
//! requires the approved geometry, WRP/RDP ceremony, resource gates, and
//! silicon evidence; this display parity alone does not establish it.
//!
//! ## Pin mapping — from [`crate::board`], not hard-coded
//!
//! Every pin, port base and alternate-function number comes from the board
//! map, mirroring `secure/src/hw/spi_hw.rs`. Naming a board is mandatory.
//!
//! ```text
//!   iota2 (B-U585I-IOT02A, Arduino R3 headers)
//!     PE12  CS   (D10 / CN13 pin 3, GPIO output active-low)
//!     PE13  SCK  (D13 / CN13 pin 6, SPI1_SCK  AF5)
//!     PE14  MISO (D12 — configured AF5, then overridden as RES; unread)
//!     PE15  MOSI (D11 / CN13 pin 4, SPI1_MOSI AF5)
//!     PE7   DC   (D4,  CN14 — Data/Command)
//!     3V3   VCC + BLK (backlight hard-wired), RES strapped to 3V3
//!
//!   pq1 (AL_A66_MB_V10, 48-pin UFQFPN)
//!     PA4   CS   ("LCM SPI CS",   GPIO output active-low)
//!     PA5   SCK  ("LCM SPI LCK",  SPI1_SCK  AF5)
//!     PA7   MOSI ("LCM SPI MOSI", SPI1_MOSI AF5)   — no MISO: PA6 is NC
//!     PB0   DC   ("LCM DC")
//!     PB1   RST  ("LCM RST")  — really driven here, so a real reset pulse
//!     PB15  EN   ("LCM EN")   — gates an AW99703; see the note below
//! ```
//!
//! Three pq1 properties broke the previous hard-coded form, and they are why
//! this port exists: the panel is on **port A**, which is a port that on a
//! 48-pin part *exists on the die but drives nothing* if you write the wrong
//! one; the SPI pins are **non-contiguous** (4/5/7, PA6 skipped), so deriving
//! them by offset from CS is wrong; and they sit **below pin 8**, so their AF
//! nibbles are in `AFRL` while iota2's 12..15 are all in `AFRH`.
//!
//! DC/RST/EN are on a **different port** from the SPI on pq1, so this driver
//! clocks every port its own pins live on rather than assuming one.
//!
//! ## Backlight — a dark pq1 panel is NOT a failure of this driver
//!
//! `LCM_EN` (PB15) only enables an AW99703 LED-driver IC whose brightness is
//! programmed over I2C2 at `0x36`. The FSBL has no I2C stage YET — #705 is
//! adding one, and the owner has chosen recoverable fail-closed for it — so
//! until that lands the success criterion for this display port is the
//! `stage-marker` page reaching `LcdInited` and `RenderFlushed` with a zero
//! timeout count, not visible pixels.
//!
//! (The secure world HAS had a driver for that chip since 2026-09; the claim
//! that none exists in the tree was true when written and is not now.)
//!
//! ## Clocking — 4 MHz MSIS, NOT the 16 MHz this file used to claim
//!
//! The FSBL brings up no PLL and writes no RCC clock configuration (only
//! peripheral clock enables), so it runs at the reset clock throughout.
//!
//! **Corrected 2026-09-16 — this file previously said "16 MHz HSI reset
//! default", which is wrong by 4×.** From the vendor SVD's reset values
//! (`STM32CubeProgrammer/SVD/STM32U585.svd`):
//!
//! ```text
//!   RCC_CFGR1 reset 0x0000_0000 -> SW[1:0] = 00      => SYSCLK is MSIS
//!   RCC_ICSCR1 reset 0x4400_0000 -> MSIRGSEL(b23) = 0 => range from RCC_CSR
//!   RCC_CSR   reset 0x0C00_4400 -> MSISSRANGE[15:12] = 4
//!   SVD enumeration: "range 4 around 4 MHz (reset value)"
//! ```
//!
//! Both range sources hold 4 at reset (`ICSCR1.MSISRANGE[31:28]` is also 4),
//! so `MSIRGSEL` does not change the answer. Corroborated on the bench: a
//! sampled `RCC_CR = 0x35` matches the SVD reset value exactly, consistent
//! with the FSBL never touching it. The giveaway in-tree was always
//! `secure/src/hw/rcc.rs`, which *enables HSI16 and switches SYSCLK to it* as
//! its first step — pointless if reset were already HSI16.
//!
//! **The FSBL now switches to HSI16 (16 MHz) at the top of `main`** — see
//! [`crate::clock`]. Everything below is MEASURED (pq1, via the `stage-marker`
//! DWT timestamps; `crate::marker`'s header carries the full budget):
//!
//!   * [`delay_ms`] derives its iteration count from the ACHIEVED clock, so
//!     delays are now correct rather than 8× long. The 850 ms of NV3007 vendor
//!     waits inside [`Lcd::init`] cost ~0.85 s as intended, and `render.rs`'s
//!     hold is honoured to within 0.03% at both nominals tested
//!     (3,000 ms → 3.001 s; 10,000 ms → 10.002 s).
//!   * [`Lcd::init`] measures **1.188 s** (was 8.41 s), of which ~0.34 s is
//!     real SPI work. `MBR = ÷4` of a 16 MHz PCLK2 is a **4 MHz** SPI clock,
//!     so the 121,552-byte repaint has a ~0.24 s shifting floor.
//!   * a [`spi_wait`] timeout costs ~2.5 s at 16 MHz (was ~10 s) — still long
//!     enough that a wrong pin map presents as a hang rather than as slowness.
//!
//! Whole boot: **12.932 s**, of which only 2.930 s is work — the rest is the
//! fingerprint hold, deliberately set to 10 s so the user has time to read the
//! 8 words. It was 39.367 s on the 4 MHz reset clock with the 8×-long loop,
//! and 5.931 s at the interim 3 s hold. Compute terms scaled 4.0× (the clock);
//! delay terms 8.0× (removing the calibration error). Boot time is now almost
//! entirely a `FINGERPRINT_HOLD_MS` policy choice, not a code one.
//!
//! 1 MHz keeps a very large margin over the NV3007's 10 ns setup/hold spec,
//! so the prescaler stays as-is; the panel is painted once at boot.
//!
//! ## Reset — per board, selected by a const
//!
//! On iota2 RES (PE14) is tied to 3V3 (both PE14 and PD15 proved un-drivable
//! at bring-up — see `lcd_nv3007.rs`), so the panel is held out of reset and
//! we reset it in software with `0x01` (SWRESET). On pq1 `LCM_RST` really is
//! driven by the MCU (PB1), so it gets a genuine pulse via [`hard_reset`],
//! which also resets state SWRESET leaves alone. [`board::LCD_RST_IS_DRIVABLE`]
//! picks between them; being a `const`, the unused arm is
//! dead-code-eliminated, so neither board carries the other's path. Both
//! mirror the validated secure `lcd::init()` sequence.
//!
//! On QEMU this driver does not run: the FSBL only ever builds for
//! `thumbv8m.main-none-eabi` (`fsbl/build.rs`), there is no QEMU FSBL path,
//! and the panel is write-only (no presence probe is possible or needed).

use core::ptr::{read_volatile, write_volatile};

use crate::board;
use crate::glyphs::glyph_col;

// ---------------------------------------------------------------------------
// MMIO addresses (STM32U585 secure aliases — TZEN=1), derived from the board
// ---------------------------------------------------------------------------

const SPI1: usize = board::LCD_SPI_BASE as usize;

// RCC offsets
const RCC_AHB2ENR1: usize = (board::RCC_S + board::RCC_AHB2ENR1_OFF) as usize;
const RCC_APB2ENR: usize = (board::RCC_S + board::RCC_APB2ENR_OFF) as usize;
const RCC_APB2RSTR: usize = (board::RCC_S + board::RCC_APB2RSTR_OFF) as usize;

/// Address of one GPIO register on an arbitrary port.
///
/// The previous form had a fixed `GPIOE_*` const per register, which cannot
/// express pq1's split across two ports (SPI on A, control lines on B).
const fn greg(port: u32, off: u32) -> usize {
    (port + off) as usize
}

// SPI1 offsets (STM32U5 SPI v2, RM0456 §68.8)
const SPI_CR1: usize = SPI1 + 0x00;
const SPI_CR2: usize = SPI1 + 0x04;
const SPI_CFG1: usize = SPI1 + 0x08;
const SPI_CFG2: usize = SPI1 + 0x0C;
const SPI_IER: usize = SPI1 + 0x10;
const SPI_SR: usize = SPI1 + 0x14;
const SPI_IFCR: usize = SPI1 + 0x18;
const SPI_TXDR: usize = SPI1 + 0x20;

// SPI SR / CR1 / IFCR bits
const SR_TXP: u32 = 1 << 1;
const SR_EOT: u32 = 1 << 3;
const CR1_SPE: u32 = 1 << 0;
const CR1_CSTART: u32 = 1 << 9;
const IFCR_EOTC: u32 = 1 << 3;
const IFCR_TXTFC: u32 = 1 << 4;
const IFCR_OVRC: u32 = 1 << 6;

// Pins and their ports, from the board map. CS sits on the SPI port on both
// boards; DC and RES do NOT (pq1 puts them on port B).
const SPI_PORT: u32 = board::LCD_SPI_PORT;
const CS_PIN: u32 = board::LCD_CS_PIN;
const DC_PORT: u32 = board::LCD_DC_PORT;
const DC_PIN: u32 = board::LCD_DC_PIN;
const RES_PORT: u32 = board::LCD_RST_PORT;
const RES_PIN: u32 = board::LCD_RST_PIN;

/// TSIZE is CR2[15:0]; chunk every bulk transfer. Even so an RGB565 pixel is
/// never split across the per-chunk SPE-toggle gap.
const MAX_CHUNK: u16 = 65_534;

// ---------------------------------------------------------------------------
// Display + font geometry (mirrors secure/src/ui/lcd.rs verbatim)
// ---------------------------------------------------------------------------

const FRAME_WIDTH: u16 = 142;
const FRAME_HEIGHT: u16 = 428;
/// NV3007 RAM extends past the visible window; the production `BlockWrite`
/// adds 12 to every X coordinate. Hardware-validated 2026-06-09.
const X_OFFSET: u16 = 12;
const Y_OFFSET: u16 = 0;

const FONT_W: usize = 5; // FONT_5X8 source width
const FONT_H: usize = 8; // FONT_5X8 source height
const SCALE: usize = 3; // integer upscale → 15×24 glyph

const GLYPH_LW: usize = FONT_W * SCALE; // 15 — landscape X
const GLYPH_LH: usize = FONT_H * SCALE; // 24 — landscape Y
const COL_PITCH: usize = 26; // landscape X between columns
const ROW_PITCH: usize = 35; // landscape Y between rows
const ORIGIN_X: usize = 6; // (428 - 16*26)/2
const ORIGIN_Y: usize = 1; // (142 - 4*35)/2

const CELL_NX: usize = GLYPH_LH; // 24 — native X extent of a glyph
const CELL_NY: usize = GLYPH_LW; // 15 — native Y extent of a glyph
const CELL_N: usize = CELL_NX * CELL_NY; // 360 RGB565 px = 720 B

const PANEL_W: usize = 142; // native X
const PANEL_H: usize = 428; // native Y

/// Hardware-validated orientation (`secure/src/ui/lcd.rs`): flip native-X
/// only renders upright + un-mirrored on the validated mount.
const FLIP_X: bool = true;
const FLIP_Y: bool = false;

const FG: u16 = 0xFFFF; // white text
const BG: u16 = 0x0000; // black background

const DISPLAY_COLS: usize = 16;
const DISPLAY_ROWS: usize = 4;

// ---------------------------------------------------------------------------
// MMIO helpers (raw — same shape as the retired oled.rs)
// ---------------------------------------------------------------------------

#[inline(always)]
fn rd(addr: usize) -> u32 {
    // SAFETY: `addr` is one of the secure-alias MMIO constants above, owned by
    // RCC / GPIOE / SPI1. The FSBL runs single-threaded with no other driver
    // initialised, so there is no race; shared RCC/GPIOE bits use RMW.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn wr(addr: usize, v: u32) {
    // SAFETY: see `rd`. SPI1 CR/CFG/IFCR/TXDR are exclusively ours; shared
    // RCC/GPIOE registers are written via disjoint-bit RMW helpers below.
    unsafe { write_volatile(addr as *mut u32, v) }
}

#[inline(always)]
fn set_bits(addr: usize, bits: u32) {
    wr(addr, rd(addr) | bits);
}

#[inline(always)]
fn modify(addr: usize, f: impl FnOnce(u32) -> u32) {
    wr(addr, f(rd(addr)));
}

/// Loop iterations per millisecond, derived from the clock [`crate::clock`]
/// actually achieved. **Never hardcode this**: a constant that disagrees with
/// the real clock is how the previous version came to run every delay 8× long
/// (a 39.4 s boot), and calibrating for a clock the part did NOT reach would
/// run them 4× SHORT — the one direction that violates the NV3007's vendor
/// minimums.
///
/// The loop costs a MEASURED 8.00 cycles/iteration (pq1, 2026-09-16: a 3,000 ms
/// nominal hold took exactly 24.003 s at 4 MHz, which pins it). So one
/// millisecond is `hz / 8000` iterations — 500 at 4 MHz, 2,000 at 16 MHz.
const CYCLES_PER_ITER: u32 = 8;

#[inline(always)]
fn iters_per_ms() -> u32 {
    crate::clock::achieved_hz() / (1_000 * CYCLES_PER_ITER)
}

/// Blocking nop-counted delay, calibrated at run time from the achieved clock.
/// Deliberately NOT the secure driver's `cortex_m::asm::delay(160_000 * ms)`,
/// which assumes the 160 MHz PLL the FSBL never brings up.
///
/// History worth keeping, because both errors were silent: the original
/// hardcoded `4_000` assumed 4 cycles/iteration at 16 MHz. The part actually
/// ran at 4 MHz and the loop actually costs 8 cycles/iteration, so every delay
/// was **8×** nominal — the NV3007 reset/SLPOUT/DISPON waits cost 6.8 s and the
/// fingerprint hold 24.0 s, together 78% of a 39.4 s boot. Deriving the figure
/// instead of asserting it makes both the clock switch and the calibration
/// self-consistent, and keeps a failed switch safe rather than dangerous.
///
/// VALIDATED on silicon at two nominals, so the constant rests on a measured
/// slope rather than a single point: with HSI16 selected, a 3,000 ms hold
/// measures 3.001 s (+0.03%) and a 10,000 ms hold 10.002 s (+0.02%) — linear
/// across a 3.3× range, confirming 8.00 cycles/iteration at 16 MHz even though
/// the loop bound is now a runtime value.
pub fn delay_ms(ms: u32) {
    let iters = iters_per_ms();
    for _ in 0..ms {
        for _ in 0..iters {
            cortex_m::asm::nop();
        }
    }
}

// ---------------------------------------------------------------------------
// DC / RES GPIO via BSRR (atomic set/clear)
// ---------------------------------------------------------------------------

#[inline(always)]
fn dc_low() {
    wr(greg(DC_PORT, board::GPIO_BSRR_OFF), 1 << (DC_PIN + 16));
}
#[inline(always)]
fn dc_high() {
    wr(greg(DC_PORT, board::GPIO_BSRR_OFF), 1 << DC_PIN);
}
#[inline(always)]
fn cs_assert() {
    wr(greg(SPI_PORT, board::GPIO_BSRR_OFF), 1 << (CS_PIN + 16));
}
#[inline(always)]
fn cs_deassert() {
    wr(greg(SPI_PORT, board::GPIO_BSRR_OFF), 1 << CS_PIN);
}
#[inline(always)]
fn res_low() {
    wr(greg(RES_PORT, board::GPIO_BSRR_OFF), 1 << (RES_PIN + 16));
}
#[inline(always)]
fn res_high() {
    wr(greg(RES_PORT, board::GPIO_BSRR_OFF), 1 << RES_PIN);
}

/// Configure one pin as a push-pull output at very-high speed, no pull.
///
/// Additionally clears `PUPDR`, which the previous hard-coded CS block did
/// not. Every LCD pin on both boards has a `PUPDR` reset value of 00 and the
/// FSBL sets no pulls, so this is a no-op in practice — it is here so that DC,
/// RES, CS and the backlight enable all go through one reviewed path.
fn config_output_pin(port: u32, pin: u32) {
    let two = pin * 2;
    let field = 0b11u32 << two;
    modify(greg(port, board::GPIO_MODER_OFF), |v| {
        (v & !field) | (0b01 << two)
    });
    modify(greg(port, board::GPIO_OTYPER_OFF), |v| v & !(1 << pin));
    set_bits(greg(port, board::GPIO_OSPEEDR_OFF), field);
    modify(greg(port, board::GPIO_PUPDR_OFF), |v| v & !field);
}

/// Configure one pin into alternate-function mode at [`board::LCD_SPI_AF`],
/// push-pull, very-high speed. Touches only this pin's bits.
///
/// Uses [`board::afr_off`] so the nibble lands in `AFRL` for pins 0..7 and
/// `AFRH` for 8..15 — the previous form wrote `AFRH` unconditionally, which
/// silently mis-configured every pq1 pin.
fn config_af_pin(pin: u32) {
    let two = pin * 2;
    let field = 0b11u32 << two;
    modify(greg(SPI_PORT, board::GPIO_MODER_OFF), |v| {
        (v & !field) | (0b10 << two)
    });
    modify(greg(SPI_PORT, board::GPIO_OTYPER_OFF), |v| v & !(1 << pin));
    set_bits(greg(SPI_PORT, board::GPIO_OSPEEDR_OFF), field);
    let sh = board::afr_shift(pin);
    modify(greg(SPI_PORT, board::afr_off(pin)), |v| {
        (v & !(0xF << sh)) | (board::LCD_SPI_AF << sh)
    });
}

// ---------------------------------------------------------------------------
// SPI1 init (ports spi_hw::init, board-derived pinout, 4 MHz PCLK2)
// ---------------------------------------------------------------------------

fn spi1_init() {
    // 1. GPIO clock for the port the SPI pins live on.
    set_bits(RCC_AHB2ENR1, board::gpio_rcc_bit(SPI_PORT));
    cortex_m::asm::dsb();
    // 2. SPI1 clock (APB2 bit 12).
    set_bits(RCC_APB2ENR, board::RCC_SPI1EN_BIT);
    cortex_m::asm::dsb();
    // 3. Reset SPI1.
    set_bits(RCC_APB2RSTR, board::RCC_SPI1RST_BIT);
    cortex_m::asm::dsb();
    modify(RCC_APB2RSTR, |v| v & !board::RCC_SPI1RST_BIT);
    cortex_m::asm::dsb();

    // 4. CS as a GPIO output, push-pull, very-high speed. Driven HIGH before
    //    the mode switch (as `secure/src/hw/spi_hw.rs` does) so the panel
    //    never sees a spurious select while the pad is being configured.
    wr(greg(SPI_PORT, board::GPIO_BSRR_OFF), 1 << CS_PIN);
    config_output_pin(SPI_PORT, CS_PIN);
    wr(greg(SPI_PORT, board::GPIO_BSRR_OFF), 1 << CS_PIN);

    // 5. SCK / MOSI (and MISO where the board routes one) as AF.
    //    Per pin rather than one contiguous run: pq1's are 5 and 7 with a gap
    //    and sit in AFRL, while iota2's 13/14/15 are a run in AFRH.
    config_af_pin(board::LCD_SCK_PIN);
    config_af_pin(board::LCD_MOSI_PIN);
    if let Some(miso) = board::LCD_MISO_PIN {
        // iota2 only. The panel is write-only on both boards, so this pad's
        // configuration is the only thing that changes — and on iota2
        // `init_dc_res_gpios` then overrides this same pin as the RES output.
        config_af_pin(miso);
    }

    // 6. SPI peripheral. SSI=1 before MASTER (avoid false mode-fault), SPE=0.
    wr(SPI_CR1, 1 << 12);
    cortex_m::asm::dsb();
    // CFG1: DSIZE=7 (8-bit), MBR=÷4 (bits [30:28]=0b001) → 4/4 = 1 MHz SPI
    // (PCLK2 is the 4 MHz MSIS reset clock, not the 16 MHz once assumed here).
    wr(SPI_CFG1, (0b001 << 28) | 7);
    // CFG2: MASTER (bit 22) + SSM (bit 26); Mode 0, MSB-first, full-duplex.
    wr(SPI_CFG2, (1 << 22) | (1 << 26));
    wr(SPI_IER, 0);
    cortex_m::asm::dsb();
}

/// DC + RES as push-pull outputs, both starting HIGH (RES deasserted, DC =
/// data), plus the backlight enable where the board has one.
///
/// On iota2 DC and RES are both on the SPI port (already clocked by
/// `spi1_init`), and RES overriding the MISO pad's AF is harmless — write-only
/// panel — because that board's panel reset is strapped to 3V3. On pq1 they
/// are on port B while the SPI is on port A, so the extra port clock is
/// load-bearing: without it these writes reach an unclocked port and the pads
/// never move.
fn init_dc_res_gpios() {
    // Clock every port this function touches, in one write.
    let mut clocks = board::gpio_rcc_bit(DC_PORT) | board::gpio_rcc_bit(RES_PORT);
    if let Some((port, _)) = board::LCD_BACKLIGHT_EN {
        clocks |= board::gpio_rcc_bit(port);
    }
    set_bits(RCC_AHB2ENR1, clocks);
    cortex_m::asm::dsb();

    config_output_pin(DC_PORT, DC_PIN);
    config_output_pin(RES_PORT, RES_PIN);

    // Start both HIGH (RES deasserted so `hard_reset` can sequence it).
    wr(greg(DC_PORT, board::GPIO_BSRR_OFF), 1 << DC_PIN);
    wr(greg(RES_PORT, board::GPIO_BSRR_OFF), 1 << RES_PIN);

    // Backlight enable, where the board has one (pq1: PB15 = "LCM EN").
    // Driven high BEFORE the output is enabled, matching the secure driver.
    //
    // NOTE: on pq1 this alone may not light the panel — LCM_EN gates an
    // AW99703 whose brightness is set over I2C2 at 0x36, and the FSBL has no
    // I2C stage. Necessary, not sufficient; see the module header.
    //
    // HWEN high only reaches Standby, which emits no light, so asserting it
    // HERE — before reset/init/fill — is correct. When #705 adds the I2C
    // stage, the write that leaves Standby must NOT go here: it belongs after
    // `fill_screen` in `Lcd::init`, because DISPON (end of the init sequence)
    // would otherwise show undefined GRAM on a lit panel (#730). The secure
    // driver's `aw99703::configure()` / `enable()` split is the shape to copy.
    if let Some((port, pin)) = board::LCD_BACKLIGHT_EN {
        wr(greg(port, board::GPIO_BSRR_OFF), 1 << pin);
        config_output_pin(port, pin);
        wr(greg(port, board::GPIO_BSRR_OFF), 1 << pin);
    }
}

/// Hardware reset pulse, for boards whose RES line actually reaches the panel.
///
/// Timing mirrors the validated secure driver
/// (`secure/src/hw/lcd_nv3007.rs::hard_reset`): high 10 ms, low 200 ms, high
/// 120 ms. Note these are `delay_ms` units, which are nop-calibrated — see
/// the calibration note on [`delay_ms`].
fn hard_reset() {
    res_high();
    delay_ms(10);
    res_low();
    delay_ms(200);
    res_high();
    delay_ms(120);
}

// ---------------------------------------------------------------------------
// SPI byte send + bounded transfer (ports lcd_nv3007's spi_begin/send/end)
// ---------------------------------------------------------------------------

fn spi_begin(tsize: u16) {
    modify(SPI_CR1, |v| v & !CR1_SPE);
    wr(SPI_CR2, u32::from(tsize));
    modify(SPI_CR1, |v| v | CR1_SPE);
    modify(SPI_CR1, |v| v | CR1_CSTART);
}

/// Bounded poll of an SPI status flag. Spins until `flag` is set or the cap is
/// hit, returning whether it was seen. On a healthy panel the flag is ready
/// within microseconds, so the cap never trips in normal operation — it exists
/// only so a stalled SPI cannot hang the bootloader forever: the FSBL arms no
/// watchdog, and an unbounded `while` here would be an unrecoverable boot hang.
///
/// The cap is ~10M iterations. The old comment priced that at "≈ 10 s at the
/// FSBL's 4 MHz MSIS clock", which has been stale since the clock switch — the
/// FSBL now runs HSI16 (`clock.rs`), so the same loop is ~4x faster.
///
/// **The result is now a control input** (#705). It used to be discarded, and
/// the comment here used to justify that: *"on timeout we give up on this
/// transfer and let boot proceed — booting beats hanging"*. That is the
/// plain-proceed policy, and it was REJECTED: proceeding means the immutable
/// stage hands off to updatable firmware after detecting that the display
/// failed, which is the forged-fingerprint hole invariant #10 exists to close.
/// The owner chose recoverable fail-closed instead, so every caller now
/// propagates this bool and `main` refuses the branch on a false verdict.
///
/// **What threading it buys, stated narrowly.** A computed verdict, and a
/// bounded time-to-decision: the first timeout aborts the chain instead of
/// letting all 121,552 bytes of a `fill_screen` each burn the full cap. It
/// does NOT detect a wrong pin map — `evt-silicon-validation.md` settles that
/// against us: *"`TXP`/`EOT` come from the shift logic and `TSIZE`, not pad
/// routing"* is **right about `spi_wait` specifically**, *"which is why the
/// timeout count is NOT the receipt"*, and the real blocking mechanism in that
/// incident is *"not yet identified"*. And with no MISO on pq1 it cannot prove
/// a single pixel appeared. See the module header's residuals.
/// Count of [`spi_wait`] polls that hit their bound. Diagnostic only
/// (`stage-marker`); the control input is the returned bool, not this counter.
/// Kept because it distinguishes "one timeout, aborted early" from "the bus is
/// dead" in a marker payload, which a bool cannot.
#[cfg(feature = "stage-marker")]
static mut SPI_WAIT_TIMEOUTS: u32 = 0;

/// How many [`spi_wait`] polls have timed out. Zero on a correctly-mapped
/// panel; large means SPI1 is not driving the pins it thinks it is.
#[cfg(feature = "stage-marker")]
pub fn spi_wait_timeouts() -> u32 {
    // SAFETY: the FSBL is single-threaded and this stage runs with no
    // interrupts enabled, so there is no concurrent accessor; `addr_of!`
    // avoids taking a reference to a `static mut`, and the read is volatile so
    // it cannot be folded away.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SPI_WAIT_TIMEOUTS)) }
}

#[inline]
fn spi_wait(flag: u32) -> bool {
    for _ in 0..10_000_000u32 {
        if (rd(SPI_SR) & flag) != 0 {
            return true;
        }
    }
    #[cfg(feature = "stage-marker")]
    {
        // SAFETY: as `spi_wait_timeouts` — single-threaded, sole accessor,
        // volatile so the increment survives optimisation.
        unsafe {
            let p = core::ptr::addr_of_mut!(SPI_WAIT_TIMEOUTS);
            core::ptr::write_volatile(p, core::ptr::read_volatile(p).saturating_add(1));
        }
    }
    false
}

/// `false` if `TXP` never asserted. The byte is written either way, so the
/// hardware sequence is byte-identical to the pre-threading behaviour on every
/// path — only what the CALLER does next is new.
fn spi_send_byte(b: u8) -> bool {
    let ok = spi_wait(SR_TXP);
    // SAFETY: TXDR is a real MMIO register; CFG1 set DSIZE=7 (8-bit), so a
    // byte-wide store is the access the peripheral expects.
    unsafe { write_volatile(SPI_TXDR as *mut u8, b) }
    ok
}

/// `false` if `EOT` never asserted. The teardown runs regardless: leaving `SPE`
/// set on a failing transfer would strand the peripheral, and the caller is
/// about to abort rather than retry.
fn spi_end() -> bool {
    let ok = spi_wait(SR_EOT);
    // ES0499 mitigation: let the last SCK pulse complete before dropping SPE.
    cortex_m::asm::delay(16);
    modify(SPI_CR1, |v| v & !CR1_SPE);
    wr(SPI_IFCR, IFCR_EOTC | IFCR_TXTFC | IFCR_OVRC);
    ok
}

fn spi_transfer(bytes: &[u8]) -> bool {
    let mut off = 0usize;
    while off < bytes.len() {
        let n = core::cmp::min(bytes.len() - off, MAX_CHUNK as usize);
        spi_begin(n as u16);
        let mut ok = true;
        for &b in &bytes[off..off + n] {
            ok = spi_send_byte(b);
            if !ok {
                // Abort this chunk. Without this a dead bus burns the full cap
                // once per byte — 121,552 times for one `fill_screen`.
                break;
            }
        }
        // Always close the frame, even when aborting, so `SPE` does not stay set.
        if !(spi_end() && ok) {
            return false;
        }
        off += n;
    }
    true
}

/// Command byte (DC=LOW) then its params (DC=HIGH) inside one CS-low window.
/// NV3007 resets the parameter index on CS rising, so multi-param commands
/// MUST keep CS asserted across the command and every parameter.
fn write_cmd_data(cmd: u8, params: &[u8]) -> bool {
    cs_assert();
    dc_low();
    spi_begin(1);
    let sent = spi_send_byte(cmd);
    // `spi_end` unconditionally, then AND — never short-circuit past the
    // teardown, or a failed command leaves SPE set and CS asserted.
    let mut ok = spi_end() && sent;
    if ok && !params.is_empty() {
        dc_high();
        ok = spi_transfer(params);
    }
    cs_deassert();
    ok
}

fn write_cmd(cmd: u8) -> bool {
    write_cmd_data(cmd, &[])
}

// ---------------------------------------------------------------------------
// NV3007 init sequence (ported 1:1 from the dgen1 production driver via
// secure/src/hw/lcd_nv3007.rs).
//
// Encoded as a FLAT `cmd, nparams, params...` byte stream rather than a
// `&[(u8, &[u8])]` table: the tuple form costs ~12 B/entry (the fat slice
// pointer) + a separate rodata array per param list (~1.5 KB total), which
// overflows the legacy 32-KiB bench FSBL FLASH region. The flat stream is one ~355 B
// rodata blob — still byte-diffable against the source, just denser.
//
// **Do not alter values without re-validating on the ZT165M017AT panel** —
// production-tuned gamma / GVDD/GVCL / GOA timing.
// ---------------------------------------------------------------------------

#[rustfmt::skip]
const INIT_SEQ: &[u8] = &[
    // Vendor command-mode unlock + analog rails.
    0xFF, 1, 0xA5,
    0x8F, 2, 0x22, 0x03,
    0x9A, 1, 0x78,
    0x9B, 1, 0x78,
    0x9C, 1, 0xA0,
    0x9D, 1, 0x17,
    0x9E, 1, 0xC3,
    0x83, 1, 0xA6,
    0x84, 1, 0xC6,
    0x85, 1, 0x62,
    // Gamma.
    0x6E, 1, 0x0F,
    0x7E, 1, 0x0F,
    0x60, 1, 0x04,
    0x70, 1, 0x00,
    0x6D, 1, 0x36,
    0x7D, 1, 0x36,
    0x61, 1, 0x05,
    0x71, 1, 0x05,
    0x6C, 1, 0x32,
    0x7C, 1, 0x31,
    0x62, 1, 0x0B,
    0x72, 1, 0x0A,
    0x68, 1, 0x4A,
    0x78, 1, 0x4C,
    0x66, 1, 0x32,
    0x76, 1, 0x30,
    0x6B, 1, 0x13,
    0x7B, 1, 0x12,
    0x63, 1, 0x09,
    0x73, 1, 0x07,
    0x6A, 1, 0x16,
    0x7A, 1, 0x14,
    0x64, 1, 0x08,
    0x74, 1, 0x06,
    0x69, 1, 0x0D,
    0x79, 1, 0x0A,
    0x65, 1, 0x04,
    0x75, 1, 0x03,
    0x67, 1, 0x33,
    0x77, 1, 0x22,
    0x6F, 1, 0x00,
    0x7F, 1, 0x00,
    // GOA timing.
    0x50, 1, 0x00,
    0x52, 1, 0xD6,
    0x53, 1, 0x04,
    0x54, 1, 0x04,
    0x55, 1, 0x1B,
    0x56, 1, 0x1B,
    0xA0, 3, 0x2A, 0x24, 0x00,
    0xA1, 1, 0x84,
    0xA2, 1, 0x85,
    0xA8, 1, 0x36,
    0xA9, 1, 0x80,
    0xAA, 1, 0x73,
    0xAB, 2, 0x03, 0x61,
    0xAC, 2, 0x03, 0x65,
    0xAD, 2, 0x03, 0x60,
    0xAE, 2, 0x03, 0x64,
    0xB9, 1, 0x82,
    0xBA, 1, 0x83,
    0xBB, 1, 0x80,
    0xBC, 1, 0x81,
    0xBD, 1, 0x02,
    0xBE, 1, 0x01,
    0xBF, 1, 0x04,
    0xC0, 1, 0x03,
    0xC4, 1, 0x33,
    0xC5, 1, 0x80,
    0xC6, 1, 0x73,
    0xC7, 1, 0x01,
    0xC8, 2, 0x33, 0x33,
    0xC9, 1, 0x5B,
    0xCA, 1, 0x5A,
    0xCB, 1, 0x5D,
    0xCC, 1, 0x5C,
    0xCD, 2, 0x33, 0x33,
    0xCE, 1, 0x5F,
    0xCF, 1, 0x5E,
    0xD0, 1, 0x61,
    0xD1, 1, 0x60,
    // Frame timing / inversion.
    0xB0, 4, 0x3A, 0x3A, 0x00, 0x00,
    0xB6, 1, 0x32,
    0xB7, 1, 0x80,
    0xB8, 1, 0x73,
    0xE0, 1, 0x00,
    0xE1, 2, 0x03, 0x0F,
    0xE2, 1, 0x04,
    0xE3, 1, 0x01,
    0xE4, 1, 0x0E,
    0xE5, 1, 0x01,
    0xE6, 1, 0x19,
    0xE7, 1, 0x10,
    0xE8, 1, 0x10,
    0xE9, 1, 0x21,
    0xEA, 1, 0x12,
    0xEB, 1, 0xD0,
    0xEC, 1, 0x04,
    0xED, 1, 0x07,
    0xEE, 1, 0x07,
    0xEF, 1, 0x09,
    0xF0, 1, 0xD0,
    0xF1, 1, 0x0E,
    0xF9, 1, 0x56,
    0xF2, 4, 0x26, 0x1B, 0x0B, 0x20,
    0xEC, 1, 0x04,
    0x35, 1, 0x00,
    0x44, 2, 0x00, 0x10,
    0x46, 1, 0x10,
    // Lock vendor command-mode, then COLMOD = RGB565.
    0xFF, 1, 0x00,
    0x3A, 1, 0x05,
];

fn run_init_sequence() -> bool {
    let mut i = 0usize;
    while i + 1 < INIT_SEQ.len() {
        let cmd = INIT_SEQ[i];
        let n = INIT_SEQ[i + 1] as usize;
        let params = &INIT_SEQ[i + 2..i + 2 + n];
        if !write_cmd_data(cmd, params) {
            return false;
        }
        i += 2 + n;
    }
    if !write_cmd(0x11) {
        return false;
    } // SLPOUT
    delay_ms(200);
    if !write_cmd(0x29) {
        return false;
    } // DISPON
    delay_ms(150);
    if !set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1) {
        return false;
    }
    delay_ms(20);
    true
}

// ---------------------------------------------------------------------------
// Address window + bulk pixel write
// ---------------------------------------------------------------------------

fn set_window(x0: u16, y0: u16, x1: u16, y1: u16) -> bool {
    let cx0 = x0 + X_OFFSET;
    let cx1 = x1 + X_OFFSET;
    let cy0 = y0 + Y_OFFSET;
    let cy1 = y1 + Y_OFFSET;
    let caset = [(cx0 >> 8) as u8, cx0 as u8, (cx1 >> 8) as u8, cx1 as u8];
    let raset = [(cy0 >> 8) as u8, cy0 as u8, (cy1 >> 8) as u8, cy1 as u8];
    // Short-circuiting is the point: on a dead bus each of these would
    // otherwise burn the full `spi_wait` cap per byte.
    write_cmd_data(0x2A, &caset) // CASET
        && write_cmd_data(0x2B, &raset) // RASET
        && write_cmd(0x2C) // RAMWR — pixel data follows
}

/// Write RGB565 pixels to the current window, big-endian (NV3007 wants high
/// byte first), chunked by pixel count. CS held low across all chunks.
fn write_pixels(buf: &[u16]) -> bool {
    if buf.is_empty() {
        return true;
    }
    cs_assert();
    dc_high();
    let pixels_per_chunk = (MAX_CHUNK / 2) as usize;
    let mut ok = true;
    for chunk in buf.chunks(pixels_per_chunk) {
        spi_begin((chunk.len() * 2) as u16);
        for &px in chunk {
            ok = spi_send_byte((px >> 8) as u8) && spi_send_byte(px as u8);
            if !ok {
                break;
            }
        }
        ok = spi_end() && ok;
        if !ok {
            break;
        }
    }
    cs_deassert();
    ok
}

/// Fill the visible area with one color, streamed (never a 121 KB buffer).
fn fill_screen(color: u16) -> bool {
    if !set_window(0, 0, FRAME_WIDTH - 1, FRAME_HEIGHT - 1) {
        return false;
    }
    let hi = (color >> 8) as u8;
    let lo = color as u8;
    cs_assert();
    dc_high();
    let pixels_per_chunk: u32 = u32::from(MAX_CHUNK / 2);
    let mut remaining = u32::from(FRAME_WIDTH) * u32::from(FRAME_HEIGHT);
    let mut ok = true;
    while remaining > 0 {
        let chunk_px = core::cmp::min(remaining, pixels_per_chunk);
        spi_begin((chunk_px * 2) as u16);
        for _ in 0..chunk_px {
            ok = spi_send_byte(hi) && spi_send_byte(lo);
            if !ok {
                break;
            }
        }
        ok = spi_end() && ok;
        if !ok {
            break;
        }
        remaining -= chunk_px;
    }
    cs_deassert();
    ok
}

// ---------------------------------------------------------------------------
// Lcd — the 16×4 text grid + per-glyph blit. `Oled`-shaped so render.rs ports
// with no structural change.
// ---------------------------------------------------------------------------

pub struct Lcd {
    /// Logical char grid — identical shape to the OLED path.
    rows: [[u8; DISPLAY_COLS]; DISPLAY_ROWS],
    /// Per-glyph RGB565 scratch (lives in the singleton, not the stack).
    cell: [u16; CELL_N],
}

impl Lcd {
    pub const fn new() -> Self {
        Self {
            rows: [[b' '; DISPLAY_COLS]; DISPLAY_ROWS],
            cell: [BG; CELL_N],
        }
    }

    /// Bring up SPI1 + DC/RES GPIO + the NV3007, then clear to black.
    /// Mirrors the validated secure `lcd::init()` (SWRESET, full dgen1 init).
    ///
    /// `false` means an SPI transfer timed out. Under the #705 fail-closed
    /// policy the caller must NOT paint over that and must not hand off.
    #[must_use]
    pub fn init(&mut self) -> bool {
        spi1_init();
        init_dc_res_gpios();

        // Reset the panel the way this board can. `LCD_RST_IS_DRIVABLE` is a
        // const, so the unused arm is dead-code-eliminated — neither board
        // pays for the other's path. iota2 has RES strapped to 3V3 (PE14 and
        // PD15 both proved un-drivable at bring-up), so it issues SWRESET;
        // pq1 routes LCM_RST to PB1 and gets a real pulse, which also resets
        // state SWRESET leaves alone.
        // NOTE the `ok &=` form on the SWRESET arm: `source_invariants.rs`
        // pins the literal substring `write_cmd(0x01); // SWRESET`, so an
        // `if !write_cmd(0x01) {` rewrite would break that test while looking
        // like an improvement.
        let mut ok = true;
        if board::LCD_RST_IS_DRIVABLE {
            hard_reset();
        } else {
            ok &= write_cmd(0x01); // SWRESET (RES tied to 3V3 → software reset)
        }
        delay_ms(150);
        ok && run_init_sequence() && fill_screen(BG)
    }

    /// Reset the char grid to spaces.
    pub fn clear(&mut self) {
        for row in &mut self.rows {
            *row = [b' '; DISPLAY_COLS];
        }
    }

    /// Stamp one ASCII line into the char grid (`row ∈ 0..4`). Clips to the
    /// printable range (anti-homoglyph) and space-pads — identical to the
    /// secure `ui::lcd::draw_line` / the OLED `draw_text`.
    pub fn draw_text(&mut self, row: usize, text: &[u8]) {
        if row >= DISPLAY_ROWS {
            return;
        }
        let mut col = 0;
        for &b in text {
            if col >= DISPLAY_COLS {
                break;
            }
            self.rows[row][col] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
            col += 1;
        }
        for c in col..DISPLAY_COLS {
            self.rows[row][c] = b' ';
        }
    }

    /// Blit the whole 16×4 grid. Every glyph cell is fully repainted (FG and
    /// BG), and the inter-cell gaps stay black from `init`'s clear.
    ///
    /// `false` means a glyph's transfer timed out, so the rendered words are
    /// incomplete and must not be treated as a fingerprint the user read.
    #[must_use]
    pub fn flush(&mut self) -> bool {
        for r in 0..DISPLAY_ROWS {
            for c in 0..DISPLAY_COLS {
                let ch = self.rows[r][c];
                let cols = [
                    glyph_col(ch, 0),
                    glyph_col(ch, 1),
                    glyph_col(ch, 2),
                    glyph_col(ch, 3),
                    glyph_col(ch, 4),
                ];
                if !self.blit_glyph(c, r, &cols) {
                    return false;
                }
            }
        }
        true
    }

    /// Render one glyph cell `(col, row)` from its 5 column-bytes. Logical
    /// LANDSCAPE pixel `(lx, ly)` maps to NATIVE via a 90° transpose + the
    /// validated `FLIP` (flip native-X only). Ported verbatim from
    /// `secure/src/ui/lcd.rs::blit_glyph` (public path; the FSBL never renders
    /// secrets, so the constant-time secret path is intentionally omitted).
    fn blit_glyph(&mut self, col: usize, row: usize, cols: &[u8; FONT_W]) -> bool {
        let lx0 = ORIGIN_X + col * COL_PITCH;
        let ly0 = ORIGIN_Y + row * ROW_PITCH;

        let nx0 = if FLIP_X {
            (PANEL_W - 1) - (ly0 + GLYPH_LH - 1)
        } else {
            ly0
        };
        let ny0 = if FLIP_Y {
            (PANEL_H - 1) - (lx0 + GLYPH_LW - 1)
        } else {
            lx0
        };

        let mut cy = 0usize;
        while cy < CELL_NY {
            let mut cx = 0usize;
            while cx < CELL_NX {
                let nx = nx0 + cx;
                let ny = ny0 + cy;
                let ly = if FLIP_X { (PANEL_W - 1) - nx } else { nx };
                let lx = if FLIP_Y { (PANEL_H - 1) - ny } else { ny };
                let gx = lx - lx0;
                let gy = ly - ly0;
                let sx = gx / SCALE;
                let sy = gy / SCALE;
                let bit = (cols[sx] >> sy) & 1;
                let mask = (bit as u16).wrapping_neg();
                self.cell[cy * CELL_NX + cx] = (mask & FG) | (!mask & BG);
                cx += 1;
            }
            cy += 1;
        }

        set_window(
            nx0 as u16,
            ny0 as u16,
            (nx0 + CELL_NX - 1) as u16,
            (ny0 + CELL_NY - 1) as u16,
        ) && write_pixels(&self.cell[..CELL_N])
    }
}

// ---------------------------------------------------------------------------
// Bench bring-up self-test (`lcd-test` feature — never ships)
// ---------------------------------------------------------------------------

/// Isolated NV3007 bring-up loop, run via `make fsbl-lcd-test-hw`. Validates
/// the FSBL display port on real silicon WITHOUT a signed slot:
///
///   1. Full-screen **green → red → blue** — confirms SPI1, the DC/RES GPIO,
///      the dgen1 init sequence, and the RGB565 color order.
///   2. A SAMPLE 8-word firmware fingerprint rendered through the EXACT
///      `Lcd::draw_text` + `flush` path `render::render_fingerprint` uses —
///      confirms the glyph blit, the 16×4 layout, and the orientation
///      (`FLIP`). The digest is a fixed non-secret constant, so the words are
///      deterministic across runs.
///
/// Loops forever. Detach probe-rs (Ctrl-C) or power-cycle to stop.
#[cfg(feature = "lcd-test")]
pub fn lcd_test_loop() -> ! {
    use sphincs_tz_bip39::firmware_fingerprint_lines;

    // Fixed, non-secret digest so the rendered words are stable + recognisable.
    const SAMPLE_DIGEST: [u8; 32] = [0xA5; 32];

    let mut lcd = Lcd::new();
    // Bench bring-up: the verdict is deliberately discarded here. This loop
    // exists to look at the panel, and halting on a timeout would remove the
    // only thing it can tell you.
    let _ = lcd.init();

    loop {
        let _ = fill_screen(0x07E0); // green
        delay_ms(800);
        let _ = fill_screen(0xF800); // red
        delay_ms(800);
        let _ = fill_screen(0x001F); // blue
        delay_ms(800);
        fill_screen(BG);

        lcd.clear();
        let rows = firmware_fingerprint_lines(&SAMPLE_DIGEST);
        for (i, row) in rows.iter().enumerate() {
            lcd.draw_text(i, row);
        }
        lcd.flush();
        delay_ms(3000);
    }
}
