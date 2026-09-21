//! AW21036 36-channel RGB LED driver — **pq1 only**.
//!
//! Datasheet: AW21036 V1.0 (Sep 2019) — register list p.28, current formula
//! p.19, I2C address table p.15, reset/standby timing p.11–13.
//!
//! ## What is actually on the board
//!
//! Schematic sheet 1 "RGB LED Driver", U109 `AW21036QNR`:
//!
//! - **9 RGB LEDs**, wired to channels `LED1..LED27` as
//!   `LED_R1,LED_G1,LED_B1, LED_R2,…, LED_B9`. `LED28..LED36` are
//!   not connected, so this driver never lights them.
//! - `AD` (pin 37) is strapped so the 7-bit address is **`0x34`** (table: AD→GND
//!   ⇒ `0x34`, VDD ⇒ `0x35`, SCL ⇒ `0x36`, SDA ⇒ `0x37`), which is what the
//!   schematic annotates and what `board::RGB_I2C_ADDR` records. The part also
//!   answers the **broadcast address `0x1C`**, which this module uses as a
//!   second witness during a self-test.
//! - `EN` (pin 36) is `RGB_EN` = **PB12** (schematic pin 25). PB11 appears in an
//!   older note and is wrong — and not bonded on this 48-pin package anyway.
//! - `SCL`/`SDA` (pins 42/41) are `I2C2_SCL`/`I2C2_SDA` = PB13/PB14, shared with
//!   the AW99703 backlight at `0x36` — which makes that chip a useful positive
//!   control for the bus itself.
//! - `ISET` (pin 40) sets the full-scale current: `I_OUT(max) = K·V_REXT/R_EXT`
//!   with `K=200`, `V_REXT=0.4 V`, i.e. `80/R_EXT`. R125 is 4.7 kΩ or 10 kΩ (the
//!   netlist is ambiguous between R125/R126), so ≈8–17 mA per channel at full
//!   scale. With 27 channels that is up to ~0.46 A off the boost-fed 3V6 rail,
//!   so [`DEFAULT_GCC`] starts well below full scale.
//!
//! ## Why three registers, not one
//!
//! Output current is the product `GCC/255 · WB/255 · COLn/255 · BRn/256` of a
//! global current ([`REG_GCCR`]), a white-balance trim (`WBR/WBG/WBB`, default
//! `0xFF`), a per-channel current ([`REG_COL0`]`+n`) and a per-channel PWM level
//! ([`REG_BR0`]`+n`). **`GCCR` and `COLn` both default to `0x00`**, so writing
//! brightness alone lights nothing — the classic first-bring-up dead end. `BRn`
//! writes also need the [`REG_UPDATE`] latch.
#![cfg(all(feature = "stm32u585", feature = "board-pq1"))]

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};
use crate::hw::soft_i2c_aux::AuxI2c;

/// 7-bit device address (AD→GND).
const ADDR: u8 = board::RGB_I2C_ADDR;
/// Broadcast address every AW21036 answers regardless of the `AD` strap.
pub const BROADCAST_ADDR: u8 = 0x1C;
/// The AW99703 backlight on the same bus — the bus's positive control.
pub const BACKLIGHT_ADDR: u8 = board::BACKLIGHT_I2C_ADDR;

// --- register map (datasheet p.28) -----------------------------------------
/// Global control: bit 7 `APSE`, bits 6:4 `CLKFRQ`, bit 0 `CHIPEN`.
const REG_GCR: u8 = 0x00;
/// `BR0..BR35` — per-channel PWM brightness, `0x01..=0x24`.
const REG_BR0: u8 = 0x01;
/// Write `0x00` to latch the `BR` registers.
const REG_UPDATE: u8 = 0x49;
/// `COL0..COL35` — per-channel constant current, `0x4A..=0x6D`.
const REG_COL0: u8 = 0x4A;
/// Global current `GCC`.
const REG_GCCR: u8 = 0x6E;
/// Spread-spectrum control; bits 7:5 are `PWMDIS2..0`, one per group of 12
/// channels. The prose calls this field `PWMDIS[2:0]`, but the register table
/// gives explicit bit positions 7/6/5 — the table is right, so `0b111 << 5`.
const REG_SSCR: u8 = 0x78;
/// Open/short detect control: bit 3 `OTH`, bit 2 `STH`, bits 1:0 `OSDE`.
const REG_OSDCR: u8 = 0x71;
/// `OSST0..OSST4` — 36 open/short status bits, `LED(k)` is bit `(k-1) % 8` of
/// `OSST[(k-1) / 8]`.
const REG_OSST0: u8 = 0x72;
/// Version, read-only. Reads [`VER_EXPECTED`].
const REG_VER: u8 = 0x7E;
/// Write `0x00` for a software reset; reads back [`RESET_ID_EXPECTED`].
const REG_RESET: u8 = 0x7F;

/// `GCR.CHIPEN = 1`, auto-power-save off, default clock.
const GCR_CHIPEN: u8 = 1 << 0;
/// Value `REG_VER` returns on a healthy AW21036 (datasheet default `A8H`).
pub const VER_EXPECTED: u8 = 0xA8;
/// Value `REG_RESET` returns when read (datasheet default `18H`).
pub const RESET_ID_EXPECTED: u8 = 0x18;
/// Software-reset magic (`RESET` ← `00H`).
const RESET_MAGIC: u8 = 0x00;
/// Per-channel current at full scale — the ceiling is set by `GCC` instead.
const COL_FULL: u8 = 0xFF;
/// `PWMDIS2|PWMDIS1|PWMDIS0` — 100 % duty on all 36 channels, which the
/// datasheet requires while open/short detection runs. Note this **bypasses
/// `BR`**, so the OSD bias current comes from `GCC x WB x COLn` alone and the
/// `BR` registers are left at their reset `0x00`.
const SSCR_PWM_DISABLED: u8 = 0b111 << 5;
/// `OSDE = 0b10`, thresholds at default (`OTH` 0.1 V, `STH` VLED-1 V).
const OSDCR_MODE_A: u8 = 0b10;
/// `OSDE = 0b11`, same thresholds.
const OSDCR_MODE_B: u8 = 0b11;
/// Total channels the part drives, wired or not.
pub const TOTAL_CHANNELS: u8 = 36;
/// Bytes of `OSST` status (36 bits over 5 registers).
pub const OSST_BYTES: usize = 5;
/// Global current for the OSD bias. The datasheet asks for ~1 mA per LED; at
/// `COL = WB = 0xFF` and 100 % duty this gives `GCC/255 x I_max`, i.e. ~1.0-2.1
/// mA across the `R_EXT` ambiguity (see the module header).
pub const OSD_GCC: u8 = 0x20;

/// Number of channels with an LED on the other end (9 RGB triples).
pub const WIRED_CHANNELS: u8 = 27;
/// Conservative global current for a first light-up: ~16 % of full scale.
pub const DEFAULT_GCC: u8 = 0x28;

const _: () = assert!(WIRED_CHANNELS % 3 == 0, "wired channels are RGB triples");
const _: () = assert!(WIRED_CHANNELS <= 36, "AW21036 has 36 channels");
const _: () = assert!(
    REG_BR0 as u16 + WIRED_CHANNELS as u16 <= REG_UPDATE as u16,
    "BR window overruns UPDATE"
);
const _: () = assert!(
    REG_COL0 as u16 + WIRED_CHANNELS as u16 <= REG_GCCR as u16,
    "COL window overruns GCCR"
);

// Delays are sized for the fastest plausible SYSCLK (160 MHz), so they are
// never *shorter* than the datasheet minimum at any slower clock the boot path
// may have left configured.
const CYCLES_PER_MS: u32 = 160_000;

/// Everything one self-test run learned, laid out so a dark board localizes
/// itself without a second run.
#[derive(Clone, Copy)]
pub struct Report {
    /// 7-bit address bitmap: address `a` is bit `a % 8` of `scan[a / 8]`.
    pub scan: [u8; 16],
    /// `REG_VER` readback, `None` if the addressing phase was not ACKed.
    pub ver: Option<u8>,
    /// `REG_RESET` readback (a second identity value).
    pub reset_id: Option<u8>,
    /// Register writes that were ACKed, of [`Report::acks_total`] attempted.
    pub acks_ok: u8,
    pub acks_total: u8,
    /// `RGB_EN` read back from `IDR` after being driven.
    pub en_level: bool,
    /// The `GCC` actually programmed.
    pub gcc: u8,
}

impl Report {
    /// Did the part identify itself *and* ACK every write?
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.ver == Some(VER_EXPECTED) && self.acks_ok == self.acks_total
    }

    /// Is `addr7` in the scan bitmap?
    #[must_use]
    pub fn saw(&self, addr7: u8) -> bool {
        let (byte, bit) = ((addr7 >> 3) as usize, addr7 & 0x07);
        byte < self.scan.len() && self.scan[byte] & (1 << bit) != 0
    }
}

/// Drive `RGB_EN` and read the pin back.
///
/// `EN` low puts the part in **shutdown**; note that per the datasheet the I2C
/// interface stays accessible in standby, so an ACK at `0x34` is *not* evidence
/// that this pin is wired correctly. Only the functional difference (identical
/// register sequence, dark with `EN` low, lit with `EN` high) is.
fn set_en(level: bool) -> bool {
    let Some(pin) = board::RGB_EN else {
        return false;
    };
    // SAFETY: RCC AHB2ENR1 secure alias; `gpio_rcc_bit` maps the port to its
    // own enable bit.
    let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
    enr.set_bits(board::gpio_rcc_bit(pin.0));
    let _ = enr.read();
    cortex_m::asm::dsb();

    // SAFETY: MODER/OTYPER/BSRR/IDR of a board-map GPIO port; each RMW is
    // confined to this pin's own bit field, and BSRR/IDR are single-bit.
    let (moder, otyper, bsrr, idr) = unsafe {
        (
            Reg32::new(pin.0 + 0x00),
            Reg32::new(pin.0 + 0x04),
            Reg32::new(pin.0 + 0x18),
            RoReg32::new(pin.0 + 0x10),
        )
    };
    let pin2 = pin.1 * 2;
    otyper.clear_bits(1 << pin.1); // push-pull: EN is a logic input, not a bus
    moder.modify(|v| (v & !(0b11 << pin2)) | (0b01 << pin2));
    if level {
        bsrr.write(1 << pin.1);
    } else {
        bsrr.write(1 << (pin.1 + 16));
    }
    cortex_m::asm::delay(CYCLES_PER_MS); // EN → I2C-ready settle
    idr.read() & (1 << pin.1) != 0
}

/// Program every wired LED to `(r, g, b)` and report what the chip said.
///
/// `gcc` is the global current; `0` selects [`DEFAULT_GCC`]. `en` drives
/// `RGB_EN` — pass `false` to run the identical sequence with the part in
/// shutdown, which is the negative control for the pin itself.
///
/// All-zero `(r, g, b)` is the "off" case: the registers are still written and
/// still ACK, so a healthy report with a dark board is a meaningful result.
pub fn light(r: u8, g: u8, b: u8, gcc: u8, en: bool) -> Report {
    let bus = AuxI2c::board_aux();
    bus.init();
    let en_level = set_en(en);

    let mut scan = [0u8; 16];
    bus.scan(&mut scan);
    let ver = bus.read_reg(ADDR, REG_VER);
    let reset_id = bus.read_reg(ADDR, REG_RESET);

    let gcc = if gcc == 0 { DEFAULT_GCC } else { gcc };
    let mut ok = 0u8;
    let mut total = 0u8;
    let mut write = |reg: u8, val: u8| {
        total = total.saturating_add(1);
        if bus.write_reg(ADDR, reg, val) {
            ok = ok.saturating_add(1);
        }
    };

    // Known state first: registers survive a standby/EN cycle, so a previous
    // run's brightness must not be inherited.
    write(REG_RESET, RESET_MAGIC);
    cortex_m::asm::delay(2 * CYCLES_PER_MS); // ≥2 ms after a software reset
    write(REG_GCR, GCR_CHIPEN);
    cortex_m::asm::delay(CYCLES_PER_MS / 4); // ≥200 µs for the OSC to settle
    write(REG_GCCR, gcc);
    for ch in 0..WIRED_CHANNELS {
        write(REG_COL0 + ch, COL_FULL);
    }
    for ch in 0..WIRED_CHANNELS {
        let level = match ch % 3 {
            0 => r,
            1 => g,
            _ => b,
        };
        write(REG_BR0 + ch, level);
    }
    write(REG_UPDATE, RESET_MAGIC); // latch BR

    let report = Report {
        scan,
        ver,
        reset_id,
        acks_ok: ok,
        acks_total: total,
        en_level,
        gcc,
    };
    secure_log!(
        "[S] aw21036: ver={:?} id={:?} acks={}/{} en={} gcc={:#04x} bl@0x36={} bcast={}",
        report.ver,
        report.reset_id,
        report.acks_ok,
        report.acks_total,
        report.en_level,
        report.gcc,
        report.saw(BACKLIGHT_ADDR),
        report.saw(BROADCAST_ADDR)
    );
    report
}

/// Result of one open/short detection pass.
///
/// Both `OSDE` encodings are captured because **the datasheet contradicts
/// itself** about which is which: the prose says `10` = open / `11` = short,
/// while the `OSDCR` register table says `10` = short / `11` = open. Rather
/// than guess, this reports both bitmaps and lets the host decide — and the
/// board itself settles it, because `LED28..LED36` have no LED attached on this
/// design, so whichever mode flags those nine is the open-detect encoding.
///
/// **Resolved on silicon 2026-09-21: the register table is right and the prose
/// is wrong — `OSDE = 0b11` is open detection.** On the EVT unit `0b11` flagged
/// all nine unwired channels plus exactly one wired one, while `0b10` (short)
/// flagged nothing; bit-identical over five runs and a 4x range of bias
/// current. Both encodings are still reported rather than hardcoding that
/// result, because the resolution is cheap, self-checking, and the alternative
/// is trusting a document that is known to be wrong in one of two places.
///
/// That same fact makes the test self-validating: if *neither* mode flags the
/// nine unwired channels, detection did not actually run, and the honest answer
/// is "inconclusive", never "pass".
#[derive(Clone, Copy)]
pub struct OsdReport {
    /// `OSST0..4` after `OSDE = 0b10`.
    pub mode_a: [u8; OSST_BYTES],
    /// `OSST0..4` after `OSDE = 0b11`.
    pub mode_b: [u8; OSST_BYTES],
    /// `VER` readback, as a witness that the part was talking at all.
    pub ver: Option<u8>,
    pub acks_ok: u8,
    pub acks_total: u8,
    pub en_level: bool,
    pub gcc: u8,
}

/// Run open/short detection over all 36 channels.
///
/// Leaves the board dark (global current zero, `PWMDIS` cleared, detection
/// disabled) so a factory sequence can run this between visual steps without
/// leaving the LEDs biased.
///
/// `gcc` is the bias current; `0` selects [`OSD_GCC`]. `en` drives `RGB_EN`.
pub fn open_short_scan(gcc: u8, en: bool) -> OsdReport {
    let bus = AuxI2c::board_aux();
    bus.init();
    let en_level = set_en(en);

    let ver = bus.read_reg(ADDR, REG_VER);
    let gcc = if gcc == 0 { OSD_GCC } else { gcc };
    let mut ok = 0u8;
    let mut total = 0u8;
    let mut write = |reg: u8, val: u8| {
        total = total.saturating_add(1);
        if bus.write_reg(ADDR, reg, val) {
            ok = ok.saturating_add(1);
        }
    };

    write(REG_RESET, RESET_MAGIC);
    cortex_m::asm::delay(2 * CYCLES_PER_MS); // >=2 ms after a software reset
    write(REG_GCR, GCR_CHIPEN);
    cortex_m::asm::delay(CYCLES_PER_MS / 4); // >=200 us for the OSC
    write(REG_SSCR, SSCR_PWM_DISABLED);
    write(REG_GCCR, gcc);
    // Every channel, not just the wired 27: an undriven channel tells us
    // nothing, and the nine unwired ones are this test's positive control.
    for ch in 0..TOTAL_CHANNELS {
        write(REG_COL0 + ch, COL_FULL);
    }
    cortex_m::asm::delay(2 * CYCLES_PER_MS); // let the bias settle

    let mut mode_a = [0u8; OSST_BYTES];
    let mut mode_b = [0u8; OSST_BYTES];
    write(REG_OSDCR, OSDCR_MODE_A);
    cortex_m::asm::delay(2 * CYCLES_PER_MS);
    for (i, slot) in mode_a.iter_mut().enumerate() {
        *slot = bus.read_reg(ADDR, REG_OSST0 + i as u8).unwrap_or(0);
    }
    write(REG_OSDCR, OSDCR_MODE_B);
    cortex_m::asm::delay(2 * CYCLES_PER_MS);
    for (i, slot) in mode_b.iter_mut().enumerate() {
        *slot = bus.read_reg(ADDR, REG_OSST0 + i as u8).unwrap_or(0);
    }

    // Park dark: detection off, PWM back under BR control, global current zero.
    write(REG_OSDCR, 0x00);
    write(REG_SSCR, 0x00);
    write(REG_GCCR, 0x00);
    write(REG_UPDATE, RESET_MAGIC);

    let report = OsdReport {
        mode_a,
        mode_b,
        ver,
        acks_ok: ok,
        acks_total: total,
        en_level,
        gcc,
    };
    secure_log!(
        "[S] aw21036: osd a={:?} b={:?} ver={:?} acks={}/{} gcc={:#04x}",
        report.mode_a,
        report.mode_b,
        report.ver,
        report.acks_ok,
        report.acks_total,
        report.gcc
    );
    report
}
