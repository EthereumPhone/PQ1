//! AW99703 backlight boost + LED-sink driver for the FSBL — **pq1 only**.
//!
//! The pq1 panel's backlight is not a GPIO. `LCM_EN` (PB15) is the AW99703's
//! `HWEN`, which only brings the part out of Shutdown into *Standby*; it emits
//! no LED current until `MODE[1:0]` is written to `01` over I2C2. Settled by
//! experiment, not inference (#705, `a3226eca`): a dev build that stalled 5 s
//! before the first register write showed a blank screen for exactly that
//! window. So without this module the FSBL renders its fingerprint onto a dark
//! panel, and the first thing a user ever sees comes from *updatable* firmware
//! — which is what invariant #10 exists to prevent.
//!
//! Mirrors `secure/src/hw/aw99703.rs`. Four deliberate divergences, each of
//! which would be a defect if copied across:
//!
//! 1. **The bit-bang quarter-period is 40 cycles, not 400.** The secure
//!    driver's `QUARTER = 400` is sized for a 160 MHz SYSCLK. The FSBL runs
//!    HSI16, so copying it would give ~10 kHz. 40 cycles at 16 MHz is ~2.5 us,
//!    i.e. a ~100 kHz bus.
//!
//!    This is a FIXED constant, which is the opposite of the repo's usual
//!    "always derive from `clock::achieved_hz()`" rule — see [`QUARTER`] for
//!    why that inversion is correct here, and do not "fix" it.
//!
//! 2. **No fault-register access.** `FLAGS1` (0x0E) / `FLAGS2` (0x0F) are
//!    deliberately not even defined. Reading one is a documented way to
//!    *restart the IC* once a flag is set (datasheet pp.23-24), and the effect
//!    on a clean part is unspecified rather than documented-safe. That is an
//!    acceptable diagnostic in the patchable secure world (#733); it is not
//!    something to freeze into a stage the RDP-2 self-lock makes permanent.
//!
//! 3. **No statics.** The FSBL links with exactly ONE `PT_LOAD` segment and
//!    `static RAM: 0 B`; a single `static mut` adds a second segment and fails
//!    `scripts/check_fsbl_geometry.py` outright. State is threaded.
//!
//! 4. **Every millisecond wait goes through [`crate::nv3007::delay_ms`]**,
//!    which derives its iteration count from the achieved clock. Never
//!    multiply an `achieved_hz()` value: `overflow-checks = true` reaches the
//!    FSBL release profile and the panic handler is `panic_halt`, so
//!    `achieved_hz() * us / 1_000_000` overflows `u32` at 16 MHz and would
//!    spin on **every boot of every unit**. Divide first, or use `delay_ms`.
//!
//! ## Ordering (#730) — configure early, illuminate last
//!
//! [`configure`] runs right after the panel GPIOs are set up and leaves the
//! chip in Standby, so the panel stays dark. [`enable`] — the single `MODE`
//! write that emits light — must not run until the panel content is painted:
//! `DISPON` is the last command of the NV3007 init sequence, so illuminating
//! earlier lights undefined GRAM.
#![cfg(feature = "board-pq1")]

use core::ptr::{read_volatile, write_volatile};

use crate::board;
use crate::nv3007::delay_ms;

// ---------------------------------------------------------------------------
// Register map (datasheet V1.6 p.28; V1.2 p.27)
// ---------------------------------------------------------------------------

/// Read FIRST, always. See [`configure`] for why this is the bus control.
const REG_CHIP_ID: u8 = 0x00;
const REG_MODE: u8 = 0x02;
const REG_LEDCUR: u8 = 0x03;
const REG_BSTCTR1: u8 = 0x04;
const REG_LEDLSB: u8 = 0x06;
const REG_LEDMSB: u8 = 0x07;

/// The value `CHIP_ID` must return. Receipt: #733, sealed EVT `003B0022`,
/// operator read `ID03 F2=00 F1=00`.
const CHIP_ID_AW99703: u8 = 0x03;

/// Channel 1 only at the chip's default 20 mA full scale. The current half is
/// a no-op (reset is `0x9F`, already `BL_FS = 0b10011`); the write's real
/// effect is clearing CH2EN/CH3EN, which matters because V1.6 p.24 scopes LED
/// fault detection to *enabled* sinks and pq1's other two sinks are
/// unconnected.
const LEDCUR_CH1_20MA: u8 = (0b10011 << 3) | 0b001;

/// No frequency shift, 1 MHz switching, `OVPSEL = 001`, OCP default.
///
/// `001` is the SHIPPING value — owner decision 2026-09-23, #705. The setting
/// below it (`000`, 16/17.5/19 V) measured fine on one unit at room
/// temperature, but a no-trip only proves `Vout` is under THAT die's
/// threshold, somewhere at or above 16 V, not under the 16 V population
/// minimum; and LED forward voltage rises as temperature falls, so the cold
/// corner was never tested. Must equal the secure driver's value: the secure
/// world reprograms this register seconds after the FSBL, so a disagreement
/// would silently be the secure world's value anyway.
const BSTCTR1_OVP: u8 = (0b00 << 6) | (1 << 5) | (0b001 << 2) | 0b10;

/// PWM-pin dimming disabled, linear map, backlight mode. `PDIS = 1` is
/// REQUIRED, not defensive: the PWM pin has an internal 400 kOhm pull-down
/// (V1.6 p.3 row A1), so at `PDIS = 0` the duty read from a pin held low is
/// zero and the panel would be dark rather than dim.
const MODE_I2C_LINEAR_BACKLIGHT: u8 = (1 << 4) | (1 << 2) | 0b01;

/// Shipping brightness: 11-bit code `0x5FF` of `0x7FF`. The owner compared
/// both on silicon and preferred this over full scale — on a white-on-black
/// trusted display, glare and perceived black level are legibility
/// properties, not taste (#705).
const BRIGHTNESS_LSB: u8 = 0x07;
const BRIGHTNESS_MSB: u8 = 0xBF;

/// `MODE`'s defined bits: `[4] PDIS`, `[2] MAP`, `[1:0] WORKMODE`. The
/// read-back is masked with this rather than compared whole, so an
/// undocumented reserved bit reading back differently cannot fail the check.
const MODE_DEFINED_BITS: u8 = 0x17;

// ---------------------------------------------------------------------------
// Bit-banged I2C — pins from the board map, never hard-coded
// ---------------------------------------------------------------------------

const SCL: (u32, u32) = (board::AUX_I2C_PORT, board::AUX_I2C_SCL_PIN);
const SDA: (u32, u32) = (board::AUX_I2C_PORT, board::AUX_I2C_SDA_PIN);
const ADDR: u8 = board::BACKLIGHT_I2C_ADDR;

const _: () = assert!(
    !(SCL.0 == SDA.0 && SCL.1 == SDA.1),
    "AW99703 SCL and SDA are the same pin"
);

/// Quarter bit-period, in CPU cycles. ~2.5 us at HSI16, so a ~100 kHz bus.
///
/// **Deliberately a fixed constant, against the repo's usual rule.** Every
/// *millisecond* delay in the FSBL derives from `clock::achieved_hz()`,
/// because a delay that is 8x long reads as a boot hang — that bug happened.
/// A bit-bang half-period is the opposite case: if the clock comes up SLOWER
/// than expected (HSI16 fails and `clock` truthfully leaves the part on the
/// 4 MHz MSIS reset clock), a fixed cycle count makes the bus *slower*, and
/// both parts on it are rated far above 100 kHz. Erring slow is free; erring
/// fast would violate a timing spec. Deriving it would invert that safety.
const QUARTER: u32 = 40;

const MODER_OFF: u32 = 0x00;
const OTYPER_OFF: u32 = 0x04;
const OSPEEDR_OFF: u32 = 0x08;
const PUPDR_OFF: u32 = 0x0C;
const IDR_OFF: u32 = 0x10;
const BSRR_OFF: u32 = 0x18;

#[inline(always)]
fn rd(addr: u32) -> u32 {
    // SAFETY: `addr` is a GPIO register of a board-map port; read-only.
    unsafe { read_volatile(addr as *const u32) }
}

#[inline(always)]
fn wr(addr: u32, v: u32) {
    // SAFETY: `addr` is a GPIO register of a board-map port. BSRR is
    // write-only and single-bit; every other write below is a disjoint-bit
    // read-modify-write confined to this pin's own field.
    unsafe { write_volatile(addr as *mut u32, v) }
}

fn q() {
    cortex_m::asm::delay(QUARTER);
}

fn release(pin: (u32, u32)) {
    wr(pin.0 + BSRR_OFF, 1 << pin.1);
}

fn pull_low(pin: (u32, u32)) {
    wr(pin.0 + BSRR_OFF, 1 << (pin.1 + 16));
}

fn level(pin: (u32, u32)) -> bool {
    rd(pin.0 + IDR_OFF) & (1 << pin.1) != 0
}

fn config_open_drain(pin: (u32, u32)) {
    let pin2 = pin.1 * 2;
    let field = 0b11u32 << pin2;
    release(pin); // latch high BEFORE enabling the output
    wr(pin.0 + OTYPER_OFF, rd(pin.0 + OTYPER_OFF) | (1 << pin.1));
    wr(
        pin.0 + PUPDR_OFF,
        (rd(pin.0 + PUPDR_OFF) & !field) | (0b01 << pin2),
    );
    wr(
        pin.0 + OSPEEDR_OFF,
        (rd(pin.0 + OSPEEDR_OFF) & !field) | (0b01 << pin2),
    );
    wr(
        pin.0 + MODER_OFF,
        (rd(pin.0 + MODER_OFF) & !field) | (0b01 << pin2),
    );
}

/// Both lines released and reading high — the only state in which it is safe
/// to issue a START.
fn bus_idle() -> bool {
    release(SDA);
    release(SCL);
    q();
    level(SDA) && level(SCL)
}

/// Free a slave that is holding SDA low, by clocking it out.
///
/// This is the one check that RECOVERS rather than refuses. The bus is shared
/// with the AW21036 RGB driver, whose I2C stays live even with its enable low,
/// so a warm reset in the middle of a transaction can leave a slave mid-byte
/// with SDA held. Nine clocks is the standard remedy: it walks the slave past
/// its last byte and its ACK slot.
///
/// A held-low SCL is NOT recoverable — the master cannot clock a bus another
/// device is holding — so that case returns `false`.
fn recover_bus() -> bool {
    if level(SCL) && !level(SDA) {
        for _ in 0..9 {
            pull_low(SCL);
            q();
            q();
            release(SCL);
            q();
            q();
            if level(SDA) {
                break;
            }
        }
        // Framing STOP so the freed slave is left in a defined state.
        pull_low(SDA);
        q();
        release(SCL);
        q();
        release(SDA);
        q();
    }
    bus_idle()
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

/// `true` if the slave ACKed.
///
/// **This cannot distinguish an ACK from a stuck-low SDA**, which is exactly
/// why [`configure`] gates everything on a `CHIP_ID` read first: on a dead bus
/// every write here "succeeds" and every read returns 0.
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

fn read_bit() -> bool {
    release(SDA);
    q();
    release(SCL);
    q();
    let b = level(SDA);
    q();
    pull_low(SCL);
    q();
    b
}

fn read_byte(ack: bool) -> u8 {
    let mut v = 0u8;
    let mut i = 8;
    while i > 0 {
        i -= 1;
        if read_bit() {
            v |= 1 << i;
        }
    }
    write_bit(!ack); // the master drives the (N)ACK bit
    v
}

fn write_reg(reg: u8, val: u8) -> bool {
    start();
    let ok = write_byte(ADDR << 1) && write_byte(reg) && write_byte(val);
    stop();
    ok
}

/// `None` means the chip did not ACK. Per the datasheet a LOW HWEN resets
/// every register AND disables the I2C interface, so "no ACK" and "registers
/// at defaults" are the same observation: the part was reset.
fn read_reg(reg: u8) -> Option<u8> {
    start();
    if !(write_byte(ADDR << 1) && write_byte(reg)) {
        stop();
        return None;
    }
    start(); // repeated START
    if !write_byte((ADDR << 1) | 1) {
        stop();
        return None;
    }
    let v = read_byte(false); // NACK: single-byte read
    stop();
    Some(v)
}

// ---------------------------------------------------------------------------
// HWEN
// ---------------------------------------------------------------------------

/// How long `HWEN` is held low to force a reset.
///
/// **ENGINEERING MARGIN, NOT A SPEC.** Searched 2026-09-23 — datasheet V1.2,
/// V1.6 (the latest, confirmed on Awinic's product page) and the web state no
/// minimum HWEN low pulse width anywhere. The only adjacent numbers are
/// `treset = 250 us` (HWEN *high* -> I2C responds), a 100 us VIN->HWEN
/// power-sequencing delay, and "the LED current will be turned off immediately
/// without any ramp".
///
/// Erring long is the safe direction: too long costs boot time, too short
/// fails to reset the part and silently leaves [`configure`]'s retry doing
/// nothing — the exact failure that retry exists to prevent.
const HWEN_LOW_MS: u32 = 10;

/// `treset` is 250 us; this is 20x, and cheap.
const HWEN_SETTLE_MS: u32 = 5;

fn hwen(high: bool) {
    if let Some((port, pin)) = board::LCD_BACKLIGHT_EN {
        if high {
            wr(port + BSRR_OFF, 1 << pin);
        } else {
            wr(port + BSRR_OFF, 1 << (pin + 16));
        }
    }
}

// ---------------------------------------------------------------------------
// Two-stage bring-up
// ---------------------------------------------------------------------------

/// Proof that [`configure`] programmed every prerequisite register.
///
/// The private field means only this module can make one, so [`enable`] — the
/// write that turns the boost on — is unreachable after a failed configure.
/// Not a `bool`, because a caller can ignore a `bool`; with the chip's
/// `BSTCTR1` reset value being `0x2E` (`OVPSEL = 011`, 38 V) against a 25 V
/// output capacitor, "enabled without its limits programmed" is the one state
/// worth making unrepresentable.
pub struct Configured(());

/// Stage 1 of 2: reset the part, verify the bus, program limits and
/// brightness. Leaves the chip in **Standby** — no LED current, panel dark.
///
/// `None` means the caller must not enable the boost.
///
/// Attempts are bounded at [`ATTEMPTS`]. Each one begins by cycling `HWEN`, so
/// it is a genuine re-init rather than a retry against whatever state the last
/// failure left: a LOW `HWEN` resets every register and disables the I2C
/// interface, which also removes any dependence on boot history.
pub fn configure() -> Option<Configured> {
    // Clock the port before touching it. `nv3007::init_dc_res_gpios` has
    // normally already done this (the backlight enable lives on the same
    // port), but this module must not depend on that ordering.
    let enr = board::RCC_S + board::RCC_AHB2ENR1_OFF;
    wr(enr, rd(enr) | board::gpio_rcc_bit(SCL.0) | board::gpio_rcc_bit(SDA.0));
    let _ = rd(enr);
    cortex_m::asm::dsb();

    for _ in 0..ATTEMPTS {
        hwen(false);
        delay_ms(HWEN_LOW_MS);
        hwen(true);
        config_open_drain(SCL);
        config_open_drain(SDA);
        delay_ms(HWEN_SETTLE_MS);

        if !bus_idle() && !recover_bus() {
            continue;
        }

        // THE BUS CONTROL. `write_byte` treats any low SDA as an ACK and
        // `read_bit` returns 0 on a stuck-low bus, so without this a dead bus
        // would pass every check below and report a perfectly configured part.
        if read_reg(REG_CHIP_ID) != Some(CHIP_ID_AW99703) {
            continue;
        }

        let written = write_reg(REG_LEDCUR, LEDCUR_CH1_20MA)
            && write_reg(REG_BSTCTR1, BSTCTR1_OVP)
            && write_reg(REG_LEDLSB, BRIGHTNESS_LSB)
            && write_reg(REG_LEDMSB, BRIGHTNESS_MSB);
        if !written {
            continue;
        }

        // Read back ONLY the over-voltage limit. Its reset value (0x2E) differs
        // from ours (0x26) and it has no reserved bits, so a full-byte compare
        // is meaningful and distinguishes four states: written, reset, dead
        // bus (0x00) and NACK.
        //
        // LEDCUR and the brightness pair are deliberately NOT verified.
        // LEDCUR's reset value already lights the panel correctly, so failing
        // on it would refuse a working unit; and the brightness reset values
        // are 0x07/0xFF, which for LEDLSB is byte-identical to what an open
        // bus returns. Each extra compare is a permanent false-refusal path.
        if read_reg(REG_BSTCTR1) == Some(BSTCTR1_OVP) {
            return Some(Configured(()));
        }
    }
    hwen(false);
    None
}

/// Stage 2 of 2: leave Standby for Backlight mode — the one write that emits
/// light. Call only once the panel shows content the caller has defined (#730).
///
/// Consumes the [`Configured`] token, so it cannot run after a failed
/// [`configure`].
#[must_use]
pub fn enable(_proof: Configured) -> bool {
    for _ in 0..ATTEMPTS {
        if write_reg(REG_MODE, MODE_I2C_LINEAR_BACKLIGHT) {
            if let Some(m) = read_reg(REG_MODE) {
                if m & MODE_DEFINED_BITS == MODE_I2C_LINEAR_BACKLIGHT {
                    return true;
                }
            }
        }
    }
    false
}

/// Drop the backlight. Used on the refusal path so a fail-closed halt is not
/// accompanied by a lit panel showing a half-painted screen.
pub fn off() {
    hwen(false);
}

/// Bounded attempts for each stage.
///
/// Two, not more. A NACK may be transient; a held-low SCL is not, and
/// [`recover_bus`] already gives the one recoverable case its own remedy. Each
/// attempt costs `HWEN_LOW_MS + HWEN_SETTLE_MS` plus bus time, on a boot
/// already spending 10 s holding the fingerprint, so a high count would trade
/// real boot latency for retries that cannot help.
const ATTEMPTS: u32 = 2;

/// CHIP_ID, BSTCTR1 and MODE packed for a `stage-marker` payload, as
/// `0x00_CC_BB_MM`. A register that did not ACK reads `0xFF`, and the top byte
/// is `0x01` if any read NACKed so `--` is distinguishable from a real 0xFF.
///
/// This exists to obtain the receipt the fail-closed refusal needs. The
/// secure world has confirmed these three values on silicon (#705:
/// `ID03 B1=26 MO=15`), but the FSBL's transport is a DIFFERENT code path —
/// `QUARTER = 40` at HSI16 against the secure world's 400 at 160 MHz — so that
/// licenses the VALUES, not the timing. Until this has been read back from an
/// FSBL, the I2C leg must not refuse a boot.
#[cfg(feature = "stage-marker")]
pub fn read_receipt() -> u32 {
    let id = read_reg(REG_CHIP_ID);
    let b1 = read_reg(REG_BSTCTR1);
    let mo = read_reg(REG_MODE);
    let nacked = u32::from(id.is_none() || b1.is_none() || mo.is_none());
    (nacked << 24)
        | (u32::from(id.unwrap_or(0xFF)) << 16)
        | (u32::from(b1.unwrap_or(0xFF)) << 8)
        | u32::from(mo.unwrap_or(0xFF))
}
