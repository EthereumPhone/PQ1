//! AW99703 backlight boost + LED-sink driver — **pq1 only**.
//!
//! The pq1 panel's backlight is not a GPIO: `LCM_EN` (PB15) is the AW99703's
//! `HWEN`, which only brings the chip out of shutdown into *Standby*. It emits
//! no LED current until `MODE[1:0]` is written to `01` (backlight) over I2C2
//! (PB13/PB14, 4.7 kΩ pull-ups to 3V3 on the RGB-driver side of the bus,
//! 7-bit address `0x36`). Datasheet: AW99703 — the register values below were
//! derived from **V1.2 (Dec 2019)**; Awinic's current revision is **V1.6
//! (Mar 2024)**, so treat any V1.2-sourced number as pending re-check.
//!
//! The PDFs are vendor-copyrighted and deliberately NOT in this repo
//! (`.gitignore`: purged from history before open-sourcing). Local copies:
//! `~/Documents/PQ1/vendor-docs/AW99703-datasheet-v1.{2,6}-*.pdf`, from
//! <https://doc.awinic.com/doc/202403/4635fa96-003b-4dd8-ad18-b47173a9429f.pdf>
//! (V1.6) and the AW99703 product page. A previous version of this comment
//! claimed a copy at `evt-images/AW99703-datasheet-v1.2.pdf`, which has never
//! existed.
//!
//! Board facts that fix the register values (schematic sheet 1, "Backlight
//! Driver"): only `LED1` is wired (`LCM_LEDK`), `LED2`/`LED3` are unconnected,
//! VIN = 3V6, and the boost output capacitor C140 is rated 25 V. Hence: enable
//! channel 1 only, disable PWM-pin dimming, and lower OVP from the 38 V
//! default so an open string cannot exceed C140's rating.
//!
//! The `PWM` pin does **not** float — corrected 2026-09-23. Datasheet p.3 row
//! A1, identical in V1.2 and V1.6: *"Input for PWM signal. With an internal
//! 400 kΩ pull-down resistor to GND."* That makes `PDIS=1` REQUIRED rather
//! than defensive: with `PDIS=0` the duty read from a pin held low is zero, so
//! the panel would be dark rather than dim, and the PWM timeout separately
//! kills the boost output in ~0.68 ms at the default sample rate. (Whether the
//! pin is additionally loaded externally is the open R112/R124 schematic
//! ambiguity noted in `lcd_nv3007.rs`; the timeout route to a dark panel holds
//! either way, since no pulses arrive.)
//!
//! Transport is a bit-banged I2C master (~100 kHz) on the two GPIOs — this
//! bus carries pixels' worth of brightness, never secure-element traffic, so
//! the reasoning in `soft_i2c` applies unchanged.
//!
//! **Not write-only.** `read_reg` and [`pre_init_snapshot`] already read the
//! part, and both revisions document two latching fault registers we have
//! never used: `FLAGS1` 0x0E (LED open/short per channel, OCP, OT) and
//! `FLAGS2` 0x0F (bit 7 OVP, bit 6 UVLO, bit 5 flash timeout). Reading one is
//! NOT passive: pp.23–24 name "reading back fault register" as one of three
//! ways to *restart the IC* once a flag is set, so any use must be a one-shot
//! diagnostic, never a poll — a poll would turn a latched protection into a
//! host-driven retry loop from display code. See the tracking issue before
//! adding a reader.
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

// Register map (V1.6 p.28; V1.2 p.27 — the old `p.26` cite matched neither).
const REG_MODE: u8 = 0x02; // [4] PDIS, [2] MAP (1 = linear), [1:0] WORKMODE (01 = backlight)
const REG_LEDCUR: u8 = 0x03; // [7:3] BL_FS = 4.8 mA + code*0.8 mA, [2:0] CH3EN/CH2EN/CH1EN
const REG_BSTCTR1: u8 = 0x04; // [7:6] SF_SFT, [5] SF (1 = 1 MHz), [4:2] OVPSEL, [1:0] OCPSEL
const REG_LEDLSB: u8 = 0x06; // [2:0] brightness LSBs — program BEFORE the MSB
const REG_LEDMSB: u8 = 0x07; // [7:0] brightness MSBs

/// Channel 1 only, at the chip's default 20 mA full scale (BL_FS 0b10011).
///
/// The current half is a no-op: the reset value is **0x9F**, whose BL_FS field
/// is already 0b10011. What this write actually does is clear CH2EN/CH3EN,
/// and that is load-bearing — V1.6 p.24 scopes LED open/short detection to
/// *enabled* sinks, so leaving the default would put pq1's two unconnected
/// sinks permanently inside the fault-detection set.
const LEDCUR_CH1_20MA: u8 = (0b10011 << 3) | 0b001;
/// No frequency shift, 1 MHz switching, **OVP = 24 V** (001), OCP 2.7 A (default).
///
/// NOT a claim that 001 is safe for C140: the OVPSEL table gives that setting
/// as 22.5 V min / 24 V typ / **25.5 V max**, so its upper bound already
/// exceeds the 25 V part. Re-verified 2026-09-23 against **V1.6 p.7**, which
/// is cell-for-cell identical to V1.2 p.7 — the concern is real and is not an
/// artefact of reading a stale revision. See `aw99703-ovp-low` for the
/// experiment that tests whether the one setting below it is usable here.
///
/// The reset value of this register is **0x2E**, i.e. `OVPSEL=011` = 38 V. So
/// a part that is powered but unconfigured sits at the highest threshold, far
/// above C140's rating — which is exactly why [`enable`] is gated on the
/// [`Configured`] token rather than on a return value a caller could ignore.
#[cfg(not(feature = "aw99703-ovp-low"))]
const BSTCTR1_OVP: u8 = (0b00 << 6) | (1 << 5) | (0b001 << 2) | 0b10;

/// DEV EXPERIMENT (#705): OVP = **19 V max** (`OVPSEL=000`, 16 / 17.5 / 19 V),
/// comfortably under C140's 25 V rating. Viable only if the LED string stays
/// below the 16 V MINIMUM trip; if it does not, the boost protection fires and
/// the backlight fails or flickers — which is the readable outcome this
/// experiment wants. Everything else in the byte is unchanged.
#[cfg(feature = "aw99703-ovp-low")]
const BSTCTR1_OVP: u8 = (0b00 << 6) | (1 << 5) | (0b000 << 2) | 0b10;
/// PWM-pin dimming disabled, linear map, backlight mode.
///
/// `PDIS=1` is required, not defensive — the PWM pin has an internal 400 kΩ
/// pull-down (module header). V1.6's *only* change over V1.5 was to
/// disambiguate this bit's description, and it resolved in favour of this
/// reading: `0: PWM dimming enable (default) / 1: PWM dimming disable`.
const MODE_I2C_LINEAR_BACKLIGHT: u8 = (1 << 4) | (1 << 2) | 0b01;
/// Demo brightness: 11-bit code 0x5FF of 0x7FF ≈ 75 % of full scale (linear map).
/// `LEDMSB` holds bits [10:3] and `LEDLSB[2:0]` bits [2:0], so 0x5FF is
/// (0xBF, 0x07).
const BRIGHTNESS_LSB: u8 = 0x07;
#[cfg(not(feature = "aw99703-full-brightness"))]
const BRIGHTNESS_MSB: u8 = 0xBF;

/// DEV EXPERIMENT (#705): 11-bit code **0x7FF**, full scale — (0xFF, 0x07).
///
/// Margin probe for `aw99703-ovp-low`. Brightness sets the LED current as a
/// fraction of `LEDCUR`'s full scale, so 0x5FF -> 0x7FF takes the string from
/// ~15 mA to the full ~20 mA, raising Vf and therefore the boost output. It
/// stays at the part's default full-scale current: this deliberately does NOT
/// raise `LEDCUR` to its 29.6 mA maximum, which could exceed the panel's
/// rated LED current, and there is exactly one sealed screen unit.
#[cfg(feature = "aw99703-full-brightness")]
const BRIGHTNESS_MSB: u8 = 0xFF;

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
    // The master drives the (N)ACK bit.
    write_bit(!ack);
    v
}

/// Read one register: write the address, repeated START, read one byte.
///
/// `None` means the chip did not ACK. Per the AW99703 datasheet a LOW HWEN
/// resets every register AND disables the I2C interface, so "no ACK" and
/// "registers at defaults" are the same observation: the part was reset.
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
// One-shot fault readout (#733) — dev images only
// ---------------------------------------------------------------------------

/// `CHIP_ID`. Read FIRST, always: it is the bus control, not a curiosity.
#[cfg(feature = "dev-testkey")]
const REG_CHIP_ID: u8 = 0x00;
/// LED open/short per channel, OCP, OT.
#[cfg(feature = "dev-testkey")]
const REG_FLAGS1: u8 = 0x0E;
/// `[7]` OVP, `[6]` UVLO, `[5]` flash timeout, `[4:0]` reserved.
#[cfg(feature = "dev-testkey")]
const REG_FLAGS2: u8 = 0x0F;
/// The value `CHIP_ID` must return for the other reads to mean anything.
#[cfg(feature = "dev-testkey")]
const CHIP_ID_AW99703: u8 = 0x03;
/// `FLAGS2` bit 7 — the over-voltage flag, i.e. the #705 question.
#[cfg(feature = "dev-testkey")]
pub const FLAGS2_OVP: u8 = 1 << 7;

/// A single snapshot of the chip's fault state. `None` in any field means the
/// chip did not ACK that read.
#[cfg(feature = "dev-testkey")]
pub struct FaultSnapshot {
    pub chip_id: Option<u8>,
    pub flags1: Option<u8>,
    pub flags2: Option<u8>,
    /// Read back, not assumed: should equal [`BSTCTR1_OVP`].
    pub bstctr1: Option<u8>,
    /// Read back: should equal [`MODE_I2C_LINEAR_BACKLIGHT`].
    pub mode: Option<u8>,
}

#[cfg(feature = "dev-testkey")]
impl FaultSnapshot {
    /// Whether anything else in this snapshot can be believed.
    ///
    /// This is the whole reason `CHIP_ID` is read first. `write_byte` treats
    /// any low SDA as an ACK and `read_bit` returns 0 on a stuck-low bus, so a
    /// dead bus yields `FLAGS = 0x00` — byte-identical to "no fault". Without
    /// this check the diagnostic is a false-negative generator.
    pub fn bus_trustworthy(&self) -> bool {
        self.chip_id == Some(CHIP_ID_AW99703)
    }

    /// `Some(true)` if the over-voltage protection has fired, `Some(false)` if
    /// it demonstrably has not, `None` if the bus reading cannot be believed.
    ///
    /// The tri-state is the point: "no OVP" and "we could not tell" must never
    /// collapse into the same answer, which is exactly what an eyeball test
    /// does.
    pub fn ovp_fired(&self) -> Option<bool> {
        if !self.bus_trustworthy() {
            return None;
        }
        self.flags2.map(|f| f & FLAGS2_OVP != 0)
    }
}

/// One-shot read of the fault registers. **Never call this on a timer.**
///
/// Replaces an operator's judgement of whether the backlight "looks right"
/// with a bit. That matters twice: the #705 OVP experiments are currently
/// graded by eye, and the bench board has no panel at all, so there is no eye
/// to grade them with.
///
/// # This read is not passive
///
/// Datasheet pp.23–24 name "reading back fault register" as one of three
/// equivalent ways to **restart the IC**, each conditioned on "After ⟨X⟩ Flag
/// is set". So on a part that has actually tripped, this call may restart it —
/// plausibly taking the backlight out. That is acceptable for a one-shot
/// diagnostic and is itself informative; it would be indefensible in a loop,
/// where it would silently convert a latched protection into a host-driven
/// retry loop issued from display code. The effect on a *clean* part is
/// unspecified rather than documented-safe.
///
/// # What is deliberately not claimed
///
/// No clear-on-read or write-1-to-clear semantics: neither datasheet revision
/// states any, and the two tables disagree on whether the bits are even
/// writable (V1.6 p.28 says `R`, p.33 says `R/W`). Nothing here writes them.
///
/// `LED1OPEN` is not an always-live indicator — p.24 samples LED-open only at
/// the rising edge of the OVP flag — so treat it as secondary to `FLAGS2`.
///
/// Reading `BSTCTR1`/`MODE` back is free and settles an open question: if they
/// return their reset defaults, or NACK (the p.24 software reset leaves ~2 ms
/// of I2C silence), then a readback restart *is* a full reset, which neither
/// revision states.
#[cfg(feature = "dev-testkey")]
pub fn read_fault_snapshot() -> FaultSnapshot {
    let chip_id = read_reg(REG_CHIP_ID);
    if chip_id != Some(CHIP_ID_AW99703) {
        // Stop here. Reading on a bus we cannot trust would produce zeros that
        // read as "no fault", and would still carry the restart side effect.
        secure_log!(
            "[S] aw99703 #733: CHIP_ID {:?} != {:#04x} — bus untrustworthy, \
             fault registers NOT read",
            chip_id,
            CHIP_ID_AW99703
        );
        return FaultSnapshot {
            chip_id,
            flags1: None,
            flags2: None,
            bstctr1: None,
            mode: None,
        };
    }

    let flags2 = read_reg(REG_FLAGS2);
    let flags1 = read_reg(REG_FLAGS1);
    let bstctr1 = read_reg(REG_BSTCTR1);
    let mode = read_reg(REG_MODE);

    secure_log!(
        "[S] aw99703 #733: ID={:#04x} FLAGS2={:?} FLAGS1={:?} BSTCTR1={:?} (want {:#04x}) \
         MODE={:?} (want {:#04x})",
        CHIP_ID_AW99703,
        flags2,
        flags1,
        bstctr1,
        BSTCTR1_OVP,
        mode,
        MODE_I2C_LINEAR_BACKLIGHT
    );
    // Braced arms: `secure_log!` expands to nothing without `debug-log`, so a
    // bare-expression arm is an incomplete expression in every other build.
    match flags2.map(|f| f & FLAGS2_OVP != 0) {
        Some(true) => {
            secure_log!("[S] aw99703 #733: OVP HAS FIRED (FLAGS2 bit 7 set)");
        }
        Some(false) => {
            secure_log!("[S] aw99703 #733: OVP has not fired");
        }
        None => {
            secure_log!("[S] aw99703 #733: FLAGS2 did not ACK");
        }
    }

    FaultSnapshot {
        chip_id,
        flags1,
        flags2,
        bstctr1,
        mode,
    }
}

/// What the backlight chip held BEFORE this boot reconfigured it (#705).
///
/// The question invariant #10 turns on is whether the AW99703 keeps its
/// configuration across a reset. If it does, a warm reset leaves the panel lit
/// and the FSBL's fingerprint window is visible; if it does not, the window is
/// dark on every boot. That is the difference between a cold-boot-only defect
/// and an always-defect, and it decides how much the FSBL has to do.
///
/// Latched at the top of `configure()`, before any write, so reading it later cannot
/// disturb the answer. `(acked, ledmsb, mode)`.
static mut PRE_INIT: (bool, u8, u8) = (false, 0, 0);

/// Snapshot of the chip state seen at the start of this boot. See [`PRE_INIT`].
pub fn pre_init_snapshot() -> (bool, u8, u8) {
    // SAFETY: single-threaded boot; written once at the top of `configure()` before
    // any reader can run.
    unsafe { PRE_INIT }
}

/// Proof that [`configure`] programmed every prerequisite register.
///
/// The private field means only this module can make one, so [`enable`] —
/// the write that actually turns the boost on — cannot be reached after a
/// failed prerequisite write. That used to be an early `return` inside one
/// function; once the enable moved to a different call site (#730) the
/// guarantee had to travel with it, and a `bool` the caller could ignore
/// would not have carried it.
pub struct Configured(());

/// Stage 1 of 2: program the limits and brightness, leaving the chip in
/// **Standby** — no LED current flows and the panel stays dark.
///
/// Call **after** `LCM_EN`/HWEN has been driven high (the LCD driver does
/// that) — HWEN low resets every register and disables the I2C interface.
/// `None` if any write NACKed; the boost must then stay off.
///
/// WHY TWO STAGES (#730). This used to be a single `init()` that ended by
/// leaving Standby, called before the panel was reset, initialised and
/// cleared. `DISPON` is the last command of the init sequence, so for the
/// ~170 ms between it and the first `fill_screen` a LIT panel showed
/// whatever its GRAM held. Configuring here keeps the settle delay and the
/// safety-limit writes early; [`enable`] goes after the panel is painted.
pub fn configure() -> Option<Configured> {
    // #705, settled by experiment 2026-09-22: the panel is DARK until the
    // chip leaves Standby. A dev build that stalled 5 s here showed a blank
    // screen for exactly that window, then light — MODE.WORKMODE defaults to
    // 00, and only the I2C write in `enable()` sets 01. Any stage running
    // earlier — notably the FSBL, which has no I2C — therefore renders onto a
    // dark panel. The delay has been removed; do not re-add it to a shipping
    // path.

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

    // #705: latch what the chip held BEFORE we reconfigure it. Must happen
    // after the pins are configured but before the first write.
    let pre_msb = read_reg(REG_LEDMSB);
    let pre_mode = read_reg(REG_MODE);
    // SAFETY: single-threaded boot, written once before any reader.
    unsafe {
        PRE_INIT = (
            pre_msb.is_some(),
            pre_msb.unwrap_or(0),
            pre_mode.unwrap_or(0),
        );
    }

    // Order: current/OVP limits first, brightness (LSB then MSB, per datasheet).
    // Leaving Standby for Backlight mode is `enable()`'s job, not this one's.
    //
    // DO NOT ENABLE THE BOOST AFTER A FAILED PREREQUISITE. This used to be
    // `ok &= write_reg(..)` five times, which wrote REG_MODE — the boost enable
    // — unconditionally even when an earlier write had NACKed. Returning `None`
    // withholds the `Configured` token `enable()` requires, which avoids the
    // worst case: enabling with REG_BSTCTR1 unwritten leaves OVP at the
    // part's 38 V default, far above C140's 25 V rating.
    //
    // NOT a claim that OVPSEL=001 makes this safe. Awinic V1.2 specifies that
    // setting as 22.5 V min / 24 V typ / **25.5 V max**, so the threshold's
    // upper bound already exceeds a 25 V part before transient margin. The
    // component margin is a separate hardware question and this early return
    // does not close it.
    //
    // Nor does it guarantee the prerequisites actually landed: `write_byte`
    // treats any low SDA as an ACK, so a stuck-low bus ACKs everything. Real
    // assurance needs read-back verification of the critical registers before
    // enable — required before any transplant into immutable FSBL code (#705).
    for (reg, val) in [
        (REG_LEDCUR, LEDCUR_CH1_20MA),
        (REG_BSTCTR1, BSTCTR1_OVP),
        (REG_LEDLSB, BRIGHTNESS_LSB),
        (REG_LEDMSB, BRIGHTNESS_MSB),
    ] {
        if !write_reg(reg, val) {
            secure_log!("[S] aw99703: NACK on reg {:#04x} — NOT enabling the boost", reg);
            return None;
        }
    }
    Some(Configured(()))
}

/// Stage 2 of 2: leave Standby for Backlight mode — the write that emits
/// light. Call only once the panel shows content the caller has defined
/// (#730). Consumes the [`Configured`] token, so it is unreachable after a
/// failed [`configure`]. Returns `true` if the chip ACKed.
pub fn enable(_proof: Configured) -> bool {
    let ok = write_reg(REG_MODE, MODE_I2C_LINEAR_BACKLIGHT);
    secure_log!(
        "[S] aw99703: backlight enable {}",
        if ok { "ACK" } else { "NACK" }
    );
    ok
}
