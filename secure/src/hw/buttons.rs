//! Two-button GPIO driver for B-U585I-IOT02A using jumper wires.
//!
//! Pin mapping from UM2839 Table 23 — Arduino connector **CN13**
//! (right side of board, upper header, 10 pins):
//!
//! ```text
//!   CN13 pin 10 (top)    SCL/D15   (PB8,  I2C1 — do not use)
//!   CN13 pin  9          SDA/D14   (PB9,  I2C1 — do not use)
//!   CN13 pin  8          VREFP
//!   CN13 pin  7          GND     ← both GND jumpers here
//!   CN13 pin  6          D13       (PE13, SPI SCK — do not use)
//!   CN13 pin  5          D12       (PE14, SPI MISO)
//!   CN13 pin  4          D11       (PE15, SPI MOSI)
//!   CN13 pin  3          D10       (PE12, SPI CS)
//!   CN13 pin  2          D9      ← RIGHT button jumper  (PA8)
//!   CN13 pin  1 (bottom) D8      ← LEFT  button jumper  (PC1)
//! ```
//!
//! Active low: shorting a GPIO jumper to the GND jumper = "press".
//! Internal pull-ups keep the pins HIGH when not shorted.
//!
//! Gestures:
//!   * short left / right        → prev / next page
//!   * long left  (>= 500 ms)    → cancel
//!   * long right (>= 500 ms)    → confirm
//!   * both pressed together     → confirm (chord, 80 ms skew window)
//!
//! The on-board blue USER button (PC13) is also monitored in test mode
//! as a reference to confirm the firmware is running.

use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// RCC (secure alias)
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;

// ---------------------------------------------------------------------------
// GPIOA (secure alias) — PA8 = RIGHT button (CN13 pin 2 / Arduino D9)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;

// ---------------------------------------------------------------------------
// GPIOC (secure alias) — PC1 = LEFT button  (CN13 pin 1 / Arduino D8)
//                         PC13 = on-board USER button (test reference)
// ---------------------------------------------------------------------------
const GPIOC_S: u32 = 0x5202_0800;

struct ButtonsRegs {
    rcc_ahb2enr1: Reg32,
    rcc_cfgr1: RoReg32,
    gpioa_moder: Reg32,
    gpioa_pupdr: Reg32,
    gpioa_idr: RoReg32,
    gpioc_moder: Reg32,
    gpioc_pupdr: Reg32,
    gpioc_idr: RoReg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register. The
// GPIO MODER/PUPDR registers are shared with other drivers but all
// access is read-modify-write on disjoint bits in the single-threaded
// secure world. RCC_AHB2ENR1 is touched by `rcc`/`uart`/`i2c_hw` but
// only via set/clear-bit RMW, so this is safe.
const REG: ButtonsRegs = unsafe {
    ButtonsRegs {
        rcc_ahb2enr1: Reg32::new(RCC_S + 0x8C),
        rcc_cfgr1: RoReg32::new(RCC_S + 0x1C),
        gpioa_moder: Reg32::new(GPIOA_S),
        gpioa_pupdr: Reg32::new(GPIOA_S + 0x0C),
        gpioa_idr: RoReg32::new(GPIOA_S + 0x10),
        gpioc_moder: Reg32::new(GPIOC_S),
        gpioc_pupdr: Reg32::new(GPIOC_S + 0x0C),
        gpioc_idr: RoReg32::new(GPIOC_S + 0x10),
    }
};

// ---------------------------------------------------------------------------
// Pin assignments (from UM2839 Table 23)
// ---------------------------------------------------------------------------
const LEFT_BIT: u32 = 1 << 1;   // PC1  (CN13 pin 1, Arduino D8)
// ---------------------------------------------------------------------------
// Board fence — this driver is `iota2`-only until the pq1 button port lands.
// ---------------------------------------------------------------------------
//
// The pins below are the dev board's: PC1 (LEFT), PA8 (RIGHT), PC13 (USER).
// On pq1 all three are wrong, and one of them is actively dangerous:
//
//   * PC1  — not bonded on the 48-pin UFQFPN package.
//   * PC13 — bonded but unused; pq1 has only TWO buttons (PA0 / PA1).
//   * PA8  — **`LDO2_EN`**, the enable for the `VDD1_3V3` rail that powers
//     BOTH secure elements.
//
// That last one is not a cosmetic mismatch. `init()` below configures its
// RIGHT pin as a pulled-up *input*, and `ui::init()` runs AFTER
// `hw::se_power::init()` in the boot sequence — so on pq1 this driver would
// quietly undo the SE rail enable a few hundred microseconds after it was
// asserted: the internal pull-up against the board's 10 kΩ `R130` pull-down
// leaves `LDO2_EN` well below the LDO's enable threshold, powering both
// chips off again. The symptom would be an SE that answers during early
// boot and then stops, which points at everything except the real cause.
//
// Rather than leave that as a runtime trap, it is a build error. Remove
// this fence in the same change that repoints the pins at
// `board::BTN_*` — and note pq1 has no third button, so the UI's
// three-action dialogs (PIN entry, seed wizard) need a chord or long-press
// decision before `gpio-buttons` is meaningful there at all.
#[cfg(feature = "board-pq1")]
compile_error!(
    "hw/buttons.rs still uses the iota2 pin map (PC1/PA8/PC13) and is unsafe on pq1: \
     PA8 is LDO2_EN, the supply enable for BOTH secure elements, and this driver \
     would reconfigure it as a pulled-up input AFTER hw::se_power::init() has \
     asserted it — silently powering the SEs back down. Port the pins to \
     board::BTN_* (and decide how two buttons cover three UI actions) before \
     enabling `gpio-buttons` on pq1. Note `ui-lcd` implies `gpio-buttons`."
);

const RIGHT_BIT: u32 = 1 << 8;  // PA8  (CN13 pin 2, Arduino D9)

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------
const DEBOUNCE_MS: u32 = 30;
const LONG_PRESS_MS: u32 = 500;
const POLL_MS: u32 = 5;
/// After one button debounces as pressed, wait up to this long for the other
/// to also go down. If both are held within the window it's treated as a
/// "confirm" chord (synthesized as `(Right, Long)` so every existing UI path
/// sees it as a confirm event without changing the `Button` enum).
const COMBO_WINDOW_MS: u32 = 80;

/// Loops-per-ms for the busy-wait delay, calibrated at init time.
static mut LOOPS_PER_MS: u32 = 32_000; // default assumes 160 MHz

/// Busy-wait delay calibrated to actual SYSCLK.
fn delay_ms(ms: u32) {
    let lpm = unsafe { LOOPS_PER_MS };
    for _ in 0..ms {
        for _ in 0..lpm {
            cortex_m::asm::nop();
        }
    }
}

/// Calibrated busy-wait, crate-visible for callers that need to drive
/// their own debounce loop (e.g. prodtest CMD_BUTTON_TEST). Same
/// timebase as the internal `delay_ms`.
pub(crate) fn busy_wait_ms(ms: u32) {
    delay_ms(ms);
}

/// Detect SYSCLK from RCC_CFGR1 SWS bits.
fn detect_sysclk_mhz() -> u32 {
    let cfgr1 = REG.rcc_cfgr1.read();
    match (cfgr1 >> 2) & 0x3 {
        0b11 => 160, // PLL1
        0b01 => 16,  // HSI16
        _ => 4,      // MSI default
    }
}

// ---------------------------------------------------------------------------
// Raw pin reads (active low: pressed = shorted to GND = reads 0)
// ---------------------------------------------------------------------------

pub(crate) fn left_pressed() -> bool {
    REG.gpioc_idr.read() & LEFT_BIT == 0  // PC1
}

pub(crate) fn right_pressed() -> bool {
    REG.gpioa_idr.read() & RIGHT_BIT == 0  // PA8
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Configure LEFT (PC1) and RIGHT (PA8) as inputs with pull-ups.
///
/// Also configures PC13 (on-board USER button) for test reference.
///
/// # Safety
/// Direct register access. Call after `rcc::init()`.
pub unsafe fn init() {
    // Calibrate delay to actual clock speed.
    // SAFETY: single-threaded secure-world write to the calibration constant.
    let mhz = detect_sysclk_mhz();
    unsafe { LOOPS_PER_MS = mhz * 200; }

    // Enable GPIO clocks: GPIOA (bit 0), GPIOC (bit 2)
    REG.rcc_ahb2enr1.set_bits((1 << 0) | (1 << 2));
    cortex_m::asm::dsb();

    // --- PC1 (LEFT, D8): clear MODER[3:2] → 00 (input), PUPDR → 01 (pull-up) ---
    REG.gpioc_moder.modify(|v| v & !(0b11 << 2));
    REG.gpioc_pupdr.modify(|v| (v & !(0b11 << 2)) | (0b01 << 2));

    // --- PA8 (RIGHT, D9): clear MODER[17:16] → 00 (input), PUPDR → 01 (pull-up) ---
    // Only touching bits 17:16. PA13 (SWDIO) and PA14 (SWCLK) are untouched —
    // they stay in AF mode for the SWD debug connection.
    REG.gpioa_moder.modify(|v| v & !(0b11 << 16));
    REG.gpioa_pupdr.modify(|v| (v & !(0b11 << 16)) | (0b01 << 16));

    // --- PC13 (USER button, test reference): MODER[27:26] → 00 (input), pull-up ---
    REG.gpioc_moder.modify(|v| v & !(0b11 << 26));
    REG.gpioc_pupdr.modify(|v| (v & !(0b11 << 26)) | (0b01 << 26));

    cortex_m::asm::dsb();
}

// ---------------------------------------------------------------------------
// Debounced button event detection
// ---------------------------------------------------------------------------

use crate::ui::{Button, Press};

/// Block until a debounced button event occurs, or `idle_check` returns true.
///
/// Returns `None` if the idle timer fired (caller should wipe secrets).
///
/// Pressing both buttons within `COMBO_WINDOW_MS` synthesizes a
/// `(Button::Right, Press::Long)` event so every existing UI path treats it
/// as a confirm.
pub fn wait_event(idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
    loop {
        if idle_check() {
            return None;
        }

        if !(left_pressed() || right_pressed()) {
            delay_ms(POLL_MS);
            continue;
        }

        // Debounce the initial press.
        delay_ms(DEBOUNCE_MS);
        if !(left_pressed() || right_pressed()) {
            continue; // bounce
        }

        // Watch for up to COMBO_WINDOW_MS to see if the second button also
        // goes down. If the user is chording confirm, this catches the
        // natural skew between their two thumbs.
        let mut elapsed: u32 = 0;
        let mut combo = left_pressed() && right_pressed();
        while !combo && elapsed < COMBO_WINDOW_MS {
            delay_ms(POLL_MS);
            elapsed += POLL_MS;
            if idle_check() {
                return None;
            }
            if left_pressed() && right_pressed() {
                combo = true;
                break;
            }
            if !left_pressed() && !right_pressed() {
                break; // first button already released — treat as noise
            }
        }

        if combo {
            // Wait for both buttons to release (debounced) so we don't emit a
            // stray single-press event from whichever one is released last.
            return wait_combo_release(idle_check);
        }

        // No combo — fall back to single-button hold tracking.
        let already_held = DEBOUNCE_MS + elapsed;
        if left_pressed() {
            return track_hold(left_pressed, Button::Left, idle_check, already_held);
        }
        if right_pressed() {
            return track_hold(right_pressed, Button::Right, idle_check, already_held);
        }
        // Neither still pressed — released during the combo window, ignore.
    }
}

/// Wait for both buttons to be released (debounced), then emit the confirm
/// event. Returns `None` if the idle timer fires.
fn wait_combo_release(idle_check: &mut dyn FnMut() -> bool) -> Option<(Button, Press)> {
    loop {
        if idle_check() {
            return None;
        }
        if !left_pressed() && !right_pressed() {
            delay_ms(DEBOUNCE_MS);
            if !left_pressed() && !right_pressed() {
                return Some((Button::Right, Press::Long));
            }
        }
        delay_ms(POLL_MS);
    }
}

/// After a debounced press, track hold duration.
/// Returns Short if released before 500ms, Long if held >= 500ms.
/// Long press fires immediately when threshold is reached, then waits for release.
fn track_hold(
    is_pressed: fn() -> bool,
    button: Button,
    idle_check: &mut dyn FnMut() -> bool,
    initial_held_ms: u32,
) -> Option<(Button, Press)> {
    let mut held_ms: u32 = initial_held_ms;

    loop {
        if idle_check() {
            return None;
        }

        delay_ms(POLL_MS);
        held_ms += POLL_MS;

        if !is_pressed() {
            // Debounce the release
            delay_ms(DEBOUNCE_MS);
            if !is_pressed() {
                return Some((button, Press::Short));
            }
            // Bounce — still pressed, keep timing
            continue;
        }

        if held_ms >= LONG_PRESS_MS {
            // Long press detected — wait for release, then return
            if !wait_release(is_pressed, idle_check) {
                return None;
            }
            return Some((button, Press::Long));
        }
    }
}

/// Busy-wait until the pin reads released (HIGH), with debounce.
///
/// The same abort predicate used by `wait_event` is polled throughout the
/// release hold. Ordinary confirmation supplies the inactivity predicate;
/// forced confirmation supplies inactivity OR its absolute deadline. A held
/// GPIO button therefore cannot suspend either timeout after the long-press
/// threshold has fired.
fn wait_release(is_pressed: fn() -> bool, idle_check: &mut dyn FnMut() -> bool) -> bool {
    loop {
        if idle_check() {
            return false;
        }
        if !is_pressed() {
            delay_ms(DEBOUNCE_MS);
            if idle_check() {
                return false;
            }
            if !is_pressed() {
                return true;
            }
        }
        delay_ms(POLL_MS);
    }
}

// ===========================================================================
// Test mode — scans GPIO pins and reports button events via semihosting
// ===========================================================================

#[cfg(feature = "button-test")]
pub unsafe fn run_test() -> ! {
    use cortex_m_semihosting::hprintln;

    init();

    let mhz = detect_sysclk_mhz();

    hprintln!("========================================");
    hprintln!("[BTN] GPIO Button Test (B-U585I-IOT02A)");
    hprintln!("[BTN] SYSCLK = {} MHz", mhz);
    hprintln!("[BTN]");
    hprintln!("[BTN] Wiring — CN13 (right side, upper):");
    hprintln!("[BTN]   LEFT  = CN13 pin 1 (D8,  PC1)");
    hprintln!("[BTN]   RIGHT = CN13 pin 2 (D9,  PA8)");
    hprintln!("[BTN]   GND   = CN13 pin 7");
    hprintln!("[BTN]");
    hprintln!("[BTN] Short GPIO wire to GND wire = press");
    hprintln!("[BTN] On-board USER btn (blue/B3) monitored");
    hprintln!("========================================");

    // ---- Phase 1: Pin scanner (15s) ----
    hprintln!("[BTN]");
    hprintln!("[BTN] Phase 1: Pin scanner (15 seconds)");
    hprintln!("[BTN] Touch CN13 pins to GND to verify.");
    hprintln!("[BTN] Monitoring: PC1 (D8), PA8 (D9), PC13 (USER)");

    let mut prev_left = left_pressed();
    let mut prev_right = right_pressed();
    let mut prev_user = REG.gpioc_idr.read() & (1 << 13) == 0;

    hprintln!("[BTN] Baseline: PC1(D8)={} PA8(D9)={} PC13(USER)={}",
        prev_left as u8, prev_right as u8, prev_user as u8);

    // Scan for ~15 seconds (15000ms / 10ms per loop = 1500 iterations)
    for _ in 0..1500u32 {
        delay_ms(10);

        let l = left_pressed();
        let r = right_pressed();
        let u = REG.gpioc_idr.read() & (1 << 13) == 0;

        if l != prev_left {
            hprintln!("[BTN]   PC1  (LEFT/D8)  {}", if l { "PRESSED" } else { "released" });
            prev_left = l;
        }
        if r != prev_right {
            hprintln!("[BTN]   PA8  (RIGHT/D9) {}", if r { "PRESSED" } else { "released" });
            prev_right = r;
        }
        if u != prev_user {
            hprintln!("[BTN]   PC13 (USER btn)  {}", if u { "PRESSED" } else { "released" });
            prev_user = u;
        }
    }

    // ---- Phase 2: Debounced button events ----
    hprintln!("[BTN]");
    hprintln!("========================================");
    hprintln!("[BTN] Phase 2: Button event detection");
    hprintln!("[BTN]   LEFT  = PC1/D8  (short <500ms, long >=500ms)");
    hprintln!("[BTN]   RIGHT = PA8/D9  (short <500ms, long >=500ms)");
    hprintln!("[BTN]   BOTH pressed together = confirm chord");
    hprintln!("[BTN]                           (reports as RIGHT LONG)");
    hprintln!("[BTN] Waiting for events...");
    hprintln!("========================================");

    loop {
        let mut no_idle = || false;
        if let Some((button, press)) = wait_event(&mut no_idle) {
            let btn = match button {
                Button::Left => "LEFT ",
                Button::Right => "RIGHT",
            };
            let pr = match press {
                Press::Short => "SHORT",
                Press::Long => "LONG ",
            };
            hprintln!("[BTN]   >> {} {}", btn, pr);
        }
    }
}
