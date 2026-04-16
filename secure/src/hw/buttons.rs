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

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// RCC
// ---------------------------------------------------------------------------
const RCC_S: u32 = 0x5602_0C00;
const RCC_AHB2ENR1: *mut u32 = (RCC_S + 0x8C) as *mut u32;
const RCC_CFGR1: *const u32 = (RCC_S + 0x1C) as *const u32;

// ---------------------------------------------------------------------------
// GPIOA (secure alias) — PA8 = RIGHT button (CN13 pin 2 / Arduino D9)
// ---------------------------------------------------------------------------
const GPIOA_S: u32 = 0x5202_0000;
const GPIOA_MODER: *mut u32 = GPIOA_S as *mut u32;
const GPIOA_PUPDR: *mut u32 = (GPIOA_S + 0x0C) as *mut u32;
const GPIOA_IDR: *const u32 = (GPIOA_S + 0x10) as *const u32;

// ---------------------------------------------------------------------------
// GPIOC (secure alias) — PC1 = LEFT button  (CN13 pin 1 / Arduino D8)
//                         PC13 = on-board USER button (test reference)
// ---------------------------------------------------------------------------
const GPIOC_S: u32 = 0x5202_0800;
const GPIOC_MODER: *mut u32 = GPIOC_S as *mut u32;
const GPIOC_PUPDR: *mut u32 = (GPIOC_S + 0x0C) as *mut u32;
const GPIOC_IDR: *const u32 = (GPIOC_S + 0x10) as *const u32;

// ---------------------------------------------------------------------------
// Pin assignments (from UM2839 Table 23)
// ---------------------------------------------------------------------------
const LEFT_BIT: u32 = 1 << 1;   // PC1  (CN13 pin 1, Arduino D8)
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

/// Detect SYSCLK from RCC_CFGR1 SWS bits.
fn detect_sysclk_mhz() -> u32 {
    let cfgr1 = unsafe { read_volatile(RCC_CFGR1) };
    match (cfgr1 >> 2) & 0x3 {
        0b11 => 160, // PLL1
        0b01 => 16,  // HSI16
        _ => 4,      // MSI default
    }
}

// ---------------------------------------------------------------------------
// Raw pin reads (active low: pressed = shorted to GND = reads 0)
// ---------------------------------------------------------------------------

fn left_pressed() -> bool {
    unsafe { read_volatile(GPIOC_IDR) & LEFT_BIT == 0 }  // PC1
}

fn right_pressed() -> bool {
    unsafe { read_volatile(GPIOA_IDR) & RIGHT_BIT == 0 }  // PA8
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Configure LEFT (PI2) and RIGHT (PA15) as inputs with pull-ups.
///
/// Also configures PC13 (on-board USER button) for test reference.
///
/// # Safety
/// Direct register access. Call after `rcc::init()`.
pub unsafe fn init() {
    // Calibrate delay to actual clock speed
    let mhz = detect_sysclk_mhz();
    LOOPS_PER_MS = mhz * 200;

    // Enable GPIO clocks: GPIOA (bit 0), GPIOC (bit 2)
    let ahb2 = read_volatile(RCC_AHB2ENR1);
    write_volatile(RCC_AHB2ENR1, ahb2 | (1 << 0) | (1 << 2));
    cortex_m::asm::dsb();

    // --- PC1 (LEFT, D8): clear MODER[3:2] → 00 (input), PUPDR → 01 (pull-up) ---
    let m = read_volatile(GPIOC_MODER);
    write_volatile(GPIOC_MODER, m & !(0b11 << 2));
    let p = read_volatile(GPIOC_PUPDR);
    write_volatile(GPIOC_PUPDR, (p & !(0b11 << 2)) | (0b01 << 2));

    // --- PA8 (RIGHT, D9): clear MODER[17:16] → 00 (input), PUPDR → 01 (pull-up) ---
    // SAFETY: only touching bits 17:16. PA13 (SWDIO) and PA14 (SWCLK) are
    // untouched — they stay in AF mode for the SWD debug connection.
    let m = read_volatile(GPIOA_MODER);
    write_volatile(GPIOA_MODER, m & !(0b11 << 16));
    let p = read_volatile(GPIOA_PUPDR);
    write_volatile(GPIOA_PUPDR, (p & !(0b11 << 16)) | (0b01 << 16));

    // --- PC13 (USER button, test reference): MODER[27:26] → 00 (input), pull-up ---
    let m = read_volatile(GPIOC_MODER);
    write_volatile(GPIOC_MODER, m & !(0b11 << 26));
    let p = read_volatile(GPIOC_PUPDR);
    write_volatile(GPIOC_PUPDR, (p & !(0b11 << 26)) | (0b01 << 26));

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
            wait_release(is_pressed);
            return Some((button, Press::Long));
        }
    }
}

/// Busy-wait until the pin reads released (HIGH), with debounce.
fn wait_release(is_pressed: fn() -> bool) {
    loop {
        if !is_pressed() {
            delay_ms(DEBOUNCE_MS);
            if !is_pressed() {
                return;
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
    let mut prev_user = read_volatile(GPIOC_IDR) & (1 << 13) == 0;

    hprintln!("[BTN] Baseline: PC1(D8)={} PA8(D9)={} PC13(USER)={}",
        prev_left as u8, prev_right as u8, prev_user as u8);

    // Scan for ~15 seconds (15000ms / 10ms per loop = 1500 iterations)
    for _ in 0..1500u32 {
        delay_ms(10);

        let l = left_pressed();
        let r = right_pressed();
        let u = read_volatile(GPIOC_IDR) & (1 << 13) == 0;

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
