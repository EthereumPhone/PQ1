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

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};

// ---------------------------------------------------------------------------
// Register handles, named by ROLE not by port
// ---------------------------------------------------------------------------
//
// The ports come from `crate::board`. Naming these `left_*`/`right_*` rather
// than `gpioa_*`/`gpioc_*` matters now that a board can put both buttons on
// the SAME port: iota2 straddles GPIOC (PC1) and GPIOA (PA8), pq1 has both on
// GPIOA (PA0/PA1). Two `Reg32` handles onto one base are harmless — `Reg32` is
// just an address wrapper — but port-named fields would read as a lie.

struct ButtonsRegs {
    rcc_ahb2enr1: Reg32,
    rcc_cfgr1: RoReg32,
    left_moder: Reg32,
    left_pupdr: Reg32,
    left_idr: RoReg32,
    right_moder: Reg32,
    right_pupdr: Reg32,
    right_idr: RoReg32,
    /// Only bound on a board that has a third button; `BTN_USER` is
    /// configured for bench reference and never read by the UI.
    user_moder: Reg32,
    user_pupdr: Reg32,
    user_idr: RoReg32,
}

/// `(port, pin)` of the optional USER button, or a harmless stand-in when the
/// board has none. `HAS_USER` gates every use, so the stand-in is never
/// touched — it exists only so the `const` register block can be built
/// unconditionally.
const USER: (u32, u32) = match board::BTN_USER {
    Some(p) => p,
    None => (board::GPIOA_S, 0),
};
const HAS_USER: bool = board::BTN_USER.is_some();

// SAFETY: each address is a real, 4-byte-aligned MMIO register. The
// GPIO MODER/PUPDR registers are shared with other drivers but all
// access is read-modify-write on disjoint bits in the single-threaded
// secure world. RCC_AHB2ENR1 is touched by `rcc`/`uart`/`i2c_hw` but
// only via set/clear-bit RMW, so this is safe.
const REG: ButtonsRegs = unsafe {
    ButtonsRegs {
        rcc_ahb2enr1: Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF),
        rcc_cfgr1: RoReg32::new(board::RCC_S + 0x1C),
        left_moder: Reg32::new(board::BTN_LEFT_PORT),
        left_pupdr: Reg32::new(board::BTN_LEFT_PORT + 0x0C),
        left_idr: RoReg32::new(board::BTN_LEFT_PORT + 0x10),
        right_moder: Reg32::new(board::BTN_RIGHT_PORT),
        right_pupdr: Reg32::new(board::BTN_RIGHT_PORT + 0x0C),
        right_idr: RoReg32::new(board::BTN_RIGHT_PORT + 0x10),
        user_moder: Reg32::new(USER.0),
        user_pupdr: Reg32::new(USER.0 + 0x0C),
        user_idr: RoReg32::new(USER.0 + 0x10),
    }
};

// ---------------------------------------------------------------------------
// Pin masks + register field shifts, derived from the board map
// ---------------------------------------------------------------------------
//
// iota2: LEFT = PC1, RIGHT = PA8 (CN13 jumpers, Arduino D8/D9).
// pq1:   LEFT = PA0, RIGHT = PA1 (solder pads J203/J205, each against a GND
//        pad; the board has no pull-up, so the internal one below is what
//        makes the active-low read work).
const LEFT_BIT: u32 = 1 << board::BTN_LEFT_PIN;
const RIGHT_BIT: u32 = 1 << board::BTN_RIGHT_PIN;
/// Bit position of a pin's 2-bit field in `MODER` / `PUPDR`.
const LEFT_PIN2: u32 = board::BTN_LEFT_PIN * 2;
const RIGHT_PIN2: u32 = board::BTN_RIGHT_PIN * 2;
const USER_PIN2: u32 = USER.1 * 2;
const USER_BIT: u32 = 1 << USER.1;
// ---------------------------------------------------------------------------
// Pin-collision guard
// ---------------------------------------------------------------------------
//
// This replaces an earlier `compile_error!` that fenced pq1 off wholesale.
// The hazard it guarded was real and specific: PA8 is the RIGHT button on
// iota2 and **`LDO2_EN`** on pq1 — the supply enable for BOTH secure
// elements — and `ui::init()` runs AFTER `hw::se_power::init()`, so
// configuring it as a pulled-up input here would silently power both chips
// back down a few hundred microseconds after they were brought up.
//
// A fence keeps one board out. This asserts the actual property, on every
// board, at compile time: a button pin may not land on any pin that
// something else owns. It is the check that would have caught the original
// bug rather than merely quarantining it, and unlike the fence it keeps
// working as new boards are added.
//
// Precedent for the shape: the exact-equality `const assert!` arms in
// `sau.rs::configure_gtzc`.

/// Pins that must never be claimed as a button, with why.
///
/// `None` entries (a line the board does not have) can never collide, so
/// the check folds them away.
const RESERVED: [(Option<(u32, u32)>, &str); 6] = [
    (board::SE_RAIL_EN, "SE supply enable (LDO2_EN)"),
    (board::OPTIGA_RST, "OPTIGA reset (SE_RST)"),
    (board::SE050_EN, "SE050 enable (SE1_EN)"),
    (
        Some((board::CONSOLE_TX_PORT, board::CONSOLE_TX_PIN)),
        "debug console UART TX",
    ),
    (Some((board::GPIOA_S, 13)), "SWDIO"),
    (Some((board::GPIOA_S, 14)), "SWCLK"),
];

/// True if `pin` collides with any reserved line.
const fn collides(pin: (u32, u32)) -> bool {
    let mut i = 0;
    while i < RESERVED.len() {
        if let Some(r) = RESERVED[i].0 {
            if r.0 == pin.0 && r.1 == pin.1 {
                return true;
            }
        }
        i += 1;
    }
    false
}

const _: () = assert!(
    !collides((board::BTN_LEFT_PORT, board::BTN_LEFT_PIN)),
    "the LEFT button pin collides with a reserved line for this board — see \
     RESERVED in hw/buttons.rs. On pq1 the classic case is PA8, which is \
     LDO2_EN (the supply enable for BOTH secure elements): claiming it as a \
     pulled-up input silently powers the secure elements down, because \
     ui::init() runs after hw::se_power::init()."
);
const _: () = assert!(
    !collides((board::BTN_RIGHT_PORT, board::BTN_RIGHT_PIN)),
    "the RIGHT button pin collides with a reserved line for this board — see \
     RESERVED in hw/buttons.rs. On pq1 the classic case is PA8, which is \
     LDO2_EN (the supply enable for BOTH secure elements): claiming it as a \
     pulled-up input silently powers the secure elements down, because \
     ui::init() runs after hw::se_power::init()."
);
const _: () = assert!(
    !(board::BTN_LEFT_PORT == board::BTN_RIGHT_PORT
        && board::BTN_LEFT_PIN == board::BTN_RIGHT_PIN),
    "LEFT and RIGHT are the same pin — the two-button UI would see one input"
);


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
    REG.left_idr.read() & LEFT_BIT == 0
}

pub(crate) fn right_pressed() -> bool {
    REG.right_idr.read() & RIGHT_BIT == 0
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Configure LEFT and RIGHT as inputs with pull-ups, on whichever pins the
/// board map names.
///
/// Also configures the USER button when the board has one — it is a bench
/// reference only, never read by the UI.
///
/// # Safety
/// Direct register access. Call after `rcc::init()`.
pub unsafe fn init() {
    // Calibrate delay to actual clock speed.
    // SAFETY: single-threaded secure-world write to the calibration constant.
    let mhz = detect_sysclk_mhz();
    unsafe { LOOPS_PER_MS = mhz * 200; }

    // Enable the GPIO clock for each button's port. On iota2 these are two
    // different ports (bits 0 | 2); on pq1 both buttons are on GPIOA so this
    // folds to bit 0 alone. Deriving it means no `cfg` is needed either way.
    let mut gpio_clocks =
        board::gpio_rcc_bit(board::BTN_LEFT_PORT) | board::gpio_rcc_bit(board::BTN_RIGHT_PORT);
    if HAS_USER {
        gpio_clocks |= board::gpio_rcc_bit(USER.0);
    }
    REG.rcc_ahb2enr1.set_bits(gpio_clocks);
    cortex_m::asm::dsb();

    // Each button: MODER field → 00 (input), PUPDR field → 01 (pull-up).
    //
    // Only the two bits belonging to each pin are touched. That is what keeps
    // PA13 (SWDIO) and PA14 (SWCLK) in AF mode for the debug connection — and
    // it is now enforced rather than merely intended: the `const assert!`
    // above rejects a board map that puts a button on either of them.
    REG.left_moder.modify(|v| v & !(0b11 << LEFT_PIN2));
    REG.left_pupdr
        .modify(|v| (v & !(0b11 << LEFT_PIN2)) | (0b01 << LEFT_PIN2));

    REG.right_moder.modify(|v| v & !(0b11 << RIGHT_PIN2));
    REG.right_pupdr
        .modify(|v| (v & !(0b11 << RIGHT_PIN2)) | (0b01 << RIGHT_PIN2));

    // USER button (bench reference), only where the board has one. pq1 has
    // two buttons and no third pin to configure.
    if HAS_USER {
        REG.user_moder.modify(|v| v & !(0b11 << USER_PIN2));
        REG.user_pupdr
            .modify(|v| (v & !(0b11 << USER_PIN2)) | (0b01 << USER_PIN2));
    }

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
    let mut prev_user = REG.user_idr.read() & USER_BIT == 0;

    hprintln!("[BTN] Baseline: PC1(D8)={} PA8(D9)={} PC13(USER)={}",
        prev_left as u8, prev_right as u8, prev_user as u8);

    // Scan for ~15 seconds (15000ms / 10ms per loop = 1500 iterations)
    for _ in 0..1500u32 {
        delay_ms(10);

        let l = left_pressed();
        let r = right_pressed();
        let u = REG.user_idr.read() & USER_BIT == 0;

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
    hprintln!("[BTN]   board = {}", board::BOARD_NAME);
    hprintln!(
        "[BTN]   LEFT  = pin {}  (short <500ms, long >=500ms)",
        board::BTN_LEFT_PIN
    );
    hprintln!(
        "[BTN]   RIGHT = pin {}  (short <500ms, long >=500ms)",
        board::BTN_RIGHT_PIN
    );
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
