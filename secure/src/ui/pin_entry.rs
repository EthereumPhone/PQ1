//! 2-button 8-digit PIN entry, fully driven from the secure UI so the PIN
//! never touches non-secure RAM.
//!
//! Controls:
//!   * tap right    → digit + 1
//!   * tap left     → digit - 1
//!   * long right   → next position (or submit on the last position)
//!   * long left    → previous position (or cancel on position 0)
//!
//! ## F-20 — Per-position random starting digit (digit scrambling)
//!
//! At session start, each of the 8 PIN positions is initialised to a
//! fresh `rng_strong`-derived digit (mod-10 reduced) instead of 0.
//! The user sees that random start when they arrive at the position
//! and scrolls Left/Right by `(target - start) mod 10` presses to
//! reach their chosen digit.
//!
//! **Attack defended:** A shoulder-surf or hand-camera attacker who
//! can count Left/Right button presses but cannot see the OLED
//! (overhead-camera-on-hands, EM monitoring of the button signal,
//! motion tracking of finger movements) cannot derive the absolute
//! digit from the press count alone — they get
//! `(target - random_start) mod 10`, but `random_start` is hidden.
//!
//! **What this does NOT defend:** Attacker with screen visibility
//! (camera on the OLED + hands together) sees the live digit
//! directly. Trezor mitigates this with a 3×3 grid where the digit
//! permutation is on the screen and the user picks by POSITION; our
//! 2-button hardware can't replicate that. Our defense is the
//! narrower button-pattern shoulder-surf class, which is real but
//! less than full grid-scramble protection.

use super::{display, input, show_status, Button, Press, DISPLAY_COLS};
use crate::timeout;
use sphincs_tz_shared::PIN_LEN;
use zeroize::Zeroize;

pub enum PinEntryResult {
    Pin([u8; PIN_LEN]),
    Cancelled,
    IdleWipe,
    /// First and confirmation PIN entries did not match. Caller should
    /// inform the user and re-prompt.
    Mismatch,
}

pub fn enter_pin() -> PinEntryResult {
    // F-20: initialise each PIN position to a fresh random digit so
    // an attacker counting Left/Right presses cannot derive the
    // absolute digit value from the press count alone (the
    // user's per-position press count is `(target - random_start) mod
    // 10`, with random_start unknown to the attacker). Defends the
    // button-pattern shoulder-surf class.
    //
    // Source: `rng_strong::fill` (STM32 ⊕ OPTIGA ⊕ SE050 XOR-fold).
    // Cost: a one-shot ~few-ms RNG draw at session entry, negligible
    // compared to PIN-entry wall time.
    //
    // **Modulo-10 bias:** with 256 byte values mapped to 10 digits,
    // values 0..=5 each get 26 mappings vs 25 for 6..=9 — a per-
    // digit probability bias of ±0.4 %. Acceptable for a shoulder-
    // surf defense where the goal is "attacker doesn't know the
    // start," not "uniform start distribution."
    //
    // **Fallback on RNG failure:** if `rng_strong::fill` returns
    // `Err` (extremely unlikely), the buffer stays at zero and the
    // PIN positions effectively start at 0 (legacy behaviour). We
    // do NOT refuse PIN entry — bricking the wallet on transient
    // RNG flake would be worse than degrading scrambling to the
    // pre-F-20 baseline.
    let mut pin = [0u8; PIN_LEN];
    #[cfg(not(test))]
    {
        let mut rand_bytes = [0u8; PIN_LEN];
        let _ = crate::rng_strong::fill(&mut rand_bytes);
        for i in 0..PIN_LEN {
            pin[i] = rand_bytes[i] % 10;
        }
        rand_bytes.zeroize();
    }
    let mut pos: usize = 0;

    timeout::reset_activity();

    loop {
        render_pin_screen(&pin, pos);

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => {
                // backend signalled idle wipe
                wipe_pin(&mut pin);
                return PinEntryResult::IdleWipe;
            }
        };

        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                pin[pos] = (pin[pos] + 1) % 10;
            }
            (Button::Left, Press::Short) => {
                pin[pos] = (pin[pos] + 9) % 10;
            }
            (Button::Right, Press::Long) => {
                if pos + 1 == PIN_LEN {
                    // Convert each digit (0-9) to its ASCII byte ('0'-'9')
                    // before returning, since the secure-element MACD chain
                    // is keyed off the ASCII representation.
                    let mut ascii = [0u8; PIN_LEN];
                    for i in 0..PIN_LEN {
                        ascii[i] = b'0' + pin[i];
                    }
                    wipe_pin(&mut pin);
                    return PinEntryResult::Pin(ascii);
                } else {
                    pos += 1;
                }
            }
            (Button::Left, Press::Long) => {
                if pos == 0 {
                    wipe_pin(&mut pin);
                    return PinEntryResult::Cancelled;
                } else {
                    pos -= 1;
                }
            }
        }
    }
}

fn render_pin_screen(pin: &[u8; PIN_LEN], pos: usize) {
    let d = display();
    d.clear();
    d.draw_line(0, "   Enter PIN");

    // Render the 8 digits, hiding past digits as '*'.
    let mut row1 = [b' '; DISPLAY_COLS];
    // Layout: 8 digits, separated by spaces, centered.
    // Total width: 8*2 - 1 = 15 chars, fits in 16 cols.
    for (i, &d) in pin.iter().enumerate() {
        let col = i * 2;
        if col >= DISPLAY_COLS {
            break;
        }
        row1[col] = if i < pos {
            b'*'
        } else if i == pos {
            // Active position: show the digit.
            b'0' + d
        } else {
            b'_'
        };
    }
    d.draw_line(1, super::ascii_str(&row1));

    // Position indicator under the active digit.
    let mut row2 = [b' '; DISPLAY_COLS];
    let col = pos * 2;
    if col < DISPLAY_COLS {
        row2[col] = b'^';
    }
    d.draw_line(2, super::ascii_str(&row2));

    d.draw_line(3, "L=- R=+ LL=back");
    d.flush();
}

fn wipe_pin(pin: &mut [u8; PIN_LEN]) {
    pin.zeroize();
    crate::fi::zeroize_barrier();
}

/// First-boot PIN selection: prompt twice and verify the entries match,
/// so the user does not typo themselves into a brick on day one.
///
/// Returns `Pin` only when both entries match exactly. On any cancel,
/// idle-wipe, or mismatch, returns the corresponding variant and zeroes any
/// PIN material that briefly held a value.
pub fn enter_pin_with_confirm() -> PinEntryResult {
    show_status("Set new PIN", "");
    let first = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        other => return other,
    };

    show_status("Confirm PIN", "");
    let second = match enter_pin() {
        PinEntryResult::Pin(p) => p,
        other => {
            // We had a first PIN in flight; wipe it before bailing.
            let mut f = first;
            f.zeroize();
            return other;
        }
    };

    // Constant-time-ish comparison: don't early-return on mismatch.
    let mut diff: u8 = 0;
    for i in 0..PIN_LEN {
        diff |= first[i] ^ second[i];
    }

    let mut a = first;
    let mut b = second;
    if diff != 0 {
        a.zeroize();
        b.zeroize();
        return PinEntryResult::Mismatch;
    }
    // a (== b) is the confirmed PIN. Move it out, wipe b.
    b.zeroize();
    PinEntryResult::Pin(a)
}
