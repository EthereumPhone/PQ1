//! First-boot seed phrase wizard. Three flows:
//!
//! 1. `choose_setup_mode` — pick "New Wallet" or "Restore from seed phrase".
//! 2. `show_mnemonic` — display all 24 words across paged screens so the user
//!    can write them down.
//! 3. `verify_mnemonic` — spot-check 3 random words against what the user
//!    just wrote down.
//! 4. `enter_mnemonic` — type in 24 words via letter-scroll + 4-letter prefix
//!    narrowing. Used by both restore and verify.
//!
//! All flows reuse the existing `Display`, `Input`, `Button`, `Press`, and
//! `timeout::is_idle` plumbing so the inactivity wipe works the same as on
//! every other trusted UI screen.
//!
//! UX conventions (consistent with `pin_entry.rs` and `confirm.rs`):
//!
//! | Action     | Effect                                       |
//! |------------|----------------------------------------------|
//! | `Right`    | next / increment                             |
//! | `Left`     | prev / decrement                             |
//! | long-Right | confirm / advance / select                   |
//! | long-Left  | cancel / back                                |
//!
//! ## X17-UI3 policy (#426)
//!
//! `timeout::reset_activity()` is called ONLY on real user activity: a
//! button event returned by `wait_button`. No wizard-step entry may
//! reset the inactivity timer — spammed navigation through step entries
//! would otherwise keep refreshing the 120 s idle window with zero user
//! interaction (the same keepalive-extension shape as X17-UI3 /
//! pin_entry.rs:83). Every input loop below resets the timer right
//! after its button wait returns `Some(ev)`, never in the prologue
//! before the loop.

use super::{display, input, show_status, Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::rng;
use crate::timeout;
use sphincs_tz_bip39::{
    is_exact_wordlist_entry, lookup_prefix, word_bytes_at, Mnemonic, PrefixLookup,
    MAX_WORD_BYTES, WORD_COUNT,
};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Port step 4 — the pixel UI's twins of the wizard pages
// ---------------------------------------------------------------------------
//
// Each painter returns `true` when the pixel UI showed the screen; `false`
// (no `ui-px`, or no verified atlas) means the caller paints its 16×4 page.

/// The chooser ask (`status_map::choice`).
fn px_choice(title: &[u8], option: &[u8]) -> bool {
    #[cfg(feature = "ui-px")]
    {
        super::px::screens::show(&super::px::status_map::choice(title, option))
    }
    #[cfg(not(feature = "ui-px"))]
    {
        let _ = (title, option);
        false
    }
}

/// Words a seed page holds on the pixel grid (two columns of four).
#[cfg(feature = "ui-px")]
const PX_WORDS_PER_PAGE: usize = 8;

/// `(total pages, words per page)` for one walk through the seed words,
/// decided ONCE before the first page: the design's grid (3 × 8) when the
/// pixel UI can paint, else the 16×4 pages (8 × 3). A later paint failure
/// cancels the walk (the wizard retries on the pages) rather than ever
/// mixing the two pagings — no word can be skipped.
fn mnemonic_paging() -> (usize, usize) {
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if super::px::assets::verify_atlas().is_ok() {
        return (WORD_COUNT / PX_WORDS_PER_PAGE, PX_WORDS_PER_PAGE);
    }
    #[cfg(all(feature = "ui-px", not(feature = "ui-lcd")))]
    return (WORD_COUNT / PX_WORDS_PER_PAGE, PX_WORDS_PER_PAGE);
    #[allow(unreachable_code)]
    (TOTAL_PAGES, WORDS_PER_PAGE)
}

/// A seed page on the pixel grid: the numbers are public, the words go
/// through the constant-time run (F-24 — `Font::blit_secret_run`), fetched
/// with the constant-time `word_bytes` (no load addressed by a word index)
/// into fixed eight-byte cells (no length-dependent copy).
#[cfg(feature = "ui-px")]
fn px_mnemonic_page(m: &Mnemonic, page: usize) -> bool {
    let mut cells = [[0u8; MAX_WORD_BYTES]; PX_WORDS_PER_PAGE];
    for (slot, cell) in cells.iter_mut().enumerate() {
        let _ = m.word_bytes(page * PX_WORDS_PER_PAGE + slot, cell);
    }
    let secret: [(usize, &[u8]); PX_WORDS_PER_PAGE] = core::array::from_fn(|k| (k, &cells[k][..]));
    let first = (page * PX_WORDS_PER_PAGE + 1) as u8;
    let ok = super::px::screens::show_with(&super::px::status_map::seed_page(first, PX_WORDS_PER_PAGE), &secret);
    for c in cells.iter_mut() {
        c.zeroize();
    }
    ok
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WizardChoice {
    NewWallet,
    Restore,
    Cancelled,
    IdleWipe,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WizardResult {
    Confirmed,
    Cancelled,
    IdleWipe,
}

#[derive(Debug)]
pub enum WizardError {
    Cancelled,
    IdleWipe,
}

// ---------------------------------------------------------------------------
// 1. Choose setup mode
// ---------------------------------------------------------------------------

/// Two-option menu, scrollable with Left/Right short, confirmed with long-Right.
pub fn choose_setup_mode() -> WizardChoice {
    let options = ["New Wallet", "Restore"];
    let mut idx: usize = 0;

    loop {
        // Port step 4: the chooser is the design's ask, the highlighted
        // option as its caption (taps switch it, the chord selects).
        if !px_choice(b"", [&b"Create new wallet"[..], b"Restore wallet"][idx]) {
            let d = display();
            d.clear();
            d.draw_line(0, "  Wallet Setup");
            for (i, label) in options.iter().enumerate() {
                let mut row = [b' '; DISPLAY_COLS];
                row[0] = if i == idx { b'>' } else { b' ' };
                let lb = label.as_bytes();
                let max = core::cmp::min(lb.len(), DISPLAY_COLS - 2);
                row[2..2 + max].copy_from_slice(&lb[..max]);
                d.draw_line(i + 1, super::ascii_str(&row));
            }
            d.draw_line(3, "L=- R=+ LR=ok");
            d.flush();
        }

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return WizardChoice::IdleWipe,
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => idx = (idx + 1) % options.len(),
            (Button::Left, Press::Short) => idx = (idx + options.len() - 1) % options.len(),
            (Button::Right, Press::Long) => {
                return if idx == 0 {
                    WizardChoice::NewWallet
                } else {
                    WizardChoice::Restore
                };
            }
            (Button::Left, Press::Long) => return WizardChoice::Cancelled,
        }
    }
}

// ---------------------------------------------------------------------------
// §32 P4/P5 — duress (decoy) PIN setup dialogs
// ---------------------------------------------------------------------------

#[cfg(any(feature = "duress-pin", feature = "duress-ui-test"))]
use sphincs_tz_shared::PIN_LEN;

/// Hold the currently-rendered status message on screen for `ms`
/// milliseconds so the user can read it before the next dialog redraws
/// over it (e.g. an error before `enter_pin_with_confirm` reclaims the
/// display). `timeout::now()` is a 1 kHz SysTick counter.
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test"))]
fn hold_message(ms: u32) {
    let start = timeout::now();
    while timeout::now().wrapping_sub(start) < ms {
        core::hint::spin_loop();
    }
}

/// Two-option yes/no chooser (mirrors `choose_setup_mode`'s navigation:
/// L/R move the `>` cursor, long-Right selects, long-Left cancels = No).
/// Returns `None` only on idle-timeout (caller treats as decline).
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test"))]
fn yes_no(title: &str) -> Option<bool> {
    let options = ["No", "Yes"];
    let mut idx: usize = 0;
    loop {
        if !px_choice(title.as_bytes(), options[idx].as_bytes()) {
            let d = display();
            d.clear();
            d.draw_line(0, title);
            for (i, label) in options.iter().enumerate() {
                let mut row = [b' '; DISPLAY_COLS];
                row[0] = if i == idx { b'>' } else { b' ' };
                let lb = label.as_bytes();
                let max = core::cmp::min(lb.len(), DISPLAY_COLS - 2);
                row[2..2 + max].copy_from_slice(&lb[..max]);
                d.draw_line(i + 1, super::ascii_str(&row));
            }
            d.draw_line(3, "L=- R=+ LR=ok");
            d.flush();
        }

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return None,
        };
        timeout::reset_activity();
        match event {
            (Button::Right, Press::Short) => idx = (idx + 1) % options.len(),
            (Button::Left, Press::Short) => idx = (idx + options.len() - 1) % options.len(),
            (Button::Right, Press::Long) => return Some(idx == 1),
            (Button::Left, Press::Long) => return Some(false), // cancel = No
        }
    }
}

/// §32 P4: optionally collect a duress (decoy) PIN at first-boot setup.
/// Returns `Some(pin)` if the user set one, confirmed-DISTINCT from the
/// main PIN; `None` to decline — the caller then provisions a decoy with
/// a RANDOM PIN (always-provision preserves deniability either way).
///
/// Bounded to 3 distinct-PIN attempts so a user repeatedly entering the
/// main PIN (or mismatching) can't lock themselves in the dialog — after
/// that it falls back to `None` (random decoy) and setup proceeds.
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test"))]
pub fn collect_duress_pin(main_pin: &[u8; PIN_LEN]) -> Option<[u8; PIN_LEN]> {
    use super::pin_entry::{enter_pin_with_confirm, PinEntryResult};

    match yes_no(" Set duress PIN?") {
        Some(true) => {}
        _ => return None,
    }

    for _ in 0..3 {
        show_status("Duress PIN", "must differ");
        match enter_pin_with_confirm() {
            PinEntryResult::Pin(p) => {
                // Constant-time-ish distinct check vs the main PIN.
                let mut diff: u8 = 0;
                for i in 0..PIN_LEN {
                    diff |= p[i] ^ main_pin[i];
                }
                if diff == 0 {
                    let mut pp = p;
                    pp.zeroize();
                    show_status("Same as main", "pick another");
                    hold_message(1800);
                    continue;
                }
                return Some(p);
            }
            PinEntryResult::Mismatch => {
                show_status("PIN mismatch", "try again");
                hold_message(1800);
                continue;
            }
            PinEntryResult::Cancelled | PinEntryResult::IdleWipe => return None,
        }
    }
    // Exhausted attempts → decline (random decoy PIN).
    None
}

/// §32 P5: ask whether a duress-PIN entry should WIPE the device rather
/// than open the decoy wallet. `true` = wipe-on-duress. Only meaningful
/// when a duress PIN was set; the caller persists the choice (default =
/// decoy) before provisioning.
#[cfg(any(feature = "duress-pin", feature = "duress-ui-test"))]
pub fn choose_duress_wipe_mode() -> bool {
    matches!(yes_no("Wipe on duress?"), Some(true))
}

// ---------------------------------------------------------------------------
// 2. Show 24-word mnemonic across pages
// ---------------------------------------------------------------------------

/// Words per page on the 16x4 OLED. Row 0 is the title; rows 1-3 hold three
/// words → 24 / 3 = 8 pages.
const WORDS_PER_PAGE: usize = 3;
const TOTAL_PAGES: usize = WORD_COUNT / WORDS_PER_PAGE; // 8

/// F-24 stage E (sub-channel 4) — decoy frame configuration.
///
/// Number of valid-but-fake BIP-39 mnemonics interleaved with the real
/// one during seed display. Each decoy is generated from independent
/// `rng_strong::fill` entropy at wizard entry and zeroized on exit.
const N_DECOYS: usize = 4;

/// How long the real mnemonic frame is held on screen before yielding
/// to a decoy frame. The 5:1 (200 ms:40 ms) cadence was the original
/// Trezor-doc-referenced design.
///
/// **Bench-validated 2026-05-19 on SSD1306 OLED + I²C @ 400 kHz: the
/// defense does NOT work** on this display class. OLED pixels are
/// bistable (hold state until repainted), so a 40 ms decoy hold is
/// fully visible to the user — the wizard's read-the-seed UX breaks.
/// Bumping REAL_FRAME_HOLD_MS to 2000 didn't help: the user still
/// sees decoys as content changes, not subliminal flickers.
///
/// **Expected to work on slow-response LCDs** (e.g., ZT165M017AT TFT
/// with NV3007 driver, Tr+Tf typ 35 ms max 40 ms). On those displays
/// the *pixel response time itself* is the persistence-of-vision
/// mechanism — a decoy painted then immediately overwritten by real
/// never reaches full transition. Re-test the cadence (probably
/// REAL=200 ms, DECOY=5-10 ms) once the new hardware is wired.
const REAL_FRAME_HOLD_MS: u32 = 200;

/// How long each decoy frame is held. Cycles through `[decoy_0 ..
/// decoy_{N_DECOYS-1}]` round-robin on consecutive decoy cycles.
const DECOY_FRAME_HOLD_MS: u32 = 40;

/// Display the 24 words paginated. The user pages forward with right, back
/// with left, confirms with long-Right (only valid on the last page so the
/// user cannot dismiss the screen without seeing every word), or cancels
/// with long-Left.
pub fn show_mnemonic(m: &Mnemonic) -> WizardResult {
    // Warn the user before showing the secret.
    show_status("Write 24 words", "L=cancel R=show");
    let mut idle = || timeout::is_idle();
    let event = match input().wait_button(&mut idle) {
        Some(ev) => ev,
        None => return WizardResult::IdleWipe,
    };
    // A button event IS real user activity — reset the timer (see the
    // X17-UI3 policy note at the top of this file). This covers the
    // R=show press that the deleted step-entry resets in
    // `show_mnemonic_simple` / `show_mnemonic_with_decoys` used to proxy.
    timeout::reset_activity();
    match event {
        (Button::Right, _) => {}
        (Button::Left, _) => return WizardResult::Cancelled,
    }

    // Decoy frames are gated on `decoy-frames` (off by default).
    // OLED displays are bistable — pixels hold state between paints,
    // so a 40 ms decoy frame is fully visible to the user; the
    // wizard's read-the-seed UX breaks at any decoy hold above the
    // OLED's render time (~36 ms over I²C @ 400 kHz). On a slow-
    // response LCD (Tr+Tf > decoy-hold), decoy pixels never fully
    // appear before being overwritten by the next real frame; turn
    // this feature on after bench-validating via `decoy-flicker-test`
    // on the target display. See `tools/sca/README.md §F-24 stage E
    // sub-channel 4` for the trade-off analysis.
    #[cfg(feature = "decoy-frames")]
    {
        show_mnemonic_with_decoys(m)
    }
    #[cfg(not(feature = "decoy-frames"))]
    {
        show_mnemonic_simple(m)
    }
}

#[cfg(not(feature = "decoy-frames"))]
fn show_mnemonic_simple(m: &Mnemonic) -> WizardResult {
    let mut page: usize = 0;
    let mut seen_last = false;
    // The pixel grid holds eight words a page, the 16×4 page three; the
    // paging is fixed for the whole walk (see `mnemonic_paging`).
    let (total_pages, per_page) = mnemonic_paging();

    loop {
        if per_page == WORDS_PER_PAGE {
            render_mnemonic_page(m, page);
        } else {
            #[cfg(feature = "ui-px")]
            if !px_mnemonic_page(m, page) {
                // The atlas stopped verifying mid-walk: never fall back to
                // a paging that would skip words — cancel, the wizard
                // retries on the 16×4 pages.
                return WizardResult::Cancelled;
            }
        }
        if page == total_pages - 1 {
            seen_last = true;
        }

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return WizardResult::IdleWipe,
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                if page + 1 < total_pages {
                    page += 1;
                }
            }
            (Button::Left, Press::Short) => {
                if page > 0 {
                    page -= 1;
                }
            }
            (Button::Right, Press::Long) => {
                if seen_last {
                    // Wipe display before returning so the words don't linger.
                    show_status("Words shown", "");
                    return WizardResult::Confirmed;
                }
                // Otherwise treat long-Right as "next page" hint.
                if page + 1 < total_pages {
                    page += 1;
                }
            }
            (Button::Left, Press::Long) => return WizardResult::Cancelled,
        }
    }
}

#[cfg(feature = "decoy-frames")]
fn show_mnemonic_with_decoys(m: &Mnemonic) -> WizardResult {
    // F-24 stage E (sub-channel 4) — generate N_DECOYS valid BIP-39
    // mnemonics. Each is built from independent rng_strong entropy and
    // interleaved with the real mnemonic during display
    // (`show_mnemonic_page_with_decoys`). Mnemonic's Drop impl zeroizes
    // `indices` so the decoys are wiped when this function returns.
    let mut decoy_entropy = [[0u8; 32]; N_DECOYS];
    for i in 0..N_DECOYS {
        if crate::rng_strong::fill(&mut decoy_entropy[i]).is_err() {
            // 3-source XOR'd TRNG fault — extremely rare in production.
            // Surface to user as "RNG failed, retry" via the wizard
            // outer loop's `Cancelled` retry path; the alternative
            // (silently degrading to no-decoys) hides a real fault.
            #[cfg(feature = "debug-log")]
            secure_log!("[wizard] decoy entropy gen FAILED at idx {}", i);
            for e in decoy_entropy.iter_mut() {
                e.zeroize();
            }
            show_status("RNG failed", "retry...");
            return WizardResult::Cancelled;
        }
    }
    let decoys: [Mnemonic; N_DECOYS] = [
        Mnemonic::from_entropy(&decoy_entropy[0]),
        Mnemonic::from_entropy(&decoy_entropy[1]),
        Mnemonic::from_entropy(&decoy_entropy[2]),
        Mnemonic::from_entropy(&decoy_entropy[3]),
    ];
    for e in decoy_entropy.iter_mut() {
        e.zeroize();
    }

    let mut page: usize = 0;
    let mut seen_last = false;

    loop {
        let event = match show_mnemonic_page_with_decoys(m, &decoys, page) {
            Some(ev) => ev,
            None => return WizardResult::IdleWipe,
        };
        if page == TOTAL_PAGES - 1 {
            seen_last = true;
        }
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                if page + 1 < TOTAL_PAGES {
                    page += 1;
                }
            }
            (Button::Left, Press::Short) => {
                if page > 0 {
                    page -= 1;
                }
            }
            (Button::Right, Press::Long) => {
                if seen_last {
                    // Wipe display before returning so the words don't linger.
                    show_status("Words shown", "");
                    return WizardResult::Confirmed;
                }
                // Otherwise treat long-Right as "next page" hint.
                if page + 1 < TOTAL_PAGES {
                    page += 1;
                }
            }
            (Button::Left, Press::Long) => return WizardResult::Cancelled,
        }
    }
    // `decoys` drops here; each Mnemonic's Drop impl zeroizes its
    // `indices` array, so the decoy values do not linger on the stack.
}

/// F-24 stage E (sub-channel 4) frame loop.
///
/// Renders the real mnemonic for [`REAL_FRAME_HOLD_MS`], then one decoy
/// frame for [`DECOY_FRAME_HOLD_MS`], cycling decoys round-robin.
/// Returns the first button event, or `None` on activity-timeout idle.
///
/// The 5:1 time ratio means the *bus signature* an attacker measures
/// is the time-weighted average across N+1 valid mnemonics — the real
/// content is not distinguishable from the decoys without independent
/// ground-truth on which frame is which. The user reads the real one
/// because it dominates persistence-of-vision (5/6 of the on-time).
#[cfg(feature = "decoy-frames")]
fn show_mnemonic_page_with_decoys(
    real: &Mnemonic,
    decoys: &[Mnemonic; N_DECOYS],
    page: usize,
) -> Option<(Button, Press)> {
    let mut frame_seq: u32 = 0;
    loop {
        let is_real = (frame_seq & 1) == 0;
        let hold_ms = if is_real {
            REAL_FRAME_HOLD_MS
        } else {
            DECOY_FRAME_HOLD_MS
        };
        let m_to_show: &Mnemonic = if is_real {
            real
        } else {
            &decoys[(frame_seq >> 1) as usize % N_DECOYS]
        };

        render_mnemonic_page(m_to_show, page);

        // Build a deadline-vs-idle closure. `wait_button` polls this
        // ~125 Hz; returning true ends the wait. We distinguish
        // "frame elapsed" from "user idle" *after* the wait returns
        // None.
        //
        // Wrapping arithmetic: `timeout::now()` wraps every ~49 days;
        // hold_ms is well under that, so a wrap inside this closure is
        // impossible in practice. The `wrapping_sub` comparison works
        // even across the once-per-49-days boundary anyway.
        let deadline = timeout::now().wrapping_add(hold_ms);
        let mut frame_or_idle = || {
            timeout::is_idle()
                || timeout::now().wrapping_sub(deadline) < 0x8000_0000
        };
        match input().wait_button(&mut frame_or_idle) {
            Some(ev) => return Some(ev),
            None => {
                if timeout::is_idle() {
                    return None;
                }
                // Frame deadline expired; advance to next frame.
            }
        }
        frame_seq = frame_seq.wrapping_add(1);
    }
}

fn render_mnemonic_page(m: &Mnemonic, page: usize) {
    let d = display();
    d.clear();

    // Title row, e.g. "Phrase 1/8"
    let mut title = [b' '; DISPLAY_COLS];
    let label = b"Phrase ";
    title[1..1 + label.len()].copy_from_slice(label);
    let p1 = (page + 1) as u8;
    title[8] = b'0' + p1;
    title[9] = b'/';
    title[10] = b'0' + TOTAL_PAGES as u8;
    d.draw_line(0, super::ascii_str(&title));

    // Three word rows: "12 abandon". Use the constant-time `word_bytes`
    // API (F-24 stage A-C): no load address depends on the secret
    // `indices[word_idx]`.
    //
    // Stash the rendered byte-rows on the stack so `flush_with_secret_rows`
    // can paint them via the constant-time glyph blit (F-24 stage D),
    // bypassing embedded-graphics' index-keyed `MonoFont::glyph` lookup
    // for these specific rows.
    let mut secret_rows_storage = [[b' '; DISPLAY_COLS]; WORDS_PER_PAGE];
    let mut secret_row_count = 0usize;
    for slot in 0..WORDS_PER_PAGE {
        let word_idx = page * WORDS_PER_PAGE + slot;
        if word_idx >= WORD_COUNT {
            break;
        }
        let mut wb = [0u8; MAX_WORD_BYTES];
        let wlen = m.word_bytes(word_idx, &mut wb) as usize;
        let row = &mut secret_rows_storage[slot];
        // 1-based human numbering, right-aligned in 2 cols.
        let n = (word_idx + 1) as u8;
        if n >= 10 {
            row[0] = b'0' + (n / 10);
        }
        row[1] = b'0' + (n % 10);
        row[2] = b' ';
        let max = core::cmp::min(wlen, DISPLAY_COLS - 3);
        row[3..3 + max].copy_from_slice(&wb[..max]);
        secret_row_count += 1;
    }

    // Build the `(page, text)` slice for `flush_with_secret_rows`.
    // Up to WORDS_PER_PAGE entries; the page index is slot + 1 (row 0
    // is the title). We use a 3-deep fixed array + a runtime length.
    let secret_rows: [(usize, &[u8]); WORDS_PER_PAGE] = [
        (1, &secret_rows_storage[0]),
        (2, &secret_rows_storage[1]),
        (3, &secret_rows_storage[2]),
    ];
    d.flush_with_secret_rows(&secret_rows[..secret_row_count]);
}

// ---------------------------------------------------------------------------
// 3. Verify mnemonic by spot-checking 3 random words
// ---------------------------------------------------------------------------

/// Pick 3 distinct word indices from a host RNG byte source, prompt the user
/// to enter each via the same word-entry widget used by recovery, and only
/// confirm if all 3 match the mnemonic.
pub fn verify_mnemonic(m: &Mnemonic) -> WizardResult {
    let mut indices = [0u8; 3];
    pick_three_distinct(&mut indices);

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[wizard] verify_mnemonic: probes=[{}, {}, {}] (1-indexed on screen: {}, {}, {})",
        indices[0], indices[1], indices[2],
        indices[0] + 1, indices[1] + 1, indices[2] + 1,
    );

    for (step, &probe) in indices.iter().enumerate() {
        let title_buf = build_check_title(probe + 1);
        let title_s = super::ascii_str(&title_buf);

        #[cfg(feature = "debug-log")]
        {
            // CT lookup — keeps the leaky `Mnemonic::word()` pattern out
            // of the source (F-22 / F-27 hygiene; debug-log is gated
            // out of production but the leaky access pattern shouldn't
            // sit in a copy-paste-able location).
            let mut eb = [0u8; MAX_WORD_BYTES];
            let elen = m.word_bytes(probe as usize, &mut eb);
            secure_log!(
                "[wizard] verify step {}/3: asking for word #{} (expected \"{}\", BIP39 idx {})",
                step + 1, probe + 1,
                super::ascii_str(&eb[..elen as usize]),
                m.word_index(probe as usize),
            );
        }

        match enter_single_word(title_s) {
            EnterWordResult::Word(idx) => {
                let expected = m.word_index(probe as usize);
                if idx != expected {
                    #[cfg(feature = "debug-log")]
                    {
                        // CT lookup — debug-log compiles out of production,
                        // but keep the leaky `WORDLIST[idx]` pattern out of
                        // the source so it can't be copy-pasted into a
                        // secret-bearing context by accident.
                        let (gb, glen) = word_bytes_at(idx);
                        let mut eb = [0u8; MAX_WORD_BYTES];
                        let elen = m.word_bytes(probe as usize, &mut eb);
                        secure_log!(
                            "[wizard] verify step {}/3: MISMATCH — got BIP39 idx {} (\"{}\") but expected {} (\"{}\") at word #{}",
                            step + 1, idx,
                            super::ascii_str(&gb[..glen as usize]),
                            expected,
                            super::ascii_str(&eb[..elen as usize]),
                            probe + 1,
                        );
                    }
                    show_status("Wrong word", "retrying...");
                    return WizardResult::Cancelled;
                }
                #[cfg(feature = "debug-log")]
                secure_log!("[wizard] verify step {}/3: OK", step + 1);
            }
            EnterWordResult::Cancelled => {
                #[cfg(feature = "debug-log")]
                secure_log!(
                    "[wizard] verify step {}/3: enter_single_word cancelled (long-Left at position 0)",
                    step + 1,
                );
                return WizardResult::Cancelled;
            }
            EnterWordResult::IdleWipe => {
                #[cfg(feature = "debug-log")]
                secure_log!("[wizard] verify step {}/3: idle wipe", step + 1);
                return WizardResult::IdleWipe;
            }
        }
    }

    show_status("Backup OK", "");
    WizardResult::Confirmed
}

fn pick_three_distinct(out: &mut [u8; 3]) {
    let mut count = 0usize;
    while count < 3 {
        // Which 3 of the 24 words to re-verify is NON-SECRET (it leaks
        // nothing about the seed), so a transient STM32U5 TRNG seed/clock
        // error here must NOT `.expect()`-panic and halt the first-boot
        // wizard (bare `rng::byte()` does). Use the graceful non-secret
        // helper, with a fallback of `count` (0/1/2 — always < WORD_COUNT
        // and mutually distinct) so the loop still terminates with a valid
        // pick on a persistent fault. A FIXED fallback would make every
        // candidate identical and spin this loop forever — strictly worse
        // than the panic — so the fallback MUST vary with `count`.
        let candidate = rng::byte_nonsecret(count as u8) % (WORD_COUNT as u8);
        if out[..count].iter().any(|&c| c == candidate) {
            continue;
        }
        out[count] = candidate;
        count += 1;
    }
}

fn build_check_title(human_index: u8) -> [u8; DISPLAY_COLS] {
    // "Check word NN" rather than "Enter word NN" — makes clear the user
    // must type the specific numbered word, not just the next word in
    // sequence. Same 13-char footprint either way; both fit DISPLAY_COLS.
    let mut row = [b' '; DISPLAY_COLS];
    let prefix = b"Check word ";
    row[1..1 + prefix.len()].copy_from_slice(prefix);
    let mut p = 1 + prefix.len();
    if human_index >= 10 {
        row[p] = b'0' + (human_index / 10);
        p += 1;
    }
    row[p] = b'0' + (human_index % 10);
    row
}

// ---------------------------------------------------------------------------
// 4. Enter a full 24-word mnemonic
// ---------------------------------------------------------------------------

/// Read 24 words from the user and assemble a `Mnemonic`. Validates the
/// BIP-39 checksum at the end and reports `Cancelled` on a bad phrase so the
/// user can try again.
pub fn enter_mnemonic() -> Result<Mnemonic, WizardError> {
    let mut indices = [0u16; WORD_COUNT];
    let mut i = 0usize;

    while i < WORD_COUNT {
        let title = build_word_progress_title(i + 1);
        let title_s = super::ascii_str(&title);

        match enter_single_word(title_s) {
            EnterWordResult::Word(idx) => {
                indices[i] = idx;
                i += 1;
            }
            EnterWordResult::Cancelled => {
                // Long-Left at letter position 0 backs up one word; otherwise
                // cancels the whole flow. enter_single_word maps both to
                // Cancelled, so the policy here is "back up unless we're at
                // word 0, in which case bail entirely".
                if i == 0 {
                    return Err(WizardError::Cancelled);
                }
                i -= 1;
                indices[i] = 0;
            }
            EnterWordResult::IdleWipe => return Err(WizardError::IdleWipe),
        }
    }

    match Mnemonic::from_indices(indices) {
        Ok(m) => {
            indices.zeroize();
            Ok(m)
        }
        Err(_) => {
            indices.zeroize();
            show_status("Bad checksum", "retry...");
            Err(WizardError::Cancelled)
        }
    }
}

fn build_word_progress_title(human_index: usize) -> [u8; DISPLAY_COLS] {
    let mut row = [b' '; DISPLAY_COLS];
    let prefix = b"Word ";
    row[1..1 + prefix.len()].copy_from_slice(prefix);
    let mut p = 1 + prefix.len();
    if human_index >= 10 {
        row[p] = b'0' + (human_index / 10) as u8;
        p += 1;
    }
    row[p] = b'0' + (human_index % 10) as u8;
    p += 1;
    let suffix = b" of 24";
    row[p..p + suffix.len()].copy_from_slice(suffix);
    row
}

// ---------------------------------------------------------------------------
// Single-word entry: scroll letters, narrow by 4-letter prefix
// ---------------------------------------------------------------------------

enum EnterWordResult {
    Word(u16),
    Cancelled,
    IdleWipe,
}

const MAX_LETTERS: usize = 4;

fn enter_single_word(title: &str) -> EnterWordResult {
    let mut buf = [b'a'; MAX_LETTERS];
    let mut len: usize = 0;

    loop {
        // Compute current prefix lookup. If we have at least one letter
        // committed, look up. If zero letters, treat as "Multiple" over the
        // entire wordlist.
        render_letter_screen(title, &buf, len);

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return EnterWordResult::IdleWipe,
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                // Scroll current letter forward.
                let cur = if len < MAX_LETTERS { buf[len] } else { buf[MAX_LETTERS - 1] };
                let next = if cur == b'z' { b'a' } else { cur + 1 };
                if len < MAX_LETTERS {
                    buf[len] = next;
                } else {
                    buf[MAX_LETTERS - 1] = next;
                }
            }
            (Button::Left, Press::Short) => {
                let cur = if len < MAX_LETTERS { buf[len] } else { buf[MAX_LETTERS - 1] };
                let prev = if cur == b'a' { b'z' } else { cur - 1 };
                if len < MAX_LETTERS {
                    buf[len] = prev;
                } else {
                    buf[MAX_LETTERS - 1] = prev;
                }
            }
            (Button::Right, Press::Long) => {
                // Commit current letter and look up.
                if len < MAX_LETTERS {
                    len += 1;
                }
                let prefix = super::ascii_str(&buf[..len]);
                match lookup_prefix(prefix) {
                    PrefixLookup::Unique(idx) => return EnterWordResult::Word(idx),
                    PrefixLookup::None => {
                        // Bad prefix — back up and let user retry.
                        show_status("No match", "back up...");
                        if len > 0 {
                            len -= 1;
                        }
                    }
                    PrefixLookup::Multiple { start, end } => {
                        // If we've typed all 4 letters and still have multiple,
                        // BIP-39 spec says this can't happen — but we also enter
                        // candidate mode here for short words like "act" whose
                        // exact 3-letter prefix matches multiple longer words.
                        if len >= MAX_LETTERS || prefix_is_exact_word(prefix) {
                            match pick_candidate(title, start, end) {
                                CandidateResult::Picked(i) => {
                                    return EnterWordResult::Word(i);
                                }
                                CandidateResult::Back => {
                                    // Stay in letter mode at current len.
                                    continue;
                                }
                                CandidateResult::IdleWipe => {
                                    return EnterWordResult::IdleWipe;
                                }
                            }
                        }
                        // else: keep typing letters
                    }
                }
            }
            (Button::Left, Press::Long) => {
                // Back up one letter; if already at 0, cancel.
                if len == 0 {
                    return EnterWordResult::Cancelled;
                }
                len -= 1;
                buf[len] = b'a';
            }
        }
    }
}

fn prefix_is_exact_word(p: &str) -> bool {
    // F-27 fix: the previous implementation did `WORDLIST.binary_search_by`
    // — visited midpoint addresses leaked the typed prefix in the
    // recovery candidate-pick gate. Route through bip39's constant-time
    // primitive instead.
    is_exact_wordlist_entry(p.as_bytes())
}

fn render_letter_screen(title: &str, buf: &[u8; MAX_LETTERS], len: usize) {
    // Port step 4: the entry row (committed letters in white rings, the
    // dialed one in the active ring) — the same letters the page shows.
    #[cfg(feature = "ui-px")]
    if super::px::screens::show(&super::px::status_map::letter_row(title.as_bytes(), buf, len)) {
        return;
    }
    let d = display();
    d.clear();
    d.draw_line(0, title);

    // Row 1: letters with cursor mark on the active position.
    // Layout: " a _ _ _ "
    let mut row1 = [b' '; DISPLAY_COLS];
    for i in 0..MAX_LETTERS {
        let col = 1 + i * 2;
        if col >= DISPLAY_COLS {
            break;
        }
        if i < len {
            row1[col] = buf[i];
        } else if i == len {
            row1[col] = buf[i]; // current letter being scrolled
        } else {
            row1[col] = b'_';
        }
    }
    d.draw_line(1, super::ascii_str(&row1));

    // Row 2: cursor caret
    let mut row2 = [b' '; DISPLAY_COLS];
    let cursor_col = 1 + len.min(MAX_LETTERS - 1) * 2;
    if cursor_col < DISPLAY_COLS {
        row2[cursor_col] = b'^';
    }
    d.draw_line(2, super::ascii_str(&row2));

    d.draw_line(3, "L/R=ltr LR=ok");
    d.flush();
}

// ---------------------------------------------------------------------------
// Candidate-pick mode (when prefix narrowing leaves multiple matches)
// ---------------------------------------------------------------------------

enum CandidateResult {
    Picked(u16),
    Back,
    IdleWipe,
}

fn pick_candidate(title: &str, start: usize, end: usize) -> CandidateResult {
    let mut cur = start;

    loop {
        render_candidate_screen(title, start, end, cur);

        let mut idle = || timeout::is_idle();
        let event = match input().wait_button(&mut idle) {
            Some(ev) => ev,
            None => return CandidateResult::IdleWipe,
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                cur = if cur + 1 >= end { start } else { cur + 1 };
            }
            (Button::Left, Press::Short) => {
                cur = if cur == start { end - 1 } else { cur - 1 };
            }
            (Button::Right, Press::Long) => {
                return CandidateResult::Picked(cur as u16);
            }
            (Button::Left, Press::Long) => {
                return CandidateResult::Back;
            }
        }
    }
}

fn render_candidate_screen(title: &str, start: usize, end: usize, cur: usize) {
    // Port step 4: the three candidates on the grid's rows, the middle one
    // the cursor — fetched with the constant-time `word_bytes_at` and drawn
    // by the constant-time run, like the page's secret rows.
    #[cfg(feature = "ui-px")]
    {
        let mut cells = [[0u8; MAX_WORD_BYTES]; 3];
        for (slot, cell) in cells.iter_mut().enumerate() {
            let idx = wrap_in_range(start, end, cur, slot as isize - 1);
            let (wb, _) = word_bytes_at(idx as u16);
            cell.copy_from_slice(&wb[..MAX_WORD_BYTES]);
        }
        let secret: [(usize, &[u8]); 3] = [(0, &cells[0][..]), (1, &cells[1][..]), (2, &cells[2][..])];
        let ok = super::px::screens::show_with(&super::px::status_map::candidate_list(title.as_bytes()), &secret);
        for c in cells.iter_mut() {
            c.zeroize();
        }
        if ok {
            return;
        }
    }
    let d = display();
    d.clear();
    d.draw_line(0, title);
    d.draw_line(3, "L/R=scrl LR=ok");

    // F-27 fix: previously read `WORDLIST[idx].as_bytes()` for each
    // visible candidate (3 indexed loads addressed by `idx`, which
    // derives from the typed prefix) AND rendered them through
    // `d.draw_line` whose embedded-graphics font path is itself a
    // non-constant-time glyph lookup (F-24 stage C). Both halves of
    // the chain now route through bip39's `word_bytes_at` (constant-
    // time wordlist load) + `flush_with_secret_rows` (constant-time
    // glyph blit, F-24 stage D primitive).
    const SLOTS: usize = DISPLAY_ROWS - 2;
    let mut secret_rows_storage = [[b' '; DISPLAY_COLS]; SLOTS];
    for slot in 0..SLOTS {
        // slot 0 → cur-1, slot 1 → cur, slot 2 → cur+1 (with wraparound).
        let offset = slot as isize - 1;
        let idx = wrap_in_range(start, end, cur, offset);
        let (wb, wlen) = word_bytes_at(idx as u16);
        let row = &mut secret_rows_storage[slot];
        row[0] = if idx == cur { b'>' } else { b' ' };
        let max = core::cmp::min(wlen as usize, DISPLAY_COLS - 2);
        row[2..2 + max].copy_from_slice(&wb[..max]);
    }
    let secret_rows: [(usize, &[u8]); SLOTS] = [
        (1, &secret_rows_storage[0]),
        (2, &secret_rows_storage[1]),
    ];
    d.flush_with_secret_rows(&secret_rows[..]);
}

fn wrap_in_range(start: usize, end: usize, cur: usize, offset: isize) -> usize {
    let len = (end - start) as isize;
    let pos = (cur as isize - start as isize + offset).rem_euclid(len);
    start + pos as usize
}

// ---------------------------------------------------------------------------
// F-24 stage E Phase 1 — hardware flicker validation harness
// ---------------------------------------------------------------------------

/// Standalone bench loop for visual validation of the decoy-frame
/// cadence. No wizard, no buttons, no SE access — just a B-U585I +
/// SSD1306 OLED rendering the 5:1 real:decoy interleave forever so a
/// bench user can stare at the screen and report whether the flicker
/// is readable.
///
/// Page 0 only. Cycles `decoy[0..N_DECOYS]` round-robin between every
/// real frame. Fixed test entropy (no RNG dependency) so the screen
/// content is deterministic across runs.
#[cfg(feature = "decoy-flicker-test")]
pub fn decoy_flicker_test_loop() -> ! {
    use sphincs_tz_bip39::Mnemonic;

    // Banner — title row reads "FLICKER TEST" so an observer can
    // identify the build at a glance. This row is PUBLIC (rendered
    // every frame, content-independent of the secret); only rows 1-3
    // get the CT-blit treatment via render_mnemonic_page.
    let real = Mnemonic::from_entropy(&[0xAAu8; 32]);
    let decoys: [Mnemonic; N_DECOYS] = [
        Mnemonic::from_entropy(&[0x11u8; 32]),
        Mnemonic::from_entropy(&[0x22u8; 32]),
        Mnemonic::from_entropy(&[0x33u8; 32]),
        Mnemonic::from_entropy(&[0x44u8; 32]),
    ];

    #[cfg(feature = "debug-log")]
    secure_log!(
        "[S] decoy-flicker-test: sweeping DECOY_HOLD (real hold = {} ms)",
        REAL_FRAME_HOLD_MS
    );

    // Page 0 = words 1-3 of the test mnemonic, real interleaved with decoys.
    // SWEEP the decoy-frame hold (~4-5 s per value) so a bench observer can find
    // the threshold where decoys stop being subliminal. On a bistable OLED this
    // fails at EVERY hold (each decoy is a fully-visible content change — the
    // documented 2026-05-19 result). On the slow-response NV3007 LCD (Tr+Tf
    // ~35 ms) decoys SHOULD become subliminal once their total on-time (the
    // ~15 ms page repaint PLUS this hold) stays under the pixel response time —
    // the partially-transitioned decoy is overwritten by the next real frame
    // before it fully appears, yet the SPI bus still carries it (the defense).
    // Note the repaint itself is ~15 ms here, so even DECOY_HOLD=0 leaves a
    // ~15 ms decoy on-time floor; that is the interesting low end.
    const DECOY_HOLD_SWEEP: [u32; 6] = [40, 25, 15, 8, 3, 0];
    let mut hold_idx: usize = 0;
    let mut decoy_idx: usize = 0;
    loop {
        let decoy_hold = DECOY_HOLD_SWEEP[hold_idx % DECOY_HOLD_SWEEP.len()];
        #[cfg(feature = "debug-log")]
        secure_log!("[S] decoy-flicker: DECOY_HOLD = {} ms", decoy_hold);
        let mut cycles = 0u32;
        while cycles < 18 {
            render_mnemonic_page(&real, 0);
            cortex_m::asm::delay(160_000 * REAL_FRAME_HOLD_MS);
            render_mnemonic_page(&decoys[decoy_idx], 0);
            if decoy_hold > 0 {
                cortex_m::asm::delay(160_000 * decoy_hold);
            }
            decoy_idx = (decoy_idx + 1) % N_DECOYS;
            cycles += 1;
        }
        hold_idx += 1;
    }
}
