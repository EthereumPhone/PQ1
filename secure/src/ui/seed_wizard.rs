//! First-boot setup wizard (the flow is `main::run_first_boot_wizard`):
//!
//! 1. `setup_intro` — welcome, the buttons, then create or import.
//! 2. `choose_pin` — what the PIN is for, then SET PIN / REPEAT PIN.
//! 3. `create_backup` — WRITE DOWN 24 WORDS, the words (`show_mnemonic`),
//!    CONFIRM TO VERIFY WORDS, then three typed checks (`verify_mnemonic`).
//! 4. `import_wallet` — ENTER YOUR 24 WORDS, then `enter_mnemonic`: 24 words
//!    via letter-scroll + 4-letter prefix narrowing (also used by the
//!    checks).
//!
//! Setup has NO inactivity timeout (owner decision 2026-10-15): nothing is
//! provisioned until the end, and a timeout used to restart setup and throw
//! away a seed the user had already written down. A seed page hides its
//! words after five minutes without a press instead (`WORDS_HIDE_MS`).
//!
//! The screens are `setup_screens`; they are walked with the signing grammar
//! (`pager`, the pixel UI's `run_pager`):
//!
//! | Action        | Effect                                           |
//! |---------------|--------------------------------------------------|
//! | tap right     | next screen (from the last: on to the next step) |
//! | tap left      | previous screen (from the first: back a step)    |
//! | both, click   | select, on a screen that asks (CREATE NEW WALLET?) |
//!
//! The PIN and word entry rows keep their own grammar (`pin_entry.rs`,
//! `enter_single_word`): short presses scroll, long-Right accepts, long-Left
//! deletes or goes back.
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

use super::setup_screens;
use super::{display, input, show_status, Button, PagerOut, Press, DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_ui_px::Screen;
use sphincs_tz_shared::PIN_LEN;
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

/// The chooser ask (`status_map::choice`), shown and ANIMATED for the whole
/// input wait (#783). Only the duress yes / no still uses it; the setup
/// choice is a page of the setup pager ([`pager`]).
///
/// Returns `None` when the pixel UI could not paint it, and the caller falls
/// back to its 16x4 page plus an ordinary `wait_button` — the same contract
/// the old `px_choice` had, except the wait now belongs to the painter.
///
/// It has to be one call, not paint-then-wait. The chooser ask is a
/// `Kind::Hero`, the one non-dialog screen whose `Anim::step` never returns
/// false (`scene::plays_forever`), so "play it until it rests" cannot
/// terminate: `play_screen`'s 3 s cap was its NORMAL exit and it fired 40%
/// into a 5 s sweep, stranding the disc off-centre. And because the old
/// paint loop sampled no input at all, a tap inside those 3 s was dropped.
/// Animating from inside the input wait removes both.
#[cfg(all(feature = "ui-px", any(feature = "duress-pin", feature = "duress-ui-test")))]
fn px_choice_wait(
    title: &[u8],
    option: &[u8],
    idle: &mut dyn FnMut() -> bool,
) -> Option<Option<(Button, Press)>> {
    match super::px::screens::show_waiting(&super::px::status_map::choice(title, option), idle) {
        super::px::screens::Waited::NoAtlas => None,
        super::px::screens::Waited::Event(ev) => Some(ev),
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
pub enum WizardResult {
    Confirmed,
    Cancelled,
    /// Only the `decoy-frames` seed walk still times out; every other setup
    /// step holds for a press instead.
    #[cfg_attr(not(feature = "decoy-frames"), allow(dead_code))]
    IdleWipe,
}

#[derive(Debug)]
pub enum WizardError {
    Cancelled,
}

// ---------------------------------------------------------------------------
// 1. The setup flow's own screens (owner decisions 2026-10-15)
// ---------------------------------------------------------------------------
//
// Welcome -> buttons -> create / import -> PIN help -> SET / REPEAT PIN ->
// (create) RECOVERY .. SAFETY -> the words -> CONFIRM TO VERIFY WORDS -> three
// typed checks, or (import) ENTER YOUR 24 WORDS -> the words typed in. The
// screens wear the setup family's look (the 3 x 3 dots on the white disc,
// `flows/setup` in the design) and are walked with the signing grammar:
// tap right = next, tap left = back, the two-button click selects on a
// screen that asks. Setup has no inactivity timeout: there is no wallet to
// protect yet, and the old timeout restarted setup and threw away a seed the
// user may already have written down.

/// What the user chose on the setup intro.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SetupChoice {
    Create,
    Import,
}

/// Walk `screens` (see [`PagerOut`]): the pixel pager when the panel can
/// draw it, otherwise each screen as a 16x4 page with the legacy buttons —
/// short right / left move, the confirm chord selects a screen that asks.
/// (The legacy driver cannot tell the chord from a right hold, so on that
/// fallback a right hold selects too.)
fn pager(screens: &[Screen], start: usize, may_back: bool, may_forward: bool) -> PagerOut {
    #[cfg(feature = "ui-px")]
    if let Some(out) = super::px::screens::pager(screens, start, may_back, may_forward) {
        return out;
    }
    let n = screens.len();
    let mut i = start.min(n.saturating_sub(1));
    loop {
        paint_fallback(&screens[i]);
        // No idle check: setup has no inactivity timeout.
        let mut never = || false;
        let Some(event) = input().wait_button(&mut never) else {
            continue;
        };
        timeout::reset_activity();
        match event {
            (Button::Right, Press::Short) => {
                if i + 1 < n {
                    i += 1;
                } else if may_forward {
                    return PagerOut::Forward;
                }
            }
            (Button::Left, Press::Short) => {
                if i > 0 {
                    i -= 1;
                } else if may_back {
                    return PagerOut::Back;
                }
            }
            (Button::Right, Press::Long) => {
                if screens[i].confirmable() {
                    return PagerOut::Selected(i);
                }
            }
            (Button::Left, Press::Long) => {}
        }
    }
}

/// A setup screen on the fallback: through the text presenter when the pixel
/// UI is the text one, else as a 16x4 page (caption or label, then lines).
fn paint_fallback(s: &Screen) {
    #[cfg(all(feature = "ui-px", not(feature = "ui-lcd")))]
    {
        let _ = super::px::screens::show(s);
    }
    #[cfg(not(all(feature = "ui-px", not(feature = "ui-lcd"))))]
    {
        let d = display();
        d.clear();
        let head = if s.caption().is_empty() { s.label() } else { s.caption() };
        // The caption (or label), then the lines. A text longer than a row
        // (CREATE NEW WALLET? is 18) breaks at its last space that fits and
        // carries on to the next row, rather than losing its end.
        let mut rows: [&[u8]; 2 * (1 + pqsigner_ui_px::screen::LINES_PER_PAGE)] = [&[]; 8];
        let mut n = 0usize;
        for k in 0..=s.nlines(0) {
            let text = if k == 0 { head } else { s.line(0, k - 1).map_or(&[][..], |(_, t)| t) };
            let (first, rest) = if text.len() > DISPLAY_COLS {
                let cut = text[..=DISPLAY_COLS].iter().rposition(|&b| b == b' ').unwrap_or(DISPLAY_COLS);
                (&text[..cut], text[cut..].trim_ascii_start())
            } else {
                (text, &[][..])
            };
            for part in [first, rest] {
                if !part.is_empty() && n < rows.len() {
                    rows[n] = part;
                    n += 1;
                }
            }
        }
        if n <= DISPLAY_ROWS || s.nlines(0) == 0 {
            for (r, text) in rows[..n].iter().take(DISPLAY_ROWS).enumerate() {
                draw_row(d, r, text);
            }
        } else {
            // Too long line by line: the label gives way (it names the
            // screen, the lines are what it says) and the lines re-flow as
            // one paragraph (RECOVERY's "Your PQ1 will now / generate a
            // 24-word / recovery phrase.") instead of losing their end.
            let mut flow = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
            let (mut r, mut c) = (0usize, 0usize);
            for k in 0..s.nlines(0) {
                let line = s.line(0, k).map_or(&[][..], |(_, t)| t);
                for word in line.split(|&b| b == b' ').filter(|w| !w.is_empty()) {
                    let word = &word[..word.len().min(DISPLAY_COLS)];
                    if c > 0 && c + 1 + word.len() > DISPLAY_COLS {
                        r += 1;
                        c = 0;
                    }
                    if r >= DISPLAY_ROWS {
                        break;
                    }
                    if c > 0 {
                        c += 1;
                    }
                    flow[r][c..c + word.len()].copy_from_slice(word);
                    c += word.len();
                }
            }
            for (r, row) in flow.iter().enumerate() {
                draw_row(d, r, row);
            }
        }
        d.flush();
    }
}

/// One 16x4 row, cut at the row's width.
#[cfg(not(all(feature = "ui-px", not(feature = "ui-lcd"))))]
fn draw_row(d: &mut super::Display, r: usize, text: &[u8]) {
    let mut row = [b' '; DISPLAY_COLS];
    let k = text.len().min(DISPLAY_COLS);
    row[..k].copy_from_slice(&text[..k]);
    d.draw_line(r, super::ascii_str(&row));
}

/// Paint `s` over the whole panel, then wait for any button with no idle
/// check and count the press as activity. A real press both ends the wait
/// and is the only thing allowed to reset the timer (#426).
fn hold(s: &Screen) {
    paint_still(s);
    let mut never = || false;
    while input().wait_button(&mut never).is_none() {}
    timeout::reset_activity();
}

/// A screen painted once, at rest (the pixel UI's `show`, else the 16x4 page).
fn paint_still(s: &Screen) {
    #[cfg(feature = "ui-px")]
    if super::px::screens::show(s) {
        return;
    }
    paint_fallback(s);
}

/// The one way back from an entry row that reported idle: PAUSED until a
/// press. Re-entering the row straight away would find the timer still
/// expired and return at once, forever (the EVT loop of 2026-10-15). And the
/// row must leave the glass first: it may show a typed prefix of a seed word,
/// a candidate list or an imported word, and nothing else will repaint it.
fn wait_for_press() {
    hold(&setup_screens::paused());
}

/// The setup intro: welcome, the buttons, then create or import. Starts on
/// the welcome, or, when the user came back from a later step, on the
/// choice they had made.
pub fn setup_intro(back_to: Option<SetupChoice>) -> SetupChoice {
    let screens = setup_screens::intro();
    let mut start = match back_to {
        None => 0,
        Some(SetupChoice::Create) => setup_screens::CREATE,
        Some(SetupChoice::Import) => setup_screens::IMPORT,
    };
    loop {
        match pager(&screens, start, false, false) {
            PagerOut::Selected(setup_screens::CREATE) => return SetupChoice::Create,
            PagerOut::Selected(setup_screens::IMPORT) => return SetupChoice::Import,
            // The confirm page's confirm selects nothing: on to the choice.
            PagerOut::Selected(setup_screens::CONFIRM_HELP) => start = setup_screens::CREATE,
            PagerOut::Selected(i) => start = i,
            PagerOut::Forward | PagerOut::Back => {}
        }
    }
}

/// Choose the PIN: what it is for, then SET PIN and REPEAT PIN. A mismatch
/// shows PIN MISMATCH and asks for both again. `None` = the user went back
/// past the explanation (to create / import).
pub fn choose_pin() -> Option<[u8; PIN_LEN]> {
    use super::pin_entry::{enter_pin_with_confirm, PinEntryResult};
    let help = [setup_screens::pin_help()];
    loop {
        if pager(&help, 0, true, true) == PagerOut::Back {
            return None;
        }
        loop {
            match enter_pin_with_confirm() {
                PinEntryResult::Pin(p) => return Some(p),
                PinEntryResult::Mismatch => show_status("PIN mismatch", ""),
                // A left hold on the first digit: back to the explanation.
                PinEntryResult::Cancelled => break,
                // No timeout in setup: hold the row until a real press, then
                // ask again (never re-enter on an expired timer).
                PinEntryResult::IdleWipe => wait_for_press(),
            }
        }
    }
}

/// Create: the intro, the 24 words, CONFIRM TO VERIFY WORDS, then three typed
/// checks. Returns once the user has walked every page and passed the
/// checks; it never gives up on `m`, so the words the user wrote down stay
/// the words of this wallet.
pub fn create_backup(m: &Mnemonic) {
    let intro = setup_screens::backup_intro();
    let written = [setup_screens::written()];
    // Back from the first word page lands on the intro's last page.
    let mut intro_at = 0;
    'intro: loop {
        // Only a right tap off the last page leaves the intro: there is no
        // back (the words are already drawn) and nothing to select.
        while pager(&intro, intro_at, false, true) != PagerOut::Forward {}
        let mut start_last = false;
        loop {
            if show_mnemonic(m, start_last) != WizardResult::Confirmed {
                // A left tap on the first page: back to the intro.
                intro_at = intro.len() - 1;
                continue 'intro;
            }
            if pager(&written, 0, true, false) == PagerOut::Back {
                start_last = true;
                continue;
            }
            if verify_mnemonic(m) == WizardResult::Confirmed {
                return;
            }
            // Cancelled out of a check: back to the words, from the start.
            start_last = false;
        }
    }
}

/// Import: the intro, then the 24 words typed in. `None` = the user went
/// back past the intro (to create / import).
pub fn import_wallet() -> Option<Mnemonic> {
    let intro = [setup_screens::import_intro()];
    loop {
        if pager(&intro, 0, true, true) == PagerOut::Back {
            return None;
        }
        if let Ok(m) = enter_mnemonic() {
            return Some(m);
        }
    }
}

// ---------------------------------------------------------------------------
// §32 P4/P5 — duress (decoy) PIN setup dialogs
// ---------------------------------------------------------------------------

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
        let mut idle = || timeout::is_idle();

        #[cfg(feature = "ui-px")]
        let waited = px_choice_wait(title.as_bytes(), options[idx].as_bytes(), &mut idle);
        #[cfg(not(feature = "ui-px"))]
        let waited: Option<Option<(Button, Press)>> = None;

        let event = match waited {
            Some(Some(ev)) => ev,
            Some(None) => return None,
            None => {
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
                match input().wait_button(&mut idle) {
                    Some(ev) => ev,
                    None => return None,
                }
            }
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

/// Display the 24 words paginated (the setup intro has announced them).
/// Tap right pages forward and, from the last page, finishes; tap left pages
/// back and, from the first page, returns `Cancelled` (back to the intro).
/// The words cannot be finished without the last page having been shown.
/// `start_last` reopens on the last page (back from CONFIRM TO VERIFY WORDS).
pub fn show_mnemonic(m: &Mnemonic, start_last: bool) -> WizardResult {
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
        let _ = start_last;
        show_mnemonic_with_decoys(m)
    }
    #[cfg(not(feature = "decoy-frames"))]
    {
        show_mnemonic_simple(m, start_last)
    }
}

/// After this long on one seed page with no press, the words leave the glass
/// (HIDDEN; any press brings the same page back). Setup has no timeout, so
/// this is the only thing that stops a device left on a seed page from
/// showing the seed indefinitely (owner decision 2026-10-15).
#[cfg(not(feature = "decoy-frames"))]
const WORDS_HIDE_MS: u32 = 5 * 60 * 1000;

#[cfg(not(feature = "decoy-frames"))]
fn show_mnemonic_simple(m: &Mnemonic, start_last: bool) -> WizardResult {
    // The pixel grid holds eight words a page, the 16×4 page three; the
    // paging is fixed for the whole walk (see `mnemonic_paging`).
    let (total_pages, per_page) = mnemonic_paging();
    let mut page: usize = if start_last { total_pages - 1 } else { 0 };
    let mut seen_last = start_last;
    // Waiting here can last minutes (the user is writing): hold the
    // watchdog's trusted-UI wait for the whole walk.
    let _trusted_ui_wait = timeout::TrustedUiWaitGuard::enter();

    loop {
        if per_page == WORDS_PER_PAGE {
            render_mnemonic_page(m, page);
        } else {
            #[cfg(feature = "ui-px")]
            if !px_mnemonic_page(m, page) {
                // The atlas stopped verifying mid-walk: never fall back to
                // a paging that would skip words — back to the intro, which
                // retries on the 16×4 pages.
                return WizardResult::Cancelled;
            }
        }
        if page == total_pages - 1 {
            seen_last = true;
        }

        let shown_at = timeout::now();
        let mut idle = || timeout::now().wrapping_sub(shown_at) > WORDS_HIDE_MS;
        let Some(event) = input().wait_button(&mut idle) else {
            // Five minutes with no press: take the words off the glass.
            hide_words();
            continue;
        };
        timeout::reset_activity();

        match event {
            (Button::Right, Press::Short) => {
                if page + 1 < total_pages {
                    page += 1;
                } else if seen_last {
                    return WizardResult::Confirmed;
                }
            }
            (Button::Left, Press::Short) => {
                if page > 0 {
                    page -= 1;
                } else {
                    return WizardResult::Cancelled;
                }
            }
            // Holds (and the chord) are not gestures on a word page.
            (_, Press::Long) => {}
        }
    }
}

/// The words leave the glass: the HIDDEN screen until any press (which
/// redraws the same page). Painted over the whole panel, so no seed pixel
/// stays on it.
#[cfg(not(feature = "decoy-frames"))]
fn hide_words() {
    hold(&setup_screens::hidden());
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
        // Only the debug-log lines read `step`.
        #[cfg(not(feature = "debug-log"))]
        let _ = step;
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

        // One check, asked until it is answered right (or cancelled).
        loop {
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
                        // The design's headshake, then the SAME check again —
                        // never a new seed (owner report 2026-10-15: a failed
                        // check used to restart setup and make the written
                        // words useless).
                        show_status("Wrong word", "");
                        continue;
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
                    // No timeout in setup: keep the row, ask again after a press.
                    wait_for_press();
                    continue;
                }
            }
            break;
        }
    }

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
            // No timeout in setup: keep the words typed so far and ask for
            // this one again after a real press.
            EnterWordResult::IdleWipe => wait_for_press(),
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
    // The pixel row's input wait, one for the whole word: it keeps the row
    // drawing through presses (owner 2026-10-15).
    let mut px = PxLetterWait::new();

    loop {
        // Compute current prefix lookup. If we have at least one letter
        // committed, look up. If zero letters, treat as "Multiple" over the
        // entire wordlist.
        let mut idle = || timeout::is_idle();
        // The pixel row keeps drawing for the whole wait (its hint swaps);
        // `None` = it could not paint: the page, and a plain wait.
        let waited = match px_letter_wait(&mut px, title, &buf, len, &mut idle) {
            Some(waited) => waited,
            None => {
                render_letter_screen(title, &buf, len);
                input().wait_button(&mut idle)
            }
        };
        let event = match waited {
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

/// The pixel row's input wait for one word (nothing without the pixel UI).
#[cfg(feature = "ui-px")]
use super::px::screens::EntryWait as PxLetterWait;
#[cfg(not(feature = "ui-px"))]
struct PxLetterWait;
#[cfg(not(feature = "ui-px"))]
impl PxLetterWait {
    fn new() -> Self {
        Self
    }
}

/// Port step 4: the entry row (committed letters in white rings, the dialed
/// one in the active ring), the same letters the page shows, kept drawing
/// for the whole input wait so its hint can swap even while the user dials.
/// `None` when the pixel UI could not paint it: the caller paints the page
/// and waits itself.
#[cfg(feature = "ui-px")]
fn px_letter_wait(
    px: &mut PxLetterWait,
    title: &str,
    buf: &[u8; MAX_LETTERS],
    len: usize,
    idle: &mut dyn FnMut() -> bool,
) -> Option<Option<(Button, Press)>> {
    let row = super::px::status_map::letter_row(title.as_bytes(), buf, len);
    match px.wait(&row, idle) {
        super::px::screens::Waited::NoAtlas => None,
        super::px::screens::Waited::Event(ev) => Some(ev),
    }
}

#[cfg(not(feature = "ui-px"))]
fn px_letter_wait(
    _px: &mut PxLetterWait,
    _title: &str,
    _buf: &[u8; MAX_LETTERS],
    _len: usize,
    _idle: &mut dyn FnMut() -> bool,
) -> Option<Option<(Button, Press)>> {
    None
}

/// The 16x4 letter page (no pixel UI, or no verified atlas).
fn render_letter_screen(title: &str, buf: &[u8; MAX_LETTERS], len: usize) {
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
