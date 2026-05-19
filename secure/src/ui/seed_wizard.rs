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

use super::{display, input, show_status, Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::rng;
use crate::timeout;
use sphincs_tz_bip39::{
    is_exact_wordlist_entry, lookup_prefix, word_bytes_at, Mnemonic, PrefixLookup,
    MAX_WORD_BYTES, WORD_COUNT,
};
use zeroize::Zeroize;

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

    timeout::reset_activity();

    loop {
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
// 2. Show 24-word mnemonic across pages
// ---------------------------------------------------------------------------

/// Words per page on the 16x4 OLED. Row 0 is the title; rows 1-3 hold three
/// words → 24 / 3 = 8 pages.
const WORDS_PER_PAGE: usize = 3;
const TOTAL_PAGES: usize = WORD_COUNT / WORDS_PER_PAGE; // 8

/// Display the 24 words paginated. The user pages forward with right, back
/// with left, confirms with long-Right (only valid on the last page so the
/// user cannot dismiss the screen without seeing every word), or cancels
/// with long-Left.
pub fn show_mnemonic(m: &Mnemonic) -> WizardResult {
    // Warn the user before showing the secret.
    show_status("Write 24 words", "L=cancel R=show");
    let mut idle = || timeout::is_idle();
    match input().wait_button(&mut idle) {
        Some((Button::Right, _)) => {}
        Some((Button::Left, _)) => return WizardResult::Cancelled,
        None => return WizardResult::IdleWipe,
    }

    let mut page: usize = 0;
    let mut seen_last = false;
    timeout::reset_activity();

    loop {
        render_mnemonic_page(m, page);
        if page == TOTAL_PAGES - 1 {
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
        secure_log!(
            "[wizard] verify step {}/3: asking for word #{} (expected \"{}\", BIP39 idx {})",
            step + 1, probe + 1, m.word(probe as usize), m.word_index(probe as usize),
        );

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
        let candidate = rng::byte() % (WORD_COUNT as u8);
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
    timeout::reset_activity();

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
    timeout::reset_activity();

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
