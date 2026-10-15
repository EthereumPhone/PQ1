//! The two non-dialog screens that are rows of things: the **entry row**
//! (DESIGN.md § Components, PIN row — `pq1/procedural/pin_slots.py`) and the
//! numbered **words grid** (`pq1/layout.py` `_words_texts`).
//!
//! Both are pictures of a record: the firmware's own input loop
//! (`pin_entry.rs`, the seed wizard) decides what the row holds and repaints
//! it on every button event. The one thing that moves on its own is the
//! entry row's hint, which swaps between two messages ([`entry_hint`]); the
//! ring bounce of the design is demo pacing the device leaves out.

use crate::font::{Align, TextRun, TierId};
use crate::motion;
use crate::raster::{Frame, Item, Rgb, ShapeMode, Xform};
use crate::scene::{CENTER_X, CHEV_LEFT_X_Q8, CHEV_RIGHT_X_Q8, CHEV_Y, CIRCLE_CY};
use crate::screen::Screen;

/// Ring geometry (the design's PIN row).
pub const RING_R: i32 = 21;
pub const RING_PITCH: i32 = 50;
/// Idle / entered stroke 2 px, the active ring 2.5 px and lifted 3 px.
const STROKE_Q8: i32 = 2 << 8;
const ACTIVE_STROKE_Q8: i32 = (5 << 8) / 2;
const ACTIVE_LIFT: i32 = 3;
/// 70 % white: an empty ring ahead of the cursor, a dialed-but-left ring.
const DIM: u8 = 179;
/// 80 % white: the hints on the chevron line.
const HINT: u8 = 204;
/// A masked (entered PIN) digit is a filled dot of this radius.
const MASK_DOT_R: i32 = 5;

/// `procedural.marks.minus` / `plus` on the hint row: bar span 0.6 × 19 px,
/// stroke 0.11 × 19 (half-width ≈ 1.05 px), 22 px in from each chevron.
const SIGN_HALF_Q4: i16 = 91; // 5.7 px
pub const MINUS: [(i16, i16); 2] = [(-SIGN_HALF_Q4, 0), (SIGN_HALF_Q4, 0)];
pub const PLUS_UPRIGHT: [(i16, i16); 2] = [(0, -SIGN_HALF_Q4), (0, SIGN_HALF_Q4)];
const SIGN_HW_Q8: i16 = 269;
const SIGN_INSET_Q8: i32 = 22 << 8;

/// The one-digit glyph strings the rings draw (static, so a text run can
/// borrow them for the frame's lifetime).
const GLYPHS: &[u8; 95] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

fn glyph_str(c: u8) -> &'static [u8] {
    match c {
        0x20..=0x7E => {
            let i = usize::from(c - 0x20);
            &GLYPHS[i..=i]
        }
        _ => &GLYPHS[0..1],
    }
}

/// The two hints that take turns between the chevrons (owner 2026-10-15):
/// how to confirm a digit or a letter, and how to step back. Both are the
/// entry loop's own gestures (the chord, or a right hold, enters; a left
/// hold goes back and, on the first slot, leaves the row).
pub const ENTRY_HINTS: [&[u8]; 2] = [b"CONFIRM (BOTH)", b"BACK (HOLD LEFT)"];

/// The hint showing at `now` and its alpha: the Confirm? band's swap (5 s a
/// message, 300 ms fades), on the WALL clock rather than the time since the
/// row settled, so the repaint on every press neither restarts the cycle nor
/// fades the hint back in. Shifted by one fade so `now` = 0 shows the first
/// hint at full strength.
#[must_use]
pub fn entry_hint(now: u32) -> (&'static [u8], u8) {
    let (which, a) = motion::confirm_band(now.wrapping_add(motion::BAND_FADE_MS));
    (ENTRY_HINTS[usize::from(which & 1)], (i64::from(a) * 255 >> 16) as u8)
}

/// Milliseconds from `now` until [`entry_hint`] next changes: 0 inside a
/// fade, else the time left in the slot's still part.
#[must_use]
pub fn entry_hint_still_for(now: u32) -> u32 {
    let local = now.wrapping_add(motion::BAND_FADE_MS) % motion::BAND_SWAP_MS;
    let still_end = motion::BAND_SWAP_MS - motion::BAND_FADE_MS;
    if (motion::BAND_FADE_MS..still_end).contains(&local) {
        still_end - local
    } else {
        0
    }
}

/// Draw an entry row record (rings, glyphs, the − / + marks and the hint at
/// `now`). The caption and the corner chevrons come from the screen's layout.
pub fn build_entry<'a>(s: &'a Screen, now: u32, frame: &mut Frame<'a>) {
    let Some((glyphs, states)) = s.entry_slots() else { return };
    let n = glyphs.len() as i32;
    let x0 = CENTER_X - (n - 1) * RING_PITCH / 2;
    for (i, (&c, &st)) in glyphs.iter().zip(states).enumerate() {
        let x = x0 + i as i32 * RING_PITCH;
        let (cy, w, ring, glyph) = match st {
            b'A' => (CIRCLE_CY - ACTIVE_LIFT, ACTIVE_STROKE_Q8, Rgb::YELLOW, Rgb::WHITE),
            b'E' => (CIRCLE_CY, STROKE_Q8, Rgb::WHITE, Rgb::WHITE),
            b'D' => (CIRCLE_CY, STROKE_Q8, Rgb::WHITE.scale(DIM), Rgb::WHITE),
            _ => (CIRCLE_CY, STROKE_Q8, Rgb::WHITE.scale(DIM), Rgb::BLACK),
        };
        frame.ring(x << 8, cy << 8, RING_R << 8, w, ring);
        match c {
            b'_' | b' ' => {}
            b'*' => {
                frame.disc(x << 8, cy << 8, MASK_DOT_R << 8, glyph);
            }
            _ => {
                frame.text(TextRun {
                        text: glyph_str(c),
                        tier: TierId::semibold(22),
                        x,
                        // Optical centring: nudged 1.5 px down.
                        y: cy + 1,
                        align: Align::Center,
                        baseline: false,
                        ls_q6: 0,
                        alpha: 255,
                    }, glyph);
            }
        }
    }
    // − beside the left chevron, + beside the right one.
    let hint = Rgb::WHITE.scale(HINT);
    let cy = CHEV_Y << 8;
    let lx = CHEV_LEFT_X_Q8 + SIGN_INSET_Q8;
    let rx = CHEV_RIGHT_X_Q8 - SIGN_INSET_Q8;
    for (pts, x) in [(&MINUS, lx), (&MINUS, rx), (&PLUS_UPRIGHT, rx)] {
        frame.shape(pts, Xform::at(x, cy), ShapeMode::Stroke { hw: SIGN_HW_Q8 }, hint, 255);
    }
    let (text, alpha) = entry_hint(now);
    frame.text(TextRun {
            text,
            // The 16 px caps face (the regular 16 tier is digits only).
            tier: TierId::semibold(16),
            x: CENTER_X,
            y: CHEV_Y,
            align: Align::Center,
            baseline: false,
            ls_q6: 64,
            alpha,
        }, hint);
}

/// Words grid geometry (`pq1/layout.py` `WORDS_ROWS` / `WORDS_COLS`).
pub const WORDS_ROWS: [i32; 4] = [32, 58, 84, 110];
/// Per column: the number's right edge, the word's left edge.
pub const WORDS_COLS: [(i32, i32); 2] = [(88, 98), (272, 282)];
/// Numbers at 50 % white (`WORDS_NUM_ALPHA`).
const NUM_ALPHA: u8 = 128;
const NUMS: [&[u8]; 24] = [
    b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b"10", b"11", b"12", b"13", b"14", b"15", b"16", b"17", b"18",
    b"19", b"20", b"21", b"22", b"23", b"24",
];

/// The number of grid cell `k` when the grid starts at word `first` (1-based).
#[must_use]
pub fn grid_number(first: usize, k: usize) -> &'static [u8] {
    NUMS.get(first.saturating_sub(1) + k).copied().unwrap_or(b"")
}

/// Where grid cell `k` (reading order) puts its number and word.
#[must_use]
pub fn grid_cell(k: usize) -> ((i32, i32), (i32, i32)) {
    let (nx, wx) = WORDS_COLS[(k / 4).min(1)];
    let y = WORDS_ROWS[k % 4];
    ((nx, y), (wx, y))
}

/// Push grid cell `k`'s number (grey, right-aligned); the word is the
/// caller's (a public word here, the constant-time secret run for a seed).
pub fn push_grid_number<'a>(frame: &mut Frame<'a>, first: usize, k: usize, alpha: u8) {
    let ((nx, y), _) = grid_cell(k);
    frame.text(TextRun {
            text: grid_number(first, k),
            tier: TierId::regular(22),
            x: nx,
            y,
            align: Align::Right,
            baseline: false,
            ls_q6: 0,
            alpha,
        }, Rgb::WHITE.scale(NUM_ALPHA));
}

/// A grid word that is drawn elsewhere: a secret the caller paints with the
/// constant-time run (the record never holds it).
pub const SECRET_PLACEHOLDER: &[u8] = b"*";
/// A secret cell that is also the list's cursor (a chevron in the number
/// column).
pub const SECRET_CURSOR: &[u8] = b"@";

/// Draw a words-grid record: up to eight numbered words, 1–4 down the left
/// column and 5–8 down the right (numbered from the record's first number;
/// 0 = an unnumbered list). Placeholder cells (`*`, `@`) are left for the
/// caller's secret run; `@` also draws the cursor chevron. The optional
/// label and the corner chevrons come from the layout.
pub fn build_words<'a>(s: &'a Screen, alpha: u8, frame: &mut Frame<'a>) {
    let first = usize::from(s.grid_first().unwrap_or(1));
    for k in 0..crate::screen::MAX_GRID_WORDS {
        let Some(w) = s.grid_word(k) else { break };
        if first > 0 {
            push_grid_number(frame, first, k, alpha);
        }
        if w == SECRET_CURSOR {
            let ((nx, y), _) = grid_cell(k);
            frame.chevron((nx - 4) << 8, y << 8, 0, Rgb::YELLOW.scale(alpha));
        }
        if w == SECRET_PLACEHOLDER || w == SECRET_CURSOR {
            continue;
        }
        let (_, (wx, y)) = grid_cell(k);
        frame.text(
            TextRun {
                text: w,
                tier: TierId::regular(22),
                x: wx,
                y,
                align: Align::Left,
                baseline: false,
                ls_q6: 0,
                alpha,
            },
            Rgb::WHITE,
        );
    }
}

/// Place a SECRET word (zero-padded to `font::SECRET_CELLS`) in grid cell
/// `k` through the constant-time run.
pub fn push_secret_word<'a>(frame: &mut Frame<'a>, k: usize, text: &'a [u8], alpha: u8) {
    let (_, (wx, y)) = grid_cell(k);
    frame.push(Item::Secret {
        text,
        tier: TierId::regular(22),
        // The first cell's glyph sits centred in a 14 px cell; start the
        // cells 2 px early so a word's ink begins on the grid's word edge.
        x: wx - 2,
        y,
        color: Rgb::WHITE.scale(alpha),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The swap: CONFIRM (BOTH) for 5 s, BACK (HOLD LEFT) for 5 s, 300 ms
    /// fades, on the wall clock; a still stretch reports how long it lasts.
    #[test]
    fn the_entry_hint_swaps_every_five_seconds() {
        assert_eq!(entry_hint(0), (ENTRY_HINTS[0], 255), "t = 0 shows the first hint in full");
        assert_eq!(entry_hint(4_000), (ENTRY_HINTS[0], 255));
        let (t, a) = entry_hint(4_550);
        assert!(t == ENTRY_HINTS[0] && a < 255 && a > 0, "fading out");
        assert_eq!(entry_hint(4_700).1, 0, "the swap point");
        assert_eq!(entry_hint(5_000), (ENTRY_HINTS[1], 255));
        assert_eq!(entry_hint(10_000), (ENTRY_HINTS[0], 255), "and back");
        assert_eq!(entry_hint_still_for(0), 4_400);
        assert_eq!(entry_hint_still_for(4_500), 0, "inside a fade: paint every frame");
        assert_eq!(entry_hint_still_for(5_000), 4_400);
        // Still exactly until the next fade begins.
        for now in (0..20_000).step_by(50) {
            let still = entry_hint_still_for(now);
            if still > 0 {
                assert_eq!(entry_hint(now), entry_hint(now + still - 1), "at {now}");
                assert!(entry_hint(now + still + 30).1 < 255, "fading just after, at {now}");
            }
        }
    }
    use crate::font::{Font, SECRET_CELLS};
    use crate::raster::{render_strip, Strip, W};
    use crate::screen::ScreenBuilder;
    use std::vec;

    const FONTS: &[u8] = include_bytes!("../../secure/assets/ui-px/fonts.bin");

    fn lit(words: &[&[u8; SECRET_CELLS]]) -> std::vec::Vec<u16> {
        let font = Font::parse(FONTS).unwrap();
        let mut f = Frame::new();
        for (k, w) in words.iter().enumerate() {
            push_secret_word(&mut f, k, &w[..], 255);
        }
        let mut buf = vec![0u16; (W * 142) as usize];
        let mut s = Strip::new(0, 142, &mut buf).unwrap();
        render_strip(&f, &font, &mut s);
        buf
    }

    #[test]
    fn secret_run_draws_the_word_and_nothing_for_padding() {
        let a = lit(&[b"abandon\0"]);
        assert!(a.iter().filter(|&&p| p != 0).count() > 100);
        let blank = lit(&[&[0u8; SECRET_CELLS]]);
        assert!(blank.iter().all(|&p| p == 0), "zero padding selects no glyph");
        // Same word, same pixels; a different word, different pixels.
        assert_eq!(a, lit(&[b"abandon\0"]));
        assert_ne!(a, lit(&[b"ability\0"]));
    }

    /// The seed run is clipped to each strip's columns (2026-10-15, the EVT
    /// "seed page draws across the screen" lag). Strips are column-major, so
    /// painting a page band by band and joining the bands must give exactly
    /// the pixels one full-width strip gives: nothing lost or doubled at a
    /// seam, whatever the band width.
    #[test]
    fn secret_run_is_identical_across_strip_widths() {
        use crate::raster::H;
        let font = Font::parse(FONTS).unwrap();
        let mut f = Frame::new();
        let words: [&[u8; SECRET_CELLS]; 8] =
            [b"abandon\0", b"ability\0", b"zoo\0\0\0\0\0", b"wrist\0\0\0", b"mandate\0", b"quantum\0", b"abstract", b"jelly\0\0\0"];
        for (k, w) in words.iter().enumerate() {
            push_secret_word(&mut f, k, &w[..], 255);
        }
        let mut whole = vec![0u16; (W * H) as usize];
        render_strip(&f, &font, &mut Strip::new(0, W, &mut whole).unwrap());
        assert!(whole.iter().filter(|&&p| p != 0).count() > 800, "the page draws");
        for band in [48, 44, 37, 1] {
            let mut joined = std::vec::Vec::new();
            let mut x0 = 0;
            while x0 < W {
                let w = band.min(W - x0);
                let mut buf = vec![0u16; (w * H) as usize];
                render_strip(&f, &font, &mut Strip::new(x0, w, &mut buf).unwrap());
                joined.extend_from_slice(&buf);
                x0 += w;
            }
            assert!(joined == whole, "band width {band}: strips disagree with the full-width render");
        }
    }

    #[test]
    fn entry_and_grid_records_round_trip() {
        let e = ScreenBuilder::entry(b"PIN", b"ENTER PIN", b"**5_____", b"EEA_____").finish().unwrap();
        assert_eq!(e.entry_slots(), Some((&b"**5_____"[..], &b"EEA_____"[..])));
        assert!(ScreenBuilder::entry(b"PIN", b"X", b"12", b"AA").finish().is_err(), "two active rings");
        assert!(ScreenBuilder::entry(b"PIN", b"X", b"123456789", b"_________").finish().is_err(), "nine rings");
        let g = ScreenBuilder::words(b"W", b"", &[b"close", b"agent", b"own", b"deputy", b"grape", b"though", b"sail", b"simple"])
            .first_number(9)
            .finish()
            .unwrap();
        assert_eq!(g.grid_first(), Some(9));
        assert_eq!(g.grid_word(0), Some(&b"close"[..]));
        assert_eq!(g.grid_word(5), Some(&b"though"[..]));
        assert_eq!(g.grid_word(7), Some(&b"simple"[..]));
        assert_eq!(g.grid_word(8), None);
        assert_eq!(grid_number(9, 7), b"16");
        assert!(ScreenBuilder::words(b"W", b"", &[b"two words"]).finish().is_err());
    }
}
