//! Constant-time glyph blit for secret-bearing OLED rows (F-24 stage D).
//!
//! `embedded_graphics::Text::draw` performs `MonoFont::glyph(char)` lookups
//! keyed on each rendered character, which loads from `FONT_5X8` at an
//! address that encodes the character. For SECRET characters (the master
//! mnemonic in the seed wizard) this becomes a 96-table-style address-
//! channel leak.
//!
//! [`render_secret_row`] is a parallel renderer used only by
//! `seed_wizard::render_mnemonic_page` for the word-display rows. It
//! mirrors the FONT_5X8 visual exactly (vendored from embedded-graphics'
//! `fonts/raw/ascii/font_5x8.raw` by `secure/build.rs::generate_font_flat`),
//! but loads glyph bytes via a constant-time scan over all 96 entries so
//! the mem_address pattern is fully deterministic.
//!
//! Stage E — the OLED itself broadcasts the resulting framebuffer over
//! its display drivers, which is EM-side leakage unfixable in firmware —
//! is documented in F-24 and accepted as residual.
//!
//! Module visibility: this file is `#[path]`-included as
//! `ui::secret_text` ONLY when the `ui-oled` feature is on (see
//! `ui/mod.rs`). Under host `cfg(test)` it is also `#[path]`-included
//! at the crate root via `ui_secret_text_under_test` so the unit
//! tests below run on `cargo test`.

include!(concat!(env!("OUT_DIR"), "/font_flat.rs"));

/// Total SSD1306 framebuffer size: 128 cols × 4 pages × 8 vertical pixels.
const DISPLAY_W_PX: usize = 128;

/// Constant-time `target == entry` for u8 — returns `0xFF` iff equal,
/// `0x00` otherwise. Mirrors `bip39::ct_eq_u16`.
#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let x: u16 = a as u16 ^ b as u16;
    let nz: u16 = (x | x.wrapping_neg()) >> 15; // 0 iff eq, 1 iff diff
    (nz as u8).wrapping_sub(1) // 0xFF iff eq, 0x00 iff diff
}

/// Look up one column-byte of a single glyph in constant time. Scans
/// all 96 entries of `FONT_FLAT_5X8` and mask-ORs the matching one.
///
/// **`core::hint::black_box` barriers are load-bearing** — without them
/// LLVM folds the loop into a direct `FONT_FLAT_5X8[ch - 0x20][col]`
/// lookup (same regression mode F-22's `ct_load_word` saw). Verified
/// empirically via the F-24 TVLA harness `make -C tools/sca glyph-leak`
/// (2026-06-09: leaky-baseline `max|t|=650.90` → LEAKAGE; this constant-time
/// scan `max|t|=0.00` over 60,173 mem-address samples → flat). If a future
/// commit removes the barriers, that harness regresses — re-run it to catch it.
#[inline(never)]
fn ct_glyph_col(ch: u8, col: usize) -> u8 {
    use core::hint::black_box;
    let mut acc: u8 = 0;
    let mut i = 0u8;
    while (i as usize) < FONT_N_GLYPHS {
        let entry_ch = FONT_FIRST_CHAR + i;
        let mask = black_box(ct_eq_u8(entry_ch, ch));
        let glyph_col = black_box(FONT_FLAT_5X8[i as usize][col]);
        acc = black_box(acc | (glyph_col & mask));
        i += 1;
    }
    acc
}

/// Render one row of secret text directly into the SSD1306 page buffer,
/// using only constant-time glyph lookups. Bypasses `embedded_graphics::Text`
/// for this row — embedded-graphics is still used for non-secret rows
/// (titles, prompts, status bars) where the address-leak is irrelevant.
///
/// `page`: which 8-pixel-tall row (0..4 on a 128×32, 0..8 on a 128×64).
/// `text`: ASCII bytes; non-printable characters render as blank (the
///   scan still happens for every position to keep the access pattern
///   identical to the all-printable case).
/// `fb`: the SSD1306 page buffer — `128 * (height / 8)` bytes. Taken as a
///   slice rather than a fixed `[u8; 512]` so the same routine serves a
///   128x32 (4 pages) and a 128x64 (8 pages); the caller's panel height is a
///   board constant.
///
/// Writes column-bytes `fb[page * 128 + p]` for `p in 0..128`. Each
/// column-byte is OR'd with the existing value, so callers must clear
/// the framebuffer first (the standard `Display::flush` shape).
///
/// Constant-time property is unaffected by the length change: the loop below
/// always runs `DISPLAY_W_PX` iterations and the secrecy lives in
/// `ct_glyph_col`'s 96-entry scan, not in the buffer bound.
pub fn render_secret_row(fb: &mut [u8], page: usize, text: &[u8]) {
    // Bounds guard replacing the old `page >= 4`: reject any row that would
    // not fit rather than assuming a page count.
    if (page + 1) * DISPLAY_W_PX > fb.len() {
        return;
    }
    let base = page * DISPLAY_W_PX;
    let mut p = 0usize;
    while p < DISPLAY_W_PX {
        let char_idx = p / FONT_GLYPH_W;
        let col_in_char = p % FONT_GLYPH_W;
        // Out-of-bounds char positions render as 0 (blank) — but we
        // STILL run the scan to keep the access pattern uniform with
        // the in-bounds case. Using a zero byte for the OOB scan
        // produces a blank glyph (NUL isn't in [0x20, 0x7F] so no
        // mask matches → acc = 0).
        let ch = if char_idx < text.len() {
            text[char_idx]
        } else {
            0u8
        };
        let col_byte = ct_glyph_col(ch, col_in_char);
        fb[base + p] |= col_byte;
        p += 1;
    }
}

/// Constant-time fetch of all `FONT_GLYPH_W` (5) column-bytes of a glyph, for
/// the LCD secret-row render path. Each column comes from the same 96-entry
/// constant-time scan (`ct_glyph_col`, with its `black_box` barriers) as
/// [`render_secret_row`], so the memory-access pattern is independent of the
/// secret character. The branchless 3×/RGB565 expansion that consumes these
/// bytes lives in `ui::lcd` and writes every pixel unconditionally, preserving
/// the constant-time property end-to-end (only the pixel VALUE — the accepted
/// F-24 stage-E display-broadcast residual — depends on the secret).
#[cfg(feature = "ui-lcd")]
pub(crate) fn secret_glyph_cols(ch: u8) -> [u8; FONT_GLYPH_W] {
    let mut out = [0u8; FONT_GLYPH_W];
    let mut c = 0usize;
    while c < FONT_GLYPH_W {
        out[c] = ct_glyph_col(ch, c);
        c += 1;
    }
    out
}

/// Non-secret glyph column-bytes via a DIRECT index — used by the LCD public
/// render path (titles / prompts / status), where the address-channel leak is
/// irrelevant. NEVER call this for secret rows; use [`secret_glyph_cols`].
#[cfg(feature = "ui-lcd")]
pub(crate) fn public_glyph_cols(ch: u8) -> [u8; FONT_GLYPH_W] {
    if ch >= FONT_FIRST_CHAR && ch <= FONT_LAST_CHAR {
        FONT_FLAT_5X8[(ch - FONT_FIRST_CHAR) as usize]
    } else {
        [0u8; FONT_GLYPH_W]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: `ct_glyph_col` reproduces the ASCII glyph for printable
    /// chars and blanks-out for out-of-range chars.
    #[test]
    fn ct_glyph_col_recovers_known_glyphs() {
        // 'a' at FONT_FLAT_5X8[0x61 - 0x20 = 0x41] = [0x30, 0x48, 0x48, 0x78, 0x00]
        for col in 0..FONT_GLYPH_W {
            assert_eq!(
                ct_glyph_col(b'a', col),
                FONT_FLAT_5X8[(b'a' - FONT_FIRST_CHAR) as usize][col],
                "col {col}",
            );
        }
        // ' ' (space) is all zeros.
        for col in 0..FONT_GLYPH_W {
            assert_eq!(ct_glyph_col(b' ', col), 0, "space col {col}");
        }
        // Out-of-range char → all zeros.
        for col in 0..FONT_GLYPH_W {
            assert_eq!(ct_glyph_col(0xFF, col), 0, "0xFF col {col}");
            assert_eq!(ct_glyph_col(0x00, col), 0, "0x00 col {col}");
        }
    }

    /// Sanity: rendering a known word produces the expected column-byte
    /// stream. Cross-checks against the same data the FONT_5X8 produces.
    #[test]
    fn render_secret_row_writes_expected_columns() {
        let mut fb = [0u8; 512];
        let text = b"a";
        render_secret_row(&mut fb, 0, text);
        // First 5 columns should match the 'a' glyph.
        for col in 0..FONT_GLYPH_W {
            assert_eq!(
                fb[col],
                FONT_FLAT_5X8[(b'a' - FONT_FIRST_CHAR) as usize][col],
                "render col {col}",
            );
        }
        // Cols 5..128 should be blank (OOB → ch=0 → no glyph match).
        for col in FONT_GLYPH_W..DISPLAY_W_PX {
            assert_eq!(fb[col], 0, "blank col {col}");
        }
    }
}
