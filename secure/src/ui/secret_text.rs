//! Constant-time glyph blit for secret-bearing trusted-display rows
//! (F-24 stage D).
//!
//! `embedded_graphics::Text::draw` performs `MonoFont::glyph(char)` lookups
//! keyed on each rendered character, which loads from `FONT_5X8` at an
//! address that encodes the character. For SECRET characters (the master
//! mnemonic in the seed wizard) this becomes a 96-table-style address-
//! channel leak.
//!
//! [`ct_glyph_cols`] loads glyph bytes via a constant-time scan over all 96
//! entries, so the mem_address pattern is fully deterministic. It mirrors the
//! FONT_5X8 visual exactly (vendored from embedded-graphics'
//! `fonts/raw/ascii/font_5x8.raw` by `secure/build.rs::generate_font_flat`).
//!
//! Stage E — the panel itself broadcasts the resulting framebuffer over its
//! display drivers, which is EM-side leakage unfixable in firmware — is
//! documented in F-24 and accepted as residual.
//!
//! Module visibility: compiled under `ui-lcd` (see `ui/mod.rs`). Under host
//! `cfg(test)` it is also `#[path]`-included at the crate root via
//! `ui_secret_text_under_test` so the unit tests below run on `cargo test`.
//!
//! A page-oriented `render_secret_row` lived here until 2026-09-23. It blitted
//! into an SSD1306 column-page framebuffer and its only caller was the bench
//! OLED backend, so it went with it. The constant-time guarantee is unaffected:
//! it never lived in that function, but in `ct_glyph_col`'s 96-entry scan,
//! which the LCD path uses and which `ct_glyph_col_recovers_known_glyphs`
//! still checks against the font table end to end.

include!(concat!(env!("OUT_DIR"), "/font_flat.rs"));

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

/// Constant-time fetch of all `FONT_GLYPH_W` (5) column-bytes of a glyph, for
/// the LCD secret-row render path. Each column comes from the same 96-entry
/// constant-time scan (`ct_glyph_col`, with its `black_box` barriers), so the
/// memory-access pattern is independent of the secret character. The branchless 3×/RGB565 expansion that consumes these
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

}
