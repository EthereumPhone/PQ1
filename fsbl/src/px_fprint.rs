//! Pixel-UI firmware fingerprint for the FSBL (`px-fingerprint`).
//!
//! The FSBL paints the same two screens the secure world's pixel UI paints
//! for the boot fingerprint — the "OS FINGERPRINT" title (fingerprint mark on
//! its white disc) and then the eight words on the numbered words grid — so
//! the boot-time trust window looks like the rest of the device instead of a
//! 5×8 bitmap font. The corner chevrons are left out: the FSBL takes no
//! button input.
//!
//! Pure (no MMIO): the panel streaming lives in `nv3007`. Host-tested
//! pixel-for-pixel against the `pqsigner-ui-px` engine in
//! `fsbl-tests/tests/px_fingerprint.rs`, which also regenerates
//! [`assets`] (`PQ1_BLESS=1`) and fails when the checked-in copy drifts.
//!
//! The words come from the prefix-5 table the FSBL already links
//! (`sphincs_tz_bip39::word_prefix_at`) plus a 1.4 KB stream of the letters
//! past the fifth ([`assets::SUFFIX_BITS`]); the full 2048-word list does not
//! fit the 32 KiB FSBL region.

#[path = "px_fprint_assets.rs"]
mod assets;

/// Landscape frame size (the pixel UI's `raster::W` / `raster::H`).
pub const W: usize = 428;
pub const H: usize = 142;

/// One landscape column in the panel's wire order: index `H - 1 - y`.
pub type Column = [u16; H];

// ---------------------------------------------------------------------------
// Title screen
// ---------------------------------------------------------------------------

/// Streams the pre-rendered title frame column by column.
///
/// Token format ([`assets::TITLE_RLE`]): `b & 0x3F` is a palette index;
/// `b >> 6` is 0..=2 for a run of 1..=3 pixels, or 3 for a run of
/// `next byte + 4` pixels.
pub struct Title {
    pos: usize,
    left: u32,
    color: u16,
}

impl Title {
    #[must_use]
    pub const fn new() -> Self {
        Self { pos: 0, left: 0, color: 0 }
    }

    /// Fill `col` with the next landscape column. A truncated stream pads
    /// with black (the host test pins that the stream covers the frame).
    pub fn next_column(&mut self, col: &mut Column) {
        for px in col.iter_mut() {
            if self.left == 0 {
                self.load();
            }
            if self.left == 0 {
                *px = 0;
                continue;
            }
            *px = self.color;
            self.left -= 1;
        }
    }

    fn load(&mut self) {
        let rle = &assets::TITLE_RLE;
        let Some(&b) = rle.get(self.pos) else { return };
        self.pos += 1;
        self.color = assets::TITLE_PALETTE.get(usize::from(b & 0x3F)).copied().unwrap_or(0);
        self.left = match b >> 6 {
            3 => {
                let n = rle.get(self.pos).copied().unwrap_or(0);
                self.pos += 1;
                u32::from(n) + 4
            }
            c => u32::from(c) + 1,
        };
    }
}

// ---------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------

/// The longest BIP-39 English word.
pub const WORD_LEN: usize = 8;

/// Word `idx` of the BIP-39 English list, NUL-padded: its five-letter prefix
/// from `prefix5` plus the letters after it from [`assets::SUFFIX_BITS`].
///
/// The stream holds, per word in list order, a 2-bit count of extra letters
/// (0..=3) and then 5 bits per letter (`letter - b'a'`), MSB first.
#[must_use]
pub fn full_word(idx: u16, prefix5: [u8; 5]) -> [u8; WORD_LEN] {
    let mut out = [0u8; WORD_LEN];
    out[..5].copy_from_slice(&prefix5);
    let mut bit = 0usize;
    let mut read = |n: usize| -> u8 {
        let mut v = 0u8;
        for _ in 0..n {
            let byte = assets::SUFFIX_BITS.get(bit / 8).copied().unwrap_or(0);
            v = (v << 1) | ((byte >> (7 - bit % 8)) & 1);
            bit += 1;
        }
        v
    };
    let mut i = 0u16;
    while i < idx {
        let extra = read(2);
        let _ = read(5 * usize::from(extra));
        i += 1;
    }
    let extra = usize::from(read(2));
    for slot in out.iter_mut().skip(5).take(extra) {
        *slot = b'a' + read(5);
    }
    out
}

// ---------------------------------------------------------------------------
// Words grid
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Placed {
    glyph: u8,
    x: i16,
    y: i16,
    number: bool,
}

const NO_GLYPH: Placed = Placed { glyph: 0, x: 0, y: 0, number: false };
/// Eight numbers plus eight words of at most eight letters.
const MAX_PLACED: usize = 8 + 8 * WORD_LEN;

/// The numbered words grid, laid out exactly like `pqsigner_ui_px::rows::
/// build_words` at full alpha: grey right-aligned numbers, white left-aligned
/// words, tier regular 22, vertically centred on the grid rows.
pub struct Grid {
    placed: [Placed; MAX_PLACED],
    n: usize,
}

impl Grid {
    /// Lay out eight NUL-padded lowercase words. A byte outside `a..=z` ends
    /// a word (the table has no glyph for it).
    #[must_use]
    pub fn new(words: &[[u8; WORD_LEN]; 8]) -> Self {
        let mut g = Self { placed: [NO_GLYPH; MAX_PLACED], n: 0 };
        for (k, word) in words.iter().enumerate() {
            let (glyph, x, y) = assets::NUMBERS[k];
            g.push(Placed { glyph, x, y, number: true });
            let baseline = assets::WORD_BASELINE[k % 4];
            let mut x_q6 = i32::from(assets::WORD_X[k / 4]) << 6;
            for &c in word {
                if !c.is_ascii_lowercase() {
                    break;
                }
                let gi = c - b'a';
                let (_, _, bx, bt, adv, _) = assets::GLYPHS[usize::from(gi)];
                let gx = ((x_q6 + 32) >> 6) + i32::from(bx);
                let gy = i32::from(baseline) - i32::from(bt);
                g.push(Placed { glyph: gi, x: gx as i16, y: gy as i16, number: false });
                x_q6 += i32::from(adv);
            }
        }
        g
    }

    fn push(&mut self, p: Placed) {
        if self.n < MAX_PLACED {
            self.placed[self.n] = p;
            self.n += 1;
        }
    }

    /// Compose landscape column `x` into `col` (black background).
    pub fn column(&self, x: usize, col: &mut Column) {
        col.fill(0);
        if x >= W {
            return;
        }
        let x = x as i32;
        for p in &self.placed[..self.n] {
            let (w, h, _, _, _, off) = assets::GLYPHS[usize::from(p.glyph)];
            let gx = x - i32::from(p.x);
            if gx < 0 || gx >= i32::from(w) {
                continue;
            }
            let (over_black, rgb) = if p.number {
                (&assets::NUM_OVER_BLACK, assets::NUM_RGB)
            } else {
                (&assets::WORD_OVER_BLACK, assets::WORD_RGB)
            };
            let stride = (usize::from(w) + 1) / 2;
            for gy in 0..i32::from(h) {
                let y = i32::from(p.y) + gy;
                if !(0..H as i32).contains(&y) {
                    continue;
                }
                let at = usize::from(off) + gy as usize * stride + gx as usize / 2;
                let b = assets::GLYPH_BITS.get(at).copied().unwrap_or(0);
                let n = usize::from(if gx % 2 == 0 { b >> 4 } else { b & 0x0F });
                if n == 0 {
                    continue;
                }
                let i = H - 1 - y as usize;
                let dst = col[i];
                col[i] = if dst == 0 { over_black[n] } else { blend_over(dst, rgb, (n * 17) as u8) };
            }
        }
    }
}

/// `pqsigner_ui_px::raster::blend_over`: `dst + (src − dst)·a` in RGB565.
fn blend_over(dst: u16, src: [u8; 3], a: u8) -> u16 {
    if a == 0 {
        return dst;
    }
    if a == 255 {
        return (u16::from(src[0] & 0xF8) << 8) | (u16::from(src[1] & 0xFC) << 3) | u16::from(src[2] >> 3);
    }
    let up = |v: u16, bits: u32| -> i32 {
        let v = i32::from(v);
        (v << (8 - bits)) | (v >> (2 * bits - 8))
    };
    let d = [up((dst >> 11) & 0x1F, 5), up((dst >> 5) & 0x3F, 6), up(dst & 0x1F, 5)];
    let a = i32::from(a);
    let ch = |d: i32, s: u8| -> u16 { (d + ((i32::from(s) - d) * a + 127) / 255) as u16 };
    let (r, g, b) = (ch(d[0], src[0]), ch(d[1], src[1]), ch(d[2], src[2]));
    ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
}
