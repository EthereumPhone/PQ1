//! Tier fitting and value splitting — DESIGN.md § Typography made total.
//!
//! The design picks "the largest tier whose content fits the detail region"
//! from a character table (docked column: 36→12, 32→14, 28→16, 22→21 chars
//! per line; full width ×1.45) and never shrinks below 22, never truncates,
//! never ellipsizes. The character table alone is not width-safe for a
//! proportional face (a run of `W` at 36 px is ~33 px per glyph), so every
//! candidate is also measured against the baked Aileron advance widths in
//! [`crate::metrics_gen`]. A value that fits no tier is an error the caller
//! turns into a refusal to sign.
//!
//! All functions are total: no panics on any input, no allocation.

use crate::metrics_gen::{TierMetrics, TIERS};
use crate::screen::{Tier, Weight, LINE_LEN};

/// Where the text sits: beside a docked disc, or across the full panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    /// 276 px beside the disc column.
    Docked,
    /// 404 px, disc parked off-panel (value screens).
    Full,
}

impl Region {
    /// Text region width in pixels (DESIGN.md § Layout grid).
    #[must_use]
    pub const fn width_px(self) -> u32 {
        match self {
            Self::Docked => 276,
            Self::Full => 404,
        }
    }

    /// Character budget per line at a tier (DESIGN.md § Choosing the size).
    #[must_use]
    pub const fn chars(self, tier: Tier) -> usize {
        match (self, tier) {
            (Self::Docked, Tier::T36) => 12,
            (Self::Docked, Tier::T32) => 14,
            (Self::Docked, Tier::T28) => 16,
            (Self::Docked, Tier::T22) => 21,
            (Self::Full, Tier::T36) => 17,
            (Self::Full, Tier::T32) => 20,
            (Self::Full, Tier::T28) => 23,
            (Self::Full, Tier::T22) => 30,
        }
    }
}

/// Tiers from largest to smallest — the order the fitter tries them.
pub const TIERS_DESC: [Tier; 4] = [Tier::T36, Tier::T32, Tier::T28, Tier::T22];

/// Baked metrics for `(px, weight)`, if that tier was baked.
#[must_use]
pub fn metrics(px: u8, semibold: bool) -> Option<&'static TierMetrics> {
    TIERS.iter().find(|t| t.px == px && t.semibold == semibold)
}

/// Advance width (Q6) of `byte` at `(px, weight)`; `None` when the glyph is
/// not baked at that tier (or the tier itself is not).
#[must_use]
pub fn advance_q6(px: u8, semibold: bool, byte: u8) -> Option<u16> {
    let m = metrics(px, semibold)?;
    let idx = usize::from(byte.checked_sub(0x20)?);
    match m.advance_q6.get(idx) {
        Some(&a) if a != 0 => Some(a),
        _ => None,
    }
}

/// Measured width (Q6) of a run with letter-spacing `ls_q6` between glyphs;
/// `None` if any glyph is not renderable at this tier/weight.
#[must_use]
pub fn measure_q6(text: &[u8], px: u8, semibold: bool, ls_q6: u16) -> Option<u32> {
    let mut w: u32 = 0;
    for (i, &b) in text.iter().enumerate() {
        w = w.checked_add(u32::from(advance_q6(px, semibold, b)?))?;
        if i + 1 < text.len() {
            w = w.checked_add(u32::from(ls_q6))?;
        }
    }
    Some(w)
}

fn weight_is_semibold(w: Weight) -> bool {
    matches!(w, Weight::SemiBold)
}

/// One candidate line: its bytes and weight.
pub type LineIn<'a> = (&'a [u8], Weight);

/// The largest tier at which every line fits both the character budget and
/// the measured width of `region`, and the line count fits the tier's
/// stacking limit. `None` ⇒ the caller refuses (never truncates).
#[must_use]
pub fn fit_tier(lines: &[LineIn<'_>], region: Region) -> Option<Tier> {
    if lines.is_empty() {
        return None;
    }
    let budget_q6 = region.width_px().checked_mul(64)?;
    'tiers: for &tier in &TIERS_DESC {
        if lines.len() > tier.max_lines() {
            continue;
        }
        for &(text, w) in lines {
            if text.len() > region.chars(tier) {
                continue 'tiers;
            }
            let Some(px) = measure_q6(text, tier.px(), weight_is_semibold(w), 0) else {
                continue 'tiers;
            };
            if px > budget_q6 {
                continue 'tiers;
            }
        }
        return Some(tier);
    }
    None
}

/// A fixed-capacity output line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub buf: [u8; LINE_LEN],
    pub len: u8,
}

impl Line {
    pub const EMPTY: Self = Self {
        buf: [b' '; LINE_LEN],
        len: 0,
    };

    /// Build from bytes; `None` if longer than [`LINE_LEN`].
    #[must_use]
    pub fn new(src: &[u8]) -> Option<Self> {
        if src.len() > LINE_LEN {
            return None;
        }
        let mut l = Self::EMPTY;
        l.buf[..src.len()].copy_from_slice(src);
        l.len = u8::try_from(src.len()).ok()?;
        Some(l)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len).min(LINE_LEN)]
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(line: &mut Line, bytes: &[u8]) -> bool {
    for &b in bytes {
        let n = usize::from(line.len);
        if n + 2 > LINE_LEN {
            return false;
        }
        line.buf[n] = HEX[usize::from(b >> 4)];
        line.buf[n + 1] = HEX[usize::from(b & 0x0F)];
        line.len += 2;
    }
    true
}

fn push_str(line: &mut Line, s: &[u8]) -> bool {
    let n = usize::from(line.len);
    if n + s.len() > LINE_LEN {
        return false;
    }
    line.buf[n..n + s.len()].copy_from_slice(s);
    line.len += u8::try_from(s.len()).unwrap_or(u8::MAX);
    true
}

/// A 42-byte ASCII address (`0x` + 40 hex, case as supplied) as two centred
/// docked 22-tier lines: `0x` + 19 hex / 21 hex — the DESIGN.md sample
/// split, no ellipsis.
#[must_use]
pub fn split_address(addr: &[u8; 42]) -> [Line; 2] {
    let mut a = Line::EMPTY;
    let mut b = Line::EMPTY;
    // Both pushes are within LINE_LEN by construction (21 ≤ 30).
    let _ = push_str(&mut a, &addr[..21]);
    let _ = push_str(&mut b, &addr[21..]);
    [a, b]
}

/// A 32-byte value on one full-width screen: `0x` + 11 bytes / 11 bytes /
/// 10 bytes at tier 22 (`flows/fingerprint/__init__.py` line rule).
#[must_use]
pub fn split_hash_full(h: &[u8; 32]) -> [Line; 3] {
    let mut l0 = Line::EMPTY;
    let mut l1 = Line::EMPTY;
    let mut l2 = Line::EMPTY;
    let _ = push_str(&mut l0, b"0x");
    let _ = push_hex(&mut l0, &h[..11]);
    let _ = push_hex(&mut l1, &h[11..22]);
    let _ = push_hex(&mut l2, &h[22..]);
    [l0, l1, l2]
}

/// A 32-byte value on a docked detail as two pages of two lines: page 1
/// `0x` + 8 bytes / 8 bytes, page 2 8 bytes / 8 bytes (DESIGN.md § Pages).
#[must_use]
pub fn split_word_docked(w: &[u8; 32]) -> [[Line; 2]; 2] {
    let mut p0a = Line::EMPTY;
    let mut p0b = Line::EMPTY;
    let mut p1a = Line::EMPTY;
    let mut p1b = Line::EMPTY;
    let _ = push_str(&mut p0a, b"0x");
    let _ = push_hex(&mut p0a, &w[..8]);
    let _ = push_hex(&mut p0b, &w[8..16]);
    let _ = push_hex(&mut p1a, &w[16..24]);
    let _ = push_hex(&mut p1b, &w[24..]);
    [[p0a, p0b], [p1a, p1b]]
}

/// Why an amount could not be laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FitErr {
    /// The number alone exceeds the 22-tier line budget for the region.
    TooWide,
    /// A byte is not renderable at any tier (non-ASCII or unbaked glyph).
    Unrenderable,
    /// Empty number.
    Empty,
}

/// Result of [`layout_amount`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmountLayout {
    pub lines: [Line; 2],
    pub n: u8,
    pub tier: Tier,
}

/// Numbers keep their unit on one line while the pair fits a one-line tier
/// (36 / 32); otherwise the pair breaks **once, after the number** — number
/// on line 1, unit on line 2 — at 28, or 22 when the number alone passes 16
/// characters. The number never breaks; a number wider than the 22-tier
/// budget is an error.
pub fn layout_amount(number: &[u8], unit: &[u8], region: Region) -> Result<AmountLayout, FitErr> {
    if number.is_empty() {
        return Err(FitErr::Empty);
    }
    // One line: "number unit" (or just the number when the unit is empty).
    let mut one = Line::EMPTY;
    let one_ok = push_str(&mut one, number)
        && (unit.is_empty() || (push_str(&mut one, b" ") && push_str(&mut one, unit)));
    if one_ok {
        for &tier in &[Tier::T36, Tier::T32] {
            if fit_tier(&[(one.as_bytes(), Weight::Regular)], region) == Some(tier) {
                return Ok(AmountLayout {
                    lines: [one, Line::EMPTY],
                    n: 1,
                    tier,
                });
            }
        }
        if unit.is_empty() {
            // A bare number: any tier that fits it on one line is fine.
            if let Some(tier) = fit_tier(&[(one.as_bytes(), Weight::Regular)], region) {
                return Ok(AmountLayout {
                    lines: [one, Line::EMPTY],
                    n: 1,
                    tier,
                });
            }
            return Err(if measure_q6(number, 22, false, 0).is_none() {
                FitErr::Unrenderable
            } else {
                FitErr::TooWide
            });
        }
    }
    // Two lines: number / unit, largest tier that takes two lines and fits.
    let num = Line::new(number).ok_or(FitErr::TooWide)?;
    let unit_line = Line::new(unit).ok_or(FitErr::TooWide)?;
    let lines = [(num.as_bytes(), Weight::Regular), (unit_line.as_bytes(), Weight::Regular)];
    match fit_tier(&lines, region) {
        Some(tier) => Ok(AmountLayout {
            lines: [num, unit_line],
            n: 2,
            tier,
        }),
        None => Err(if measure_q6(number, 22, false, 0).is_none() || measure_q6(unit, 22, false, 0).is_none() {
            FitErr::Unrenderable
        } else {
            FitErr::TooWide
        }),
    }
}

/// An address laid out for a docked 22-tier detail: two ≤ 21-character
/// lines when both fit the measured width, else three 14-character lines
/// (an uppercase-heavy EIP-55 string can exceed 276 px at 21 characters —
/// the character table alone is not width-safe, and clipping is never an
/// option). Both shapes are the DESIGN.md address treatment: centred lines
/// of ≤ 21 characters, split mid-string, no ellipsis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrLines {
    pub lines: [Line; 3],
    pub n: u8,
}

impl AddrLines {
    #[must_use]
    pub fn as_slice(&self) -> &[Line] {
        &self.lines[..usize::from(self.n).min(3)]
    }
}

#[must_use]
pub fn layout_address(addr: &[u8; 42]) -> AddrLines {
    let [a, b] = split_address(addr);
    let budget = Region::Docked.width_px() * 64;
    let fits = |l: &Line| measure_q6(l.as_bytes(), 22, false, 0).is_some_and(|w| w <= budget);
    if fits(&a) && fits(&b) {
        return AddrLines {
            lines: [a, b, Line::EMPTY],
            n: 2,
        };
    }
    let mut l0 = Line::EMPTY;
    let mut l1 = Line::EMPTY;
    let mut l2 = Line::EMPTY;
    let _ = push_str(&mut l0, &addr[..14]);
    let _ = push_str(&mut l1, &addr[14..28]);
    let _ = push_str(&mut l2, &addr[28..]);
    AddrLines {
        lines: [l0, l1, l2],
        n: 3,
    }
}

/// A resolved identity over its address: the name rides `SemiBold` on its own
/// line only when it fits one docked 22-tier line (characters and measured
/// width) AND the address needs only two lines; otherwise the address stands
/// alone. The address lines are the fact; the name is the advisory hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameAddr {
    pub name: Option<Line>,
    pub addr: AddrLines,
}

#[must_use]
pub fn layout_name_over_address(name: Option<&[u8]>, addr: &[u8; 42]) -> NameAddr {
    let addr_lines = layout_address(addr);
    let name = name.and_then(|n| {
        if addr_lines.n != 2 || n.is_empty() || n.len() > Region::Docked.chars(Tier::T22) {
            return None;
        }
        let w = measure_q6(n, 22, true, 0)?;
        if w > Region::Docked.width_px() * 64 {
            return None;
        }
        Line::new(n)
    });
    NameAddr {
        name,
        addr: addr_lines,
    }
}

#[cfg(kani)]
mod kani_harnesses {
    //! Bounded proofs: the fitter and splitters never panic and never
    //! truncate, for any input up to the bound. `cargo kani -p pqsigner-ui-px`.
    use super::*;

    #[kani::proof]
    #[kani::unwind(70)]
    fn fit_tier_total() {
        let n: usize = kani::any();
        kani::assume(n <= 32);
        let buf: [u8; 32] = kani::any();
        let region = if kani::any() { Region::Docked } else { Region::Full };
        let w = if kani::any() { Weight::Regular } else { Weight::SemiBold };
        let r = fit_tier(&[(&buf[..n], w)], region);
        if let Some(t) = r {
            assert!(n <= region.chars(t));
        }
    }

    #[kani::proof]
    #[kani::unwind(70)]
    fn layout_amount_never_breaks_number() {
        let n: usize = kani::any();
        let u: usize = kani::any();
        kani::assume(n <= 24 && u <= 6);
        let num: [u8; 24] = kani::any();
        let unit: [u8; 6] = kani::any();
        let region = if kani::any() { Region::Docked } else { Region::Full };
        if let Ok(a) = layout_amount(&num[..n], &unit[..u], region) {
            // Line 1 always starts with the whole number.
            assert!(a.lines[0].as_bytes().starts_with(&num[..n]));
            assert!(a.n == 1 || a.lines[1].as_bytes() == &unit[..u]);
        }
    }

    #[kani::proof]
    fn splits_are_lossless() {
        let h: [u8; 32] = kani::any();
        let [a, b, c] = split_hash_full(&h);
        assert!(a.as_bytes().len() + b.as_bytes().len() + c.as_bytes().len() == 66);
        let [[p, q], [r, s]] = split_word_docked(&h);
        assert!(p.as_bytes().len() + q.as_bytes().len() + r.as_bytes().len() + s.as_bytes().len() == 66);
        let addr: [u8; 42] = kani::any();
        let [x, y] = split_address(&addr);
        assert!(x.as_bytes() == &addr[..21] && y.as_bytes() == &addr[21..]);
        let la = layout_address(&addr);
        let total: usize = la.as_slice().iter().map(|l| l.as_bytes().len()).sum();
        assert!(total == 42);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_tiers_present() {
        for (px, sb) in [(36, false), (32, false), (28, false), (22, false), (22, true), (18, false), (16, true), (16, false)] {
            assert!(metrics(px, sb).is_some(), "tier {px}/{sb}");
        }
        assert!(metrics(36, true).is_none());
        assert!(advance_q6(36, false, b'A').is_some());
        assert!(advance_q6(36, false, b'{').is_none(), "trimmed charset");
        assert!(advance_q6(16, false, b'A').is_none(), "pager tier is digits only");
        assert!(advance_q6(22, false, 0x19).is_none());
        assert!(advance_q6(22, false, 0x7F).is_none(), "ellipsis only in caption tiers");
        assert!(advance_q6(18, false, 0x7F).is_some());
    }

    #[test]
    fn tier_table_matches_design() {
        let d = Region::Docked;
        assert_eq!((d.chars(Tier::T36), d.chars(Tier::T32), d.chars(Tier::T28), d.chars(Tier::T22)), (12, 14, 16, 21));
        let f = Region::Full;
        assert_eq!((f.chars(Tier::T36), f.chars(Tier::T32), f.chars(Tier::T28), f.chars(Tier::T22)), (17, 20, 23, 30));
    }

    #[test]
    fn fit_examples_from_the_design() {
        // "25,000 USDC" (11 chars) → 36 on a docked detail.
        assert_eq!(fit_tier(&[(b"25,000 USDC", Weight::Regular)], Region::Docked), Some(Tier::T36));
        // "250.000000 USDC" (15) → 28.
        assert_eq!(fit_tier(&[(b"250.000000 USDC", Weight::Regular)], Region::Docked), Some(Tier::T28));
        // Two lines "Nonce: 8" / "Standard call" → 28.
        assert_eq!(fit_tier(&[(b"Nonce: 8", Weight::Regular), (b"Standard call", Weight::Regular)], Region::Docked), Some(Tier::T28));
        // A 20-char line → 22.
        assert_eq!(fit_tier(&[(b"Function: 0x12345678", Weight::Regular), (b"Data: 64 B", Weight::Regular)], Region::Docked), Some(Tier::T22));
        // Three lines only at 22.
        assert_eq!(fit_tier(&[(b"a", Weight::Regular), (b"b", Weight::Regular), (b"c", Weight::Regular)], Region::Docked), Some(Tier::T22));
        // Four lines never.
        assert_eq!(fit_tier(&[(&b"a"[..], Weight::Regular); 4], Region::Docked), None);
        // A SemiBold line forces 22 (the only baked SemiBold value tier).
        assert_eq!(fit_tier(&[(b"USD Coin", Weight::SemiBold)], Region::Docked), Some(Tier::T22));
        // 22 chars docked never fit.
        assert_eq!(fit_tier(&[(&[b'a'; 22], Weight::Regular)], Region::Docked), None);
        // ...but do at full width.
        assert_eq!(fit_tier(&[(&[b'a'; 22], Weight::Regular)], Region::Full), Some(Tier::T28));
        assert_eq!(fit_tier(&[], Region::Docked), None);
    }

    #[test]
    fn width_check_catches_wide_runs_the_char_table_allows() {
        // 12 'W' fits the 36-tier char budget but not 276 px.
        let wide = [b'W'; 12];
        assert!(measure_q6(&wide, 36, false, 0).unwrap() > 276 * 64);
        assert_ne!(fit_tier(&[(&wide, Weight::Regular)], Region::Docked), Some(Tier::T36));
        assert!(fit_tier(&[(&wide, Weight::Regular)], Region::Docked).is_some());
        // 21 'W' at 22 px docked: 21 × ~18 px > 276 → refused, not clipped.
        let w21 = [b'W'; 21];
        assert_eq!(fit_tier(&[(&w21, Weight::Regular)], Region::Docked), None);
        // Unbaked glyph at every tier → None.
        assert_eq!(fit_tier(&[(b"caf\xc3\xa9", Weight::Regular)], Region::Full), None);
    }

    #[test]
    fn fit_is_exhaustive_over_lengths_and_never_panics() {
        for region in [Region::Docked, Region::Full] {
            for n in 0..=40usize {
                let s = [b'0'; 40];
                let r = fit_tier(&[(&s[..n], Weight::Regular)], region);
                if n == 0 || n > region.chars(Tier::T22) {
                    // Empty text still has a tier; overlong never does.
                    assert_eq!(r.is_some(), n == 0 || n <= region.chars(Tier::T22));
                }
                if let Some(t) = r {
                    assert!(n <= region.chars(t));
                }
            }
        }
    }

    #[test]
    fn address_split_is_lossless() {
        let addr = *b"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let [a, b] = split_address(&addr);
        assert_eq!(a.as_bytes(), b"0xA0b86991c6218b36c1d");
        assert_eq!(b.as_bytes(), b"19D4a2e9Eb0cE3606eB48");
        let mut back = [0u8; 42];
        back[..21].copy_from_slice(a.as_bytes());
        back[21..].copy_from_slice(b.as_bytes());
        assert_eq!(back, addr);
        assert_eq!(fit_tier(&[(a.as_bytes(), Weight::Regular), (b.as_bytes(), Weight::Regular)], Region::Docked), Some(Tier::T22));
    }

    #[test]
    fn hash_splits_are_lossless() {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let hex: alloc_free_hex::Hex64 = alloc_free_hex::Hex64::of(&h);
        let [l0, l1, l2] = split_hash_full(&h);
        assert_eq!(l0.as_bytes().len(), 24);
        assert_eq!(l1.as_bytes().len(), 22);
        assert_eq!(l2.as_bytes().len(), 20);
        let mut joined = [0u8; 66];
        joined[..24].copy_from_slice(l0.as_bytes());
        joined[24..46].copy_from_slice(l1.as_bytes());
        joined[46..].copy_from_slice(l2.as_bytes());
        assert_eq!(&joined[..2], b"0x");
        assert_eq!(&joined[2..], &hex.0[..]);
        assert_eq!(fit_tier(&[(l0.as_bytes(), Weight::Regular), (l1.as_bytes(), Weight::Regular), (l2.as_bytes(), Weight::Regular)], Region::Full), Some(Tier::T22));

        let [[a, b], [c, d]] = split_word_docked(&h);
        let mut joined = [0u8; 66];
        joined[..18].copy_from_slice(a.as_bytes());
        joined[18..34].copy_from_slice(b.as_bytes());
        joined[34..50].copy_from_slice(c.as_bytes());
        joined[50..].copy_from_slice(d.as_bytes());
        assert_eq!(&joined[..2], b"0x");
        assert_eq!(&joined[2..], &hex.0[..]);
        for l in [a, b, c, d] {
            assert!(l.as_bytes().len() <= Region::Docked.chars(Tier::T22));
        }
    }

    #[test]
    fn amount_layout_rules() {
        let a = layout_amount(b"0.05", b"ETH", Region::Docked).unwrap();
        assert_eq!((a.n, a.tier), (1, Tier::T36));
        assert_eq!(a.lines[0].as_bytes(), b"0.05 ETH");
        // 15 chars: breaks once after the number at 28.
        let a = layout_amount(b"250.000000", b"USDC", Region::Docked).unwrap();
        assert_eq!((a.n, a.tier), (2, Tier::T28));
        assert_eq!(a.lines[0].as_bytes(), b"250.000000");
        assert_eq!(a.lines[1].as_bytes(), b"USDC");
        // Number past 16 chars → 22.
        let a = layout_amount(b"1234567890.123456789", b"USDC", Region::Docked).unwrap();
        assert_eq!((a.n, a.tier), (2, Tier::T22));
        // Number past 21 chars docked → refused.
        assert_eq!(layout_amount(b"1234567890123456789012", b"USDC", Region::Docked), Err(FitErr::TooWide));
        // ...but fits full width.
        assert!(layout_amount(b"1234567890123456789012", b"units", Region::Full).is_ok());
        assert_eq!(layout_amount(b"", b"ETH", Region::Docked), Err(FitErr::Empty));
        assert_eq!(layout_amount(b"1\xff", b"ETH", Region::Docked), Err(FitErr::Unrenderable));
        // Bare numbers.
        let a = layout_amount(b"250000000", b"", Region::Full).unwrap();
        assert_eq!((a.n, a.tier), (1, Tier::T36));
    }

    #[test]
    fn name_over_address() {
        let addr = *b"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let n = layout_name_over_address(Some(b"USD Coin"), &addr);
        assert_eq!(n.name.unwrap().as_bytes(), b"USD Coin");
        assert!(layout_name_over_address(Some(&[b'W'; 21]), &addr).name.is_none(), "too wide → omitted");
        assert!(layout_name_over_address(Some(&[b'a'; 22]), &addr).name.is_none(), "too long → omitted");
        assert!(layout_name_over_address(Some(b""), &addr).name.is_none());
        assert!(layout_name_over_address(None, &addr).name.is_none());
        assert_eq!(n.addr.n, 2);
        assert_eq!(&n.addr.lines[..2], &split_address(&addr));
    }

    #[test]
    fn wide_addresses_take_three_lines_and_drop_the_name() {
        // An uppercase-heavy EIP-55 string exceeds 276 px at 21 chars per line.
        let wide = *b"0xABABABABABABABABABABABABABABABABABABABAB";
        let a = layout_address(&wide);
        assert_eq!(a.n, 3);
        let mut joined = [0u8; 42];
        joined[..14].copy_from_slice(a.lines[0].as_bytes());
        joined[14..28].copy_from_slice(a.lines[1].as_bytes());
        joined[28..].copy_from_slice(a.lines[2].as_bytes());
        assert_eq!(joined, wide, "three-line split is lossless");
        for l in a.as_slice() {
            assert!(measure_q6(l.as_bytes(), 22, false, 0).unwrap() <= 276 * 64);
        }
        assert!(layout_name_over_address(Some(b"Name"), &wide).name.is_none());
        // A narrow address keeps the two-line form.
        assert_eq!(layout_address(b"0x5afe000000000000000000000000000000000001").n, 2);
    }

    mod alloc_free_hex {
        pub struct Hex64(pub [u8; 64]);
        impl Hex64 {
            pub fn of(b: &[u8; 32]) -> Self {
                let mut o = [0u8; 64];
                for (i, x) in b.iter().enumerate() {
                    o[2 * i] = super::HEX[usize::from(x >> 4)];
                    o[2 * i + 1] = super::HEX[usize::from(x & 15)];
                }
                Self(o)
            }
        }
    }
}
