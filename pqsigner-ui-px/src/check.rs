//! The design rules as a deterministic checker over emitted screen records
//! (the firmware-facing twin of upstream `tools/check` — which walks the
//! live Python and cannot see a firmware transcript).
//!
//! Two entry points: [`check_screens`] applies the per-record rules to any
//! sequence of screens (a body under test, a golden fixture); [`check_flow`]
//! adds the flow-shape rules of a finished confirmation transcript (opening
//! and returning hero, the `Confirm?` rule, no page-wrapped `Legacy`
//! record). Every rule here is one that a firmware emitter could drift from
//! without a compile error; the host tests run the checker on every
//! scenario so such a drift is a red test, not a design regression on the
//! glass.
//!
//! Rules (DESIGN.md § Pre-ship check, § Flow shape, § Text rules, and
//! upstream `tools/check` F-CONFIRM / the `layout.insert_confirm` and
//! CHAIN placement build errors):
//!
//! * every record is well-formed printable ASCII;
//! * a detail / value screen carries a valid tier (36 / 32 / 28 / 22 — so
//!   never below the 12 px floor) and every line fits its region at that
//!   tier both by character budget and by measured width: nothing is ever
//!   truncated;
//! * a value screen shows one value: 1–3 regular lines, no SemiBold head;
//! * commit is armed only on a hero or the `Confirm?`;
//! * a `0x…` word on a screen is unbroken: its hex digits, across the
//!   screen's lines and pages, total 40 (an address) or 64 (a 32-byte word);
//! * a chain screen (`CHAIN`) follows the `TO` or `AMOUNT` it qualifies;
//! * flow shape: hero first (committing), last byte-equal to it, exactly
//!   two heroes; `Confirm?` exactly at index 5 iff ≥ 7 detail-like screens,
//!   else none; no `Legacy` record.

use crate::fit::{measure_q6, Region};
use crate::screen::{screen_exact, Kind, Screen, Screens, Tier, Weight};

/// Why a transcript failed the design rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    Empty,
    Malformed(usize),
    NotHeroFirst,
    NotHeroLast,
    HeroCount(usize),
    LegacyPresent(usize),
    /// The `Confirm?` rule: where it is (if anywhere) vs the detail count.
    ConfirmMisplaced { at: Option<usize>, details: usize },
    TierMissing(usize),
    LineOverflow { screen: usize, page: u8, line: u8 },
    ValueNotSingle(usize),
    CommitOnDetail(usize),
    AddressBroken(usize),
    ChainPlacement(usize),
    /// A caption / label byte its face does not carry (it would silently
    /// vanish on the glass: the 18 px caption and 16 px label faces are caps,
    /// digits and `?.,:/-'&%+!()`).
    GlyphMissing(usize),
}

/// `Confirm?` sits here when the rule inserts it.
pub const CONFIRM_INDEX: usize = 5;
/// … and the rule inserts it from this many detail-like screens.
pub const CONFIRM_MIN_DETAILS: usize = 7;

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// The per-record rules over `screens`.
pub fn check_screens(screens: &[Screen]) -> Result<(), Violation> {
    if screens.is_empty() {
        return Err(Violation::Empty);
    }
    for (i, s) in screens.iter().enumerate() {
        if !s.is_well_formed() {
            return Err(Violation::Malformed(i));
        }
        let kind = s.kind().ok_or(Violation::Malformed(i))?;
        if s.commit() && !kind.may_commit() {
            return Err(Violation::CommitOnDetail(i));
        }
        if matches!(kind, Kind::Detail | Kind::Value) {
            let tier = s.tier().ok_or(Violation::TierMissing(i))?;
            let region = if kind == Kind::Value { Region::Full } else { Region::Docked };
            let budget_q6 = u32::from(region.width_px()) * 64;
            let mut lines_total = 0usize;
            let mut semibold = false;
            for p in 0..s.npages() {
                for l in 0..s.nlines(p) {
                    let (w, text) = s.line(p, l).ok_or(Violation::Malformed(i))?;
                    lines_total += 1;
                    let sb = matches!(w, Weight::SemiBold);
                    semibold |= sb;
                    let fits = text.len() <= region.chars(tier)
                        && measure_q6(text, tier.px(), sb, 0).is_some_and(|px| px <= budget_q6);
                    if !fits {
                        return Err(Violation::LineOverflow { screen: i, page: p, line: l });
                    }
                }
            }
            if kind == Kind::Value && (lines_total == 0 || semibold) {
                return Err(Violation::ValueNotSingle(i));
            }
            check_words_unbroken(s, i)?;
        }
        // The caption (18 px regular; a words grid's band label is 16 px
        // SemiBold) and the detail label (16 px SemiBold) must be drawable.
        let caption_face = if kind == Kind::Words { (16, true) } else { (18, false) };
        let drawable = |text: &[u8], (px, sb): (u8, bool)| text.iter().all(|&b| b == b' ' || crate::fit::advance_q6(px, sb, b).is_some());
        if !matches!(kind, Kind::Legacy | Kind::Confirm)
            && (!drawable(s.caption(), caption_face) || !drawable(s.label(), (16, true)))
        {
            return Err(Violation::GlyphMissing(i));
        }
        if s.id() == b"CHAIN" {
            let prev = i.checked_sub(1).map(|j| screens[j].id());
            if !matches!(prev, Some(b"TO" | b"AMOUNT")) {
                return Err(Violation::ChainPlacement(i));
            }
        }
    }
    Ok(())
}

/// A `0x` word's hex digits, gathered across the following hex-only lines
/// (and pages), must total 40 or 64.
fn check_words_unbroken(s: &Screen, i: usize) -> Result<(), Violation> {
    let mut run: Option<usize> = None;
    let finish = |run: &mut Option<usize>| -> Result<(), Violation> {
        if let Some(n) = run.take() {
            if n != 40 && n != 64 {
                return Err(Violation::AddressBroken(i));
            }
        }
        Ok(())
    };
    for p in 0..s.npages() {
        for l in 0..s.nlines(p) {
            let Some((_, text)) = s.line(p, l) else { continue };
            if text.starts_with(b"0x") && text[2..].iter().all(|&b| is_hex(b)) {
                finish(&mut run)?;
                run = Some(text.len() - 2);
            } else if run.is_some() && !text.is_empty() && text.iter().all(|&b| is_hex(b)) {
                if let Some(n) = run.as_mut() {
                    *n += text.len();
                }
            } else {
                finish(&mut run)?;
            }
        }
    }
    finish(&mut run)
}

/// The per-record rules plus the flow shape of a finished transcript.
pub fn check_flow(screens: &Screens) -> Result<(), Violation> {
    let visible = screens.as_slice();
    check_screens(visible)?;
    let first = &visible[0];
    if first.kind() != Some(Kind::Hero) || !first.commit() {
        return Err(Violation::NotHeroFirst);
    }
    let last = &visible[visible.len() - 1];
    if visible.len() < 2 || !screen_exact(first, last) {
        return Err(Violation::NotHeroLast);
    }
    let heroes = visible.iter().filter(|s| s.kind() == Some(Kind::Hero)).count();
    if heroes != 2 {
        return Err(Violation::HeroCount(heroes));
    }
    if let Some(i) = visible.iter().position(|s| s.kind() == Some(Kind::Legacy)) {
        return Err(Violation::LegacyPresent(i));
    }
    let details = visible.iter().filter(|s| s.kind().is_some_and(Kind::is_detail_like)).count();
    let at = visible.iter().position(|s| s.kind() == Some(Kind::Confirm));
    let confirms = visible.iter().filter(|s| s.kind() == Some(Kind::Confirm)).count();
    let expected = if details >= CONFIRM_MIN_DETAILS { Some(CONFIRM_INDEX) } else { None };
    if at != expected || confirms > 1 {
        return Err(Violation::ConfirmMisplaced { at, details });
    }
    let _ = Tier::T22;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::{Icon, ScreenBuilder, Side};

    fn hero() -> Screen {
        ScreenBuilder::hero(b"APPROVE", Icon::Safe, b"APPROVE SAFE TX?").finish().unwrap()
    }
    fn detail(id: &[u8], lines: &[&[u8]]) -> Screen {
        let mut b = ScreenBuilder::detail(id, Icon::Safe, Side::Left, b"LABEL").tier(Tier::T22);
        for l in lines {
            b = b.line(l, Weight::Regular);
        }
        b.finish().unwrap()
    }
    fn flow(n_details: usize, confirm: bool) -> Screens {
        let mut s = Screens::blank();
        s.push(&hero()).unwrap();
        for i in 0..n_details {
            if confirm && s.len() == CONFIRM_INDEX {
                s.push(&ScreenBuilder::confirm(Icon::Safe).finish().unwrap()).unwrap();
            }
            let _ = i;
            s.push(&detail(b"D", &[b"value"])).unwrap();
        }
        if confirm && s.len() == CONFIRM_INDEX {
            s.push(&ScreenBuilder::confirm(Icon::Safe).finish().unwrap()).unwrap();
        }
        s.push(&hero()).unwrap();
        s
    }

    #[test]
    fn accepts_the_two_confirm_shapes() {
        assert_eq!(check_flow(&flow(3, false)), Ok(()));
        assert_eq!(check_flow(&flow(7, true)), Ok(()));
    }

    #[test]
    fn confirm_rule_is_two_sided() {
        assert!(matches!(check_flow(&flow(7, false)), Err(Violation::ConfirmMisplaced { at: None, details: 7 })));
        // A Confirm? in a flow below the threshold, wherever it sits.
        let mut s = Screens::blank();
        s.push(&hero()).unwrap();
        s.push(&detail(b"D", &[b"a"])).unwrap();
        s.push(&detail(b"D", &[b"b"])).unwrap();
        s.push(&ScreenBuilder::confirm(Icon::Safe).finish().unwrap()).unwrap();
        s.push(&detail(b"D", &[b"c"])).unwrap();
        s.push(&hero()).unwrap();
        assert!(matches!(check_flow(&s), Err(Violation::ConfirmMisplaced { at: Some(3), details: 3 })));
        // Enough details but the Confirm? off its index.
        let mut s = flow(7, false);
        s.buf[4] = ScreenBuilder::confirm(Icon::Safe).finish().unwrap();
        assert!(matches!(check_flow(&s), Err(Violation::ConfirmMisplaced { at: Some(4), details: 6 })));
    }

    #[test]
    fn hero_shape_and_legacy() {
        let mut s = flow(3, false);
        let last = s.len() - 1;
        s.buf[last] = detail(b"D", &[b"x"]);
        assert_eq!(check_flow(&s), Err(Violation::NotHeroLast));
        let mut s = flow(3, false);
        s.buf[1] = Screen::legacy(&[[b' '; 16]; 4]);
        assert!(matches!(check_flow(&s), Err(Violation::LegacyPresent(1))));
        // A commit-armed detail is already malformed at the record level
        // (`is_well_formed`); the explicit rule is belt and braces.
        let mut s = flow(3, false);
        s.buf[2].0[5] = b'Y';
        assert_eq!(check_flow(&s), Err(Violation::Malformed(2)));
    }

    #[test]
    fn words_must_be_unbroken() {
        let ok = detail(b"TO", &[b"0x5a5A5a5a5A5a5a5a5a5", b"A5a5A5A5a5a5A5A5A5A5A"]);
        assert_eq!(check_screens(&[ok]), Ok(()));
        let short = detail(b"TO", &[b"0x5a5A5a5a5A5a5a5a5a5", b"A5a5A5A5a5a5A5A5A5A5"]);
        assert_eq!(check_screens(&[short]), Err(Violation::AddressBroken(0)));
        let hash = ScreenBuilder::value(b"H", Icon::Safe, b"HASH")
            .tier(Tier::T22)
            .line(b"0x65a2f079b0f8a8dab455a6", Weight::Regular)
            .line(b"d59796e93aa75e2bb981b9", Weight::Regular)
            .line(b"d2da4c074b1c3e8bc4c4", Weight::Regular)
            .finish()
            .unwrap();
        assert_eq!(check_screens(&[hash]), Ok(()));
    }

    #[test]
    fn value_screens_carry_one_value_and_lines_fit() {
        let sb = ScreenBuilder::value(b"V", Icon::Safe, b"V")
            .tier(Tier::T22)
            .line(b"head", Weight::SemiBold)
            .line(b"1.5 ETH", Weight::Regular)
            .finish()
            .unwrap();
        assert_eq!(check_screens(&[sb]), Err(Violation::ValueNotSingle(0)));
        // 22 characters do not fit a docked line at tier 36.
        let wide = ScreenBuilder::detail(b"D", Icon::Safe, Side::Left, b"L")
            .tier(Tier::T36)
            .line(b"WWWWWWWWWWWWWWWWWWWWWW", Weight::Regular)
            .finish()
            .unwrap();
        assert!(matches!(check_screens(&[wide]), Err(Violation::LineOverflow { screen: 0, page: 0, line: 0 })));
    }

    #[test]
    fn chain_follows_to_or_amount() {
        let to = detail(b"TO", &[b"0x5a5A5a5a5A5a5a5a5a5", b"A5a5A5A5a5a5A5A5A5A5A"]);
        let chain = detail(b"CHAIN", &[b"Base"]);
        assert_eq!(check_screens(&[to, chain]), Ok(()));
        assert_eq!(check_screens(&[chain, to]), Err(Violation::ChainPlacement(0)));
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::*;
    use crate::screen::{Icon, ScreenBuilder, Side};

    /// The flow checker is total over any small transcript shape built from
    /// the three record kinds, and accepts exactly the two-sided Confirm?
    /// rule on well-formed flows.
    #[kani::proof]
    #[kani::unwind(12)]
    fn check_flow_total_and_confirm_rule_exact() {
        let n: usize = kani::any();
        kani::assume((2..=10).contains(&n));
        let hero = ScreenBuilder::hero(b"ASK", Icon::Safe, b"ASK?").finish().unwrap();
        let detail = ScreenBuilder::detail(b"D", Icon::Safe, Side::Left, b"L")
            .tier(Tier::T22)
            .line(b"x", Weight::Regular)
            .finish()
            .unwrap();
        let confirm = ScreenBuilder::confirm(Icon::Safe).finish().unwrap();
        let mut s = Screens::blank();
        s.push(&hero).unwrap();
        for _ in 1..n - 1 {
            s.push(if kani::any() { &detail } else { &confirm }).unwrap();
        }
        s.push(&hero).unwrap();
        let r = check_flow(&s);
        let details = s.as_slice().iter().filter(|x| x.kind() == Some(Kind::Detail)).count();
        let confirms = s.as_slice().iter().filter(|x| x.kind() == Some(Kind::Confirm)).count();
        let at = s.as_slice().iter().position(|x| x.kind() == Some(Kind::Confirm));
        let rule_ok = if details >= CONFIRM_MIN_DETAILS { confirms == 1 && at == Some(CONFIRM_INDEX) } else { confirms == 0 };
        assert_eq!(r.is_ok(), rule_ok);
    }
}
