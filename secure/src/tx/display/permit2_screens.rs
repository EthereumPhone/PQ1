//! Pixel-UI screens for a Uniswap Permit2 permit signed off-chain
//! (`SIGN_OFFCHAIN` kind 6) — the second painter over
//! `permit2::render_permit2_offchain_pages`, bound to it by `px_lift`.
//!
//! ```text
//!  PERMIT2 APPROVE USDC?              hero (`PERMIT2` moves Confirm? past the body)
//!  NETWORK · KIND · SPENDER
//!  per token: AMOUNT · TOKEN · [EXPIRY]   (allowance)   AMOUNT · TOKEN   (pull)
//!  [NONCE]                            the one-time nonce (pulls)
//!  DEADLINE
//! ```
//!
//! Same facts and the same exactness rules as the pages: "unlimited" only
//! for the exact `uint160` maximum, "any amount" only for the exact
//! `uint256` maximum, an expiration of 0 is "this block only", a value no
//! date can show is the full 32-byte word, and a token with no verified
//! metadata is its full address plus the raw amount word.

use super::permit2::{
    amount_kind, amount_verb, kind_line, permit2_body_pages, word_as_date, word_as_short_decimal, AmountKind,
    MAX_DATE_SECS,
};
use super::screen_kit::{addr42, address_look, caption_fits, token_amount_as_page, token_look, wrap, BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::U256;
use crate::tx::eip712::cowswap::CowLeg;
use crate::tx::eip712::permit2::{VerifiedPermit2, PERMIT2_ADDRESS};
use crate::ui::DISPLAY_COLS;
use pqsigner_erc7730::display::render::formatters::format_iso8601_utc;
use pqsigner_tx::permit2::Permit2Core;
use pqsigner_ui_px::fit::{layout_address, Region};
use pqsigner_ui_px::{Icon, Screens, Weight};

/// The hero id. Listed in `pqsigner_ui_px::screen::STRUCTURED_OFFCHAIN_HERO_IDS`,
/// so `Confirm?` follows the whole permit (the off-chain rule).
pub(crate) const HERO_ID: &[u8] = b"PERMIT2";

const SIGNED: &[u8] = b"PERMIT2 SIGNED";
const DECLINED: &[u8] = b"PERMIT2 DECLINED";
const FAILED: &[u8] = b"PERMIT2 FAILED";

const IDS_AMT: [&[u8]; 6] = [b"AMT1", b"AMT2", b"AMT3", b"AMT4", b"AMT5", b"AMT6"];
const IDS_TOK: [&[u8]; 6] = [b"TOK1", b"TOK2", b"TOK3", b"TOK4", b"TOK5", b"TOK6"];
const IDS_EXP: [&[u8]; 6] = [b"EXP1", b"EXP2", b"EXP3", b"EXP4", b"EXP5", b"EXP6"];

/// The disc: a single token's look (the ERC-20 approve family's), a batch
/// the Permit2 contract's hashed ramp.
pub(crate) fn family(v: &VerifiedPermit2) -> Family {
    let look = match (&v.legs[0], v.core.count) {
        (CowLeg::Decoded { symbol, symbol_len, .. }, 1) => token_look(&symbol[..usize::from(*symbol_len)]),
        (CowLeg::AddrHex, 1) => address_look(Icon::Eth, &v.core.entries[0].token),
        _ => address_look(Icon::Eth, &PERMIT2_ADDRESS),
    };
    Family { look, signed: SIGNED, declined: DECLINED, failed: FAILED }
}

fn symbol_of(leg: &CowLeg) -> Option<&[u8]> {
    match leg {
        CowLeg::Decoded { symbol, symbol_len, .. } => Some(&symbol[..usize::from(*symbol_len)]),
        CowLeg::AddrHex => None,
    }
}

/// `PERMIT2 APPROVE USDC?`, `PERMIT2 APPROVE 3 TOKENS?`, `PERMIT2 ONE-TIME
/// PULL USDC?` … — the most specific caption that fits, else the generic.
fn hero(e: &mut Emit<'_>, v: &VerifiedPermit2) -> Result<(), ()> {
    let c = &v.core;
    let single_kind = amount_kind(c, &c.entries[0].amount);
    let verb: &[u8] = match (c.is_allowance(), single_kind, c.count) {
        (true, AmountKind::Revoke, 1) => b"PERMIT2 REVOKE",
        (true, _, _) => b"PERMIT2 APPROVE",
        (false, _, _) => b"PERMIT2 ONE-TIME PULL",
    };
    if c.count == 1 {
        if let Some(sym) = symbol_of(&v.legs[0]) {
            let t = Text::new().push(verb).push(b" ").push(sym).push(b"?");
            if t.ok() && caption_fits(t.as_bytes()) {
                return e.hero(HERO_ID, t.as_bytes());
            }
        }
    } else {
        let t = Text::new().push(verb).push(b" ").push_u64(u64::from(c.count)).push(b" TOKENS?");
        if t.ok() && caption_fits(t.as_bytes()) {
            return e.hero(HERO_ID, t.as_bytes());
        }
    }
    let t = Text::new().push(verb).push(b"?");
    if t.ok() && caption_fits(t.as_bytes()) {
        return e.hero(HERO_ID, t.as_bytes());
    }
    e.hero(HERO_ID, b"SIGN PERMIT2?")
}

/// `APPROVE 2/3`, `PULL MAX`, … (the page painter's label, upper-cased, no
/// colon; at most 12 characters: `PULL MAX 6/6`).
fn ordinal(verb: &[u8], i: usize, n: usize) -> Text {
    let mut up = [0u8; 8];
    let verb = &verb[..verb.len().min(up.len())];
    for (d, s) in up.iter_mut().zip(verb) {
        *d = s.to_ascii_uppercase();
    }
    let t = Text::new().push(&up[..verb.len()]);
    if n > 1 {
        t.push(b" ").push_u64(i as u64 + 1).push(b"/").push_u64(n as u64)
    } else {
        t
    }
}

/// A verified name (a token's, the spender's) over the FULL address, on one
/// page when both fit, else over two (never an address split across pages).
fn token_detail(e: &mut Emit<'_>, id: &[u8], label: &[u8], name: &[u8], token: &[u8; 20]) -> Result<(), ()> {
    let addr = layout_address(&addr42(token));
    let name = wrap(name, Region::Docked).ok_or(())?;
    let mut nl: [(&[u8], Weight); 3] = [(&[], Weight::SemiBold); 3];
    let mut al: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
    if name.n > nl.len() {
        return Err(());
    }
    for (d, l) in nl.iter_mut().zip(name.as_slice()) {
        d.0 = l.as_bytes();
    }
    for (d, l) in al.iter_mut().zip(addr.as_slice()) {
        d.0 = l.as_bytes();
    }
    let (nn, an) = (name.n, addr.as_slice().len());
    if nn + an <= 3 {
        let mut both: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
        both[..nn].copy_from_slice(&nl[..nn]);
        both[nn..nn + an].copy_from_slice(&al[..an]);
        e.detail(id, label, &both[..nn + an], false)
    } else {
        e.detail_two_pages(id, label, &nl[..nn], &al[..an], false)
    }
}

/// A date as its page rows' two strings (`YYYY-MM-DD`, `HH:MM:SS UTC`).
fn date_rows(secs: u64) -> Option<([u8; DISPLAY_COLS], [u8; DISPLAY_COLS])> {
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    format_iso8601_utc(secs, &mut r1, &mut r2).then_some((r1, r2))
}

fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    &row[..end]
}

fn emit_token(e: &mut Emit<'_>, c: &Permit2Core, i: usize, leg: &CowLeg) -> Result<(), ()> {
    let n = usize::from(c.count);
    let entry = &c.entries[i];
    let kind = amount_kind(c, &entry.amount);
    let label = ordinal(amount_verb(c, kind), i, n);
    let tok_label = if n > 1 { Text::new().push(b"TOKEN ").push_u64(i as u64 + 1).push(b"/").push_u64(n as u64) } else { Text::new().push(b"TOKEN") };
    let sentinel: Option<(&[u8], &[u8])> = match kind {
        AmountKind::Unlimited => Some((b"Unlimited", b"(uint160 max)")),
        AmountKind::AnyAmount => Some((b"Any amount", b"(uint256 max)")),
        _ => None,
    };
    match leg {
        CowLeg::Decoded { decimals, symbol, symbol_len, name, name_len } => {
            let sym = &symbol[..usize::from(*symbol_len)];
            match sentinel {
                Some((what, why)) => e.detail(
                    IDS_AMT[i],
                    label.as_bytes(),
                    &[(what, Weight::Regular), (sym, Weight::Regular), (why, Weight::Regular)],
                    true,
                )?,
                None => {
                    let meta = Erc20Metadata { chain_id: 0, contract: [0u8; 20], decimals: *decimals, name: &[], symbol: sym };
                    let amt = token_amount_as_page(&U256(entry.amount), &meta).ok_or(())?;
                    e.amount(IDS_AMT[i], label.as_bytes(), &amt, kind == AmountKind::Revoke)?;
                }
            }
            token_detail(e, IDS_TOK[i], tok_label.as_bytes(), &name[..usize::from(*name_len)], &entry.token)?;
        }
        CowLeg::AddrHex => {
            let addr = layout_address(&addr42(&entry.token));
            e.addr_lines(IDS_TOK[i], tok_label.as_bytes(), &addr, Some(b"! Unknown token"))?;
            match (sentinel, kind) {
                (Some((what, why)), _) => {
                    e.detail(IDS_AMT[i], label.as_bytes(), &[(what, Weight::Regular), (why, Weight::Regular)], true)?;
                }
                (None, AmountKind::Revoke) => {
                    e.detail(IDS_AMT[i], label.as_bytes(), &[(b"0 (revoke)", Weight::Regular)], true)?;
                }
                _ => e.word_value(IDS_AMT[i], label.as_bytes(), &entry.amount)?,
            }
        }
    }
    if c.is_allowance() {
        let nonce = Text::new().push(b"nonce ").push_u64(entry.nonce);
        let exp_label: &[u8] = b"EXPIRES";
        if entry.expiration == 0 {
            e.detail(
                IDS_EXP[i],
                exp_label,
                &[(b"this block only", Weight::Regular), (b"(expiration 0)", Weight::Regular), (nonce.as_bytes(), Weight::Regular)],
                true,
            )?;
        } else if entry.expiration <= MAX_DATE_SECS {
            let (d, t) = date_rows(entry.expiration).ok_or(())?;
            e.detail(
                IDS_EXP[i],
                exp_label,
                &[(trimmed(&d), Weight::Regular), (trimmed(&t), Weight::Regular), (nonce.as_bytes(), Weight::Regular)],
                false,
            )?;
        } else {
            let unix = Text::new().push_u64(entry.expiration);
            e.detail(
                IDS_EXP[i],
                exp_label,
                &[(b"! far future", Weight::Regular), (unix.as_bytes(), Weight::Regular), (nonce.as_bytes(), Weight::Regular)],
                true,
            )?;
        }
    }
    Ok(())
}

/// Screens [`emit_offchain`] produces.
pub(crate) fn body_screens(v: &VerifiedPermit2) -> usize {
    let c = &v.core;
    let per = if c.is_allowance() { 3 } else { 2 };
    4 + usize::from(c.count) * per + usize::from(!c.is_allowance()) + 1
}

/// The permit, hero first. `wallet` is the signing wallet.
pub(crate) fn emit_offchain(
    out: &mut Screens,
    v: &VerifiedPermit2,
    wallet: &[u8; 20],
    resolver: &NameResolver<'_>,
) -> Result<BodyReceipt, ()> {
    let c = &v.core;
    let mut e = Emit::new(out, c.chain_id, family(v).look);
    hero(&mut e, v)?;
    e.network()?;

    // ── KIND ────────────────────────────────────────────────────────
    let kind = kind_line(c).as_bytes();
    if c.is_allowance() {
        e.detail(b"KIND", b"PERMIT2", &[(kind, Weight::Regular), (b"reusable until expiry", Weight::Regular)], false)?;
    } else {
        e.detail_two_pages(
            b"KIND",
            b"PERMIT2",
            &[(kind, Weight::Regular), (b"! Spender picks", Weight::Regular)],
            &[(b"recipient and", Weight::Regular), (b"amount <= max", Weight::Regular)],
            true,
        )?;
    }

    // ── SPENDER ─────────────────────────────────────────────────────
    // A verified name (or the this-wallet warning) over the FULL address;
    // `Emit::addr` would drop a name too wide for one docked line
    // ("Uniswap Universal Router"), so the name wraps instead.
    if c.spender == *wallet {
        token_detail(&mut e, b"SPENDER", b"SPENDER", b"! = this wallet", &c.spender)?;
    } else if let Some(name) = resolver.lookup(c.chain_id, &c.spender) {
        token_detail(&mut e, b"SPENDER", b"SPENDER", name, &c.spender)?;
    } else {
        let a = layout_address(&addr42(&c.spender));
        e.addr_lines(b"SPENDER", b"SPENDER", &a, None)?;
    }

    // ── Tokens ──────────────────────────────────────────────────────
    for i in 0..usize::from(c.count) {
        emit_token(&mut e, c, i, &v.legs[i])?;
    }

    // ── One-time nonce ──────────────────────────────────────────────
    if !c.is_allowance() {
        match word_as_short_decimal(&c.nonce) {
            Some(n) => {
                let t = Text::new().push_u64(n);
                e.detail(b"NONCE", b"PULL NONCE", &[(t.as_bytes(), Weight::Regular), (b"(one-time)", Weight::Regular)], false)?;
            }
            None => e.word_value(b"NONCE", b"PULL NONCE", &c.nonce)?,
        }
    }

    // ── Deadline ────────────────────────────────────────────────────
    let dl_label: &[u8] = if c.is_allowance() { b"SIG DEADLINE" } else { b"DEADLINE" };
    if let Some(secs) = word_as_date(&c.deadline) {
        let (d, t) = date_rows(secs).ok_or(())?;
        e.detail(b"DEADLINE", dl_label, &[(trimmed(&d), Weight::Regular), (trimmed(&t), Weight::Regular)], false)?;
    } else if c.deadline == [0xff; 32] {
        e.detail(b"DEADLINE", dl_label, &[(b"! no deadline", Weight::Regular), (b"(uint256 max)", Weight::Regular)], true)?;
    } else {
        e.word_value(b"DEADLINE", dl_label, &c.deadline)?;
    }

    if e.n != body_screens(v) {
        return Err(());
    }
    Ok(BodyReceipt { screens: e.n, legacy_pages: permit2_body_pages(v) })
}
