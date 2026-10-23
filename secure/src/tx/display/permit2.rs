//! Trusted-UI pages for a Uniswap Permit2 permit signed off-chain
//! (`SIGN_OFFCHAIN` kind 6). The pixel UI draws the same facts
//! (`permit2_screens`), bound to these pages by `px_lift`.
//!
//! ```text
//!   header      Sign Permit2? / chain / chain name / what it grants
//!   spender     the spender: verified name, else the full address
//!   [transfer]  ! the spender picks recipient + amount (<= the max shown)
//!   per token   amount (exact; "Unlimited" only for the uint160 max,
//!               "Any amount" only for the uint256 max) · token name over its
//!               FULL address, or the full address + the raw amount word ·
//!               [allowance] expiry + allowance nonce
//!   [transfer]  the one-time nonce (decimal, or the full word)
//!   deadline    the signature deadline (date, or the full word)
//!   confirm     the long-press footer
//! ```
//!
//! Nothing is truncated: an amount the painters cannot show exactly is
//! refused before any page is published
//! ([`permit2_amounts_are_exactly_renderable`]), and values that fit no
//! date (past the year 9999) get the full 32-byte word on its own page.

use super::primitives::{format_u64, hex_nibble, write_addr_full, write_addr_full_or_name, write_chain, write_cow_leg_amount, write_line};
use super::Pages;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::CowLeg;
use crate::tx::eip712::permit2::{VerifiedPermit2, UINT160_MAX_WORD};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_erc7730::display::render::formatters::format_iso8601_utc;
use pqsigner_tx::permit2::Permit2Core;
use sphincs_tz_shared::{PERMIT2_MAX_TOKENS, PERMIT2_VARIANT_BATCH, PERMIT2_VARIANT_SINGLE};

/// The largest timestamp the 4-digit-year date rows can show (9999-12-31T23:59:59Z).
pub(crate) const MAX_DATE_SECS: u64 = 253_402_300_799;

/// Body pages of the worst-case permit (a six-token allowance batch), the
/// handler-owned suffix (2 fingerprint + 3 context pages) included, must fit
/// the page budget: 1 + 1 + 6 x 3 + 1 + 1 + 1 (confirm) + 5.
const _: () = assert!(1 + 1 + PERMIT2_MAX_TOKENS * 3 + 2 + 1 + 5 <= super::MAX_PAGES);
// ... and the worst-case transfer batch (note page, 2 per token, nonce and
// deadline both as full words).
const _: () = assert!(1 + 1 + 1 + PERMIT2_MAX_TOKENS * 2 + 2 + 2 + 1 + 5 <= super::MAX_PAGES);

/// A deadline word as unix seconds, when a date can show it.
pub(crate) fn word_as_date(w: &[u8; 32]) -> Option<u64> {
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    let s = u64::from_be_bytes(b);
    (s <= MAX_DATE_SECS).then_some(s)
}

/// A uint256 word as a `u64` with at most 16 decimal digits (fits one row).
pub(crate) fn word_as_short_decimal(w: &[u8; 32]) -> Option<u64> {
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    let v = u64::from_be_bytes(b);
    (v < 10_000_000_000_000_000).then_some(v)
}

/// How one token amount reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AmountKind {
    /// Exactly `type(uint160).max` on an allowance: never decremented.
    Unlimited,
    /// Exactly `type(uint256).max` on a transfer: no cap on the pull.
    AnyAmount,
    /// Zero on an allowance: the permit revokes it.
    Revoke,
    /// Any other value.
    Value,
}

pub(crate) fn amount_kind(core: &Permit2Core, amount: &[u8; 32]) -> AmountKind {
    if core.is_allowance() {
        if *amount == UINT160_MAX_WORD {
            return AmountKind::Unlimited;
        }
        if *amount == [0u8; 32] {
            return AmountKind::Revoke;
        }
    } else if *amount == [0xff; 32] {
        return AmountKind::AnyAmount;
    }
    AmountKind::Value
}

/// Execute the real amount painter for every token before any page is
/// published; `false` = refuse (an amount the trusted display cannot show
/// exactly).
#[must_use]
pub fn permit2_amounts_are_exactly_renderable(v: &VerifiedPermit2) -> bool {
    v.core.live().iter().zip(v.legs.iter()).all(|(e, leg)| {
        if amount_kind(&v.core, &e.amount) != AmountKind::Value {
            return true;
        }
        match leg {
            CowLeg::Decoded { decimals, symbol, symbol_len, .. } => {
                let mut r1 = [b' '; DISPLAY_COLS];
                let mut r2 = [b' '; DISPLAY_COLS];
                write_cow_leg_amount(&mut r1, &mut r2, &e.amount, *decimals, &symbol[..usize::from(*symbol_len)])
            }
            // Shown as the full word: exact by construction.
            CowLeg::AddrHex => true,
        }
    })
}

/// The header page's third row: what the permit grants.
pub(crate) fn kind_line(core: &Permit2Core) -> &'static str {
    match core.variant {
        PERMIT2_VARIANT_SINGLE => "Allowance",
        PERMIT2_VARIANT_BATCH => "Allowances",
        _ if core.count == 1 => "One-time pull",
        _ => "One-time pulls",
    }
}

/// Body pages for a permit (the confirm page included).
#[must_use]
pub fn permit2_body_pages(v: &VerifiedPermit2) -> usize {
    let c = &v.core;
    let mut n = 2; // header + spender
    if !c.is_allowance() {
        n += 1; // the "spender picks" note
    }
    n += usize::from(c.count) * if c.is_allowance() { 3 } else { 2 };
    if !c.is_allowance() {
        n += if word_as_short_decimal(&c.nonce).is_some() { 1 } else { 2 };
    }
    n += if word_as_date(&c.deadline).is_some() || c.deadline == [0xff; 32] { 1 } else { 2 };
    n + 1
}

fn write_bytes(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS);
    row[..n].copy_from_slice(&bytes[..n]);
}

/// `prefix` then the decimal `v`, or `None` if they do not fit one row.
fn write_prefixed_u64(row: &mut [u8; DISPLAY_COLS], prefix: &[u8], v: u64) -> bool {
    let mut tmp = [0u8; 20];
    let Some(n) = format_u64(v, &mut tmp) else {
        return false;
    };
    if prefix.len() + n > DISPLAY_COLS {
        return false;
    }
    *row = [b' '; DISPLAY_COLS];
    row[..prefix.len()].copy_from_slice(prefix);
    row[prefix.len()..prefix.len() + n].copy_from_slice(&tmp[..n]);
    true
}

/// The token's ordinal label, e.g. `Approve 2/3:` (or `Approve:` alone).
fn ordinal_label(row: &mut [u8; DISPLAY_COLS], verb: &[u8], i: usize, n: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut p = 0;
    for &b in verb {
        row[p] = b;
        p += 1;
    }
    if n > 1 {
        row[p] = b' ';
        row[p + 1] = b'1' + i as u8;
        row[p + 2] = b'/';
        row[p + 3] = b'0' + n as u8;
        p += 4;
    }
    row[p] = b':';
}

/// The undecoded token page's label: `Approve ?token:` alone, or
/// `Appr 2/3 ?tok` in a batch.
fn unknown_token_label(row: &mut [u8; DISPLAY_COLS], kind: AmountKind, allowance: bool, i: usize, n: usize) {
    let (long, short): (&str, &[u8]) = match (allowance, kind) {
        (true, AmountKind::Revoke) => ("Revoke ?token:", b"Revk"),
        (true, _) => ("Approve ?token:", b"Appr"),
        (false, _) => ("Pull max ?token:", b"Pull"),
    };
    if n == 1 {
        write_line(row, long);
        return;
    }
    *row = [b' '; DISPLAY_COLS];
    row[..4].copy_from_slice(short);
    row[4] = b' ';
    row[5] = b'1' + i as u8;
    row[6] = b'/';
    row[7] = b'0' + n as u8;
    row[8..13].copy_from_slice(b" ?tok");
}

/// A 32-byte word as 4 rows x 16 hex characters.
fn write_word_page(pages: &mut Pages, p: usize, word: &[u8; 32]) {
    for r in 0..DISPLAY_ROWS {
        let row = pages.row_mut(p, r);
        *row = [b' '; DISPLAY_COLS];
        for i in 0..8 {
            let b = word[r * 8 + i];
            row[i * 2] = hex_nibble(b >> 4);
            row[i * 2 + 1] = hex_nibble(b & 0x0f);
        }
    }
}

/// The verb the amount page is labelled with.
pub(crate) fn amount_verb(core: &Permit2Core, kind: AmountKind) -> &'static [u8] {
    match (core.is_allowance(), kind) {
        (true, AmountKind::Revoke) => b"Revoke",
        (true, _) => b"Approve",
        (false, _) => b"Pull max",
    }
}

/// Render a verified permit. `wallet` is the signing wallet (a spender equal
/// to it is labelled). `Err` only if a page the budget asserts cover could
/// not be laid out — a refusal, never a truncation.
pub fn render_permit2_offchain_pages(
    v: &VerifiedPermit2,
    wallet: &[u8; 20],
    resolver: &NameResolver<'_>,
) -> Result<Pages, ()> {
    let c = &v.core;
    let total = permit2_body_pages(v);
    if total > super::MAX_PAGES {
        return Err(());
    }
    let mut pages = Pages::empty_with_len(total);
    let mut p = 0;

    // ── Header ──────────────────────────────────────────────────────
    write_line(pages.row_mut(p, 0), "Sign Permit2?");
    {
        let [_, r1, r2, _] = pages.page_mut(p);
        write_chain(r1, r2, c.chain_id);
    }
    write_line(pages.row_mut(p, 3), kind_line(c));
    p += 1;

    // ── Spender ─────────────────────────────────────────────────────
    write_line(pages.row_mut(p, 0), if c.spender == *wallet { "Spender=wallet!" } else { "Spender:" });
    {
        let [_, a, b, d] = pages.page_mut(p);
        write_addr_full_or_name(a, b, d, &c.spender, c.chain_id, resolver);
    }
    p += 1;

    if !c.is_allowance() {
        write_line(pages.row_mut(p, 0), "! Spender picks");
        write_line(pages.row_mut(p, 1), "recipient and");
        write_line(pages.row_mut(p, 2), "amount <= max");
        write_line(pages.row_mut(p, 3), "> next");
        p += 1;
    }

    // ── Tokens ──────────────────────────────────────────────────────
    let n = usize::from(c.count);
    for (i, (e, leg)) in c.live().iter().zip(v.legs.iter()).enumerate() {
        let kind = amount_kind(c, &e.amount);
        let verb = amount_verb(c, kind);
        match leg {
            CowLeg::Decoded { decimals, symbol, symbol_len, name, name_len } => {
                ordinal_label(pages.row_mut(p, 0), verb, i, n);
                {
                    let [_, r1, r2, _] = pages.page_mut(p);
                    let sym = &symbol[..usize::from(*symbol_len)];
                    match kind {
                        AmountKind::Unlimited => {
                            write_line(r1, "Unlimited");
                            write_bytes(r2, sym);
                        }
                        AmountKind::AnyAmount => {
                            write_line(r1, "Any amount");
                            write_bytes(r2, sym);
                        }
                        AmountKind::Revoke | AmountKind::Value => {
                            if !write_cow_leg_amount(r1, r2, &e.amount, *decimals, sym) {
                                return Err(());
                            }
                        }
                    }
                }
                write_line(pages.row_mut(p, 3), "> next");
                write_bytes(pages.row_mut(p + 1, 0), &name[..usize::from(*name_len)]);
                {
                    let [_, a, b, d] = pages.page_mut(p + 1);
                    write_addr_full(a, b, d, &e.token);
                }
                p += 2;
            }
            CowLeg::AddrHex => {
                // No verified metadata: the full token address under a
                // "?token" label, then the amount as its full raw word (or,
                // for the three exact sentinels, what the word means).
                unknown_token_label(pages.row_mut(p, 0), kind, c.is_allowance(), i, n);
                {
                    let [_, a, b, d] = pages.page_mut(p);
                    write_addr_full(a, b, d, &e.token);
                }
                match kind {
                    AmountKind::Value => write_word_page(&mut pages, p + 1, &e.amount),
                    _ => {
                        let (r1, r2) = match kind {
                            AmountKind::Unlimited => ("Unlimited", "(uint160 max)"),
                            AmountKind::AnyAmount => ("Any amount", "(uint256 max)"),
                            _ => ("0 (revoke)", ""),
                        };
                        write_line(pages.row_mut(p + 1, 0), "Amount (raw):");
                        write_line(pages.row_mut(p + 1, 1), r1);
                        write_line(pages.row_mut(p + 1, 2), r2);
                        write_line(pages.row_mut(p + 1, 3), "> next");
                    }
                }
                p += 2;
            }
        }
        if c.is_allowance() {
            write_line(pages.row_mut(p, 0), "Expiry; nonce:");
            {
                let [_, r1, r2, r3] = pages.page_mut(p);
                if e.expiration == 0 {
                    write_line(r1, "this block only");
                    write_line(r2, "(expiration 0)");
                } else if e.expiration <= MAX_DATE_SECS {
                    if !format_iso8601_utc(e.expiration, r1, r2) {
                        return Err(());
                    }
                } else {
                    write_line(r1, "! far future");
                    if !write_prefixed_u64(r2, b"", e.expiration) {
                        return Err(());
                    }
                }
                if !write_prefixed_u64(r3, b"nonce ", e.nonce) && !write_prefixed_u64(r3, b"#", e.nonce) {
                    return Err(());
                }
            }
            p += 1;
        }
    }

    // ── One-time nonce ──────────────────────────────────────────────
    if !c.is_allowance() {
        write_line(pages.row_mut(p, 0), "Nonce (1-time):");
        match word_as_short_decimal(&c.nonce) {
            Some(nonce) => {
                if !write_prefixed_u64(pages.row_mut(p, 1), b"", nonce) {
                    return Err(());
                }
                write_line(pages.row_mut(p, 3), "> next");
                p += 1;
            }
            None => {
                write_line(pages.row_mut(p, 1), "(word, next pg)");
                write_line(pages.row_mut(p, 3), "> next");
                write_word_page(&mut pages, p + 1, &c.nonce);
                p += 2;
            }
        }
    }

    // ── Deadline ────────────────────────────────────────────────────
    write_line(pages.row_mut(p, 0), if c.is_allowance() { "Sig valid until:" } else { "Valid until:" });
    if let Some(secs) = word_as_date(&c.deadline) {
        let [_, r1, r2, _] = pages.page_mut(p);
        if !format_iso8601_utc(secs, r1, r2) {
            return Err(());
        }
        write_line(pages.row_mut(p, 3), "> next");
        p += 1;
    } else if c.deadline == [0xff; 32] {
        write_line(pages.row_mut(p, 1), "! no deadline");
        write_line(pages.row_mut(p, 2), "(uint256 max)");
        write_line(pages.row_mut(p, 3), "> next");
        p += 1;
    } else {
        write_line(pages.row_mut(p, 1), "! far future");
        write_line(pages.row_mut(p, 2), "(word, next pg)");
        write_line(pages.row_mut(p, 3), "> next");
        write_word_page(&mut pages, p + 1, &c.deadline);
        p += 2;
    }

    // ── Confirm ─────────────────────────────────────────────────────
    write_line(pages.row_mut(p, 0), "");
    write_line(pages.row_mut(p, 1), "  Long-press:");
    write_line(pages.row_mut(p, 2), "L=Cancel");
    write_line(pages.row_mut(p, 3), "R=Confirm");
    p += 1;

    if p != total {
        return Err(());
    }
    Ok(pages)
}
