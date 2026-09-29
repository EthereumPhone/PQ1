//! Pixel-UI screens for the blind sign — the second painter over
//! `blind_sign::render_blind_sign_pages` (upstream `blind/bare_call`,
//! `blind/call_with_value`, `blind/unknown_call`).
//!
//! ```text
//!  CONFIRM UNKNOWN CALL? · NETWORK · BLIND SIGN · [FUNCTION|GUESS] · TO · AMOUNT
//!  · CALL DATA · DATA HASH · MAX FEE · WORST CASE · DETAILS
//! ```
//!
//! Where the page painter showed 16 of the 32 calldata-hash bytes and the
//! first 32 characters of the function signature, the screens show all of
//! them. The disc is the blind mark on the placeholder ramp hashed from the
//! call target.

use sha2::{Digest, Sha256};

use super::primitives::native_ticker;
use super::screen_kit::{address_look, native_amount, wrap, BodyReceipt, Emit, Text};
use super::userop_screens::{emit_fee_and_details, Family};
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::eip1559::Eip1559Tx;
use pqsigner_ui_px::fit::Region;
use pqsigner_ui_px::screen::LINES_PER_PAGE;
use pqsigner_ui_px::{Icon, Look, Screens, Weight};

pub(crate) fn family(tx: &Eip1559Tx) -> Family {
    Family {
        look: target_look(tx),
        signed: b"UNKNOWN CALL SIGNED",
        declined: b"UNKNOWN CALL DECLINED",
    }
}

/// The blind mark on the ramp hashed from the call target.
pub(crate) fn target_look(tx: &Eip1559Tx) -> Look {
    match &tx.to {
        Some(to) => address_look(Icon::Blind, to),
        None => Look::plain(Icon::Blind),
    }
}

/// `FUNCTION` (curated) / `GUESS` (self-attested) over the whole text
/// signature, wrapped; `head` is an optional loud first line.
pub(crate) fn emit_function(e: &mut Emit<'_>, meta: &SelectorMeta<'_>, head: Option<&[u8]>) -> Result<(), ()> {
    let (id, label, loud): (&[u8], &[u8], bool) = match meta.provenance {
        SelectorProvenance::Curated => (b"FUNCTION", b"FUNCTION", false),
        SelectorProvenance::SelfAttest => (b"GUESS", b"GUESS", true),
    };
    let w = wrap(meta.text_sig, Region::Docked).ok_or(())?;
    let mut lines: [(&[u8], Weight); 2 * LINES_PER_PAGE] = [(b"", Weight::Regular); 2 * LINES_PER_PAGE];
    let mut n = 0usize;
    if let Some(h) = head {
        lines[0] = (h, Weight::SemiBold);
        n = 1;
    }
    for l in w.as_slice() {
        if n >= lines.len() {
            return Err(());
        }
        lines[n] = (l.as_bytes(), Weight::Regular);
        n += 1;
    }
    e.detail_multi(id, label, &lines[..n], loud || head.is_some())
}

/// `TO` (the call target, or the contract-creation marker).
pub(crate) fn emit_to(e: &mut Emit<'_>, tx: &Eip1559Tx, resolver: &NameResolver<'_>) -> Result<(), ()> {
    match &tx.to {
        Some(to) => e.addr(b"TO", b"TO", to, resolver),
        None => e.detail(b"TO", b"TO", &[(b"(contract create)", Weight::Regular)], true),
    }
}

pub(crate) fn emit(
    out: &mut Screens,
    tx: &Eip1559Tx,
    data: &[u8],
    selector: Option<&SelectorMeta<'_>>,
    resolver: &NameResolver<'_>,
    fam: Family,
) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, tx.chain_id, fam.look);
    e.hero(b"UNKNOWN", b"CONFIRM UNKNOWN CALL?")?;
    e.network()?;
    e.detail(
        b"BLINDSGN",
        b"BLIND SIGN",
        &[(b"Unknown call", Weight::Regular), (b"Verify on dapp", Weight::Regular)],
        true,
    )?;
    if let Some(meta) = selector {
        emit_function(&mut e, meta, None)?;
    }
    emit_to(&mut e, tx, resolver)?;

    // ── AMOUNT: the native value, loud when non-zero ────────────────
    if tx.value.is_zero() {
        let z = Text::new().push(b"0 ").push(native_ticker(tx.chain_id));
        e.detail(b"AMOUNT", b"AMOUNT", &[(z.as_bytes(), Weight::Regular)], false)?;
    } else {
        let amt = native_amount(&tx.value, tx.chain_id).ok_or(())?;
        e.amount(b"AMOUNT", b"! VALUE", &amt, true)?;
    }

    // ── CALL DATA: selector + length, then the full SHA-256 ─────────
    let sel = if data.len() >= 4 {
        Text::new().push(b"Selector: 0x").push_hex(&data[..4])
    } else {
        Text::new().push(b"Selector: (none)")
    };
    let len = Text::new().push(b"Data: ").push_u64(data.len() as u64).push(b" B");
    e.detail(
        b"CALLDATA",
        b"CALL DATA",
        &[(sel.as_bytes(), Weight::Regular), (len.as_bytes(), Weight::Regular)],
        false,
    )?;
    let hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    };
    e.word_value(b"DATAHASH", b"DATA HASH", &hash)?;

    emit_fee_and_details(&mut e, tx)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: 9 + usize::from(selector.is_some()),
    })
}
