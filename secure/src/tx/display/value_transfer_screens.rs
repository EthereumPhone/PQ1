//! Pixel-UI screens for the plain value transfer / contract call — the
//! second painter over `value_transfer::render_pages` (upstream flows
//! `send` and `contract_call`).
//!
//! ```text
//!  SEND 0.250000 ETH? | CONFIRM CONTRACT CALL?     hero
//!  NETWORK · TO · VALUE · MAX FEE · WORST CASE · DETAILS
//! ```
//!
//! The page painter's six pages: banner + chain, `To:`, `Value:`, the two
//! fee pages, `Nonce` + `Data`. The value is also on its own `VALUE` detail
//! — the hero caption carries it only when it renders there exactly.

use super::primitives::{known_native_ticker, native_ticker};
use super::screen_kit::{caption_fits, native_amount, BodyReceipt, Emit, Text};
use super::userop_screens::{emit_fee_and_details, Family};
use crate::names::NameResolver;
use crate::tx::eip1559::Eip1559Tx;
use pqsigner_ui_px::{placeholder_ramp, Icon, Look, Screens, Weight};

/// The page count of `value_transfer::render_pages`.
pub(crate) const LEGACY_PAGES: usize = 6;

/// The native currency's disc: the ether mark on the mono body for ETH,
/// the placeholder ramp hashed from any other ticker.
pub(crate) fn native_look(chain_id: u64) -> Look {
    match known_native_ticker(chain_id) {
        Some(b"ETH") => Look::plain(Icon::Eth),
        _ => Look {
            icon: Icon::Eth,
            tint: Some(placeholder_ramp(native_ticker(chain_id))),
        },
    }
}

pub(crate) fn family(tx: &Eip1559Tx) -> Family {
    let look = native_look(tx.chain_id);
    if tx.value.is_zero() {
        Family {
            look,
            signed: b"CONTRACT CALL SIGNED",
            declined: b"CONTRACT CALL DECLINED",
        }
    } else {
        Family {
            look,
            signed: b"TRANSACTION SIGNED",
            declined: b"TRANSACTION DECLINED",
        }
    }
}

pub(crate) fn emit(out: &mut Screens, tx: &Eip1559Tx, resolver: &NameResolver<'_>, fam: Family) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, tx.chain_id, fam.look);
    let amt = native_amount(&tx.value, tx.chain_id).ok_or(())?;

    // ── Hero ────────────────────────────────────────────────────────
    if tx.value.is_zero() {
        e.hero(b"CALL", b"CONFIRM CONTRACT CALL?")?;
    } else {
        let full = Text::new().push(b"SEND ").push(amt.digits()).push(b" ").push(amt.unit()).push(b"?");
        let short = Text::new().push(b"SEND ").push(native_ticker(tx.chain_id)).push(b"?");
        if full.ok() && caption_fits(full.as_bytes()) {
            e.hero(b"SEND", full.as_bytes())?;
        } else if short.ok() && caption_fits(short.as_bytes()) {
            e.hero(b"SEND", short.as_bytes())?;
        } else {
            e.hero(b"SEND", b"CONFIRM SEND?")?;
        }
    }

    e.network()?;

    // ── TO ──────────────────────────────────────────────────────────
    match &tx.to {
        Some(to) => e.addr(b"TO", b"TO", to, resolver)?,
        None => e.detail(b"TO", b"TO", &[(b"(contract create)", Weight::Regular)], true)?,
    }

    // ── VALUE ───────────────────────────────────────────────────────
    e.amount(b"VALUE", b"VALUE", &amt, false)?;

    emit_fee_and_details(&mut e, tx)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: LEGACY_PAGES,
    })
}
