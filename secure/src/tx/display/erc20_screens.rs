//! Pixel-UI screens for a direct ERC-20 call — the second painter over
//! `erc20_known::render_erc20_known_pages` (upstream `send_token`,
//! `send_token_named`, `transfer_token`, `approve_token`) and
//! `erc20_unknown::render_erc20_unknown_pages` (`transfer_unknown_token`).
//!
//! ```text
//!  known:   SEND 12.500000 USDC? · NETWORK · [FROM] · TO|SPENDER · AMOUNT
//!           · CONTRACT (token name over the address) · MAX FEE · WORST CASE · DETAILS
//!  unknown: TRANSFER UNKNOWN TOKEN? · NETWORK · CONTRACT · [FROM] · AMOUNT (RAW)
//!           · TO|SPENDER · MAX FEE · WORST CASE · DETAILS
//! ```
//!
//! The known token wears its logo disc (USDC / USDT / DAI), the ether mark
//! (WETH) or the placeholder ramp of its symbol; the unknown token the
//! placeholder ramp hashed from its contract address (DESIGN.md § Color).

use super::screen_kit::{
    addr42, address_look, caption_fits, raw_units, token_amount_as_page, token_look, wrap, BodyReceipt, Emit, Text,
};
use super::userop_screens::{emit_fee_and_details, Family};
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};
use pqsigner_ui_px::fit::{fit_tier, layout_address, Region};
use pqsigner_ui_px::{Icon, Look, Screens, Weight};

fn amount_of(call: &Erc20Call) -> U256 {
    match call {
        Erc20Call::Transfer { amount, .. }
        | Erc20Call::TransferFrom { amount, .. }
        | Erc20Call::Approve { amount, .. } => *amount,
    }
}

fn recipient_of(call: &Erc20Call) -> [u8; 20] {
    match call {
        Erc20Call::Transfer { to, .. } | Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    }
}

fn captions(call: &Erc20Call) -> (&'static [u8], &'static [u8]) {
    match call {
        Erc20Call::Approve { amount, .. } if amount.is_zero() => (b"REVOKE SIGNED", b"REVOKE DECLINED"),
        Erc20Call::Approve { .. } => (b"APPROVAL SIGNED", b"APPROVAL DECLINED"),
        _ => (b"TRANSFER SIGNED", b"TRANSFER DECLINED"),
    }
}

pub(crate) fn known_family(call: &Erc20Call, meta: &Erc20Metadata<'_>) -> Family {
    let (signed, declined) = captions(call);
    Family {
        look: token_look(meta.symbol),
        signed,
        declined,
    }
}

pub(crate) fn unknown_family(tx: &Eip1559Tx, call: &Erc20Call) -> Family {
    let (signed, declined) = captions(call);
    let look = match &tx.to {
        Some(c) => address_look(Icon::Eth, c),
        None => Look::plain(Icon::Eth),
    };
    Family { look, signed, declined }
}

/// `FROM` (transferFrom only) and `TO` / `SPENDER`.
fn emit_from(e: &mut Emit<'_>, call: &Erc20Call, resolver: &NameResolver<'_>) -> Result<(), ()> {
    if let Erc20Call::TransferFrom { from, .. } = call {
        e.addr(b"FROM", b"FROM", from, resolver)?;
    }
    Ok(())
}

fn emit_recipient(e: &mut Emit<'_>, call: &Erc20Call, resolver: &NameResolver<'_>) -> Result<(), ()> {
    let (id, label): (&[u8], &[u8]) = match call {
        Erc20Call::Approve { .. } => (b"SPENDER", b"SPENDER"),
        _ => (b"TO", b"TO"),
    };
    e.addr(id, label, &recipient_of(call), resolver)
}

/// The known-token hero: the verb, the exact amount and the symbol when the
/// caption band renders them, else the verb and the symbol, else the verb.
fn known_hero(e: &mut Emit<'_>, call: &Erc20Call, meta: &Erc20Metadata<'_>) -> Result<(), ()> {
    let amount = amount_of(call);
    let (id, verb, generic): (&[u8], &[u8], &[u8]) = match call {
        Erc20Call::Transfer { .. } => (b"SEND", b"SEND ", b"SEND TOKEN?"),
        Erc20Call::TransferFrom { .. } => (b"PULL", b"PULL ", b"PULL TOKEN?"),
        Erc20Call::Approve { .. } if amount.is_zero() => (b"REVOKE", b"REVOKE ", b"REVOKE APPROVAL?"),
        Erc20Call::Approve { .. } => (b"APPROVE", b"APPROVE ", b"APPROVE TOKEN?"),
    };
    let with_amount = matches!(call, Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. });
    if with_amount {
        if let Some(a) = token_amount_as_page(&amount, meta) {
            let t = Text::new().push(verb).push(a.digits()).push(b" ").push(a.unit()).push(b"?");
            if t.ok() && caption_fits(t.as_bytes()) {
                return e.hero(id, t.as_bytes());
            }
        }
    }
    let t = Text::new().push(verb).push(meta.symbol).push(b"?");
    if t.ok() && caption_fits(t.as_bytes()) {
        return e.hero(id, t.as_bytes());
    }
    e.hero(id, generic)
}

pub(crate) fn emit_known(
    out: &mut Screens,
    tx: &Eip1559Tx,
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
    resolver: &NameResolver<'_>,
    fam: Family,
) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, tx.chain_id, fam.look);
    known_hero(&mut e, call, meta)?;
    e.network()?;
    emit_from(&mut e, call, resolver)?;
    emit_recipient(&mut e, call, resolver)?;

    // ── AMOUNT (labelled by the verb) ───────────────────────────────
    let amount = amount_of(call);
    let label: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"SEND",
        Erc20Call::TransferFrom { .. } => b"PULL",
        Erc20Call::Approve { .. } => b"APPROVE",
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        e.detail(b"AMOUNT", label, &[(b"unlimited", Weight::Regular)], true)?;
    } else {
        let amt = token_amount_as_page(&amount, meta).ok_or(())?;
        e.amount(b"AMOUNT", label, &amt, false)?;
    }

    // ── CONTRACT: verified token name over the raw contract address ─
    let to = tx.to.ok_or(())?;
    let a = layout_address(&addr42(&to));
    let head: &[u8] = if !meta.name.is_empty() && fit_tier(&[(meta.name, Weight::SemiBold)], Region::Docked).is_some() {
        meta.name
    } else {
        meta.symbol
    };
    if a.as_slice().len() == 2 {
        e.addr_lines(b"CONTRACT", b"CONTRACT", &a, Some(head))?;
    } else {
        e.detail(b"TOKEN", b"TOKEN", &[(head, Weight::SemiBold)], false)?;
        e.addr_lines(b"CONTRACT", b"CONTRACT", &a, None)?;
    }

    emit_fee_and_details(&mut e, tx)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: 8 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
    })
}

pub(crate) fn emit_unknown(
    out: &mut Screens,
    tx: &Eip1559Tx,
    call: &Erc20Call,
    resolver: &NameResolver<'_>,
    fam: Family,
) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, tx.chain_id, fam.look);
    let amount = amount_of(call);
    let (id, ask, method): (&[u8], &[u8], &[u8]) = match call {
        Erc20Call::Transfer { .. } => (b"TRANSFER", b"TRANSFER UNKNOWN TOKEN?", b"transfer"),
        Erc20Call::TransferFrom { .. } => (b"PULL", b"PULL UNKNOWN TOKEN?", b"transferFrom"),
        Erc20Call::Approve { .. } => (b"APPROVE", b"APPROVE UNKNOWN TOKEN?", b"approve"),
    };
    e.hero(id, ask)?;
    e.network()?;

    // ── CONTRACT: the address alone, flagged unknown ────────────────
    let to = tx.to.ok_or(())?;
    let a = layout_address(&addr42(&to));
    if a.as_slice().len() == 2 {
        e.addr_lines(b"CONTRACT", b"CONTRACT", &a, Some(b"! Unknown token"))?;
    } else {
        e.detail(b"UNKNOWN", b"UNKNOWN", &[(b"! Unknown token", Weight::Regular), (b"(decimals = ?)", Weight::Regular)], true)?;
        e.addr_lines(b"CONTRACT", b"CONTRACT", &a, None)?;
    }
    emit_from(&mut e, call, resolver)?;

    // ── AMOUNT (raw, undivided) ─────────────────────────────────────
    let head = Text::new().push(b"(RAW) ").push(method);
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        e.detail(b"AMOUNT", b"AMOUNT", &[(head.as_bytes(), Weight::Regular), (b"unlimited", Weight::Regular)], true)?;
    } else if matches!(call, Erc20Call::Approve { .. }) && amount.is_zero() {
        e.detail(b"AMOUNT", b"AMOUNT", &[(head.as_bytes(), Weight::Regular), (b"Revoke approval", Weight::Regular)], false)?;
    } else {
        let amt = raw_units(&amount).ok_or(())?;
        match wrap(amt.digits(), Region::Docked) {
            Some(w) if w.n <= 2 => {
                let l = w.as_slice();
                let mut lines: [(&[u8], Weight); 3] = [(head.as_bytes(), Weight::Regular); 3];
                for (i, line) in l.iter().enumerate() {
                    lines[1 + i] = (line.as_bytes(), Weight::Regular);
                }
                e.detail(b"AMOUNT", b"AMOUNT", &lines[..1 + l.len()], false)?;
            }
            _ => {
                let w = wrap(amt.digits(), Region::Full).ok_or(())?;
                if w.n > 3 {
                    return Err(());
                }
                let mut lines: [(&[u8], Weight); 3] = [(b"", Weight::Regular); 3];
                for (i, line) in w.as_slice().iter().enumerate() {
                    lines[i] = (line.as_bytes(), Weight::Regular);
                }
                e.value(b"AMOUNT", b"RAW AMOUNT", &lines[..w.n])?;
            }
        }
    }

    emit_recipient(&mut e, call, resolver)?;
    emit_fee_and_details(&mut e, tx)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: 8 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
    })
}
