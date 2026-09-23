//! Pixel-UI screens for the single-UserOp routes (port step 2): the value
//! transfer / contract call, ERC-20 with and without verified metadata, the
//! typed-call decode and the blind sign.
//!
//! [`classify`] walks the tail of `dispatch::pick_sign_pages_inner`'s ladder
//! (below the Safe / CoW / ERC-7730 / known-call gates, which the caller has
//! already ruled out) with the same predicates, and [`emit`] hands the route
//! to its family emitter (`value_transfer_screens`, `erc20_screens`,
//! `typed_call::screens`, `blind_sign_screens`). Each emitter draws the
//! facts its page painter shows; [`body_pages_match`] re-runs that painter
//! and requires its pages to equal the proven body byte-for-byte, so the
//! two classifications provably picked the same route.

use super::blind_sign_screens;
use super::erc20_screens;
use super::screen_kit::{BodyReceipt, Emit, Text};
use super::trailer_screens;
use super::value_transfer_screens;
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, parse_erc20_calldata, Erc20Call};
use crate::names::NameResolver;
use crate::selectors::SelectorMeta;
use crate::tx::eip1559::Eip1559Tx;
use pqsigner_ui_px::{Look, Screens, Weight};

/// The verified inputs the dispatcher rendered the route from.
pub(crate) struct UserOpInputs<'a> {
    pub(crate) tx: &'a Eip1559Tx,
    pub(crate) inner_data: &'a [u8],
    pub(crate) erc20: Option<&'a Erc20Metadata<'a>>,
    pub(crate) selector: Option<&'a SelectorMeta<'a>>,
    pub(crate) resolver: &'a NameResolver<'a>,
}

/// A family's disc and its ending captions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Family {
    pub(crate) look: Look,
    pub(crate) signed: &'static [u8],
    pub(crate) declined: &'static [u8],
}

impl Family {
    pub(crate) const SAFE: Self = Self {
        look: Look::SAFE,
        signed: b"SIGNED SAFE TX",
        declined: b"SAFE TX DECLINED",
    };
}

/// Which single-UserOp page painter the dispatcher picked.
pub(crate) enum Route<'a> {
    Value,
    Erc20Known(Erc20Call, &'a Erc20Metadata<'a>),
    Erc20Unknown(Erc20Call),
    Typed(&'a SelectorMeta<'a>),
    Blind,
}

/// `pick_sign_pages_inner` below its higher-priority routes, predicate for
/// predicate. `Err` = the dispatcher would have refused (and never reached
/// a confirmation).
pub(crate) fn classify<'a>(inp: &UserOpInputs<'a>) -> Result<Route<'a>, ()> {
    let tx = inp.tx;
    if inp.inner_data.is_empty() {
        return Ok(Route::Value);
    }
    if let Some(call) = parse_erc20_calldata(inp.inner_data) {
        let meta = inp
            .erc20
            .filter(|m| m.chain_id == tx.chain_id)
            .filter(|m| super::value_page::direct_erc20_meta_matches(&m.contract, tx.to.as_ref()));
        return Ok(match meta {
            Some(meta) => {
                let amount = match &call {
                    Erc20Call::Transfer { amount, .. }
                    | Erc20Call::TransferFrom { amount, .. }
                    | Erc20Call::Approve { amount, .. } => amount,
                };
                let unlimited = matches!(&call, Erc20Call::Approve { .. }) && is_unlimited_amount(amount);
                if !unlimited && !super::primitives::token_amount_is_exactly_renderable(amount, meta) {
                    return Err(());
                }
                Route::Erc20Known(call, meta)
            }
            None => Route::Erc20Unknown(call),
        });
    }
    if let Some(meta) = inp.selector {
        if super::typed_call::try_render_typed_call(tx, inp.inner_data, meta, inp.resolver).is_some() {
            return Ok(Route::Typed(meta));
        }
    }
    Ok(Route::Blind)
}

/// The route's own page painter, re-run (the binding witness).
fn render_route_pages(route: &Route<'_>, inp: &UserOpInputs<'_>) -> Option<Pages> {
    let (tx, r) = (inp.tx, inp.resolver);
    Some(match route {
        Route::Value => super::value_transfer::render_pages(tx, r),
        Route::Erc20Known(call, meta) => super::erc20_known::render_erc20_known_pages(tx, call, meta, r),
        Route::Erc20Unknown(call) => super::erc20_unknown::render_erc20_unknown_pages(tx, call, r),
        Route::Typed(meta) => super::typed_call::try_render_typed_call(tx, inp.inner_data, meta, r)?,
        Route::Blind => super::blind_sign::render_blind_sign_pages(tx, inp.inner_data, inp.selector, r),
    })
}

/// The route body the dispatcher produced (`pages[..body_len]`) is exactly
/// what the route's painter renders for these inputs.
#[inline(never)]
pub(crate) fn body_pages_match(pages: &Pages, body_len: usize, inp: &UserOpInputs<'_>) -> bool {
    let Ok(route) = classify(inp) else {
        return false;
    };
    let Some(rendered) = render_route_pages(&route, inp) else {
        return false;
    };
    if rendered.len != body_len || body_len == 0 || body_len > pages.len {
        return false;
    }
    let mut acc = 0u8;
    for (a, b) in rendered.as_slice().iter().zip(pages.as_slice()[..body_len].iter()) {
        for (ra, rb) in a.iter().zip(b.iter()) {
            for (x, y) in ra.iter().zip(rb.iter()) {
                acc |= x ^ y;
            }
        }
    }
    acc == 0
}

/// The family (disc + ending captions) of the route these inputs take.
pub(crate) fn family(inp: &UserOpInputs<'_>) -> Result<Family, ()> {
    Ok(match classify(inp)? {
        Route::Value => value_transfer_screens::family(inp.tx),
        Route::Erc20Known(call, meta) => erc20_screens::known_family(&call, meta),
        Route::Erc20Unknown(call) => erc20_screens::unknown_family(inp.tx, &call),
        Route::Typed(meta) => super::typed_call::screens::family(inp.tx, meta),
        Route::Blind => blind_sign_screens::family(inp.tx),
    })
}

/// Emit the route body's screens (hero first). Returns the receipt and the
/// family the trailers and endings wear.
pub(crate) fn emit(out: &mut Screens, inp: &UserOpInputs<'_>) -> Result<(BodyReceipt, Family), ()> {
    let route = classify(inp)?;
    let fam = family(inp)?;
    let start = out.len();
    let receipt = match &route {
        Route::Value => value_transfer_screens::emit(out, inp.tx, inp.resolver, fam)?,
        Route::Erc20Known(call, meta) => erc20_screens::emit_known(out, inp.tx, call, meta, inp.resolver, fam)?,
        Route::Erc20Unknown(call) => erc20_screens::emit_unknown(out, inp.tx, call, inp.resolver, fam)?,
        Route::Typed(meta) => super::typed_call::screens::emit(out, inp.tx, inp.inner_data, meta, inp.resolver, fam)?,
        Route::Blind => blind_sign_screens::emit(out, inp.tx, inp.inner_data, inp.selector, inp.resolver, fam)?,
    };
    if out.len() != start + receipt.screens {
        return Err(());
    }
    Ok((receipt, fam))
}

/// The tail every single-UserOp page painter ends with — the compact fee
/// envelope (two pages, from the same builder) and the `Nonce` footer page
/// — as `MAX FEE`, `WORST CASE` and `DETAILS` (nonce + calldata length).
pub(crate) fn emit_fee_and_details(e: &mut Emit<'_>, tx: &Eip1559Tx) -> Result<(), ()> {
    for worst in [false, true] {
        let side = e.next_side();
        let s = trailer_screens::fee_screen(worst, tx, e.look, side)?;
        e.push(s)?;
    }
    let nonce = Text::new().push(b"Nonce: ").push_u64(tx.nonce);
    let data = Text::new().push(b"Data: ").push_u64(tx.data_len as u64).push(b" B");
    if !nonce.ok() || !data.ok() {
        return Err(());
    }
    e.detail(
        b"DETAILS",
        b"DETAILS",
        &[(nonce.as_bytes(), Weight::Regular), (data.as_bytes(), Weight::Regular)],
        false,
    )
}
