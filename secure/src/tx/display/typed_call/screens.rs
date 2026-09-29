//! Pixel-UI screens for the typed-call decode — the second painter over
//! [`super::try_render_typed_call`] (upstream `blind/typed_call/sign_with_args`).
//!
//! ```text
//!  CONFIRM BLIND SIGN? · NETWORK · FUNCTION|GUESS · ARG 0..N · TO · [VALUE]
//!  · MAX FEE · WORST CASE · DETAILS
//! ```
//!
//! Each `ARG i` screen is derived from the arg page the painter produced
//! (the type line and the value rows), re-wrapped for the design; address
//! arguments use the design's name-over-address layout from the same
//! decoded word. The whole text signature is shown where the page cut it at
//! 32 characters. A value the page could only show as `!OVERFLOW` refuses.

use super::super::blind_sign_screens::{emit_function, emit_to, target_look};
use super::super::screen_kit::{native_amount, wrap, BodyReceipt, Emit};
use super::super::userop_screens::{emit_fee_and_details, Family};
use super::super::Pages;
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::eip1559::Eip1559Tx;
use crate::tx::typed_call::abi;
use crate::tx::typed_call::parser::{parse_text_sig, TypeRef};
use crate::ui::DISPLAY_COLS;
use pqsigner_ui_px::fit::Region;
use pqsigner_ui_px::screen::LINES_PER_PAGE;
use pqsigner_ui_px::{Screens, Weight};

pub(crate) fn family(tx: &Eip1559Tx, _meta: &SelectorMeta<'_>) -> Family {
    Family {
        look: target_look(tx),
        signed: b"CALL SIGNED",
        declined: b"CALL DECLINED",
    }
}

fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
    let mut n = DISPLAY_COLS;
    while n > 0 && row[n - 1] == b' ' {
        n -= 1;
    }
    &row[..n]
}

/// `arg 0 uint256:` → `uint256:` (the page's own type label).
fn type_line(row0: &[u8]) -> &[u8] {
    let mut spaces = 0;
    for (i, &b) in row0.iter().enumerate() {
        if b == b' ' {
            spaces += 1;
            if spaces == 2 {
                return &row0[i + 1..];
            }
        }
    }
    row0
}

/// One `ARG i` screen from its proven page.
#[allow(clippy::too_many_arguments)]
fn emit_arg(
    e: &mut Emit<'_>,
    i: usize,
    kind: TypeRef,
    page: &[[u8; DISPLAY_COLS]; 4],
    body: &[u8],
    body_off: usize,
    resolver: &NameResolver<'_>,
) -> Result<(), ()> {
    let id = [b'A', b'R', b'G', b'0' + i as u8];
    let label = [b'A', b'R', b'G', b' ', b'0' + i as u8];
    if matches!(kind, TypeRef::Address) {
        let addr = abi::read_address(body, body_off).ok_or(())?;
        return e.addr(&id, &label, &addr, resolver);
    }
    let ty = type_line(trimmed(&page[0]));
    let mut lines: [(&[u8], Weight); 2 * LINES_PER_PAGE] = [(b"", Weight::Regular); 2 * LINES_PER_PAGE];
    lines[0] = (ty, Weight::SemiBold);
    let mut n = 1usize;
    // Numbers and hex words the page broke at column 16 are one value.
    let mut joined = [0u8; 2 * DISPLAY_COLS];
    let contiguous = matches!(kind, TypeRef::Uint(_) | TypeRef::Int(_) | TypeRef::BytesN(_));
    let w;
    if contiguous {
        let a = trimmed(&page[1]);
        let b = trimmed(&page[2]);
        joined[..a.len()].copy_from_slice(a);
        joined[a.len()..a.len() + b.len()].copy_from_slice(b);
        let v = &joined[..a.len() + b.len()];
        if v.is_empty() || v.starts_with(b"!") {
            return Err(());
        }
        w = wrap(v, Region::Docked).ok_or(())?;
        for l in w.as_slice() {
            if n >= lines.len() {
                return Err(());
            }
            lines[n] = (l.as_bytes(), Weight::Regular);
            n += 1;
        }
    } else {
        for row in &page[1..] {
            let t = trimmed(row);
            if t.is_empty() {
                continue;
            }
            if n >= lines.len() {
                return Err(());
            }
            lines[n] = (t, Weight::Regular);
            n += 1;
        }
    }
    e.detail_multi(&id, &label, &lines[..n], false)
}

pub(crate) fn emit(
    out: &mut Screens,
    tx: &Eip1559Tx,
    inner_data: &[u8],
    meta: &SelectorMeta<'_>,
    resolver: &NameResolver<'_>,
    fam: Family,
) -> Result<BodyReceipt, ()> {
    // The painter's own pages: the arg rows come from them, and their count
    // is the body length the lift binds.
    let pages: Pages = super::try_render_typed_call(tx, inner_data, meta, resolver).ok_or(())?;
    let parsed = parse_text_sig(meta.text_sig).ok_or(())?;
    let body = inner_data.get(4..).ok_or(())?;
    let walked = abi::walk(&parsed, body).ok_or(())?;

    let mut e = Emit::new(out, tx.chain_id, fam.look);
    let (ask, banner): (&[u8], &[u8]) = match meta.provenance {
        SelectorProvenance::Curated => (b"CONFIRM BLIND SIGN?", b"! BLIND SIGN"),
        SelectorProvenance::SelfAttest => (b"CONFIRM UNVERIFIED CALL?", b"! UNVERIFIED"),
    };
    e.hero(b"BLIND", ask)?;
    e.network()?;
    emit_function(&mut e, meta, Some(banner))?;
    for i in 0..walked.arg_count {
        let a = &walked.args[i];
        let kind = *parsed.arena.get(a.type_id);
        emit_arg(&mut e, i, kind, pages.buf.get(1 + i).ok_or(())?, body, a.body_off, resolver)?;
    }
    emit_to(&mut e, tx, resolver)?;
    if !tx.value.is_zero() {
        let amt = native_amount(&tx.value, tx.chain_id).ok_or(())?;
        e.amount(b"VALUE", b"! VALUE", &amt, true)?;
    }
    emit_fee_and_details(&mut e, tx)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: pages.len,
    })
}
