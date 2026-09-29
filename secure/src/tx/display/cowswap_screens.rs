//! Pixel-UI screens for a verified CoW Swap `GPv2Order` — the second painter
//! over `cowswap_display::append_order_body_pages`, shared by the direct
//! order route (upstream flows `cowswap/swap`, `cowswap/address_mode`) and
//! the Safe-wrapped presign (`safe_screens`), exactly like the page body.
//!
//! ```text
//!  SIGN COWSWAP?                                   hero (direct route)
//!  NETWORK · ORDER
//!  SELL · [SELL TOKEN] · BUY MIN · [BUY TOKEN]     one leg = amount + token
//!  RECEIVER · EXPIRES · FEE (SELL) · SOURCES · APP DATA
//! ```
//!
//! A decoded leg is its amount in the verified symbol plus the token's name
//! over its FULL contract address (the page's anti-DB-spoof backstop); an
//! undecoded leg is the full address plus the raw uint256 amount word.
//! Amounts use the page painter's own representation
//! (`write_token_amount_two_rows`: widened exact fraction, else labelled
//! base units), so a value the page renders exactly is rendered exactly here.

use super::screen_kit::{addr42, raw_units, token_amount_as_page, wrap, BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use crate::erc20::bundle::Erc20Metadata;
use crate::tx::eip1559::U256;
use crate::tx::eip712::cowswap::{CowLeg, VerifiedCowswapV3};
use crate::tx::eip712::cowswap_display::{order_body_page_count, render_cowswap_pages};
use pqsigner_ui_px::fit::{layout_address, split_word_docked, Region};
use pqsigner_ui_px::{Look, Screens, Weight};

// CoW canonical offsets (mirror `cowswap_display.rs`).
const OFF_CHAIN_ID: usize = 0;
const OFF_SELL_TOKEN: usize = 8;
const OFF_BUY_TOKEN: usize = 28;
const OFF_RECEIVER: usize = 48;
const OFF_SELL_AMOUNT: usize = 68;
const OFF_BUY_AMOUNT: usize = 100;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_VALID_TO: usize = 164;
const OFF_KIND: usize = 168;
const OFF_PARTIAL: usize = 169;
const OFF_SELL_TOKEN_BAL: usize = 170;
const OFF_BUY_TOKEN_BAL: usize = 171;
const OFF_APP_DATA: usize = 172;

/// The CoW Swap family: the branded disc and its endings.
pub(crate) const FAMILY: Family = Family {
    look: Look::COWSWAP,
    signed: b"COWSWAP SIGNED",
    declined: b"COWSWAP DECLINED",
};

fn word_at(c: &[u8; 204], off: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&c[off..off + 32]);
    w
}

fn addr_at(c: &[u8; 204], off: usize) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&c[off..off + 20]);
    a
}

fn chain_id(c: &[u8; 204]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&c[OFF_CHAIN_ID..OFF_CHAIN_ID + 8]);
    u64::from_be_bytes(b)
}

fn leg_screens(leg: &CowLeg) -> usize {
    match leg {
        CowLeg::Decoded { .. } | CowLeg::AddrHex => 2,
    }
}

/// Screens [`emit_order_body`] produces — kept in lockstep with the emitter
/// (the Safe emitter's `expected_body_screens` counts through it).
pub(crate) fn order_body_screens(sell: &CowLeg, buy: &CowLeg) -> usize {
    leg_screens(sell) + leg_screens(buy) + 1 /* receiver */ + 1 /* expires */ + 1 /* fee */ + 1 /* sources */ + 1 /* appData */
}

/// A leg amount in the page painter's representation.
fn leg_amount(amount: &U256, decimals: u8, symbol: &[u8]) -> Option<super::screen_kit::Amount> {
    let meta = Erc20Metadata {
        chain_id: 0,
        contract: [0u8; 20],
        decimals,
        name: &[],
        symbol,
    };
    token_amount_as_page(amount, &meta)
}

fn emit_leg(e: &mut Emit<'_>, c: &[u8; 204], leg: &CowLeg, sell: bool) -> Result<(), ()> {
    let kind = c[OFF_KIND];
    let (tok_off, amt_off) = if sell { (OFF_SELL_TOKEN, OFF_SELL_AMOUNT) } else { (OFF_BUY_TOKEN, OFF_BUY_AMOUNT) };
    let amount = U256(word_at(c, amt_off));
    // Sell-order: sell exactly / buy at least; buy-order: sell at most / buy exactly.
    let label: &[u8] = match (kind, sell) {
        (0, true) => b"SELL",
        (0, false) => b"BUY MIN",
        (_, true) => b"SELL MAX",
        (_, false) => b"BUY",
    };
    let (id_tok, id_amt, lbl_tok): (&[u8], &[u8], &[u8]) = if sell {
        (b"SELLTOK", b"SELLAMT", b"SELL TOKEN")
    } else {
        (b"BUYTOK", b"BUYAMT", b"BUY TOKEN")
    };
    let token = layout_address(&addr42(&addr_at(c, tok_off)));
    match leg {
        CowLeg::Decoded { decimals, symbol, symbol_len, name, name_len } => {
            let amt = leg_amount(&amount, *decimals, &symbol[..usize::from(*symbol_len)]).ok_or(())?;
            e.amount(if sell { b"SELL" } else { b"BUY" }, label, &amt, false)?;
            // The token: its verified name over the FULL contract address —
            // on one page when both fit, else the name, then the address
            // whole on the second page (never an address split over pages).
            let name = wrap(&name[..usize::from(*name_len)], Region::Docked).ok_or(())?;
            let mut nl: [(&[u8], Weight); 3] = [(&[], Weight::SemiBold); 3];
            let mut al: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
            if name.n > nl.len() {
                return Err(());
            }
            for (d, l) in nl.iter_mut().zip(name.as_slice()) {
                d.0 = l.as_bytes();
            }
            for (d, l) in al.iter_mut().zip(token.as_slice()) {
                d.0 = l.as_bytes();
            }
            let (nn, an) = (name.n, token.as_slice().len());
            if nn + an <= 3 {
                let mut both: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
                both[..nn].copy_from_slice(&nl[..nn]);
                both[nn..nn + an].copy_from_slice(&al[..an]);
                e.detail(id_tok, lbl_tok, &both[..nn + an], false)
            } else {
                e.detail_two_pages(id_tok, lbl_tok, &nl[..nn], &al[..an], false)
            }
        }
        CowLeg::AddrHex => {
            e.addr_lines(id_tok, lbl_tok, &token, None)?;
            e.word_value(id_amt, label, &amount.0)
        }
    }
}

/// The order body (both legs, receiver, expiry, fee, balance sources and
/// appData) — the twin of `append_order_body_pages`. `owner_label` is the
/// zero-receiver wording (`Some` on the Safe-wrapped route, where GPv2
/// routes proceeds to the uid owner = the Safe); the direct route passes
/// `None` and shows the zero address verbatim, like its page.
pub(crate) fn emit_order_body(e: &mut Emit<'_>, v3: &VerifiedCowswapV3, owner_label: Option<&[u8]>) -> Result<(), ()> {
    let c = &v3.canonical;
    emit_leg(e, c, &v3.sell, true)?;
    emit_leg(e, c, &v3.buy, false)?;
    let receiver = addr_at(c, OFF_RECEIVER);
    match owner_label {
        Some(label) if receiver == [0u8; 20] => {
            e.detail(b"RECEIVER", b"RECEIVER", &[(label, Weight::Regular)], false)?;
        }
        _ => {
            let a = layout_address(&addr42(&receiver));
            e.addr_lines(b"RECEIVER", b"RECEIVER", &a, None)?;
        }
    }
    let valid_to = u32::from_be_bytes([c[OFF_VALID_TO], c[OFF_VALID_TO + 1], c[OFF_VALID_TO + 2], c[OFF_VALID_TO + 3]]);
    let exp = Text::new().push(b"unix ").push_u64(u64::from(valid_to));
    let partial: &[u8] = if c[OFF_PARTIAL] == 0 { b"Partial: no" } else { b"Partial: yes" };
    e.detail(b"EXPIRES", b"EXPIRES", &[(exp.as_bytes(), Weight::Regular), (partial, Weight::Regular)], false)?;
    // Fee in the sell token, full magnitude (a huge fee is a drain).
    let fee = U256(word_at(c, OFF_FEE_AMOUNT));
    let fee_amt = match &v3.sell {
        CowLeg::Decoded { decimals, symbol, symbol_len, .. } => {
            leg_amount(&fee, *decimals, &symbol[..usize::from(*symbol_len)])
        }
        CowLeg::AddrHex => raw_units(&fee),
    }
    .ok_or(())?;
    e.amount(b"FEE", b"FEE (SELL)", &fee_amt, false)?;
    let src: &[u8] = match c[OFF_SELL_TOKEN_BAL] {
        0 => b"sell: erc20",
        1 => b"sell: external",
        2 => b"sell: internal",
        _ => b"sell: ?",
    };
    let dst: &[u8] = match c[OFF_BUY_TOKEN_BAL] {
        0 => b"buy: erc20",
        1 => b"buy: internal",
        _ => b"buy: ?",
    };
    e.detail(b"SOURCES", b"SOURCES", &[(src, Weight::Regular), (dst, Weight::Regular)], false)?;
    let app = word_at(c, OFF_APP_DATA);
    e.detail_paged(b"APPDATA", b"APP DATA", &split_word_docked(&app))
}

/// The `ORDER` detail: the order kind (the page's `kind=SELL|BUY` row).
pub(crate) fn kind_line(v3: &VerifiedCowswapV3) -> &'static [u8] {
    if v3.canonical[OFF_KIND] == 0 {
        b"SELL order"
    } else {
        b"BUY order"
    }
}

/// The page count of `render_cowswap_pages`: header + order body + confirm.
pub(crate) fn direct_legacy_pages(v3: &VerifiedCowswapV3) -> usize {
    1 + order_body_page_count(&v3.sell, &v3.buy) + 1
}

/// The direct order route (no Safe context): hero, NETWORK, ORDER, then
/// the shared order body. The page painter's trailing confirm page has no
/// screen (the returning hero and the design's `Confirm?` replace it).
pub(crate) fn emit_direct(out: &mut Screens, v3: &VerifiedCowswapV3) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, chain_id(&v3.canonical), FAMILY.look);
    e.hero(b"SIGN", b"SIGN COWSWAP?")?;
    e.network()?;
    e.detail(b"ORDER", b"ORDER", &[(kind_line(v3), Weight::Regular)], false)?;
    emit_order_body(&mut e, v3, None)?;
    if e.n != 3 + order_body_screens(&v3.sell, &v3.buy) {
        return Err(());
    }
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: direct_legacy_pages(v3),
    })
}

/// The binding witness: the direct route's page painter, re-run.
pub(crate) fn render_direct_pages(v3: &VerifiedCowswapV3) -> super::Pages {
    render_cowswap_pages(&v3.canonical, &v3.sell, &v3.buy)
}
