//! Per-formatter renderers driven by `FormatOp` (0x01..0x0E).
//!
//! Each formatter writes 1–2 pages into the supplied [`Pages`] buffer
//! and returns `Result<(), RenderErr>`. Page budget is enforced via
//! [`Pages::push_blank`] returning `Err(())` on overflow, which we map
//! to `RenderErr::PageBudget`.
//!
//! ## Path resolution
//!
//! Phase 4 ships a minimal direct path walker rather than going through
//! `pqsigner_erc7730::walker::resolve_path`. The reason: Phase 3's
//! walker requires an [`AbiView`] tree describing the runtime ABI
//! shape, and the on-device IR does not carry ABI type information
//! (the host-side `dbgen` knows the format-key signature but does not
//! emit it on-wire). Phase 4 sidesteps the gap by walking the path
//! program manually, accumulating a slot offset, and reading the
//! corresponding 32-byte word straight out of `inner_data` post-
//! selector. Each formatter then re-interprets those 32 bytes per the
//! type its `FormatOp` implies (uint256, address, bool, …).
//!
//! For STATIC types (uint*, int*, address, bytes32, bool, static
//! tuples) this is correct. DYNAMIC types (bytes, string, dynamic
//! arrays, dynamic tuples) are out of scope for Phase 4 — the slot
//! would carry a 32-byte BE offset rather than the value, and a
//! formatter that tried to render it as Uint would surface the offset
//! instead of the value. The seed corpus is all static types except
//! `OpenSea` ([`bytes`] for `calldata`/`replacementPattern`), which
//! the `Calldata` formatter routes through `calldata_nested` (which
//! itself rejects in Phase 4 and falls through to blind-sign).

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use super::super::primitives::{
    chain_name, write_addr_full, write_addr_full_or_name, write_amount_two_rows,
    write_line, AmountFit,
};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::erc7730::{container_field, Erc7730Ir, FieldEntry, FormatOp, PathOp};
use crate::tx::erc7730_render::params::{
    ParamSet, DATE_ENC_BLOCKHEIGHT, DATE_ENC_TIMESTAMP,
};
use crate::tx::erc7730_render::RenderErr;
use crate::ui::{ascii_str, DISPLAY_COLS};

use super::Pages;

/// Resolved form of a path program — either a slot inside the
/// structured calldata body or a well-known envelope field.
pub(super) enum Resolved<'a> {
    /// 32-byte BE word from `body[slot * 32 .. (slot+1) * 32]`.
    Slot32(&'a [u8; 32]),
    /// `@`-rooted access; caller looks up the field on `tx`.
    Container(u16),
}

/// Walk a path program (length-prefixed at `ir.pool[path_off]`) and
/// produce a [`Resolved`] reference. Fails on:
///
/// - empty / missing path (`path_off == 0` or pool out-of-range);
/// - unsupported root (`$` metadata);
/// - non-`FieldIdx` descent (`ArrayIdx`/`ArrayLast`/`ArrayAll`/
///   `ArraySlice` — Phase 4 only renders static-tuple paths);
/// - slot offset past the supplied `body`.
pub(super) fn resolve_path<'a>(
    ir: &Erc7730Ir<'_>,
    path_off: u16,
    body: &'a [u8],
) -> Result<Resolved<'a>, RenderErr> {
    if path_off == 0 {
        return Err(RenderErr::Reject("7730 missing path"));
    }
    let off = path_off as usize;
    let len = *ir
        .pool
        .get(off)
        .ok_or(RenderErr::Reject("7730 bad path off"))? as usize;
    let prog = ir
        .pool
        .get(off + 1..off + 1 + len)
        .ok_or(RenderErr::Reject("7730 truncated path"))?;
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }

    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let mut p = 1usize;

    match root {
        PathOp::RootStructured => {
            // Sum FieldIdx values → byte slot.
            let mut slot = 0usize;
            while p < prog.len() {
                let op = PathOp::try_from(prog[p])
                    .map_err(|_| RenderErr::Reject("7730 bad op"))?;
                p += 1;
                match op {
                    PathOp::FieldIdx => {
                        if p + 2 > prog.len() {
                            return Err(RenderErr::Reject("7730 trunc field"));
                        }
                        let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
                        p += 2;
                        slot = slot
                            .checked_add(idx)
                            .ok_or(RenderErr::Reject("7730 slot ovf"))?;
                    }
                    PathOp::ArrayIdx
                    | PathOp::ArrayLast
                    | PathOp::ArraySlice
                    | PathOp::ArrayAll
                    | PathOp::RootStructured
                    | PathOp::RootContainer
                    | PathOp::RootMetadata => {
                        return Err(RenderErr::Reject("7730 path op p4 unsup"));
                    }
                }
            }
            let start = slot
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let end = start
                .checked_add(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let word = body
                .get(start..end)
                .ok_or(RenderErr::Reject("7730 short body"))?;
            // Slice → array conversion is infallible (we just checked
            // the length) but TryInto wants Result, so unwrap is fine.
            Ok(Resolved::Slot32(<&[u8; 32]>::try_from(word).unwrap()))
        }
        PathOp::RootContainer => {
            if p + 3 > prog.len() {
                return Err(RenderErr::Reject("7730 trunc cnt"));
            }
            if prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad op"));
            }
            let field_idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            // Tail must be empty (we only support a single `@.<name>`
            // step in Phase 4 — sub-fields of the envelope are not a
            // thing for any current ERC-7730 descriptor).
            if p + 3 != prog.len() {
                return Err(RenderErr::Reject("7730 cnt deep"));
            }
            Ok(Resolved::Container(field_idx))
        }
        PathOp::RootMetadata => Err(RenderErr::Reject("7730 $ root unsup")),
        PathOp::FieldIdx
        | PathOp::ArrayIdx
        | PathOp::ArrayLast
        | PathOp::ArraySlice
        | PathOp::ArrayAll => Err(RenderErr::Reject("7730 path no root")),
    }
}

/// Read a container field value (u256-shaped) by its keccak-prefix
/// index. Returns a 32-byte BE word equivalent for the formatter to
/// re-interpret.
pub(super) fn container_u256(tx: &Eip1559Tx, idx: u16) -> Result<[u8; 32], RenderErr> {
    match idx {
        container_field::VALUE => Ok(tx.value.0),
        container_field::CHAIN_ID => {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&tx.chain_id.to_be_bytes());
            Ok(b)
        }
        container_field::NONCE => {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&tx.nonce.to_be_bytes());
            Ok(b)
        }
        _ => Err(RenderErr::Reject("7730 cnt no u256")),
    }
}

/// Read a container field as an address. Returns the 20-byte slice for
/// `@.to` / `@.from`.
pub(super) fn container_addr(tx: &Eip1559Tx, idx: u16) -> Result<[u8; 20], RenderErr> {
    match idx {
        container_field::TO => tx.to.ok_or(RenderErr::Reject("7730 no to")),
        // `@.from` is the AA wallet's own address — derived elsewhere
        // (cmd_sign_userop computes it). Phase 4 v1 surfaces "0x00…"
        // since the renderer is at the display layer and doesn't have
        // the bootstrap pubkey on hand. Phase 5 wires this if any
        // descriptor needs it.
        container_field::FROM => Ok([0u8; 20]),
        _ => Err(RenderErr::Reject("7730 cnt no addr")),
    }
}

/// Dispatcher — one renderer per `FormatOp`. Step 3 reads
/// `field.format_op`, parses params, walks the path, and emits 1–2
/// pages. Visibility filtering happens in the entry-point loop.
pub(super) fn dispatch(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let op = FormatOp::try_from(field.format_op)
        .map_err(|_| RenderErr::Reject("7730 bad format op"))?;
    match op {
        FormatOp::Raw => render_raw(field, pages, ir, body, tx, params),
        FormatOp::Amount => render_amount(field, pages, ir, body, tx, params),
        FormatOp::TokenAmount => render_token_amount(field, pages, ir, body, tx, erc20, params),
        FormatOp::NftName => render_nft_name(field, pages, ir, body, tx, resolver, params),
        FormatOp::Date => render_date(field, pages, ir, body, tx, params),
        FormatOp::Duration => render_duration(field, pages, ir, body, tx),
        FormatOp::AddressName => render_address_name(field, pages, ir, body, tx, resolver),
        FormatOp::Enum => render_enum(field, pages, ir, body, tx, params),
        FormatOp::Unit => render_unit(field, pages, ir, body, tx, params),
        FormatOp::Calldata => super::calldata_nested::render(field, pages, params),
        FormatOp::ChainId => render_chain_id(field, pages, ir, body, tx),
        FormatOp::TokenTicker => render_token_ticker(field, pages, ir, body, tx, erc20, params),
        FormatOp::InteroperableAddressName => {
            render_interop_address_name(field, pages, ir, body, tx, resolver)
        }
        FormatOp::Encrypted => render_encrypted(field, pages, params),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Per-FormatOp renderers
// ─────────────────────────────────────────────────────────────────────

fn render_raw(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx).unwrap_or([0u8; 32]),
    };
    // 64 hex chars over rows 1+2; row 3 = "> next".
    let [_, row1, row2, row3] = pages.page_mut(p);
    write_hex_word(row1, &bytes[..16]);
    write_hex_word(row2, &bytes[16..]);
    write_line(row3, "> next");
    Ok(())
}

fn render_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(raw);
    let decimals = u32::from(params.decimals.unwrap_or(18));
    let unit_bytes = params.base.unwrap_or(b"ETH");
    let [_, r1, r2, foot] = pages.page_mut(p);
    let fit = write_amount_two_rows(r1, r2, &value, decimals, 6, true, ascii_str(unit_bytes));
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
    Ok(())
}

fn render_token_amount(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Resolve the amount slot.
    let raw = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(raw);

    // Resolve token contract address (params.tokenPath wins; falls
    // back to params.token literal). Used to decide which decimals /
    // symbol to display.
    let token_addr = resolve_token_address(ir, body, tx, params).ok();

    // Match against the supplied `erc20` bundle if the addresses agree.
    let (decimals, ticker): (u32, &[u8]) = match (token_addr, erc20) {
        (Some(addr), Some(meta)) if addr == meta.contract => {
            (u32::from(meta.decimals), meta.symbol)
        }
        _ => (18, b"???"),
    };

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, foot] = pages.page_mut(p);
    // Threshold check (Aragon/Coinbase Wallet/Rabby convention): when
    // the descriptor supplies a `threshold` param and the on-chain
    // value is greater-than-or-equal, render "unlimited <ticker>"
    // instead of the digit string. BE byte arrays compare
    // lexicographically — which is the same as numeric on full-width
    // u256, so a direct `>=` over the raw bytes is correct.
    if let Some(threshold) = params.threshold {
        if value.0 >= *threshold {
            write_unlimited_row(r1, ticker);
            write_line(foot, "> next");
            return Ok(());
        }
    }
    let fit = write_amount_two_rows(r1, r2, &value, decimals, 6, true, ascii_str(ticker));
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
    Ok(())
}

/// Render `"unlimited <ticker>"` into a single 16-col OLED row. Used
/// by `render_token_amount` when the descriptor's `threshold` param
/// classifies the on-chain value as the approve-all sentinel.
fn write_unlimited_row(row: &mut [u8; DISPLAY_COLS], ticker: &[u8]) {
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"unlimited ";
    let n = core::cmp::min(prefix.len(), buf.len());
    buf[..n].copy_from_slice(&prefix[..n]);
    let room = buf.len() - n;
    let take = core::cmp::min(ticker.len(), room);
    buf[n..n + take].copy_from_slice(&ticker[..take]);
    *row = buf;
}

fn render_nft_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _resolver: &NameResolver<'_>,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    // Phase 4 v1: render token id (decimal if u64-fits, else hex). The
    // collection-name lookup needs an NFT-specific name DB which is
    // not yet on-device — that lands in Phase 5 alongside the deep
    // calldata renderer.
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let [_, r1, r2, foot] = pages.page_mut(p);
    let value = U256(bytes);
    let _ = write_amount_two_rows(r1, r2, &value, 0, 0, false, "");
    write_line(r2, "(NFT token id)");
    write_line(foot, "> next");
    Ok(())
}

fn render_date(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let secs = read_u64_be_tail(&bytes);
    let enc = params.date_encoding.unwrap_or(DATE_ENC_TIMESTAMP);
    let [_, r1, r2, foot] = pages.page_mut(p);
    if enc == DATE_ENC_BLOCKHEIGHT {
        // "block #N" on row 1.
        let mut row = [b' '; DISPLAY_COLS];
        let mut pos = 0;
        for &b in b"block #" {
            if pos < row.len() {
                row[pos] = b;
                pos += 1;
            }
        }
        pos = write_decimal_into(&mut row, pos, secs);
        let _ = pos;
        *r1 = row;
    } else {
        format_iso8601_utc(secs, r1, r2);
    }
    write_line(foot, "> next");
    Ok(())
}

fn render_duration(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let secs = read_u64_be_tail(&bytes);
    let [_, r1, _r2, foot] = pages.page_mut(p);
    format_duration(secs, r1);
    write_line(foot, "> next");
    Ok(())
}

fn render_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => {
            // address is right-aligned in a 32-byte slot.
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            a
        }
        Resolved::Container(idx) => container_addr(tx, idx)?,
    };
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, r3] = pages.page_mut(p);
    write_addr_full_or_name(r1, r2, r3, &addr, tx.chain_id, resolver);
    Ok(())
}

fn render_enum(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    // Phase 4 v1: render the enum index numerically with the enum_ref
    // pool offset shown as a hint. Resolving the actual enum text
    // requires the pool TLV-decoder for the enum row, which the
    // current dbgen emits but the renderer doesn't yet consume —
    // wired in Phase 5 alongside the dynamic-types support.
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(bytes);
    let [_, r1, r2, foot] = pages.page_mut(p);
    let _ = write_amount_two_rows(r1, r2, &value, 0, 0, false, "");
    let _ = params.enum_ref;
    write_line(foot, "> next");
    Ok(())
}

fn render_unit(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let bytes = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => *b,
        Resolved::Container(idx) => container_u256(tx, idx)?,
    };
    let value = U256(bytes);
    let decimals = u32::from(params.decimals.unwrap_or(0));
    let unit_bytes = params.base.unwrap_or(b"");
    let [_, r1, r2, foot] = pages.page_mut(p);
    let fit = write_amount_two_rows(r1, r2, &value, decimals, 6, true, ascii_str(unit_bytes));
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!UNIT OVERFLOW",
        },
    );
    Ok(())
}

fn render_chain_id(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    _ir: &Erc7730Ir<'_>,
    _body: &[u8],
    tx: &Eip1559Tx,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, foot] = pages.page_mut(p);
    // "<decimal id>" on row 1, "<chain_name>" on row 2.
    let mut decimal = [b' '; DISPLAY_COLS];
    write_decimal_into(&mut decimal, 0, tx.chain_id);
    *r1 = decimal;
    write_line(r2, chain_name(tx.chain_id));
    write_line(foot, "> next");
    Ok(())
}

fn render_token_ticker(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    erc20: Option<&Erc20Metadata<'_>>,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let addr = resolve_token_address(ir, body, tx, params).ok();
    let [_, r1, _r2, foot] = pages.page_mut(p);
    match (addr, erc20) {
        (Some(a), Some(meta)) if a == meta.contract => {
            write_line_bytes(r1, meta.symbol);
        }
        _ => write_line(r1, "(unknown token)"),
    }
    write_line(foot, "> next");
    Ok(())
}

fn render_interop_address_name(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    _resolver: &NameResolver<'_>,
) -> Result<(), RenderErr> {
    // ERC-3770 long form: `eip155:<chainId>:0x<addr>`. The chain short-
    // name registry is out of scope (would require a separate name DB
    // on-device); long form is unambiguous and self-describing.
    let addr = match resolve_path(ir, field.path_off, body)? {
        Resolved::Slot32(b) => {
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            a
        }
        Resolved::Container(idx) => container_addr(tx, idx)?,
    };
    let p1 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p1, field.label);
    let [_, r1, _r2, foot1] = pages.page_mut(p1);
    let mut row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    for &b in b"eip155:" {
        if pos < row.len() {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal_into(&mut row, pos, tx.chain_id);
    if pos < row.len() {
        row[pos] = b':';
    }
    *r1 = row;
    write_line(foot1, "> next");

    let p2 = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_line(pages.row_mut(p2, 0), "Address:");
    let [_, r1, r2, r3] = pages.page_mut(p2);
    write_addr_full(r1, r2, r3, &addr);
    Ok(())
}

fn render_encrypted(
    field: &FieldEntry<'_>,
    pages: &mut Pages,
    params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    write_label_row(pages, p, field.label);
    let [_, r1, r2, foot] = pages.page_mut(p);
    write_line(r1, "[ENCRYPTED]");
    if let Some(fb) = params.fallback_label {
        write_line_bytes(r2, fb);
    }
    write_line(foot, "> next");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

pub(super) fn write_label_row(pages: &mut Pages, page: usize, label: &[u8]) {
    let row = pages.row_mut(page, 0);
    // Reuse the same "ASCII bytes into 16-col row, space-padded"
    // semantics that blind_sign uses for verified-name labels.
    write_line_bytes(row, label);
}

pub(super) fn write_line_bytes(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let n = text.len().min(DISPLAY_COLS);
    row[..n].copy_from_slice(&text[..n]);
}

/// Write 16 bytes of hex (32 chars) into a 16-col row. Used by Raw +
/// fingerprint pages. We deliberately do NOT include the "0x" prefix
/// — the next-page row would lose 2 visual chars and the hex pages
/// are visually anchored by row separators.
fn write_hex_word(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let take = bytes.len().min(DISPLAY_COLS / 2);
    for (i, &b) in bytes[..take].iter().enumerate() {
        row[i * 2] = hex_nibble(b >> 4);
        row[i * 2 + 1] = hex_nibble(b & 0x0F);
    }
}

#[inline]
pub(super) fn hex_nibble(n: u8) -> u8 {
    match n & 0x0F {
        0..=9 => b'0' + n,
        v => b'a' + (v - 10),
    }
}

/// Read the low 8 bytes of a 32-byte BE word as a u64. High 24 bytes
/// must be zero; we don't check that here (the formatter that calls
/// this is responsible for the type expectation), so out-of-range
/// values silently truncate. The seed corpus's `Date`/`Duration`
/// fields are always u64-shaped.
fn read_u64_be_tail(bytes: &[u8; 32]) -> u64 {
    u64::from_be_bytes(bytes[24..].try_into().unwrap())
}

/// Format a u64 as decimal at `out[pos..]`. Returns the new position.
pub(super) fn write_decimal_into(
    out: &mut [u8; DISPLAY_COLS],
    pos: usize,
    mut n: u64,
) -> usize {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if n == 0 {
        if pos < out.len() {
            out[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    while n > 0 && i < buf.len() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut p = pos;
    for j in (0..i).rev() {
        if p >= out.len() {
            break;
        }
        out[p] = buf[j];
        p += 1;
    }
    p
}

/// Render unix-seconds `secs` into rows `r1` + `r2` as `YYYY-MM-DD` /
/// `HH:MM:SS UTC`. Always-fits since the format is < 16 chars per row.
fn format_iso8601_utc(
    secs: u64,
    r1: &mut [u8; DISPLAY_COLS],
    r2: &mut [u8; DISPLAY_COLS],
) {
    let (year, mon, day, hour, min, sec) = unix_to_ymdhms(secs);

    for cell in r1.iter_mut() {
        *cell = b' ';
    }
    for cell in r2.iter_mut() {
        *cell = b' ';
    }

    // Row 1: "YYYY-MM-DD" (10 chars), padded.
    write_2digit(&mut r1[0..2], (year / 100) as u8);
    write_2digit(&mut r1[2..4], (year % 100) as u8);
    r1[4] = b'-';
    write_2digit(&mut r1[5..7], mon);
    r1[7] = b'-';
    write_2digit(&mut r1[8..10], day);

    // Row 2: "HH:MM:SS UTC" (12 chars).
    write_2digit(&mut r2[0..2], hour);
    r2[2] = b':';
    write_2digit(&mut r2[3..5], min);
    r2[5] = b':';
    write_2digit(&mut r2[6..8], sec);
    r2[9] = b'U';
    r2[10] = b'T';
    r2[11] = b'C';
}

fn write_2digit(out: &mut [u8], n: u8) {
    out[0] = b'0' + (n / 10) % 10;
    out[1] = b'0' + (n % 10);
}

/// Convert unix seconds → `(year, month, day, hour, min, sec)` UTC.
/// Civil-from-days algorithm by Howard Hinnant (public domain).
fn unix_to_ymdhms(secs: u64) -> (u16, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let hour = (sod / 3600) as u8;
    let min = ((sod % 3600) / 60) as u8;
    let sec = (sod % 60) as u8;

    // Civil-from-days: offset by 719_468 so 1970-01-01 → 0.
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = (y + if m <= 2 { 1 } else { 0 }) as u16;

    (year, m, d, hour, min, sec)
}

/// "Xd Yh Zm Ws" duration into a single row. Omits leading zero
/// components.
fn format_duration(mut secs: u64, row: &mut [u8; DISPLAY_COLS]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let d = secs / 86_400;
    secs %= 86_400;
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;
    let mut pos = 0usize;
    if d > 0 {
        pos = write_decimal_into(row, pos, d);
        if pos < row.len() {
            row[pos] = b'd';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, h);
        if pos < row.len() {
            row[pos] = b'h';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    if m > 0 || h > 0 || d > 0 {
        pos = write_decimal_into(row, pos, m);
        if pos < row.len() {
            row[pos] = b'm';
            pos += 1;
        }
        if pos < row.len() {
            row[pos] = b' ';
            pos += 1;
        }
    }
    pos = write_decimal_into(row, pos, s);
    if pos < row.len() {
        row[pos] = b's';
    }
}

/// Resolve the token contract address from a `tokenAmount` /
/// `tokenTicker` field's parameters: `params.token_path` wins, then
/// `params.token` literal.
fn resolve_token_address(
    ir: &Erc7730Ir<'_>,
    body: &[u8],
    tx: &Eip1559Tx,
    params: &ParamSet<'_>,
) -> Result<[u8; 20], RenderErr> {
    if let Some(tp) = params.token_path {
        // tp is a path program (NO leading length byte — dbgen pushes
        // it raw via `push_tlv(PARAM_TOKEN_PATH, &prog)`). Resolve
        // it directly without re-parsing through `path_bytes`.
        return resolve_path_bytes(tp, body, tx).map(|w| {
            let mut a = [0u8; 20];
            a.copy_from_slice(&w[12..]);
            a
        });
    }
    if let Some(t) = params.token {
        return Ok(*t);
    }
    let _ = ir;
    Err(RenderErr::Reject("7730 no token"))
}

/// Resolve a path program (raw, no length prefix) to a 32-byte word.
/// Mirrors [`resolve_path`] but operates on a pre-extracted program
/// slice — used by `tokenPath` which is stored as a raw program inside
/// the parameter TLV blob.
fn resolve_path_bytes(prog: &[u8], body: &[u8], tx: &Eip1559Tx) -> Result<[u8; 32], RenderErr> {
    if prog.is_empty() {
        return Err(RenderErr::Reject("7730 empty path"));
    }
    let root = PathOp::try_from(prog[0]).map_err(|_| RenderErr::Reject("7730 bad root"))?;
    let mut p = 1usize;

    match root {
        PathOp::RootStructured => {
            let mut slot = 0usize;
            while p < prog.len() {
                let op = PathOp::try_from(prog[p])
                    .map_err(|_| RenderErr::Reject("7730 bad op"))?;
                p += 1;
                match op {
                    PathOp::FieldIdx => {
                        if p + 2 > prog.len() {
                            return Err(RenderErr::Reject("7730 trunc field"));
                        }
                        let idx = u16::from_be_bytes([prog[p], prog[p + 1]]) as usize;
                        p += 2;
                        slot = slot
                            .checked_add(idx)
                            .ok_or(RenderErr::Reject("7730 slot ovf"))?;
                    }
                    _ => return Err(RenderErr::Reject("7730 path p4 unsup")),
                }
            }
            let start = slot
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let end = start
                .checked_add(32)
                .ok_or(RenderErr::Reject("7730 slot ovf"))?;
            let word = body
                .get(start..end)
                .ok_or(RenderErr::Reject("7730 short body"))?;
            let mut out = [0u8; 32];
            out.copy_from_slice(word);
            Ok(out)
        }
        PathOp::RootContainer => {
            if p + 3 != prog.len() || prog[p] != PathOp::FieldIdx as u8 {
                return Err(RenderErr::Reject("7730 cnt bad"));
            }
            let idx = u16::from_be_bytes([prog[p + 1], prog[p + 2]]);
            match idx {
                container_field::TO => {
                    let addr = tx.to.ok_or(RenderErr::Reject("7730 no to"))?;
                    let mut out = [0u8; 32];
                    out[12..].copy_from_slice(&addr);
                    Ok(out)
                }
                _ => container_u256(tx, idx),
            }
        }
        _ => Err(RenderErr::Reject("7730 path no root")),
    }
}

