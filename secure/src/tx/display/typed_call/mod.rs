//! Phase 2 typed-args calldata renderer — the gate that fires between
//! "calldata didn't decode as ERC-20" and the BLIND SIGN word-dump
//! fallback. See `docs/calldata-decoding-handoff.md` for the full spec.
//!
//! Trust framing — Phase 2 trusts the *types* (vendor-curated text_sig,
//! Merkle-verified, cross-checked against `calldata[0..4]`), not the
//! contract's semantics. The "BLIND SIGN" banner stays on page 0
//! because we still don't know what the contract DOES with the args.
//! Phase 3 (per-contract attestation) is the moment that banner can
//! flip to "VERIFIED CONTRACT".
//!
//! Module layout:
//!   * `parser` — text-sig tokenizer + type-arena.
//!   * `abi` — strict two-pass ABI walker over `inner_data[4..]`.
//!   * `mod.rs` (this file) — page assembly + per-arg renderers.
//!
//! Decline-and-fall-back is the contract: any parser failure, any
//! shape mismatch, any unsupported type, any over-cap argument count
//! ⇒ `try_render_typed_call` returns `None` and the caller renders
//! the Phase 1 BLIND SIGN flow with the FUNCTION page intact.

use sha2::{Digest, Sha256};

use super::primitives::{
    chain_name, hex_nibble, write_addr_full_or_name, write_chain, write_eth_two_rows,
    write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row, write_tip_row,
    AmountFit,
};
use super::Pages;
use crate::names::NameResolver;
use crate::selectors::SelectorMeta;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use crate::tx::typed_call::abi::{self, walk, Walked};
use crate::tx::typed_call::parser::{parse_text_sig, ParsedSig, TypeId, TypeRef};

/// Hard cap on how many typed args we render. Top-level `MAX_ARGS` in
/// the parser is 16 (mirrors the Python validator), but the page
/// budget caps us at 6 — anything past that falls back to BLIND SIGN.
const MAX_TYPED_ARGS_RENDERED: usize = 6;

/// Try to render a Phase 2 typed-args display. Returns `None` on any
/// parse / shape / cap failure ⇒ caller falls back to
/// `render_blind_sign_pages`.
pub(super) fn try_render_typed_call(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    meta: &SelectorMeta<'_>,
    resolver: &NameResolver<'_>,
) -> Option<Pages> {
    if inner_data.len() < 4 {
        return None;
    }

    // Cross-check is a defence-in-depth re-run of what cmd_sign_userop
    // already did. Cheap, and it pins the invariant locally.
    if inner_data[0..4] != meta.selector {
        return None;
    }

    let parsed = parse_text_sig(meta.text_sig)?;
    if parsed.arg_count > MAX_TYPED_ARGS_RENDERED {
        return None;
    }

    let body = &inner_data[4..];
    let walked = walk(&parsed, body)?;

    // Page count budget:
    //   1  banner page (BLIND SIGN + text_sig)
    //   N  typed args
    //   1  To: <contract>
    //   ?  Value (only when nonzero)
    //   1  Chain
    //   1  Max fee + tip
    //   1  Worst-case
    //   1  Nonce + buttons
    let value_page = if tx.value.is_zero() { 0 } else { 1 };
    let total = 1 + walked.arg_count + 1 + value_page + 4;
    if total > super::MAX_PAGES {
        return None;
    }

    let mut pages = Pages::with_len(total);
    let mut page_idx = 0usize;

    // ── Page 0: ! BLIND SIGN + text_sig wrapped ─────────────────────
    {
        let [r0, r1, r2, r3] = &mut pages.buf[page_idx];
        write_line(r0, "! BLIND SIGN");
        write_text_sig_rows(r1, r2, meta.text_sig);
        write_line(r3, "> next");
    }
    page_idx += 1;

    // ── Pages 1..1+N: typed args ────────────────────────────────────
    for i in 0..walked.arg_count {
        if !render_arg(
            &mut pages,
            page_idx,
            i,
            &parsed,
            &walked.args[i],
            body,
            tx.chain_id,
            resolver,
        )? {
            // Per-type renderer can decline (e.g. inner type the
            // first cut doesn't support). Any decline ⇒ fall back.
            return None;
        }
        page_idx += 1;
    }

    // ── Page (next): To: <contract> ─────────────────────────────────
    write_line(&mut pages.buf[page_idx][0], "To:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[page_idx];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    } else {
        write_line(&mut pages.buf[page_idx][1], "(contract create)");
    }
    page_idx += 1;

    // ── Page (next, optional): Value: ───────────────────────────────
    if value_page == 1 {
        write_line(&mut pages.buf[page_idx][0], "! VALUE:");
        let [_lbl, r1, r2, foot] = &mut pages.buf[page_idx];
        let fit = write_eth_two_rows(r1, r2, &tx.value);
        write_line(
            foot,
            match fit {
                AmountFit::Full => "> next",
                AmountFit::Overflow => "!AMOUNT OVERFLOW",
            },
        );
        page_idx += 1;
    }

    // ── Page (next): Chain ──────────────────────────────────────────
    write_line(&mut pages.buf[page_idx][0], "Chain:");
    write_chain(&mut pages.buf[page_idx][1], tx.chain_id);
    write_line(&mut pages.buf[page_idx][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[page_idx][3], "> next");
    page_idx += 1;

    // ── Page (next): Max fee + tip ──────────────────────────────────
    write_line(&mut pages.buf[page_idx][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[page_idx][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[page_idx][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[page_idx][3], "> next");
    page_idx += 1;

    // ── Page (next): Worst-case fee budget + gas ────────────────────
    write_line(&mut pages.buf[page_idx][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[page_idx][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[page_idx][2], tx.gas_limit);
    write_line(&mut pages.buf[page_idx][3], "> next");
    page_idx += 1;

    // ── Page (last): Nonce + buttons ────────────────────────────────
    write_nonce_row(&mut pages.buf[page_idx][0], tx.nonce);
    write_line(&mut pages.buf[page_idx][1], "");
    write_line(&mut pages.buf[page_idx][2], "L=Cancel");
    write_line(&mut pages.buf[page_idx][3], "R=Confirm");
    page_idx += 1;

    debug_assert_eq!(page_idx, total);
    Some(pages)
}

// ---------------------------------------------------------------------------
// Per-arg dispatch
// ---------------------------------------------------------------------------

/// Render one top-level arg into the page at `page_idx`. Row 0 carries
/// the label; rows 1..3 carry the value via per-type helpers.
///
/// Returns `Ok(true)` on success, `Ok(false)` if the per-type helper
/// declined (renderer-level fallback to BLIND SIGN), `None` if a
/// downstream decode failed (data corruption — also fall back).
fn render_arg(
    pages: &mut Pages,
    page_idx: usize,
    arg_idx: usize,
    parsed: &ParsedSig<'_>,
    walked: &Walked,
    body: &[u8],
    chain_id: u64,
    resolver: &NameResolver<'_>,
) -> Option<bool> {
    // Pre-decode anything that needs the body before we take a mut
    // borrow on the page (so a decode failure doesn't leave the page
    // half-rendered).
    let kind = *parsed.arena.get(walked.type_id);
    let [r0, r1, r2, r3] = &mut pages.buf[page_idx];
    write_arg_label(r0, arg_idx, parsed, walked.type_id);
    let ok = match kind {
        TypeRef::Address => {
            let addr = abi::read_address(body, walked.body_off)?;
            write_addr_full_or_name(r1, r2, r3, &addr, chain_id, resolver);
            true
        }
        TypeRef::Bool => {
            let v = abi::read_bool(body, walked.body_off)?;
            write_line(r1, if v { "true" } else { "false" });
            true
        }
        TypeRef::Uint(_) => {
            let v = abi::read_u256(body, walked.body_off)?;
            write_uint_two_rows(r1, r2, &v)
        }
        TypeRef::Int(bits) => {
            let v = abi::read_u256(body, walked.body_off)?;
            write_int_two_rows(r1, r2, bits, &v)
        }
        TypeRef::BytesN(n) => {
            let w = abi::word(body, walked.body_off)?;
            write_bytesn_rows(r1, r2, n, w)
        }
        TypeRef::Bytes | TypeRef::String => {
            let len = walked.count;
            let payload_off = walked.body_off + 32;
            let payload = body.get(payload_off..payload_off + len as usize)?;
            let is_string = matches!(kind, TypeRef::String);
            write_bytes_or_string_rows(r1, r2, r3, len, payload, is_string);
            true
        }
        TypeRef::Array { elem, fixed_len } => {
            let count = walked.count;
            let elem_kind = *parsed.arena.get(elem);
            let elem_word_off = match fixed_len {
                Some(_) => walked.body_off,        // inline in head
                None => walked.body_off + 32,      // skip length word
            };
            write_array_rows(
                r1,
                r2,
                r3,
                count,
                &elem_kind,
                body,
                elem_word_off,
                chain_id,
                resolver,
            )
        }
        TypeRef::Tuple { .. } => false, // walker should already have declined
    };
    Some(ok)
}

// ---------------------------------------------------------------------------
// Row helpers
// ---------------------------------------------------------------------------

fn write_arg_label(
    row: &mut [u8; DISPLAY_COLS],
    arg_idx: usize,
    parsed: &ParsedSig<'_>,
    type_id: TypeId,
) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    pos = write_str(row, pos, b"arg ");
    pos = write_decimal(row, pos, arg_idx as u64);
    pos = write_str(row, pos, b" ");
    pos = write_typename(row, pos, parsed, type_id);
    if pos < DISPLAY_COLS {
        row[pos] = b':';
    }
}

fn write_typename(
    row: &mut [u8; DISPLAY_COLS],
    pos: usize,
    parsed: &ParsedSig<'_>,
    id: TypeId,
) -> usize {
    match parsed.arena.get(id) {
        TypeRef::Address => write_str(row, pos, b"address"),
        TypeRef::Bool => write_str(row, pos, b"bool"),
        TypeRef::Bytes => write_str(row, pos, b"bytes"),
        TypeRef::String => write_str(row, pos, b"string"),
        TypeRef::BytesN(n) => {
            let p = write_str(row, pos, b"bytes");
            write_decimal(row, p, *n as u64)
        }
        TypeRef::Uint(bits) => {
            let p = write_str(row, pos, b"uint");
            write_decimal(row, p, *bits as u64)
        }
        TypeRef::Int(bits) => {
            let p = write_str(row, pos, b"int");
            write_decimal(row, p, *bits as u64)
        }
        TypeRef::Array { elem, fixed_len } => {
            let p = write_typename(row, pos, parsed, *elem);
            let p = write_str(row, p, b"[");
            let p = match fixed_len {
                Some(n) => write_decimal(row, p, *n as u64),
                None => p,
            };
            write_str(row, p, b"]")
        }
        TypeRef::Tuple { .. } => write_str(row, pos, b"(...)"),
    }
}

fn write_str(row: &mut [u8; DISPLAY_COLS], pos: usize, s: &[u8]) -> usize {
    let mut p = pos;
    for &b in s {
        if p >= DISPLAY_COLS {
            return p;
        }
        row[p] = b;
        p += 1;
    }
    p
}

fn write_decimal(row: &mut [u8; DISPLAY_COLS], pos: usize, mut n: u64) -> usize {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if n == 0 {
        buf[0] = b'0';
        i = 1;
    } else {
        while n > 0 {
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
    }
    let mut p = pos;
    for j in 0..i {
        if p >= DISPLAY_COLS {
            return p;
        }
        row[p] = buf[i - 1 - j];
        p += 1;
    }
    p
}

/// Write the verified `text_sig` across two rows (16 cols each = 32
/// chars max). Truncates with "..." marker on the second row when the
/// signature is longer.
fn write_text_sig_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    text: &[u8],
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let n1 = core::cmp::min(text.len(), DISPLAY_COLS);
    row1[..n1].copy_from_slice(&text[..n1]);
    if text.len() > DISPLAY_COLS {
        let rest = &text[DISPLAY_COLS..];
        if rest.len() <= DISPLAY_COLS {
            row2[..rest.len()].copy_from_slice(rest);
        } else {
            // Show first 13 chars of rest, then "..."
            row2[..13].copy_from_slice(&rest[..13]);
            row2[13..16].copy_from_slice(b"...");
        }
    }
}

/// `uintN` decimal across rows 1+2. Returns `false` only on truly
/// pathological 78-digit values (the OLED can show 32 digits across
/// two rows).
fn write_uint_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let mut tmp = [0u8; 96];
    match value.format_decimal(0, 0, false, &mut tmp) {
        Some(n) if n <= DISPLAY_COLS => {
            row1[..n].copy_from_slice(&tmp[..n]);
            true
        }
        Some(n) if n <= 2 * DISPLAY_COLS => {
            row1.copy_from_slice(&tmp[..DISPLAY_COLS]);
            row2[..n - DISPLAY_COLS].copy_from_slice(&tmp[DISPLAY_COLS..n]);
            true
        }
        _ => {
            write_line(row1, "!OVERFLOW");
            true
        }
    }
}

/// `intN` two's-complement → signed decimal across rows 1+2. The
/// negative range is decoded by negating the U256 and prefixing '-'.
fn write_int_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    bits: u16,
    value: &U256,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];

    // Sign bit lives at position (bits-1) inside the right-aligned
    // bigint. For bits=256 it's the MSB of value.0[0]; for bits=N it's
    // bit (N-1) counted from the LSB.
    let bit_idx = (bits - 1) as usize;
    let byte_from_lsb = bit_idx / 8;
    let bit_in_byte = bit_idx % 8;
    let byte_idx = 31 - byte_from_lsb;
    let is_neg = (value.0[byte_idx] >> bit_in_byte) & 1 == 1;

    // Compute absolute value: for negatives, two's complement within
    // the N-bit window: abs = (~value + 1) masked to N bits.
    let abs = if is_neg {
        let mut tmp = value.0;
        // Bitwise NOT
        for b in tmp.iter_mut() {
            *b = !*b;
        }
        // +1 with carry
        let mut carry: u16 = 1;
        for b in tmp.iter_mut().rev() {
            let s = *b as u16 + carry;
            *b = s as u8;
            carry = s >> 8;
        }
        // Mask to N bits.
        if bits < 256 {
            let high_bytes_to_zero = (256 - bits as usize) / 8;
            for i in 0..high_bytes_to_zero {
                tmp[i] = 0;
            }
            let extra_bits = (256 - bits as usize) % 8;
            if extra_bits != 0 {
                tmp[high_bytes_to_zero] &= 0xff >> extra_bits;
            }
        }
        U256(tmp)
    } else {
        *value
    };

    let mut tmp = [0u8; 96];
    match abs.format_decimal(0, 0, false, &mut tmp) {
        Some(n) => {
            let total = if is_neg { n + 1 } else { n };
            if total <= DISPLAY_COLS {
                let mut p = 0;
                if is_neg {
                    row1[0] = b'-';
                    p = 1;
                }
                row1[p..p + n].copy_from_slice(&tmp[..n]);
                true
            } else if total <= 2 * DISPLAY_COLS {
                let mut buf = [0u8; 96];
                let mut p = 0;
                if is_neg {
                    buf[0] = b'-';
                    p = 1;
                }
                buf[p..p + n].copy_from_slice(&tmp[..n]);
                row1.copy_from_slice(&buf[..DISPLAY_COLS]);
                row2[..total - DISPLAY_COLS]
                    .copy_from_slice(&buf[DISPLAY_COLS..total]);
                true
            } else {
                write_line(row1, "!OVERFLOW");
                true
            }
        }
        None => {
            write_line(row1, "!OVERFLOW");
            true
        }
    }
}

/// `bytesN` hex render. The N data bytes occupy `word[0..N]` (left-
/// padded per ABI). For N <= 7 we fit in one row; for N <= 14 we use
/// two rows; for larger N we use a head/tail elision.
fn write_bytesn_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    n: u8,
    word: &[u8],
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let n = n as usize;
    if n == 0 || n > 32 || word.len() < n {
        return false;
    }
    let total_chars = 2 + 2 * n; // "0x" + 2N hex
    if total_chars <= DISPLAY_COLS {
        // Single row.
        row1[0] = b'0';
        row1[1] = b'x';
        for i in 0..n {
            row1[2 + i * 2] = hex_nibble(word[i] >> 4);
            row1[2 + i * 2 + 1] = hex_nibble(word[i] & 0x0f);
        }
    } else if total_chars <= 2 * DISPLAY_COLS {
        // Two rows: 0x + 7 bytes on row 1, rest on row 2.
        row1[0] = b'0';
        row1[1] = b'x';
        let chars_r1 = (DISPLAY_COLS - 2) / 2; // 7 bytes
        for i in 0..chars_r1 {
            row1[2 + i * 2] = hex_nibble(word[i] >> 4);
            row1[2 + i * 2 + 1] = hex_nibble(word[i] & 0x0f);
        }
        let rest = n - chars_r1;
        for i in 0..rest {
            row2[i * 2] = hex_nibble(word[chars_r1 + i] >> 4);
            row2[i * 2 + 1] = hex_nibble(word[chars_r1 + i] & 0x0f);
        }
    } else {
        // Head/tail elision: first 7 + ... + last 6 (matches the
        // calldata-hash row helper in primitives.rs).
        row1[0] = b'0';
        row1[1] = b'x';
        for i in 0..7 {
            row1[2 + i * 2] = hex_nibble(word[i] >> 4);
            row1[2 + i * 2 + 1] = hex_nibble(word[i] & 0x0f);
        }
        row2[0] = b'.';
        row2[1] = b'.';
        row2[2] = b'.';
        row2[3] = b' ';
        for i in 0..6 {
            let b = word[n - 6 + i];
            row2[4 + i * 2] = hex_nibble(b >> 4);
            row2[4 + i * 2 + 1] = hex_nibble(b & 0x0f);
        }
    }
    true
}

/// Dynamic `bytes` / `string` render across three rows:
///   row1: "len: <N>"
///   row2: ASCII preview (first 14 chars + "…") for printable strings,
///         "(non-ASCII)" otherwise.
///   row3: "sha: <8 hex>…<8 hex>" — SHA-256 fingerprint head/tail.
fn write_bytes_or_string_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    len: u32,
    payload: &[u8],
    is_string: bool,
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    // Row 1: "len: <N>"
    let mut p = write_str(row1, 0, b"len: ");
    p = write_decimal(row1, p, len as u64);
    let _ = p;

    // Row 2: ASCII preview (only for `string` and only if all printable).
    let preview_room = DISPLAY_COLS;
    if is_string && payload.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        if payload.len() <= preview_room {
            row2[..payload.len()].copy_from_slice(payload);
        } else {
            // first (preview_room - 1) chars + ellipsis '~'
            let head = preview_room - 1;
            row2[..head].copy_from_slice(&payload[..head]);
            row2[head] = b'~';
        }
    } else if !is_string {
        let _ = write_str(row2, 0, b"(binary)");
    } else {
        let _ = write_str(row2, 0, b"(non-ASCII)");
    }

    // Row 3: "sha: <8 hex>…<8 hex>" — first 4 + last 4 bytes of digest.
    let hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(payload);
        h.finalize().into()
    };
    let mut p = write_str(row3, 0, b"sha: ");
    for i in 0..3 {
        if p + 1 >= DISPLAY_COLS {
            break;
        }
        row3[p] = hex_nibble(hash[i] >> 4);
        row3[p + 1] = hex_nibble(hash[i] & 0x0f);
        p += 2;
    }
    if p < DISPLAY_COLS {
        row3[p] = b'.';
        p += 1;
    }
    for i in 0..2 {
        if p + 1 >= DISPLAY_COLS {
            break;
        }
        row3[p] = hex_nibble(hash[30 + i] >> 4);
        row3[p + 1] = hex_nibble(hash[30 + i] & 0x0f);
        p += 2;
    }
    let _ = p;
}

/// Array render (covers both `T[N]` and `T[]`):
///   row1: "[<N> items]"
///   row2: "first: <decoded element>" (only if N > 0 and elem is renderable)
///   row3: blank
fn write_array_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    count: u32,
    elem: &TypeRef,
    body: &[u8],
    first_elem_off: usize,
    chain_id: u64,
    resolver: &NameResolver<'_>,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    // Row 1: "[<N> items]"
    let mut p = write_str(row1, 0, b"[");
    p = write_decimal(row1, p, count as u64);
    let _ = write_str(row1, p, b" items]");

    // Row 2: "first: ..." preview, only when N >= 1 and elem is a
    // renderable static primitive.
    if count == 0 {
        return true;
    }
    let mut p = write_str(row2, 0, b"first: ");
    match elem {
        TypeRef::Address => {
            // Inline the truncated form: 0x + 4 hex + … + 3 hex (10 chars).
            let addr = match abi::read_address(body, first_elem_off) {
                Some(a) => a,
                None => return false,
            };
            // Names lookup intentionally skipped here — we have only ~9
            // chars; show truncated hex for disambiguation.
            let _ = resolver; // suppressed; re-use later.
            let _ = chain_id;
            if p + 12 <= DISPLAY_COLS {
                row2[p] = b'0';
                row2[p + 1] = b'x';
                p += 2;
                for i in 0..3 {
                    row2[p] = hex_nibble(addr[i] >> 4);
                    row2[p + 1] = hex_nibble(addr[i] & 0x0f);
                    p += 2;
                }
                row2[p] = b'.';
                p += 1;
                for i in 0..2 {
                    row2[p] = hex_nibble(addr[18 + i] >> 4);
                    row2[p + 1] = hex_nibble(addr[18 + i] & 0x0f);
                    p += 2;
                }
            }
            true
        }
        TypeRef::Bool => {
            let v = match abi::read_bool(body, first_elem_off) {
                Some(v) => v,
                None => return false,
            };
            let _ = write_str(row2, p, if v { b"true" } else { b"false" });
            true
        }
        TypeRef::Uint(_) | TypeRef::Int(_) => {
            let v = match abi::read_u256(body, first_elem_off) {
                Some(v) => v,
                None => return false,
            };
            let mut tmp = [0u8; 96];
            match v.format_decimal(0, 0, false, &mut tmp) {
                Some(n) if p + n <= DISPLAY_COLS => {
                    row2[p..p + n].copy_from_slice(&tmp[..n]);
                }
                Some(_) => {
                    let _ = write_str(row2, p, b"...");
                }
                None => {
                    let _ = write_str(row2, p, b"!OVF");
                }
            }
            true
        }
        TypeRef::BytesN(n) => {
            let w = match abi::word(body, first_elem_off) {
                Some(w) => w,
                None => return false,
            };
            let bytes_to_show = core::cmp::min(*n as usize, 4);
            if p + 2 + 2 * bytes_to_show <= DISPLAY_COLS {
                row2[p] = b'0';
                row2[p + 1] = b'x';
                p += 2;
                for i in 0..bytes_to_show {
                    row2[p] = hex_nibble(w[i] >> 4);
                    row2[p + 1] = hex_nibble(w[i] & 0x0f);
                    p += 2;
                }
                if (*n as usize) > bytes_to_show && p < DISPLAY_COLS {
                    row2[p] = b'.';
                }
            }
            true
        }
        // Element types that aren't a static primitive shouldn't have
        // got past the walker; still, handle defensively.
        _ => false,
    }
}

// Page-assembly tests live in the e2e harness (Scenario 5b/5d) since
// they require an Eip1559Tx + NameResolver. Parser + ABI walker have
// host-runnable unit tests in `crate::tx::typed_call::{parser, abi}`.
