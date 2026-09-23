//! Phase 2 typed-args calldata renderer — the gate that fires between
//! "calldata didn't decode as ERC-20" and the BLIND SIGN word-dump
//! fallback. See `docs/archive/calldata-decoding-handoff.md` for the full spec.
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

use super::primitives::{
    build_legacy_fee_pages, hex_nibble, write_addr_full_or_name, write_chain, write_line,
    write_native_amount_two_rows, write_nonce_row, AmountFit,
};
use super::Pages;
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use crate::tx::typed_call::abi::{self, walk, Walked};
use crate::tx::typed_call::parser::{parse_text_sig, ParsedSig, TypeId, TypeRef};

/// Hard cap on how many typed args we render. Top-level `MAX_ARGS` in
/// the parser is 16 (mirrors the Python validator), but the page
/// budget caps us at 6 — anything past that falls back to BLIND SIGN.
const MAX_TYPED_ARGS_RENDERED: usize = 6;

/// The pixel-UI twin of this painter (`ui-px`, port step 2).
#[cfg(any(test, feature = "ui-px"))]
pub(crate) mod screens;

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

    // ── Page 0: banner + text_sig wrapped ───────────────────────────
    //
    // Banner copy is provenance-dependent:
    //   * Curated     → "! BLIND SIGN"  (vendor-attested name; contract
    //                    semantics still unknown)
    //   * SelfAttest  → "! UNVERIFIED"  (companion-supplied name; could
    //                    be a crafted ~2³² keccak-collision — the user
    //                    must verify the function name against the dapp)
    //
    // Both paths keep the trusted-UI tail (To, Value, Chain, fees,
    // nonce) identical because those values come from the EIP-1559
    // envelope and are not affected by which selector source the
    // companion picked.
    {
        let banner = match meta.provenance {
            SelectorProvenance::Curated => "! BLIND SIGN",
            SelectorProvenance::SelfAttest => "! UNVERIFIED",
        };
        let [r0, r1, r2, r3] = &mut pages.buf[page_idx];
        write_line(r0, banner);
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
        let fit = write_native_amount_two_rows(r1, r2, &tx.value, tx.chain_id);
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
    {
        let [_label, id, continuation_or_name, _foot] = &mut pages.buf[page_idx];
        write_chain(id, continuation_or_name, tx.chain_id);
    }
    write_line(&mut pages.buf[page_idx][3], "> next");
    page_idx += 1;

    // ── Pages (next): exact max/tip and worst-case fee envelope ─────
    let fee_pages = build_legacy_fee_pages(
        &tx.max_fee_per_gas,
        &tx.max_priority_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    )
    .pages;
    pages.buf[page_idx] = fee_pages[0];
    pages.buf[page_idx + 1] = fee_pages[1];
    page_idx += 2;

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
        TypeRef::Uint(bits) => {
            let v = abi::read_u256(body, walked.body_off)?;
            write_uint_two_rows(r1, r2, bits, &v)
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
            // Returns `false` for any non-empty payload → decline to
            // blind-sign (audit 2026-06-25 LOW-1, parity with `bytesN>15`).
            write_bytes_or_string_rows(r1, r2, r3, len, payload, is_string)
        }
        TypeRef::Array { elem, fixed_len } => {
            let count = walked.count;
            // WYSIWYS (audit 2026-06-18 — array-tail hiding). This arg gets
            // exactly ONE page, and `write_array_rows` can only render
            // element 0 (`first: …`) plus the `[N items]` count. For any
            // array with more than one element, elements 1..N are part of
            // the signed `executeWithOffchainCount(...,data)` calldata but
            // would never reach a page — a benign `first:` recipient/amount
            // lulling the user while an attacker leg in slot 1 is signed
            // unseen (e.g. `disperse([friend,attacker],[tiny,balance])`).
            //
            // The renderer cannot honestly show the whole array on one
            // OLED page, so it DECLINES rather than rendering a misleading
            // partial: returning `false` makes `try_render_typed_call`
            // bail to `None`, and the caller falls back to the loud Phase-1
            // BLIND SIGN flow (banner + selector + full calldata SHA-256),
            // which hides nothing behind a fake-friendly decode. This is
            // the same "refuse rather than truncate" rule the Safe
            // multiSend page-budget gate already enforces. Arrays of 0 or 1
            // elements are rendered in full below (nothing is hidden).
            if count > 1 {
                return Some(false);
            }
            let elem_kind = *parsed.arena.get(elem);
            let elem_word_off = match fixed_len {
                Some(_) => walked.body_off,   // inline in head
                None => walked.body_off + 32, // skip length word
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
fn write_text_sig_rows(row1: &mut [u8; DISPLAY_COLS], row2: &mut [u8; DISPLAY_COLS], text: &[u8]) {
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

/// Zero every bit at position `>= bits` (counted from the LSB) of a
/// 32-byte big-endian word, matching Solidity's calldata clean-up of a
/// sub-256-bit `uintN` / positive-`intN` argument (`and(word, 2^N - 1)`
/// / `signextend`). No-op for `bits >= 256`.
///
/// Shared by the `uintN` / `intN` value renderers and the count==1
/// `uintN[]` element renderer so the trusted display shows exactly the
/// magnitude the contract executes, never the raw 32-byte word (audit
/// 2026-06-26 — typed-call integer over-display). Byte-for-byte the same
/// masking the signed-int negative branch already used inline.
fn mask_low_bits(word: &mut [u8; 32], bits: u16) {
    let bits = bits as usize;
    if bits >= 256 {
        return;
    }
    let high_bytes_to_zero = (256 - bits) / 8;
    for b in word.iter_mut().take(high_bytes_to_zero) {
        *b = 0;
    }
    let extra_bits = (256 - bits) % 8;
    if extra_bits != 0 {
        word[high_bytes_to_zero] &= 0xff >> extra_bits;
    }
}

/// `uintN` decimal across rows 1+2. Returns `false` only on truly
/// pathological 78-digit values (the OLED can show 32 digits across
/// two rows).
///
/// The 32-byte word is first cleaned to its low `bits` bits (audit
/// 2026-06-26 — typed-call uintN over-display). Solidity's calldata
/// decoder masks a `uintN` argument to `word & (2^N - 1)`, so a word
/// carrying non-zero bits above N executes as the masked value while the
/// raw word reads LARGER on screen — a `uint64` word `2^64 + 5` rendered
/// `18446744073709551621` while the contract acted on `5`. The
/// `address`/`bool` readers already reject such dirty words; masking here
/// shows exactly the magnitude the contract executes (never larger), the
/// most WYSIWYS-faithful choice. `mask_low_bits` is a no-op for
/// `bits >= 256` (plain `uint256`).
fn write_uint_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    bits: u16,
    value: &U256,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let mut word = value.0;
    mask_low_bits(&mut word, bits);
    let value = U256(word);
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
        // Mask to N bits — the low-N two's-complement magnitude.
        mask_low_bits(&mut tmp, bits);
        U256(tmp)
    } else {
        // Positive `intN`: Solidity sign-extends from bit N-1, so with the
        // sign bit clear every higher bit is zero. Mask to N bits so dirty
        // high bits the EVM discards cannot inflate the displayed magnitude
        // (audit 2026-06-26 — typed-call intN over-display; sibling of the
        // uintN fix). No-op for `bits >= 256`.
        let mut tmp = value.0;
        mask_low_bits(&mut tmp, bits);
        U256(tmp)
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
                row2[..total - DISPLAY_COLS].copy_from_slice(&buf[DISPLAY_COLS..total]);
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
        // N >= 16: the full 2N+2 hex chars do not fit the two rows this
        // arg page has. A head/tail elision (first 7 + ... + last 6) would
        // hide the middle bytes of a signed `bytesN` identifier — a
        // brute-forceable display collision and the unfixed sibling of the
        // array-tail elision (audit 2026-06-23 — bytesN>=16). DECLINE so
        // the caller falls back to the loud blind-sign flow (banner + full
        // calldata SHA-256) rather than render a truncated value that
        // looks decoded. (The rows were cleared above; the caller discards
        // this Pages on a decline.)
        return false;
    }
    true
}

/// Dynamic `bytes` / `string`:
///   - empty payload (`len == 0`): fully represented by the "len: 0" row →
///     render and return `true`.
///   - non-empty payload: DECLINE (return `false`).
///
/// Audit 2026-06-25 LOW-1 (parity with `write_bytesn_rows`): a head/tail
/// SHA-256 fingerprint row anchors only 40 bits (`hash[0..3] ‖ hash[30..32]`)
/// of an attacker-chosen, *signed* payload — the dynamic sibling of the
/// `bytesN>15` decline. Showing it dressed up as a decoded field (under the
/// arg label) understates how little of the payload the user can actually
/// cross-check. Returning `false` makes `render_arg` bail the whole
/// typed-call decode to the loud blind-sign flow (banner + selector + the
/// full ERC-8213 256-bit calldata fingerprint the handler always appends),
/// which hides nothing behind a truncated-but-decoded-looking value.
fn write_bytes_or_string_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    row3: &mut [u8; DISPLAY_COLS],
    len: u32,
    payload: &[u8],
    is_string: bool,
) -> bool {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    *row3 = [b' '; DISPLAY_COLS];

    // Row 1: "len: <N>"
    let mut p = write_str(row1, 0, b"len: ");
    p = write_decimal(row1, p, len as u64);
    let _ = p;

    if len == 0 {
        // Empty payload carries no hidden bytes; "len: 0" is a faithful,
        // complete rendering. (`payload` is the empty slice here.)
        let _ = (payload, is_string);
        return true;
    }

    // Non-empty: decline to the loud blind-sign flow (see doc comment). The
    // rows are discarded by the caller on a decline.
    false
}

/// Array render (covers both `T[N]` and `T[]`), used only for the
/// count <= 1 case (`render_arg` declines count > 1 outright):
///   row1: "[<N> items]"
///   row2: "first: <decoded element>" — only when the sole element renders
///         in FULL on this inline row. Returns `false` (→ blind-sign
///         fallback) for any element that would be truncated or elided
///         (addresses, >=1e9 amounts, bytesN > 4): a partially-shown value
///         on a decoded-looking page is the count==1 analog of the
///         array-tail hiding bug (audit 2026-06-18).
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
            // WYSIWYS (audit 2026-06-18 — count==1 array elision). Only 5 of
            // the 20 address bytes fit on this single inline row and the
            // NameResolver is skipped, so a recipient shown here looks decoded
            // yet is neither fully visible nor name/scam-checked. DECLINE so
            // the arg falls back to the loud blind-sign flow (banner + full
            // calldata SHA-256), matching the count>1 "refuse rather than
            // truncate" rule. The earlier `count > 1` gate only caught hidden
            // *tail* elements; a single attacker recipient was still truncated
            // behind a decoded-looking page.
            false
        }
        TypeRef::Bool => {
            let v = match abi::read_bool(body, first_elem_off) {
                Some(v) => v,
                None => return false,
            };
            let _ = write_str(row2, p, if v { b"true" } else { b"false" });
            true
        }
        TypeRef::Int(_) => {
            // Signed int array element: `read_u256` + the unsigned
            // `format_decimal` below would print a negative element (sign bit
            // set) as its unsigned magnitude — a sign flip the EVM does NOT
            // make (it sign-extends on array access), so the displayed value
            // could read positive while the signed calldata holds a negative
            // (e.g. an `int8[]` word `0x..00c8` shows `200` but executes as
            // `-56`). The top-level int path renders sign-aware via
            // `write_int_two_rows`; this inline array row has no space for that
            // form, so DECLINE to the loud blind-sign fallback rather than
            // misrepresent the sign (audit 2026-06-26 — defense-in-depth; no
            // curated `intN[]` selector reaches this today, but `SelfAttest`
            // sigs can, and curator parity is checked only on parse, not render
            // fidelity).
            false
        }
        TypeRef::Uint(bits) => {
            let v = match abi::read_u256(body, first_elem_off) {
                Some(v) => v,
                None => return false,
            };
            // Clean to N bits like the top-level uintN path (audit
            // 2026-06-26 — typed-call uintN over-display): the fit check and
            // the rendered digits must reflect the EXECUTED magnitude
            // (`word & (2^N-1)`), not the raw word, so dirty high bits cannot
            // inflate a count==1 element's preview.
            let mut w = v.0;
            mask_low_bits(&mut w, *bits);
            let v = U256(w);
            let mut tmp = [0u8; 96];
            // WYSIWYS (audit 2026-06-18 — count==1 array elision). Render the
            // element only if its full decimal fits on the inline row. If it
            // would elide to "..." (any value needing >9 digits after the
            // "first: " prefix — i.e. >=1e9 raw, which is essentially every
            // non-dust 18-decimal amount), the magnitude would be invisible
            // while still bound into the signed calldata. DECLINE instead, so
            // the arg falls back to the loud blind-sign flow with the full
            // calldata SHA-256. Mirrors the count>1 decline.
            match v.format_decimal(0, 0, false, &mut tmp) {
                Some(n) if p + n <= DISPLAY_COLS => {
                    row2[p..p + n].copy_from_slice(&tmp[..n]);
                    true
                }
                _ => false,
            }
        }
        TypeRef::BytesN(n) => {
            let w = match abi::word(body, first_elem_off) {
                Some(w) => w,
                None => return false,
            };
            let n = *n as usize;
            // WYSIWYS (audit 2026-06-18 — count==1 array elision). Show in full
            // only if all N bytes fit on the inline row; otherwise DECLINE
            // rather than render a truncated "0x..a." that looks decoded.
            if n == 0 || n > 4 || p + 2 + 2 * n > DISPLAY_COLS {
                return false;
            }
            row2[p] = b'0';
            row2[p + 1] = b'x';
            p += 2;
            for i in 0..n {
                row2[p] = hex_nibble(w[i] >> 4);
                row2[p + 1] = hex_nibble(w[i] & 0x0f);
                p += 2;
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

#[cfg(test)]
mod tests {
    //! Regression tests for the `uintN` / `intN` calldata clean-up
    //! (audit 2026-06-26 — typed-call integer over-display). The trusted
    //! display must show `word & (2^N-1)` (the magnitude the contract
    //! executes), never the raw 32-byte word, so dirty high bits cannot
    //! make a value read LARGER on screen than it acts on chain.
    use super::*;

    /// Trailing-space-trimmed view of a rendered row.
    fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
        let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        &row[..end]
    }

    /// 32-byte BE word = `2^64 + 5` (a `uint64`/`int64` whose low 64 bits
    /// are 5 but with a non-zero bit at position 64 the EVM discards).
    fn word_2pow64_plus_5() -> [u8; 32] {
        let mut w = [0u8; 32];
        w[23] = 1; // bit 64
        w[31] = 5; // low bits
        w
    }

    #[test]
    fn mask_low_bits_keeps_low_n() {
        let mut w = word_2pow64_plus_5();
        mask_low_bits(&mut w, 64);
        let mut expect = [0u8; 32];
        expect[31] = 5;
        assert_eq!(w, expect, "bits above N must be zeroed");
    }

    #[test]
    fn mask_low_bits_noop_for_256() {
        let mut w = [0xabu8; 32];
        let orig = w;
        mask_low_bits(&mut w, 256);
        assert_eq!(w, orig, "uint256 is never masked");
    }

    #[test]
    fn mask_low_bits_partial_byte() {
        // uint20: low 4 bits of byte 29 + all of bytes 30,31.
        let mut w = [0xffu8; 32];
        mask_low_bits(&mut w, 20);
        assert_eq!(&w[..29], &[0u8; 29][..]);
        assert_eq!(w[29], 0x0f);
        assert_eq!(w[30], 0xff);
        assert_eq!(w[31], 0xff);
    }

    #[test]
    fn uint_n_dirty_high_bits_render_masked_value() {
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(write_uint_two_rows(
            &mut r1,
            &mut r2,
            64,
            &U256(word_2pow64_plus_5())
        ));
        assert_eq!(
            trimmed(&r1),
            b"5",
            "uint64 must show its executed low-64-bit value, not the raw word"
        );
        assert_eq!(trimmed(&r2), b"");
    }

    #[test]
    fn uint256_renders_full_word_unmasked() {
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(write_uint_two_rows(
            &mut r1,
            &mut r2,
            256,
            &U256(word_2pow64_plus_5())
        ));
        // bits == 256 ⇒ no mask: the whole 2^64 + 5 (20 digits) is shown,
        // spilling across both rows (16 + 4).
        let mut combined = [b' '; 2 * DISPLAY_COLS];
        combined[..DISPLAY_COLS].copy_from_slice(&r1);
        combined[DISPLAY_COLS..].copy_from_slice(&r2);
        let end = combined
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |i| i + 1);
        assert_eq!(&combined[..end], b"18446744073709551621");
    }

    #[test]
    fn positive_int_n_dirty_high_bits_render_masked() {
        // int64: sign bit (63) clear ⇒ positive; bit 64 is discarded.
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(write_int_two_rows(
            &mut r1,
            &mut r2,
            64,
            &U256(word_2pow64_plus_5())
        ));
        assert_eq!(
            trimmed(&r1),
            b"5",
            "positive intN must mask the high bits the EVM signextends away"
        );
    }

    #[test]
    fn negative_int_n_unchanged() {
        // int8 == -1 (low byte 0xFF, sign bit set). Masking must not
        // regress the (already-correct) negative path.
        let mut wbytes = [0u8; 32];
        wbytes[31] = 0xff;
        let mut r1 = [b' '; DISPLAY_COLS];
        let mut r2 = [b' '; DISPLAY_COLS];
        assert!(write_int_two_rows(&mut r1, &mut r2, 8, &U256(wbytes)));
        assert_eq!(trimmed(&r1), b"-1");
    }
}

#[cfg(test)]
mod array_wysiwys_tests {
    //! WYSIWYS regression (audit 2026-06-18 — array-tail hiding). A typed
    //! array arg gets exactly one OLED page, on which only element 0 can
    //! render. Any array with >1 element must DECLINE (→ blind-sign
    //! fallback) so elements 1..N are never signed-but-not-shown behind a
    //! benign `first: …` page. These exercise the real `render_arg` body.
    use super::*;

    fn word_be32(v: u32) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[28..32].copy_from_slice(&v.to_be_bytes());
        w
    }
    fn addr_word(b: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        for i in 12..32 {
            w[i] = b;
        }
        w
    }

    /// Canonical `address[]` calldata body (no selector), `n` elements.
    fn address_array_body(n: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32)); // offset to the length word
        body.extend_from_slice(&word_be32(n)); // element count
        for i in 0..n {
            body.extend_from_slice(&addr_word(0x10 + i as u8));
        }
        body
    }

    /// Walk `sig` over `body` and render its first arg into a scratch page,
    /// returning the `render_arg` verdict (`Some(false)` == declined).
    fn render_first_arg(sig: &[u8], body: &[u8]) -> Option<bool> {
        let parsed = parse_text_sig(sig).expect("sig parses");
        let walked = walk(&parsed, body).expect("body walks");
        let mut pages = Pages::with_len(1);
        let resolver = NameResolver::new();
        render_arg(
            &mut pages,
            0,
            0,
            &parsed,
            &walked.args[0],
            body,
            1,
            &resolver,
        )
    }

    #[test]
    fn multi_element_dyn_array_declines_to_blind_sign() {
        // 2-element address[] — element 1 (the attacker leg in a
        // disperse-style drain) would be signed-but-not-shown.
        let body = address_array_body(2);
        assert_eq!(
            render_first_arg(b"f(address[])", &body),
            Some(false),
            "an array with a hidden tail element must decline, not render a partial"
        );
    }

    #[test]
    fn single_element_address_array_declines() {
        // A 20-byte address cannot be shown in full on the inline "first:"
        // row (only 5 of 20 bytes fit, name lookup skipped), so a single-
        // element address[] must DECLINE to blind-sign rather than render a
        // truncated, name-unchecked recipient that looks decoded
        // (audit 2026-06-18 — count==1 array elision).
        let body = address_array_body(1);
        assert_eq!(render_first_arg(b"f(address[])", &body), Some(false));
    }

    /// Canonical `uint256[]` calldata body (no selector), one element `v`.
    fn single_uint_array_body(v: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(32)); // offset to the length word
        body.extend_from_slice(&word_be32(1)); // element count
        body.extend_from_slice(&word_be32(v)); // the sole element
        body
    }

    #[test]
    fn single_element_small_uint_array_renders() {
        // A 1-element uint256[] whose value fits the 9-col inline budget is
        // shown in full — nothing hidden, so it renders.
        let body = single_uint_array_body(12_345);
        assert_eq!(render_first_arg(b"f(uint256[])", &body), Some(true));
    }

    #[test]
    fn single_element_large_uint_array_declines() {
        // 1e9 (10 digits) overflows the 9-col inline budget and would render
        // as "first: ..." — the magnitude signed-but-not-shown. Any non-dust
        // 18-decimal amount lands here. Must DECLINE, not elide.
        let body = single_uint_array_body(1_000_000_000);
        assert_eq!(render_first_arg(b"f(uint256[])", &body), Some(false));
    }

    #[test]
    fn single_element_int_array_declines() {
        // A signed `intN[]` element cannot be shown sign-aware on the inline
        // "first:" row, so even a small magnitude that fits the budget as an
        // unsigned value must DECLINE — otherwise a negative element renders
        // positive (`0x..00c8` shows `200`, executes as `-56`). Contrast
        // `single_element_small_uint_array_renders`, which renders the same
        // word because an *unsigned* read has no sign to flip (audit
        // 2026-06-26 — intN[] sign-flip).
        let body = single_uint_array_body(200);
        assert_eq!(render_first_arg(b"f(int8[])", &body), Some(false));
        // Wider signed widths decline too.
        assert_eq!(render_first_arg(b"f(int256[])", &body), Some(false));
    }

    #[test]
    fn empty_dyn_array_renders() {
        // 0 elements — `[0 items]`, nothing to hide.
        let body = address_array_body(0);
        assert_eq!(render_first_arg(b"f(address[])", &body), Some(true));
    }

    #[test]
    fn multi_element_static_array_declines() {
        // Fixed-size `uint256[3]` hides elements 1..2 just the same.
        let mut body = Vec::new();
        body.extend_from_slice(&word_be32(1));
        body.extend_from_slice(&word_be32(2));
        body.extend_from_slice(&word_be32(3));
        assert_eq!(render_first_arg(b"f(uint256[3])", &body), Some(false));
    }

    #[test]
    fn bytes32_declines_to_blind_sign() {
        // bytes32's 64 hex chars cannot fit the 2-row arg page; the pre-fix
        // head/tail elision hid the middle 19 bytes (a brute-forceable
        // display collision letting an attacker swap a signed identifier).
        // It must DECLINE to blind-sign (audit 2026-06-23 — bytesN>=16).
        let body = vec![0xABu8; 32];
        assert_eq!(render_first_arg(b"f(bytes32)", &body), Some(false));
    }

    #[test]
    fn bytes16_declines_to_blind_sign() {
        // bytes16 = "0x" + 32 hex = 34 chars > 2 rows (32) → still elides →
        // must decline. The boundary case just above the two-row budget.
        let mut body = vec![0xCDu8; 16];
        body.resize(32, 0); // right-pad to a full ABI word
        assert_eq!(render_first_arg(b"f(bytes16)", &body), Some(false));
    }

    #[test]
    fn bytes15_renders_in_full() {
        // bytes15 = "0x" + 30 hex = 32 chars fits exactly two rows, so it
        // renders in full — nothing hidden, no decline.
        let mut body = vec![0xCDu8; 15];
        body.resize(32, 0); // right-pad to a full ABI word
        assert_eq!(render_first_arg(b"f(bytes15)", &body), Some(true));
    }
}
