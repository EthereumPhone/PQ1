//! Trust level 3 — non-empty calldata that doesn't match any known
//! ERC-20 selector. Ledger-style "BLIND SIGN" flow: the user is told
//! loudly that the wallet does not understand what this transaction
//! will do, so they can only verify it against the dapp they're
//! interacting with.
//!
//! We additionally surface the SHA-256 of the calldata so the dapp
//! can display the same hash and the user can compare — this closes
//! a specific class of attack where NS replays a legitimate selector
//! with mutated arguments.

use sha2::{Digest, Sha256};

use super::primitives::{
    build_legacy_fee_pages, write_addr_full_or_name, write_calldata_hash_rows, write_chain,
    write_data_len_row, write_line, write_native_amount_rows, write_native_currency_row,
    write_nonce_row, write_selector_row, AmountFit,
};
use super::Pages;
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::eip1559::Eip1559Tx;

/// Render a blind-sign confirmation flow.
///
/// When `selector` is `Some(...)` the caller has Merkle-verified the
/// `(selector, text_sig)` pair against `SELECTOR_DB_ROOT` AND
/// cross-checked `selector == data[0..4]`, so the returned Pages
/// gain one extra "FUNCTION:" page right after the BLIND SIGN
/// banner. The banner itself stays — the verified mapping attests
/// only the function NAME, not what the contract does with it.
pub fn render_blind_sign_pages(
    tx: &Eip1559Tx,
    data: &[u8],
    selector: Option<&SelectorMeta<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
    // Page count: 9 baseline + 1 if we have a verified function name.
    let extra = if selector.is_some() { 1 } else { 0 };
    let mut pages = Pages::with_len(9 + extra);

    // ── Page 0: loud banner ─────────────────────────────────────────
    write_line(&mut pages.buf[0][0], "! BLIND SIGN");
    write_line(&mut pages.buf[0][1], "Unknown call");
    write_line(&mut pages.buf[0][2], "Verify on dapp");
    write_line(&mut pages.buf[0][3], "> next");

    // ── Optional Page 1: verified function name (FUNCTION:/GUESS:) ──
    //
    // Only present when the host attached a selector bundle that
    // crossed the gateway checks. Label depends on provenance:
    //   * Curated    → "FUNCTION:" (vendor-attested name)
    //   * SelfAttest → "GUESS:"    (companion-supplied; the leading
    //                   `! BLIND SIGN` banner above already warns)
    // Both paths attest only the NAME of the function, not its
    // semantics on this contract.
    let mut next_page = 1usize;
    if let Some(meta) = selector {
        let label = match meta.provenance {
            SelectorProvenance::Curated => "FUNCTION:",
            SelectorProvenance::SelfAttest => "GUESS:",
        };
        write_line(&mut pages.buf[next_page][0], label);
        // text_sig is ASCII-clean and ≤ 63 bytes (verified upstream).
        // Wrap across rows 1..=2 (16 cols each = 32 chars). Tail
        // beyond 32 chars is summarised on row 3.
        let text = meta.text_sig;
        let row1_len = text.len().min(16);
        write_line_bytes(&mut pages.buf[next_page][1], &text[..row1_len]);
        if text.len() > 16 {
            let row2_len = (text.len() - 16).min(16);
            write_line_bytes(&mut pages.buf[next_page][2], &text[16..16 + row2_len]);
        }
        if text.len() > 32 {
            // Indicate truncation with "...> next" on the foot row.
            write_line(&mut pages.buf[next_page][3], "...> next");
        } else {
            write_line(&mut pages.buf[next_page][3], "> next");
        }
        next_page += 1;
    }

    // ── Page 1 (or 2): To: (full 40-hex) ────────────────────────────
    write_line(&mut pages.buf[next_page][0], "To:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    } else {
        write_line(&mut pages.buf[next_page][1], "(contract create)");
    }
    next_page += 1;

    // ── Value — EXTRA loud when non-zero on blind-sign ──────────────
    if tx.value.is_zero() {
        write_native_currency_row(&mut pages.buf[next_page][0], b"Value: 0 ", tx.chain_id, b"");
        write_line(&mut pages.buf[next_page][1], "");
        write_line(&mut pages.buf[next_page][2], "");
        write_line(&mut pages.buf[next_page][3], "> next");
    } else {
        write_line(&mut pages.buf[next_page][0], "! VALUE:");
        let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
        // Rows 1-2 and `> next`, or rows 1-3 when only a third wrapped row
        // holds every digit.
        if write_native_amount_rows(r1, r2, foot, &tx.value, tx.chain_id) == AmountFit::Overflow {
            write_line(foot, "!AMOUNT OVERFLOW");
        }
    }
    next_page += 1;

    // ── Selector + data length ──────────────────────────────────────
    write_selector_row(&mut pages.buf[next_page][0], data);
    write_data_len_row(&mut pages.buf[next_page][1], data.len());
    write_line(&mut pages.buf[next_page][3], "> next");
    next_page += 1;

    // ── Calldata SHA-256 for dapp cross-check ──────────────────────
    write_line(&mut pages.buf[next_page][0], "Data hash:");
    let hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    };
    {
        let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
        write_calldata_hash_rows(r1, r2, &hash);
        write_line(foot, "> next");
    }
    next_page += 1;

    // ── Chain ───────────────────────────────────────────────────────
    write_line(&mut pages.buf[next_page][0], "Chain:");
    {
        let [_label, id, continuation_or_name, _foot] = &mut pages.buf[next_page];
        write_chain(id, continuation_or_name, tx.chain_id);
    }
    write_line(&mut pages.buf[next_page][3], "> next");
    next_page += 1;

    // ── Exact max/tip and worst-case fee envelope ───────────────────
    let fee_pages = build_legacy_fee_pages(
        &tx.max_fee_per_gas,
        &tx.max_priority_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    )
    .pages;
    pages.buf[next_page] = fee_pages[0];
    pages.buf[next_page + 1] = fee_pages[1];
    next_page += 2;

    // ── Nonce + buttons ─────────────────────────────────────────────
    write_nonce_row(&mut pages.buf[next_page][0], tx.nonce);
    write_line(&mut pages.buf[next_page][1], "");
    write_line(&mut pages.buf[next_page][2], "L=Cancel");
    write_line(&mut pages.buf[next_page][3], "R=Confirm");

    pages
}

/// Local helper: copy ASCII bytes into a 16-column row, space-padding
/// any trailing columns. The supplied slice is already ASCII-gated by
/// the bundle verifier, so we don't need to filter again.
fn write_line_bytes(row: &mut [u8; crate::ui::DISPLAY_COLS], text: &[u8]) {
    for cell in row.iter_mut() {
        *cell = b' ';
    }
    let n = text.len().min(crate::ui::DISPLAY_COLS);
    row[..n].copy_from_slice(&text[..n]);
}
