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
    chain_name, write_addr_full_or_name, write_calldata_hash_rows, write_chain, write_data_len_row,
    write_eth_two_rows, write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row,
    write_selector_row, write_tip_row, AmountFit,
};
use super::Pages;
use crate::names::NameResolver;
use crate::selectors::SelectorMeta;
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

    // ── Optional Page 1: verified function name (FUNCTION:) ─────────
    //
    // Only present when the host attached a selector bundle that
    // crossed both the Merkle gate and the `selector == data[0..4]`
    // cross-check. The banner above stays loud — Phase 1 attests only
    // the NAME of the function, not its semantics on this contract.
    let mut next_page = 1usize;
    if let Some(meta) = selector {
        write_line(&mut pages.buf[next_page][0], "FUNCTION:");
        // text_sig is ASCII-clean and ≤ 63 bytes (verified upstream).
        // Wrap across rows 1..=2 (16 cols each = 32 chars). Tail
        // beyond 32 chars is summarised on row 3.
        let text = meta.text_sig;
        let row1_len = text.len().min(16);
        write_line_bytes(&mut pages.buf[next_page][1], &text[..row1_len]);
        if text.len() > 16 {
            let row2_len = (text.len() - 16).min(16);
            write_line_bytes(
                &mut pages.buf[next_page][2],
                &text[16..16 + row2_len],
            );
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
        write_line(&mut pages.buf[next_page][0], "Value: 0 ETH");
        write_line(&mut pages.buf[next_page][1], "");
        write_line(&mut pages.buf[next_page][2], "");
    } else {
        write_line(&mut pages.buf[next_page][0], "! VALUE:");
        let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
        let fit = write_eth_two_rows(r1, r2, &tx.value);
        write_line(
            foot,
            match fit {
                AmountFit::Full => "> next",
                AmountFit::Overflow => "!AMOUNT OVERFLOW",
            },
        );
    }
    write_line(&mut pages.buf[next_page][3], "> next");
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
    write_chain(&mut pages.buf[next_page][1], tx.chain_id);
    write_line(&mut pages.buf[next_page][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[next_page][3], "> next");
    next_page += 1;

    // ── Max fee + tip ───────────────────────────────────────────────
    write_line(&mut pages.buf[next_page][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[next_page][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[next_page][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[next_page][3], "> next");
    next_page += 1;

    // ── Worst-case fee budget + gas ─────────────────────────────────
    write_line(&mut pages.buf[next_page][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[next_page][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[next_page][2], tx.gas_limit);
    write_line(&mut pages.buf[next_page][3], "> next");
    next_page += 1;

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
