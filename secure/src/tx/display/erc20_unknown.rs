//! Trust level 2.5 — decoded ERC-20 method but the contract is NOT in
//! the Merkle-verified metadata DB. The method structure is trusted
//! (selectors + calldata ABI decoded safely) but token identity is
//! unknown, so amounts render as the raw `uint256` with no decimals.

use super::primitives::{
    build_legacy_fee_pages, write_addr_full_or_name, write_chain, write_line, write_nonce_row,
    write_raw_integer_rows, AmountFit,
};
use super::Pages;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};

pub fn render_erc20_unknown_pages(
    tx: &Eip1559Tx,
    call: &Erc20Call,
    resolver: &NameResolver<'_>,
) -> Pages {
    // transferFrom debits a third-party `from` account that is part of the
    // signed calldata; surface it on its own page so it is never hidden
    // (WYSIWYS, audit 2026-06-18). transfer/approve have no `from`.
    let from: Option<[u8; 20]> = match call {
        Erc20Call::TransferFrom { from, .. } => Some(*from),
        _ => None,
    };
    let n_pages = if from.is_some() { 9 } else { 8 };
    let mut pages = Pages::with_len(n_pages);
    let mut p = 0usize;

    // ── Warning banner + method ────────────────────────────────────
    write_line(&mut pages.buf[p][0], "! Unknown token");
    let method = match call {
        Erc20Call::Transfer { .. } => "transfer",
        Erc20Call::TransferFrom { .. } => "transferFrom",
        Erc20Call::Approve { .. } => "approve",
    };
    write_line(&mut pages.buf[p][1], method);
    write_line(&mut pages.buf[p][2], "(decimals = ?)");
    write_line(&mut pages.buf[p][3], "> next");
    // Native-ETH `value` carried on an ERC-20-shaped call is rendered by
    // the dispatcher-level value page that `pick_sign_pages` splices in
    // right after this banner whenever `value != 0` (audit C-1) — so the
    // value-hiding path that motivated the finding is closed centrally,
    // without this renderer having to spend its only spare row.
    p += 1;

    // ── Contract address ───────────────────────────────────────────
    write_line(&mut pages.buf[p][0], "Contract:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[p];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    }
    p += 1;

    // ── From (debited account) — transferFrom only ─────────────────
    if let Some(from) = from {
        write_line(&mut pages.buf[p][0], "From (debited):");
        let [_lbl, a, b, c] = &mut pages.buf[p];
        write_addr_full_or_name(a, b, c, &from, tx.chain_id, resolver);
        p += 1;
    }

    // ── Recipient / Spender ────────────────────────────────────────
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[p][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let [_lbl, a, b, c] = &mut pages.buf[p];
        write_addr_full_or_name(a, b, c, &recipient, tx.chain_id, resolver);
    }
    p += 1;

    // ── Raw uint256 amount (two-row) ───────────────────────────────
    write_line(&mut pages.buf[p][0], "Amount (raw):");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    write_line(&mut pages.buf[p][3], "> next");
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[p][1], "unlimited");
    } else if matches!(call, Erc20Call::Approve { .. }) && amount.is_zero() {
        // approve(spender, 0) is an allowance REVOCATION — say so in
        // words (same framing as the known-token header,
        // pqsigner-erc7730 `write_erc20_header`) instead of painting a
        // raw `0` that reads like a rendering glitch (#474). The
        // `is_unlimited_amount` branch keeps precedence; zero can never
        // reach it.
        write_line(&mut pages.buf[p][1], "Revoke approval");
    } else {
        // Raw integer, every digit: one row, or wrapped with continuation
        // marks over rows 1-3 (until 2026-11-14 it was cut at column 16
        // with no mark, so row 2 read as a number of its own).
        let [_lbl, r1, r2, r3] = &mut pages.buf[p];
        if write_raw_integer_rows(r1, r2, r3, &amount) == AmountFit::Overflow {
            write_line(r1, "!OVERFLOW");
        }
    }
    p += 1;

    // ── Chain ───────────────────────────────────────────────────────
    write_line(&mut pages.buf[p][0], "Chain:");
    {
        let [_label, id, continuation_or_name, _foot] = &mut pages.buf[p];
        write_chain(id, continuation_or_name, tx.chain_id);
    }
    write_line(&mut pages.buf[p][3], "> next");
    p += 1;

    // ── Exact max/tip and worst-case fee envelope ──────────────────
    let fee_pages = build_legacy_fee_pages(
        &tx.max_fee_per_gas,
        &tx.max_priority_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    )
    .pages;
    pages.buf[p] = fee_pages[0];
    pages.buf[p + 1] = fee_pages[1];
    p += 2;

    // ── Nonce + buttons ────────────────────────────────────────────
    write_nonce_row(&mut pages.buf[p][0], tx.nonce);
    write_line(&mut pages.buf[p][1], "");
    write_line(&mut pages.buf[p][2], "L=Cancel");
    write_line(&mut pages.buf[p][3], "R=Confirm");

    pages
}
