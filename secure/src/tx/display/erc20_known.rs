//! Trust level 2 — decoded ERC-20 method targeting a contract pinned
//! in the metadata DB. Token identity (name, symbol, decimals) comes
//! from the Merkle-verified `Erc20Metadata`, so amounts render in the
//! token's native units and the header shows "Send 100 USDC".
//!
//! Anti-spoof rules:
//!
//!   * The amount page uses fixed-width fractional digits so "1 USDC"
//!     cannot visually collide with "1.000000 USDC".
//!   * The recipient/spender is shown across 3 rows — the full 40-hex
//!     address — so an attacker can't collide middle bytes.
//!   * The contract page renders the raw `tx.to` so a malicious DB
//!     row that points "USDC" at an attacker's contract still surfaces
//!     the actual contract address.
//!   * An `approve` with an amount ≥ 2^200 shows as the literal word
//!     `unlimited` instead of a ~1e77 number that looks finite.

use super::primitives::{
    chain_name, write_addr_full_or_name, write_chain, write_erc20_header, write_fee_budget_row,
    write_gas, write_gwei, write_line, write_nonce_row, write_tip_row,
    write_token_amount_two_rows, write_token_name, AmountFit,
};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};

pub fn render_erc20_known_pages(
    tx: &Eip1559Tx,
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
    resolver: &NameResolver<'_>,
) -> Pages {
    let mut pages = Pages::with_len(8);

    // ── Page 0: "Send USDC" + token name ───────────────────────────
    write_erc20_header(&mut pages.buf[0][0], call, meta);
    write_token_name(&mut pages.buf[0][1], meta);
    // Row 2: warn visibly if tx carries non-zero native ETH on an
    // ERC-20 call (legitimate ERC-20 calls never need native value).
    if !tx.value.is_zero() {
        write_line(&mut pages.buf[0][2], "! native ETH!");
    }
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: Recipient / Spender ────────────────────────────────
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[1][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full_or_name(a, b, c, &recipient, tx.chain_id, resolver);
    }

    // ── Page 2: Amount ──────────────────────────────────────────────
    write_line(&mut pages.buf[2][0], "Amount:");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[2][1], "unlimited");
        write_line(&mut pages.buf[2][2], "");
        write_line(&mut pages.buf[2][3], "> next");
    } else {
        let [_lbl, r1, r2, foot] = &mut pages.buf[2];
        let fit = write_token_amount_two_rows(r1, r2, &amount, meta);
        write_line(
            foot,
            match fit {
                AmountFit::Full => "> next",
                AmountFit::Overflow => "!AMOUNT OVERFLOW",
            },
        );
    }

    // ── Page 3: Raw contract address (anti-spoof) ──────────────────
    write_line(&mut pages.buf[3][0], "Contract:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[3];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    }

    // ── Page 4: Chain ──────────────────────────────────────────────
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // ── Page 5: Max fee + tip ──────────────────────────────────────
    write_line(&mut pages.buf[5][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    // ── Page 6: Worst-case fee budget + gas ────────────────────────
    write_line(&mut pages.buf[6][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[6][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[6][2], tx.gas_limit);
    write_line(&mut pages.buf[6][3], "> next");

    // ── Page 7: Nonce + buttons ────────────────────────────────────
    write_nonce_row(&mut pages.buf[7][0], tx.nonce);
    write_line(&mut pages.buf[7][1], "");
    write_line(&mut pages.buf[7][2], "L=Cancel");
    write_line(&mut pages.buf[7][3], "R=Confirm");

    pages
}
