//! Trust level 2.5 — decoded ERC-20 method but the contract is NOT in
//! the Merkle-verified metadata DB. The method structure is trusted
//! (selectors + calldata ABI decoded safely) but token identity is
//! unknown, so amounts render as the raw `uint256` with no decimals.

use super::primitives::{
    chain_name, write_addr_full, write_chain, write_fee_budget_row, write_gas, write_gwei,
    write_line, write_nonce_row, write_tip_row,
};
use super::Pages;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

pub fn render_erc20_unknown_pages(tx: &Eip1559Tx, call: &Erc20Call) -> Pages {
    let mut pages = Pages::with_len(8);

    // ── Page 0: Warning banner + method ────────────────────────────
    write_line(&mut pages.buf[0][0], "! Unknown token");
    let method = match call {
        Erc20Call::Transfer { .. } => "transfer",
        Erc20Call::TransferFrom { .. } => "transferFrom",
        Erc20Call::Approve { .. } => "approve",
    };
    write_line(&mut pages.buf[0][1], method);
    write_line(&mut pages.buf[0][2], "(decimals = ?)");
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: Contract address ───────────────────────────────────
    write_line(&mut pages.buf[1][0], "Contract:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full(a, b, c, addr);
    }

    // ── Page 2: Recipient / Spender ────────────────────────────────
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[2][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let [_lbl, a, b, c] = &mut pages.buf[2];
        write_addr_full(a, b, c, &recipient);
    }

    // ── Page 3: Raw uint256 amount (two-row) ───────────────────────
    write_line(&mut pages.buf[3][0], "Amount (raw):");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[3][1], "unlimited");
    } else {
        // Raw integer: emit as a 78-digit max decimal across rows 1+2.
        let mut tmp = [0u8; 96];
        match amount.format_decimal(0, 0, false, &mut tmp) {
            Some(n) if n <= DISPLAY_COLS => {
                pages.buf[3][1][..n].copy_from_slice(&tmp[..n]);
            }
            Some(n) if n <= 2 * DISPLAY_COLS => {
                pages.buf[3][1].copy_from_slice(&tmp[..DISPLAY_COLS]);
                pages.buf[3][2][..n - DISPLAY_COLS]
                    .copy_from_slice(&tmp[DISPLAY_COLS..n]);
            }
            _ => {
                write_line(&mut pages.buf[3][1], "!OVERFLOW");
            }
        }
    }
    write_line(&mut pages.buf[3][3], "> next");

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
