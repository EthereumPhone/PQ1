//! Trust level 2.5 — decoded ERC20 method but the contract is NOT in
//! the metadata DB. The method structure is trusted (selectors +
//! calldata ABI decoded safely) but the token identity is unknown,
//! so amounts are shown as raw uint256 without decimals.

use super::primitives::{
    chain_name, write_addr, write_chain, write_gas, write_gwei, write_line, write_nonce_row,
    write_tip_row,
};
use super::Pages;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

pub fn render_erc20_unknown_pages(tx: &Eip1559Tx, call: &Erc20Call) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: warning header
    write_line(&mut pages.buf[0][0], "! Unknown token");
    let method = match call {
        Erc20Call::Transfer { .. } => "transfer",
        Erc20Call::TransferFrom { .. } => "transferFrom",
        Erc20Call::Approve { .. } => "approve",
    };
    write_line(&mut pages.buf[0][1], method);
    write_line(&mut pages.buf[0][2], "(decimals=?)");
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: contract address
    write_line(&mut pages.buf[1][0], "Contract:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: recipient
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
        let (left, right) = pages.buf[2].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], &recipient);
    }
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: amount as raw uint256 (no decimals known)
    write_line(&mut pages.buf[3][0], "Amount (raw):");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[3][1], "unlimited");
    } else {
        let mut tmp = [0u8; 16];
        let n = amount.format_decimal(0, 0, &mut tmp);
        let copy = core::cmp::min(n, DISPLAY_COLS);
        pages.buf[3][1][..copy].copy_from_slice(&tmp[..copy]);
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: chain
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // Page 5: fees
    write_line(&mut pages.buf[5][0], "Max fee:");
    write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    // Page 6: nonce + buttons
    write_nonce_row(&mut pages.buf[6][0], tx.nonce);
    write_gas(&mut pages.buf[6][1], tx.gas_limit);
    write_line(&mut pages.buf[6][2], "L=Cancel");
    write_line(&mut pages.buf[6][3], "R=Confirm");

    pages
}
