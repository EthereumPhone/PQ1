//! Trust level 2 — decoded ERC20 method targeting a contract pinned
//! in the metadata DB. Token identity (name, symbol, decimals) comes
//! from the DB-trusted `Erc20Metadata`, so amounts are rendered in
//! the token's native units and the header line shows "Send 100 USDC"
//! rather than a raw uint256.
//!
//! Anti-spoof rule: page 3 always shows the raw `to` contract address
//! so a malicious DB row pointing an attacker contract at "USDC" can
//! still be caught by a careful user reading the address.

use super::primitives::{
    chain_name, write_addr, write_chain, write_erc20_header, write_gas, write_gwei, write_line,
    write_nonce_row, write_tip_row, write_token_amount, write_token_name,
};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::tx::eip1559::{Eip1559Tx, U256};

pub fn render_erc20_known_pages(
    tx: &Eip1559Tx,
    call: &Erc20Call,
    meta: &Erc20Metadata<'_>,
) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: header — verb + amount + symbol (truncated to 16 cols)
    write_erc20_header(&mut pages.buf[0][0], call, meta);
    // Row 1/2: full token name (DB-trusted)
    write_token_name(&mut pages.buf[0][1], meta);
    // Row 3
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: recipient (the address the token moves TO, from decoded calldata)
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } => "Recipient:",
        Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[1][0], recipient_label);
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], &recipient);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: amount in full precision (or "unlimited" for huge approve)
    write_line(&mut pages.buf[2][0], "Amount:");
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
        write_line(&mut pages.buf[2][1], "unlimited");
    } else {
        write_token_amount(&mut pages.buf[2][1], &amount, meta);
    }
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: raw contract address — the anti-spoof page
    write_line(&mut pages.buf[3][0], "Contract:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[3].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: chain + gas
    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    // Page 5: max fee + tip
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
