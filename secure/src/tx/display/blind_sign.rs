//! Trust level 3 — non-empty calldata that doesn't match any known
//! ERC20 selector. Ledger-style "BLIND SIGNING" flow: the user is told
//! loudly that the wallet does not understand what this transaction
//! will do, so they can only verify it against the dapp they're
//! interacting with.

use super::primitives::{
    chain_name, write_addr, write_chain, write_data_len_row, write_eth, write_gas, write_gwei,
    write_line, write_nonce_row, write_selector_row, write_tip_row,
};
use super::Pages;
use crate::tx::eip1559::Eip1559Tx;

pub fn render_blind_sign_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(7);

    // Page 0: BLIND SIGNING banner
    write_line(&mut pages.buf[0][0], "! BLIND SIGN");
    write_line(&mut pages.buf[0][1], "Unknown call");
    write_line(&mut pages.buf[0][2], "Verify on dapp");
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: contract address
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        write_addr(&mut left[1], &mut right[0], addr);
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: value
    write_line(&mut pages.buf[2][0], "Value:");
    write_eth(&mut pages.buf[2][1], &tx.value);
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: selector + length
    write_selector_row(&mut pages.buf[3][0], data);
    write_data_len_row(&mut pages.buf[3][1], data.len());
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
