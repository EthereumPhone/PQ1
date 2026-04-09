//! `tx.to.is_none()` — CREATE transaction. Treated with the same
//! caution as a blind contract call but with a separate banner so
//! the user can tell them apart.

use super::primitives::{
    chain_name, write_chain, write_data_len_row, write_eth, write_gas, write_gwei, write_line,
    write_nonce_row, write_tip_row,
};
use super::Pages;
use crate::tx::eip1559::Eip1559Tx;

pub fn render_contract_creation_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(6);

    write_line(&mut pages.buf[0][0], "! CONTRACT");
    write_line(&mut pages.buf[0][1], "  CREATION");
    write_line(&mut pages.buf[0][2], "to: (none)");
    write_line(&mut pages.buf[0][3], "> next");

    write_line(&mut pages.buf[1][0], "Value:");
    write_eth(&mut pages.buf[1][1], &tx.value);
    write_line(&mut pages.buf[1][3], "> next");

    write_data_len_row(&mut pages.buf[2][0], data.len());
    write_line(&mut pages.buf[2][1], "(init bytecode)");
    write_line(&mut pages.buf[2][3], "> next");

    write_line(&mut pages.buf[3][0], "Chain:");
    write_chain(&mut pages.buf[3][1], tx.chain_id);
    write_line(&mut pages.buf[3][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[3][3], "> next");

    write_line(&mut pages.buf[4][0], "Max fee:");
    write_gwei(&mut pages.buf[4][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[4][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[4][3], "> next");

    write_nonce_row(&mut pages.buf[5][0], tx.nonce);
    write_gas(&mut pages.buf[5][1], tx.gas_limit);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}
