//! `tx.to.is_none()` — CREATE transaction. Treated with the same
//! caution as a blind contract call but with a separate banner so the
//! user can tell them apart.
//!
//! Currently unreachable in the production `cmd_sign_userop` path
//! (that handler always sends `to` as a fixed 20-byte address), but
//! kept production-ready so that any future flow which exposes CREATE
//! txs inherits the same trusted-display contract.

use sha2::{Digest, Sha256};

use super::primitives::{
    chain_name, write_calldata_hash_rows, write_chain, write_data_len_row, write_eth_two_rows,
    write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row, write_tip_row,
    AmountFit,
};
use super::Pages;
use crate::tx::eip1559::Eip1559Tx;

pub fn render_contract_creation_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(8);

    write_line(&mut pages.buf[0][0], "! CONTRACT");
    write_line(&mut pages.buf[0][1], "  CREATION");
    write_line(&mut pages.buf[0][2], "to: (none)");
    write_line(&mut pages.buf[0][3], "> next");

    write_line(&mut pages.buf[1][0], "Value:");
    {
        let [_lbl, r1, r2, foot] = &mut pages.buf[1];
        let fit = write_eth_two_rows(r1, r2, &tx.value);
        write_line(
            foot,
            match fit {
                AmountFit::Full => "> next",
                AmountFit::Overflow => "!AMOUNT OVERFLOW",
            },
        );
    }

    write_data_len_row(&mut pages.buf[2][0], data.len());
    write_line(&mut pages.buf[2][1], "(init bytecode)");
    write_line(&mut pages.buf[2][3], "> next");

    // Init-code hash for dapp cross-check.
    write_line(&mut pages.buf[3][0], "Init hash:");
    let hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    };
    {
        let [_lbl, r1, r2, foot] = &mut pages.buf[3];
        write_calldata_hash_rows(r1, r2, &hash);
        write_line(foot, "> next");
    }

    write_line(&mut pages.buf[4][0], "Chain:");
    write_chain(&mut pages.buf[4][1], tx.chain_id);
    write_line(&mut pages.buf[4][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[4][3], "> next");

    write_line(&mut pages.buf[5][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[5][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[5][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[5][3], "> next");

    write_line(&mut pages.buf[6][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[6][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[6][2], tx.gas_limit);
    write_line(&mut pages.buf[6][3], "> next");

    write_nonce_row(&mut pages.buf[7][0], tx.nonce);
    write_line(&mut pages.buf[7][1], "");
    write_line(&mut pages.buf[7][2], "L=Cancel");
    write_line(&mut pages.buf[7][3], "R=Confirm");

    pages
}
