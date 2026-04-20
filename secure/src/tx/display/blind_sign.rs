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
    chain_name, write_addr_full, write_calldata_hash_rows, write_chain, write_data_len_row,
    write_eth_two_rows, write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row,
    write_selector_row, write_tip_row, AmountFit,
};
use super::Pages;
use crate::tx::eip1559::Eip1559Tx;

pub fn render_blind_sign_pages(tx: &Eip1559Tx, data: &[u8]) -> Pages {
    let mut pages = Pages::with_len(9);

    // ── Page 0: loud banner ─────────────────────────────────────────
    write_line(&mut pages.buf[0][0], "! BLIND SIGN");
    write_line(&mut pages.buf[0][1], "Unknown call");
    write_line(&mut pages.buf[0][2], "Verify on dapp");
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: To: (full 40-hex) ───────────────────────────────────
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full(a, b, c, addr);
    } else {
        write_line(&mut pages.buf[1][1], "(contract create)");
    }

    // ── Page 2: Value — EXTRA loud when non-zero on blind-sign ─────
    if tx.value.is_zero() {
        write_line(&mut pages.buf[2][0], "Value: 0 ETH");
        write_line(&mut pages.buf[2][1], "");
        write_line(&mut pages.buf[2][2], "");
    } else {
        write_line(&mut pages.buf[2][0], "! VALUE:");
        let [_lbl, r1, r2, foot] = &mut pages.buf[2];
        let fit = write_eth_two_rows(r1, r2, &tx.value);
        write_line(
            foot,
            match fit {
                AmountFit::Full => "> next",
                AmountFit::Overflow => "!AMOUNT OVERFLOW",
            },
        );
    }
    write_line(&mut pages.buf[2][3], "> next");

    // ── Page 3: Selector + data length ──────────────────────────────
    write_selector_row(&mut pages.buf[3][0], data);
    write_data_len_row(&mut pages.buf[3][1], data.len());
    write_line(&mut pages.buf[3][3], "> next");

    // ── Page 4: Calldata SHA-256 for dapp cross-check ──────────────
    write_line(&mut pages.buf[4][0], "Data hash:");
    let hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    };
    {
        let [_lbl, r1, r2, foot] = &mut pages.buf[4];
        write_calldata_hash_rows(r1, r2, &hash);
        write_line(foot, "> next");
    }

    // ── Page 5: Chain ───────────────────────────────────────────────
    write_line(&mut pages.buf[5][0], "Chain:");
    write_chain(&mut pages.buf[5][1], tx.chain_id);
    write_line(&mut pages.buf[5][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[5][3], "> next");

    // ── Page 6: Max fee + tip ───────────────────────────────────────
    write_line(&mut pages.buf[6][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[6][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[6][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[6][3], "> next");

    // ── Page 7: Worst-case fee budget + gas ────────────────────────
    write_line(&mut pages.buf[7][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[7][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[7][2], tx.gas_limit);
    write_line(&mut pages.buf[7][3], "> next");

    // ── Page 8: Nonce + buttons ────────────────────────────────────
    write_nonce_row(&mut pages.buf[8][0], tx.nonce);
    write_line(&mut pages.buf[8][1], "");
    write_line(&mut pages.buf[8][2], "L=Cancel");
    write_line(&mut pages.buf[8][3], "R=Confirm");

    pages
}
