//! Trust level 1 — plain ETH transfer with empty calldata.
//!
//! Page layout (6 pages):
//!
//! ```text
//!  0: "Send ETH?"        1: "To:"               2: "Value:"
//!     Chain: <n>            0x1234567890abcd       12345678901234.00
//!     <chain name>          1234567890abcdef       56789 ETH
//!     > next                0123456789             > next
//!
//!  3: "Max fee:"         4: "Worst-case:"       5: "Nonce: <n>"
//!     <gwei> gwei           <max_fee*gas> ETH      Data: <n> B
//!     Tip: <gwei>           (gas: <limit>)         L=Cancel
//!     > next                > next                 R=Confirm
//! ```
//!
//! Every numeric field is overflow-safe: the helpers in
//! [`super::primitives`] refuse to silently truncate. If a value won't
//! fit, the renderer paints `!OVERFLOW` so the user can abort.

use super::primitives::{
    chain_name, write_addr_full_or_name, write_chain, write_data_len_row, write_eth_two_rows,
    write_fee_budget_row, write_gas, write_gwei, write_line, write_nonce_row, write_tip_row,
    AmountFit,
};
use super::Pages;
use crate::names::NameResolver;
use crate::tx::eip1559::Eip1559Tx;

pub fn render_pages(tx: &Eip1559Tx, resolver: &NameResolver<'_>) -> Pages {
    let mut pages = Pages::with_len(6);

    // ── Page 0: banner + chain ───────────────────────────────────────
    if tx.value.is_zero() {
        write_line(&mut pages.buf[0][0], "Contract call?");
    } else {
        write_line(&mut pages.buf[0][0], "Send ETH?");
    }
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: To: (3 rows of full 40-hex address) ─────────────────
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    } else {
        write_line(&mut pages.buf[1][1], "(contract create)");
    }

    // ── Page 2: Value (2-row amount) ────────────────────────────────
    write_line(&mut pages.buf[2][0], "Value:");
    {
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

    // ── Page 3: Max fee + tip ───────────────────────────────────────
    write_line(&mut pages.buf[3][0], "Max fee:");
    let _ = write_gwei(&mut pages.buf[3][1], &tx.max_fee_per_gas);
    write_tip_row(&mut pages.buf[3][2], &tx.max_priority_fee_per_gas);
    write_line(&mut pages.buf[3][3], "> next");

    // ── Page 4: Worst-case fee budget + gas limit ───────────────────
    write_line(&mut pages.buf[4][0], "Worst-case:");
    write_fee_budget_row(&mut pages.buf[4][1], &tx.max_fee_per_gas, tx.gas_limit);
    write_gas(&mut pages.buf[4][2], tx.gas_limit);
    write_line(&mut pages.buf[4][3], "> next");

    // ── Page 5: Nonce + data + buttons ──────────────────────────────
    write_nonce_row(&mut pages.buf[5][0], tx.nonce);
    write_data_len_row(&mut pages.buf[5][1], tx.data_len);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}
