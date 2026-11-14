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
//!  3: "Fees: max / tip"  4: "Worst-case:"       5: "Nonce: <n>"
//!     <max gwei>             <max_fee*gas> ETH      Data: <n> B
//!     <tip gwei>             (gas: <limit>)         L=Cancel
//!     > next                > next                 R=Confirm
//! ```
//!
//! Every numeric field is overflow-safe: the helpers in
//! [`super::primitives`] refuse to silently truncate. If a value won't
//! fit, the renderer paints `!OVERFLOW` so the user can abort.

use super::primitives::{
    build_legacy_fee_pages, write_addr_full_or_name, write_chain, write_data_len_row, write_line,
    write_native_amount_rows, write_native_currency_row, write_nonce_row, AmountFit,
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
        write_native_currency_row(&mut pages.buf[0][0], b"Send ", tx.chain_id, b"?");
    }
    {
        let [_banner, id, continuation_or_name, _foot] = &mut pages.buf[0];
        write_chain(id, continuation_or_name, tx.chain_id);
    }
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: To: (3 rows of full 40-hex address) ─────────────────
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full_or_name(a, b, c, addr, tx.chain_id, resolver);
    } else {
        write_line(&mut pages.buf[1][1], "(contract create)");
    }

    // ── Page 2: Value (2-row amount, 3 when only a third wrapped row ──
    //    holds every digit) ─────────────────────────────────────────
    write_line(&mut pages.buf[2][0], "Value:");
    {
        let [_lbl, r1, r2, foot] = &mut pages.buf[2];
        if write_native_amount_rows(r1, r2, foot, &tx.value, tx.chain_id) == AmountFit::Overflow {
            write_line(foot, "!AMOUNT OVERFLOW");
        }
    }

    // ── Pages 3-4: exact max/tip and worst-case fee envelope ────────
    let fee_pages = build_legacy_fee_pages(
        &tx.max_fee_per_gas,
        &tx.max_priority_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    )
    .pages;
    pages.buf[3] = fee_pages[0];
    pages.buf[4] = fee_pages[1];

    // ── Page 5: Nonce + data + buttons ──────────────────────────────
    write_nonce_row(&mut pages.buf[5][0], tx.nonce);
    write_data_len_row(&mut pages.buf[5][1], tx.data_len);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}
