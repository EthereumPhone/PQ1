//! Trust level 1 — plain ETH transfer with empty calldata.
//!
//! Five-page flow:
//!
//! ```text
//! Page 0: Confirm Tx?     Page 1: To:           Page 2: Value:
//!         Chain: <n>              0x1234abcd...         1.234567 ETH
//!         <chain name>            ...efgh5678           (gas: <limit>)
//!         > next                  > next                > next
//!
//! Page 3: Max fee:        Page 4: Data: <n>B
//!         <gwei> gwei             Nonce: <n>
//!         Tip: <gwei>             L=Cancel
//!         > next                  R=Confirm
//! ```

use super::primitives::{
    chain_name, format_u64, write_chain, write_eth, write_gas, write_gwei, write_line,
};
use super::Pages;
use crate::tx::eip1559::Eip1559Tx;
use crate::ui::DISPLAY_COLS;

pub fn render_pages(tx: &Eip1559Tx) -> Pages {
    let mut pages = Pages::with_len(5);

    // Page 0: Confirm Tx? + chain
    write_line(&mut pages.buf[0][0], "Confirm Tx?");
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
    write_line(&mut pages.buf[0][3], "> next");

    // Page 1: To
    write_line(&mut pages.buf[1][0], "To:");
    if let Some(addr) = &tx.to {
        let (left, right) = pages.buf[1].split_at_mut(2);
        super::primitives::write_addr(&mut left[1], &mut right[0], addr);
    } else {
        write_line(&mut pages.buf[1][1], "(create)");
    }
    write_line(&mut pages.buf[1][3], "> next");

    // Page 2: Value
    write_line(&mut pages.buf[2][0], "Value:");
    write_eth(&mut pages.buf[2][1], &tx.value);
    write_gas(&mut pages.buf[2][2], tx.gas_limit);
    write_line(&mut pages.buf[2][3], "> next");

    // Page 3: Fees
    write_line(&mut pages.buf[3][0], "Max fee:");
    write_gwei(&mut pages.buf[3][1], &tx.max_fee_per_gas);
    {
        let mut row2 = [b' '; DISPLAY_COLS];
        let prefix = b"Tip: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = tx.max_priority_fee_per_gas.format_decimal(9, 3, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" gwei";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row2[pos] = b;
                pos += 1;
            }
        }
        pages.buf[3][2] = row2;
    }
    write_line(&mut pages.buf[3][3], "> next");

    // Page 4: Data + nonce + confirm/cancel
    {
        let mut row0 = [b' '; DISPLAY_COLS];
        let prefix = b"Data: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.data_len as u64, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        let suffix = b" B";
        for &b in suffix {
            if pos < DISPLAY_COLS {
                row0[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][0] = row0;
    }
    {
        let mut row1 = [b' '; DISPLAY_COLS];
        let prefix = b"Nonce: ";
        let mut pos = 0;
        for &b in prefix {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        let mut tmp = [0u8; 16];
        let n = format_u64(tx.nonce, &mut tmp);
        for &b in &tmp[..n] {
            if pos < DISPLAY_COLS {
                row1[pos] = b;
                pos += 1;
            }
        }
        pages.buf[4][1] = row1;
    }
    write_line(&mut pages.buf[4][2], "L=Cancel");
    write_line(&mut pages.buf[4][3], "R=Confirm");

    pages
}
