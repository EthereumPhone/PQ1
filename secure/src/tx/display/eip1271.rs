//! EIP-1271 off-chain signature confirmation pages.
//!
//! The firmware never sees the structured payload behind the 32-byte
//! `replaySafeHash` — the companion has already wrapped the dapp's raw
//! hash through Solady's nested EIP-712 by the time the bytes reach
//! us. So the trusted display surfaces the four facts the user can
//! actually verify against the dapp:
//!
//!   * which `(account, slot)` is signing,
//!   * which chain's wallet the sig is bound to (replay-safe wrap
//!     baked the chain id into the hash already, but the user still
//!     needs to recognise it),
//!   * the full 32-byte hash (split across two pages so all 64 hex
//!     chars are visible without truncation),
//!   * the off-chain budget context (`local + 1 / cap`, gap to the
//!     next required UserOp).

use super::primitives::{chain_name, hex_nibble, write_chain, write_line};
use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Render the EIP-1271 off-chain sign confirmation flow.
///
/// `local_offchain_after` is the per-slot off-chain count that this
/// signature would publish (i.e. `local + 1`). `last_userop` is the
/// last value durably committed on-chain; their delta is what
/// `MAX_OFFCHAIN_GAP` bounds. `cap` is `MAX_SLOT_USES`.
pub fn render_eip1271_pages(
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    hash: &[u8; 32],
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
) -> Pages {
    let mut pages = Pages::with_len(6);

    // ── Page 0: banner ─────────────────────────────────────────────
    write_line(&mut pages.buf[0][0], "EIP-1271 Sign?");
    write_line(&mut pages.buf[0][1], "! Off-chain sig");
    write_line(&mut pages.buf[0][2], "Verify on dapp");
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: chain ──────────────────────────────────────────────
    write_line(&mut pages.buf[1][0], "Chain:");
    write_chain(&mut pages.buf[1][1], chain_id);
    write_line(&mut pages.buf[1][2], chain_name(chain_id));
    write_line(&mut pages.buf[1][3], "> next");

    // ── Page 2: account + slot ─────────────────────────────────────
    write_acct_row(&mut pages.buf[2][0], account_index);
    write_slot_row(&mut pages.buf[2][1], slot_index);
    write_line(&mut pages.buf[2][2], "");
    write_line(&mut pages.buf[2][3], "> next");

    // ── Page 3: hash bytes 0..16 ───────────────────────────────────
    write_line(&mut pages.buf[3][0], "Hash 1/2:");
    write_hex_row(&mut pages.buf[3][1], &hash[0..8]);
    write_hex_row(&mut pages.buf[3][2], &hash[8..16]);
    write_line(&mut pages.buf[3][3], "> next");

    // ── Page 4: hash bytes 16..32 ──────────────────────────────────
    write_line(&mut pages.buf[4][0], "Hash 2/2:");
    write_hex_row(&mut pages.buf[4][1], &hash[16..24]);
    write_hex_row(&mut pages.buf[4][2], &hash[24..32]);
    write_line(&mut pages.buf[4][3], "> next");

    // ── Page 5: budget summary + buttons ───────────────────────────
    write_budget_row(&mut pages.buf[5][0], local_offchain_after, cap);
    write_gap_row(&mut pages.buf[5][1], local_offchain_after, last_userop);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}

fn write_hex_row(row: &mut [u8; DISPLAY_COLS], bytes: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let n = core::cmp::min(bytes.len(), DISPLAY_COLS / 2);
    for i in 0..n {
        row[i * 2] = hex_nibble(bytes[i] >> 4);
        row[i * 2 + 1] = hex_nibble(bytes[i] & 0x0f);
    }
}

fn write_acct_row(row: &mut [u8; DISPLAY_COLS], account_index: u32) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Account: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, account_index as u64);
    let _ = pos;
}

fn write_slot_row(row: &mut [u8; DISPLAY_COLS], slot_index: u32) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Slot: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, slot_index as u64);
    let _ = pos;
}

fn write_budget_row(row: &mut [u8; DISPLAY_COLS], used: u64, cap: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    pos = write_decimal(row, pos, used);
    if pos < DISPLAY_COLS {
        row[pos] = b'/';
        pos += 1;
    }
    pos = write_decimal(row, pos, cap);
    let _ = pos;
}

fn write_gap_row(row: &mut [u8; DISPLAY_COLS], local_after: u64, last_userop: u64) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Gap: ";
    let mut pos = 0;
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    let gap = local_after.saturating_sub(last_userop);
    pos = write_decimal(row, pos, gap);
    let _ = pos;
}

fn write_decimal(row: &mut [u8; DISPLAY_COLS], pos: usize, mut n: u64) -> usize {
    let mut buf = [0u8; 20];
    let mut len = 0usize;
    if n == 0 {
        if pos < DISPLAY_COLS {
            row[pos] = b'0';
            return pos + 1;
        }
        return pos;
    }
    while n > 0 {
        buf[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut p = pos;
    for i in 0..len {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = buf[len - 1 - i];
        p += 1;
    }
    p
}
