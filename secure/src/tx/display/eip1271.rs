//! EIP-1271 off-chain signature confirmation pages.
//!
//! Two flows:
//!
//!   * `render_eip1271_personal_sign_pages` — surfaces the actual
//!     `personal_sign` message text (paginated as printable ASCII)
//!     plus the wallet address that will be doing the signing. The
//!     firmware itself recomputes the replay-safe hash from this
//!     message, so what the user reads here is byte-equivalent to
//!     what gets signed.
//!
//!   * `render_eip1271_raw32_pages` — fallback for the raw-hash path
//!     (e.g. an EIP-712 typed-data digest the firmware can't break
//!     apart). Shows the 32 hex bytes split across two pages.
//!
//! Both render the same chain / account / slot context and the same
//! per-slot off-chain budget summary (`local + 1 / cap`, gap to next
//! UserOp).

use super::primitives::{
    chain_name, hex_nibble, write_addr_full, write_chain, write_line,
};
use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Render the PersonalSign EIP-1271 confirmation flow.
///
/// `wallet_addr` is the on-chain proxy address signing the message
/// (the verifying contract bound into the EIP-712 domain separator).
/// `msg` is the raw `personal_sign` message — printable ASCII bytes
/// render as themselves; non-printable bytes render as `?`.
pub fn render_eip1271_personal_sign_pages(
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    wallet_addr: &[u8; 20],
    msg: &[u8],
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
    account_deployed: bool,
) -> Pages {
    // 5 fixed pages (banner / chain / account / wallet addr / final
    // confirm) + the message body. Each message page surfaces 3 rows
    // × 16 cols = 48 chars; the 4th row is a "Msg N/M > next" footer.
    const TEXT_ROWS_PER_PAGE: usize = 3;
    const CHARS_PER_PAGE: usize = TEXT_ROWS_PER_PAGE * DISPLAY_COLS;

    let msg_pages = if msg.is_empty() {
        1
    } else {
        (msg.len() + CHARS_PER_PAGE - 1) / CHARS_PER_PAGE
    };
    let total = 5 + msg_pages;
    // `Pages::with_len` will assert if MAX_PAGES is too small. The
    // bound matches the static cap on `MAX_OFFCHAIN_PERSONAL_SIGN_LEN`
    // / CHARS_PER_PAGE + 5 fixed pages.
    let mut pages = Pages::with_len(total);

    // ── Page 0: banner ─────────────────────────────────────────────
    write_line(&mut pages.buf[0][0], "EIP-1271 Sign?");
    write_line(&mut pages.buf[0][1], "personal_sign");
    if account_deployed {
        write_line(&mut pages.buf[0][2], "Verify on dapp");
    } else {
        // ERC-6492: the dapp will receive a wrapped sig that
        // counterfactually deploys this wallet on first use.
        write_line(&mut pages.buf[0][2], "! Pre-deploy 6492");
    }
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

    // ── Page 3: wallet address (the EIP-712 verifyingContract) ─────
    write_line(&mut pages.buf[3][0], "Signer:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[3];
        write_addr_full(a, b, c, wallet_addr);
    }

    // ── Pages 4..4+msg_pages: message text ─────────────────────────
    for p in 0..msg_pages {
        let page_idx = 4 + p;
        let off = p * CHARS_PER_PAGE;
        let end = core::cmp::min(off + CHARS_PER_PAGE, msg.len());
        let chunk = &msg[off..end];
        for r in 0..TEXT_ROWS_PER_PAGE {
            let row_off = r * DISPLAY_COLS;
            let row_end = core::cmp::min(row_off + DISPLAY_COLS, chunk.len());
            let row = &mut pages.buf[page_idx][r];
            *row = [b' '; DISPLAY_COLS];
            if row_off < chunk.len() {
                let slice = &chunk[row_off..row_end];
                for (i, &b) in slice.iter().enumerate() {
                    row[i] = sanitise_byte(b);
                }
            }
        }
        // Footer: "Msg N/M  > next" or "Msg N/M  > sign" on the last
        // text page; the very last page (final confirm) has its own
        // L=Cancel / R=Confirm prompts.
        write_msg_footer(&mut pages.buf[page_idx][3], p + 1, msg_pages);
    }

    // ── Final page: budget + confirm ───────────────────────────────
    let last_page = total - 1;
    write_budget_row(&mut pages.buf[last_page][0], local_offchain_after, cap);
    write_gap_row(&mut pages.buf[last_page][1], local_offchain_after, last_userop);
    write_line(&mut pages.buf[last_page][2], "L=Cancel");
    write_line(&mut pages.buf[last_page][3], "R=Confirm");

    pages
}

/// Render the raw-hash EIP-1271 confirmation flow (fallback when the
/// companion only has the final 32-byte hash, no message).
pub fn render_eip1271_raw32_pages(
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    hash: &[u8; 32],
    local_offchain_after: u64,
    last_userop: u64,
    cap: u64,
    account_deployed: bool,
) -> Pages {
    let mut pages = Pages::with_len(6);

    write_line(&mut pages.buf[0][0], "EIP-1271 Sign?");
    write_line(&mut pages.buf[0][1], "! Raw 32-byte");
    if account_deployed {
        write_line(&mut pages.buf[0][2], "Verify on dapp");
    } else {
        write_line(&mut pages.buf[0][2], "! Pre-deploy 6492");
    }
    write_line(&mut pages.buf[0][3], "> next");

    write_line(&mut pages.buf[1][0], "Chain:");
    write_chain(&mut pages.buf[1][1], chain_id);
    write_line(&mut pages.buf[1][2], chain_name(chain_id));
    write_line(&mut pages.buf[1][3], "> next");

    write_acct_row(&mut pages.buf[2][0], account_index);
    write_slot_row(&mut pages.buf[2][1], slot_index);
    write_line(&mut pages.buf[2][2], "");
    write_line(&mut pages.buf[2][3], "> next");

    write_line(&mut pages.buf[3][0], "Hash 1/2:");
    write_hex_row(&mut pages.buf[3][1], &hash[0..8]);
    write_hex_row(&mut pages.buf[3][2], &hash[8..16]);
    write_line(&mut pages.buf[3][3], "> next");

    write_line(&mut pages.buf[4][0], "Hash 2/2:");
    write_hex_row(&mut pages.buf[4][1], &hash[16..24]);
    write_hex_row(&mut pages.buf[4][2], &hash[24..32]);
    write_line(&mut pages.buf[4][3], "> next");

    write_budget_row(&mut pages.buf[5][0], local_offchain_after, cap);
    write_gap_row(&mut pages.buf[5][1], local_offchain_after, last_userop);
    write_line(&mut pages.buf[5][2], "L=Cancel");
    write_line(&mut pages.buf[5][3], "R=Confirm");

    pages
}

// ───────────────────────────── helpers ──────────────────────────────

fn sanitise_byte(b: u8) -> u8 {
    // Render printable ASCII as-is; everything else (control bytes, hi-
    // bit / UTF-8 continuation bytes) becomes '?' so the trusted
    // display can never paint a glyph the user couldn't read on a
    // standard ASCII rendering of the dapp's message.
    if (0x20..=0x7E).contains(&b) {
        b
    } else {
        b'?'
    }
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

fn write_msg_footer(row: &mut [u8; DISPLAY_COLS], page: usize, total: usize) {
    *row = [b' '; DISPLAY_COLS];
    let mut pos = 0;
    let prefix = b"Msg ";
    for &b in prefix {
        if pos < DISPLAY_COLS {
            row[pos] = b;
            pos += 1;
        }
    }
    pos = write_decimal(row, pos, page as u64);
    if pos < DISPLAY_COLS {
        row[pos] = b'/';
        pos += 1;
    }
    pos = write_decimal(row, pos, total as u64);
    // Tail "> next" if there's room.
    let nav = b"  > next";
    if pos + nav.len() <= DISPLAY_COLS {
        row[pos..pos + nav.len()].copy_from_slice(nav);
    }
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
