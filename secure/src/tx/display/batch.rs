//! Per-tx and final-summary page wrappers for `CMD_SIGN_USEROP_BATCH`.
//!
//! Clear-signing for batches is per-inner-tx: every member call gets
//! the same trusted-UI render the single-tx path would produce, plus a
//! leading 1-page "BATCH SIGN | Tx i of N" banner that anchors the
//! user to which member they're approving. After all N have been
//! confirmed, [`build_final_summary_pages`] emits a one-page "Sign
//! batch?" gate so the user has an unambiguous final affirmative
//! consent before the firmware computes the SPHINCS+C10 sig.

use super::Pages;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Prepend a 1-page "BATCH SIGN | Tx i of N" banner to a per-tx
/// [`Pages`] so the user always knows which inner tx is currently on
/// screen.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   row 0:                    (blank)
///   row 1:    BATCH SIGN
///   row 2:     Tx i of N
///   row 3:                    (blank)
/// ```
///
/// `tx_index` is 0-based; the banner renders it as 1-based for the
/// user (`Tx 1 of 3`, `Tx 2 of 3`, …).
///
/// Refuses (returns the input unchanged) if `inner.len + 1 > MAX_PAGES`
/// — the per-tx renderer ate the banner budget. This can only happen if
/// a future renderer grows past `MAX_PAGES - 1`; surfaced in tests.
pub fn wrap_pages_with_batch_banner(inner: Pages, tx_index: usize, batch_total: usize) -> Pages {
    let new_len = inner.len + 1;
    if new_len > super::MAX_PAGES {
        // Renderer overflowed our banner budget; fall back to the bare
        // pages so the user at least sees the inner tx.
        return inner;
    }

    let mut out = Pages::empty_with_len(new_len);

    // Banner page is page 0.
    out.row_mut(0, 0).copy_from_slice(&[b' '; DISPLAY_COLS]);
    write_centered(out.row_mut(0, 1), b"BATCH SIGN");
    let mut buf = [b' '; DISPLAY_COLS];
    write_tx_position(&mut buf, tx_index, batch_total);
    out.row_mut(0, 2).copy_from_slice(&buf);
    out.row_mut(0, 3).copy_from_slice(&[b' '; DISPLAY_COLS]);

    // Copy inner pages onto pages 1..=inner.len.
    for i in 0..inner.len {
        for r in 0..DISPLAY_ROWS {
            out.row_mut(i + 1, r).copy_from_slice(&inner.buf[i][r]);
        }
    }

    out
}

/// Build the one-page final summary that asks the user to authorise
/// the entire batch sign.
///
/// Layout:
///
/// ```text
///   row 0:                    (blank)
///   row 1:   Sign N txs?
///   row 2:    Long-right
///   row 3:    to confirm
/// ```
///
/// The page renderer for [`crate::ui::confirm`] already shows a global
/// "long-right = confirm, long-left = cancel" affordance, but the
/// explicit instruction here removes any doubt about what the user is
/// authorising.
pub fn build_final_summary_pages(batch_total: usize) -> Pages {
    let mut out = Pages::empty_with_len(1);
    out.row_mut(0, 0).copy_from_slice(&[b' '; DISPLAY_COLS]);

    let mut buf = [b' '; DISPLAY_COLS];
    write_sign_n_txs(&mut buf, batch_total);
    out.row_mut(0, 1).copy_from_slice(&buf);

    write_centered(out.row_mut(0, 2), b"Long-right");
    write_centered(out.row_mut(0, 3), b"to confirm");
    out
}

/// Write `text` into `row`, centered.
fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

/// Write " Tx i of N" centered into `row`. Both `i` and `N` rendered
/// 1..=MAX_BATCH_TXS so single-digit display is fine.
fn write_tx_position(row: &mut [u8; DISPLAY_COLS], tx_index_zero_based: usize, total: usize) {
    let i_one_based = tx_index_zero_based + 1;
    // "Tx N of M" — at most "Tx 9 of 9" = 9 chars; cleaner with single
    // digit. MAX_BATCH_TXS is currently 4 so this is fine.
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"Tx ";
    let mut p = 0usize;
    for &c in prefix.iter() {
        buf[p] = c;
        p += 1;
    }
    p += write_dec(&mut buf, p, i_one_based);
    let mid = b" of ";
    for &c in mid.iter() {
        buf[p] = c;
        p += 1;
    }
    p += write_dec(&mut buf, p, total);
    let len = p;
    *row = [b' '; DISPLAY_COLS];
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&buf[..len]);
}

/// Write "Sign N txs?" centered.
fn write_sign_n_txs(row: &mut [u8; DISPLAY_COLS], total: usize) {
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"Sign ";
    let mut p = 0usize;
    for &c in prefix.iter() {
        buf[p] = c;
        p += 1;
    }
    p += write_dec(&mut buf, p, total);
    for &c in b" txs?".iter() {
        buf[p] = c;
        p += 1;
    }
    let len = p;
    *row = [b' '; DISPLAY_COLS];
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&buf[..len]);
}

/// Write `value` as decimal ASCII into `buf` starting at `pos`. Returns
/// the number of bytes written. `value` must fit in the remaining buffer.
fn write_dec(buf: &mut [u8; DISPLAY_COLS], pos: usize, value: usize) -> usize {
    if value == 0 {
        buf[pos] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[pos + i] = tmp[n - 1 - i];
    }
    n
}
