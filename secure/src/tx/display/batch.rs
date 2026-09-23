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

type BannerPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

const BATCH_BANNER_CFI_STEP: u32 = 0xB47C_91E3;
pub(crate) const BATCH_BANNER_CFI_EXPECTED: u32 = crate::cfi_expected!(BATCH_BANNER_CFI_STEP);

const BATCH_MEMBER_CONFIRM_CFI_STEP: u32 = 0x6D2A_C4F1;

/// Caller-owned receipt for the ordered set of affirmatively confirmed batch
/// members. A per-member banner proof only exists when an iteration runs; this
/// receipt additionally proves that the loop reached every declared index.
pub(crate) struct BatchMemberConfirmReceipt {
    confirmed: u32,
    cfi: crate::fi::CfiCounter,
}

impl BatchMemberConfirmReceipt {
    pub(crate) const fn new() -> Self {
        Self {
            confirmed: 0,
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    /// Volatile fail-initialization retained at the caller boundary so stale
    /// stack contents cannot masquerade as a completed prior batch if a later
    /// record call is fault-skipped.
    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        // SAFETY: both fields are uniquely borrowed and the replacement CFI
        // counter has no destructor.
        unsafe {
            core::ptr::write_volatile(&mut self.confirmed, 0);
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Record exactly the next zero-based member after its affirmative UI
    /// sentinel passed. Out-of-order, duplicate, or skipped indices refuse.
    #[inline(never)]
    pub(crate) fn record_confirmed(&mut self, expected_index: usize) -> Result<(), ()> {
        let expected = u32::try_from(expected_index).map_err(|_| ())?;
        let next = expected.checked_add(1).ok_or(())?;
        // SAFETY: unique live receipt; volatile publication keeps the count
        // independently observable from the CFI accumulator under LTO.
        let current = unsafe { core::ptr::read_volatile(&self.confirmed) };
        if current != expected {
            return Err(());
        }
        unsafe { core::ptr::write_volatile(&mut self.confirmed, next) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(BATCH_MEMBER_CONFIRM_CFI_STEP);
        Ok(())
    }

    /// Prove exact ordered cardinality plus one completed CFI step per member.
    #[inline(never)]
    pub(crate) fn completion_proof(&self, expected_count: usize) -> u32 {
        let Ok(expected_count_u32) = u32::try_from(expected_count) else {
            return crate::fi::FAIL_SENTINEL;
        };
        // SAFETY: immutable live receipt, deliberately sampled twice around a
        // randomized gap so a single corrupt load cannot forge cardinality.
        let confirmed_a = unsafe { core::ptr::read_volatile(&self.confirmed) };
        crate::fi::wait_random();
        let confirmed_b = unsafe { core::ptr::read_volatile(&self.confirmed) };
        let expected_cfi = crate::fi::CfiCounter::INIT_VALUE
            .wrapping_add(BATCH_MEMBER_CONFIRM_CFI_STEP.wrapping_mul(expected_count_u32));
        crate::fi::scrub_sentinel_register();
        let cfi_verdict = self.cfi.check_into_sentinel(expected_cfi);
        let all_ok = confirmed_a == expected_count_u32
            && confirmed_b == expected_count_u32
            && cfi_verdict == crate::fi::OK_SENTINEL;
        // The final sentinel closure captures only a boolean (0/1), never the
        // preceding OK sentinel, so a skipped call cannot inherit permission.
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(all_ok))
    }
}

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
/// Returns `Err(())` if `inner.len + 1 > MAX_PAGES` — the per-tx renderer ate
/// the banner budget. The caller must then refuse to sign: dropping the
/// "BATCH SIGN | Tx i of N" banner (finding F5) would release a Type-2 slot
/// signature without the per-tx anchor that tells the user which member they
/// are approving. Fail closed rather than signing the bare inner pages.
#[inline(never)]
pub fn wrap_pages_with_batch_banner(
    inner: &Pages,
    tx_index: usize,
    batch_total: usize,
    out: &mut Pages,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    // Fail-initialize caller-owned output. A skipped whole call therefore
    // leaves both an empty transcript and a short caller-owned CFI receipt.
    // SAFETY: `out` is a unique mutable borrow and zero is a valid length.
    unsafe { core::ptr::write_volatile(&mut out.len, 0) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    let new_len = inner.len.checked_add(1).ok_or(())?;
    if new_len > super::MAX_PAGES {
        return Err(());
    }

    for page in &mut out.buf[..new_len] {
        *page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    }
    // Publish the bounded visible length before using the checked row helpers;
    // no caller can observe it until this non-inlined operation returns.
    unsafe { core::ptr::write_volatile(&mut out.len, new_len) };
    out.buf[0] = build_batch_banner_page(tx_index, batch_total);

    // Copy inner pages onto pages 1..=inner.len.
    for i in 0..inner.len {
        for r in 0..DISPLAY_ROWS {
            out.buf[i + 1][r].copy_from_slice(&inner.buf[i][r]);
        }
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(BATCH_BANNER_CFI_STEP);
    Ok(())
}

pub(crate) fn build_batch_banner_page(tx_index: usize, batch_total: usize) -> BannerPage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    write_centered(&mut page[1], b"BATCH SIGN");
    write_tx_position(&mut page[2], tx_index, batch_total);
    page
}

fn page_exact(actual: &BannerPage, expected: &BannerPage) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

/// Independently prove the exact leading banner and every copied transcript
/// byte. A skipped/partial copy loop, wrong shift, corrupted banner, stale
/// length, or skipped whole operation therefore fails before later appends.
#[inline(never)]
pub(crate) fn batch_banner_copy_proof(
    inner: &Pages,
    wrapped: &Pages,
    tx_index: usize,
    batch_total: usize,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let Some(expected_len) = inner.len.checked_add(1) else {
            return false;
        };
        if core::hint::black_box(wrapped.len != expected_len)
            || !wrapped.as_slice().first().is_some_and(|page| {
                page_exact(page, &build_batch_banner_page(tx_index, batch_total))
            })
        {
            return false;
        }
        let mut diff = 0u8;
        for page_index in 0..inner.len {
            for row in 0..DISPLAY_ROWS {
                for col in 0..DISPLAY_COLS {
                    diff |= inner.buf[page_index][row][col] ^ wrapped.buf[page_index + 1][row][col];
                }
            }
        }
        core::hint::black_box(diff == 0)
    })
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
