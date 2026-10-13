//! "Update signature count?" confirm pages for `CMD_OFFCHAIN_SYNC`.
//!
//! `CMD_OFFCHAIN_SYNC` lets the (untrusted) companion set a durable floor on a
//! slot's `last_userop_count` so a firmware that was reflashed (or a second
//! device on the same seed) can re-learn the on-chain off-chain-signature
//! count and stop emitting non-monotonic counts. The value is
//! security-relevant: it is folded into the slot's combined 65,536-signature
//! budget on the next sign. The *durable write itself* also creates a fresh
//! page-123 journal entry for a **companion-chosen, seed-independent**
//! `(account_index, chain_id, slot_index)` tuple. With no consent gate a
//! hostile companion can spray distinct tuples to fill the page and wedge
//! compaction into a permanent, seed-survivable signing brick
//! (`docs/security/vulns/VULN-offchain-sync-page123-exhaustion-brick.md`).
//!
//! This is the trusted-display affirmative-consent step the handler shows
//! before writing an entry for a slot it has **not** seen before, or before
//! raising an existing slot's floor. The pages bind that consent to the exact
//! device count, requested count and resulting remaining budget, in plain
//! language (sweep 2026-10-13 finding #2: the old "SYNC COUNTER? / Off-chain
//! floor / Current / Target" wording told a user nothing about what they were
//! spending). A sync the policy flags ([`SyncVerdict::Warn`]: a jump above
//! `SYNC_WARN_JUMP` or fewer than `SYNC_WARN_LEFT` signatures left) gets an
//! extra "!! CAREFUL !!" page; a sync that would leave nothing is refused by
//! the handler before any page is built.
//!
//! [`SyncVerdict::Warn`]: pqsigner_aa::offchain_gate::SyncVerdict::Warn

use super::primitives::write_chain;
use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Page count without / with the warning page.
pub const OFFCHAIN_SYNC_PAGES: usize = 4;
pub const OFFCHAIN_SYNC_PAGES_WARN: usize = 5;

/// Build the "Update signature count?" confirmation shown before a new-slot
/// or floor-raising `CMD_OFFCHAIN_SYNC` durable write.
///
/// Layout (16 cols × 4 rows; row 3 shares space with the ` i/n` indicator):
///
/// ```text
///   p0:                 p1:                p2:                [p3, warn only]:   last:
///     (blank)             Chain: <id>        On device: <n>     !! CAREFUL !!      Only if you
///     Update signature    (chain name)       From app: <n>      Jump: +<n>         restored or use
///     count from app?     Account: <n>       Sigs left: <n>     Left: <n>          a 2nd device.
///     (blank)             Slot: <n>          (blank)            (blank)            L=No  R=Yes
/// ```
///
/// * `device_count` — the device's effective off-chain count
///   (`max(local_offchain, last_userop)`).
/// * `target_count` — the post-clamp target the handler will write.
/// * `left_after` — signatures (of either kind) the slot still allows after
///   the write (`sync_left_after`).
///
/// Counts are runtime-bounded by the handler to `0..=MAX_SLOT_USES`, so every
/// decimal fits its row exactly and cannot be truncated.
#[must_use]
pub fn build_offchain_sync_pages(
    account_index: u8,
    chain_id: u64,
    slot_index: u32,
    device_count: u64,
    target_count: u64,
    left_after: u64,
    warn: bool,
) -> Pages {
    // Defence in depth: the warning is also derived here from the very values
    // shown, with the shared policy thresholds, so suppressing it needs BOTH
    // the handler's sentinel-derived `warn` and this derivation to fail.
    let warn = warn
        || target_count.saturating_sub(device_count) > pqsigner_aa::offchain_gate::SYNC_WARN_JUMP
        || left_after < pqsigner_aa::offchain_gate::SYNC_WARN_LEFT;
    let mut out = Pages::empty_with_len(if warn {
        OFFCHAIN_SYNC_PAGES_WARN
    } else {
        OFFCHAIN_SYNC_PAGES
    });

    // Page 0 — the question, in words a user understands.
    write_centered(out.row_mut(0, 1), b"Update signature");
    write_centered(out.row_mut(0, 2), b"count from app?");

    // Page 1 — which key. `write_chain` uses both rows so every 10–20 digit
    // u64 remains lossless; short ids use row 1 for the advisory chain name.
    {
        let [id, continuation_or_name, _account, _slot] = out.page_mut(1);
        write_chain(id, continuation_or_name, chain_id);
    }
    write_label_dec(out.row_mut(1, 2), b"Account: ", u64::from(account_index));
    write_label_dec(out.row_mut(1, 3), b"Slot: ", u64::from(slot_index));

    // Page 2 — the exact state transition and what it leaves.
    write_label_dec(out.row_mut(2, 0), b"On device: ", device_count);
    write_label_dec(out.row_mut(2, 1), b"From app: ", target_count);
    write_label_dec(out.row_mut(2, 2), b"Sigs left: ", left_after);

    let mut last = 3;
    if warn {
        // Page 3 — the loud warning (pixel UI: pulsing rings).
        write_centered(out.row_mut(3, 0), b"!! CAREFUL !!");
        write_label_dec(out.row_mut(3, 1), b"Jump: +", target_count.saturating_sub(device_count));
        write_label_dec(out.row_mut(3, 2), b"Left: ", left_after);
        last = 4;
    }

    // Last page — when an honest sync happens, and the buttons.
    write_left(out.row_mut(last, 0), b"Only if you");
    write_left(out.row_mut(last, 1), b"restored or use");
    write_left(out.row_mut(last, 2), b"a 2nd device.");
    write_left(out.row_mut(last, 3), b"L=No  R=Yes");

    out
}

fn write_left(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    row[..len].copy_from_slice(&text[..len]);
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

/// Left-aligned `"<label><decimal>"`. Callers runtime-bound values that carry
/// security meaning so their complete decimal form fits; the writer itself
/// remains bounds-safe for every `u64`.
fn write_label_dec(row: &mut [u8; DISPLAY_COLS], label: &[u8], value: u64) {
    *row = [b' '; DISPLAY_COLS];
    let mut p = 0usize;
    for &c in label.iter() {
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = c;
        p += 1;
    }
    write_dec(row, p, value);
}

fn write_dec(row: &mut [u8; DISPLAY_COLS], pos: usize, value: u64) -> usize {
    if value == 0 {
        if pos < DISPLAY_COLS {
            row[pos] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut written = 0;
    for i in 0..n {
        let p = pos + i;
        if p >= DISPLAY_COLS {
            break;
        }
        row[p] = tmp[n - 1 - i];
        written += 1;
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_text(row: &[u8; DISPLAY_COLS]) -> &str {
        core::str::from_utf8(row).expect("renderer emits ASCII")
    }

    #[test]
    fn sync_pages_bind_exact_counts_and_remaining_budget() {
        let pages = build_offchain_sync_pages(7, 1, 42, 9, 40, 65_487, false);
        assert_eq!(pages.len, OFFCHAIN_SYNC_PAGES);
        assert_eq!(row_text(&pages.buf[0][1]), "Update signature");
        assert_eq!(row_text(&pages.buf[0][2]), "count from app? ");
        assert_eq!(row_text(&pages.buf[2][0]), "On device: 9    ");
        assert_eq!(row_text(&pages.buf[2][1]), "From app: 40    ");
        assert_eq!(row_text(&pages.buf[2][2]), "Sigs left: 65487");
        assert_eq!(row_text(&pages.buf[3][3]), "L=No  R=Yes     ");
    }

    #[test]
    fn every_row_fits_and_the_largest_values_are_lossless() {
        let pages = build_offchain_sync_pages(255, u64::MAX, u32::MAX, 65_535, 65_535, 65_536, true);
        assert_eq!(row_text(&pages.buf[2][0]), "On device: 65535");
        assert_eq!(row_text(&pages.buf[2][1]), "From app: 65535 ");
        assert_eq!(row_text(&pages.buf[2][2]), "Sigs left: 65536");
        assert_eq!(row_text(&pages.buf[3][1]), "Jump: +0        ");
        // Row 3 of every fixed-text page leaves room for the ` i/n` page
        // indicator (page 1's `Slot: N` row is value-dependent; the overlay
        // simply yields there, as before).
        for p in [0, 2, 3, 4] {
            assert!(row_text(&pages.buf[p][3]).trim_end().len() <= 11, "page {p} row 3");
        }
    }

    #[test]
    fn warning_page_is_inserted_only_when_flagged() {
        let plain = build_offchain_sync_pages(0, 8453, 3, 12, 40, 65_484, false);
        let warn = build_offchain_sync_pages(0, 8453, 3, 0, 64_000, 1_536, true);
        assert_eq!(plain.len, OFFCHAIN_SYNC_PAGES);
        assert_eq!(warn.len, OFFCHAIN_SYNC_PAGES_WARN);
        assert_eq!(row_text(&warn.buf[3][0]), " !! CAREFUL !!  ");
        assert_eq!(row_text(&warn.buf[3][1]), "Jump: +64000    ");
        assert_eq!(row_text(&warn.buf[3][2]), "Left: 1536      ");
        assert_eq!(row_text(&warn.buf[4][0]), row_text(&plain.buf[3][0]));
        assert!((0..plain.len).all(|p| row_text(&plain.buf[p][0]).trim() != "!! CAREFUL !!"));
    }

    #[test]
    fn warning_cannot_be_dropped_by_the_handler_flag_alone() {
        // A cleared `warn` flag (e.g. one data fault in the handler) still
        // yields the warning when the shown values warrant it.
        let big_jump = build_offchain_sync_pages(0, 8453, 3, 0, 64_000, 1_536, false);
        assert_eq!(big_jump.len, OFFCHAIN_SYNC_PAGES_WARN);
        let little_left = build_offchain_sync_pages(0, 8453, 3, 10, 20, 999, false);
        assert_eq!(little_left.len, OFFCHAIN_SYNC_PAGES_WARN);
        let plain = build_offchain_sync_pages(0, 8453, 3, 10, 1_010, 1_000, false);
        assert_eq!(plain.len, OFFCHAIN_SYNC_PAGES);
    }

    #[test]
    fn changing_any_bound_value_changes_trusted_pixels() {
        let a = build_offchain_sync_pages(0, 1, 0, 10, 11, 100, false);
        let b = build_offchain_sync_pages(0, 1, 0, 12, 11, 100, false);
        let c = build_offchain_sync_pages(0, 1, 0, 10, 13, 100, false);
        let d = build_offchain_sync_pages(0, 1, 0, 10, 11, 101, false);
        assert_ne!(a.buf[2], b.buf[2], "device count must be display-bound");
        assert_ne!(a.buf[2], c.buf[2], "target count must be display-bound");
        assert_ne!(a.buf[2], d.buf[2], "remaining budget must be display-bound");
    }
}
