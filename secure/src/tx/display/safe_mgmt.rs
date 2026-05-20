//! Page renderer for Safe-native owner / module / guard / fallback
//! ops decoded by [`crate::tx::eip712::safe::mgmt_decode`].
//!
//! Pure-display: no crypto, no flash, no NS-pointer touch. The
//! cryptographic bind between `raw_data` and the on-chain
//! `safeTxHash` is established upstream in
//! [`crate::tx::eip712::safe::verify`]; by the time we render the
//! page strings, the canonical fields are byte-equivalent to what
//! the on-chain Safe will execute.
//!
//! This file is the renderer half; the classifier + parsed-op enum
//! lives next to the EIP-712 Safe verifier so it stays host-testable
//! (the `tx/display` tree as a whole is `#[cfg(not(test))]`-gated
//! because it depends on the secure-only UI layer).

// Re-exports so safe_display can keep its existing `super::safe_mgmt::*`
// import surface stable.
pub(super) use crate::tx::eip712::safe::mgmt_decode::{
    classify_safe_mgmt, page_count, SafeMgmtOp, ThresholdValue,
};

use super::primitives::{format_u64, write_addr_full_or_name, write_line};
use super::Pages;
use crate::names::NameResolver;
use crate::ui::DISPLAY_COLS;

/// Sentinel address used by Safe's owner / module linked-list to
/// mark the start of the list. Rendered as the human-readable
/// `"SENTINEL"` rather than `0x000…001` so the user can tell the
/// "first item" pointer apart from a real address.
const LINKED_LIST_SENTINEL: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 0x01;
    a
};

/// Render the per-op pages immediately after the Safe-tx header
/// block. Returns the index of the next free page slot.
pub(super) fn render_safe_mgmt_pages(
    pages: &mut Pages,
    start: usize,
    op: &SafeMgmtOp,
    chain_id: u64,
    _safe_addr: &[u8; 20],
    resolver: &NameResolver<'_>,
) -> usize {
    let mut p = start;
    match *op {
        SafeMgmtOp::AddOwnerWithThreshold {
            new_owner,
            new_threshold,
        } => {
            write_line(&mut pages.buf[p][0], "Add Safe owner");
            write_threshold_row(&mut pages.buf[p][1], &new_threshold);
            if matches!(new_threshold, ThresholdValue::Fits(1)) {
                write_line(&mut pages.buf[p][2], "! MULTISIG OFF");
            } else {
                write_line(&mut pages.buf[p][2], "");
            }
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "New owner:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &new_owner, chain_id, resolver);
            }
            p += 1;
        }
        SafeMgmtOp::RemoveOwner {
            prev_owner,
            owner,
            new_threshold,
        } => {
            write_line(&mut pages.buf[p][0], "Remove Safe ownr");
            write_threshold_row(&mut pages.buf[p][1], &new_threshold);
            if matches!(new_threshold, ThresholdValue::Fits(1)) {
                write_line(&mut pages.buf[p][2], "! MULTISIG OFF");
            } else {
                write_line(&mut pages.buf[p][2], "");
            }
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Removing:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &owner, chain_id, resolver);
            }
            p += 1;
            write_line(&mut pages.buf[p][0], "Prev (list ptr):");
            write_prev_pointer_row(&mut pages.buf[p][1], &prev_owner);
            write_line(&mut pages.buf[p][2], "");
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
        }
        SafeMgmtOp::SwapOwner {
            prev_owner,
            old_owner,
            new_owner,
        } => {
            write_line(&mut pages.buf[p][0], "Swap Safe owner");
            write_line(&mut pages.buf[p][1], "");
            write_prev_pointer_row(&mut pages.buf[p][2], &prev_owner);
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Old owner:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &old_owner, chain_id, resolver);
            }
            p += 1;
            write_line(&mut pages.buf[p][0], "New owner:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &new_owner, chain_id, resolver);
            }
            p += 1;
        }
        SafeMgmtOp::ChangeThreshold { new_threshold } => {
            write_line(&mut pages.buf[p][0], "Change thrshld");
            write_threshold_row(&mut pages.buf[p][1], &new_threshold);
            if matches!(new_threshold, ThresholdValue::Fits(1)) {
                write_line(&mut pages.buf[p][2], "! MULTISIG OFF");
            } else if matches!(new_threshold, ThresholdValue::Fits(0)) {
                write_line(&mut pages.buf[p][2], "! THRSHLD = 0");
            } else {
                write_line(&mut pages.buf[p][2], "");
            }
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
        }
        SafeMgmtOp::EnableModule { module } => {
            write_line(&mut pages.buf[p][0], "! ENABLE MODULE");
            write_line(&mut pages.buf[p][1], "Grants exec auth");
            write_line(&mut pages.buf[p][2], "to module addr");
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Module addr:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &module, chain_id, resolver);
            }
            p += 1;
        }
        SafeMgmtOp::DisableModule {
            prev_module,
            module,
        } => {
            write_line(&mut pages.buf[p][0], "Disable module");
            write_line(&mut pages.buf[p][1], "");
            write_prev_pointer_row(&mut pages.buf[p][2], &prev_module);
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Module addr:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &module, chain_id, resolver);
            }
            p += 1;
        }
        SafeMgmtOp::SetGuard { guard } => {
            let zero = [0u8; 20];
            write_line(&mut pages.buf[p][0], "! CHANGE GUARD");
            if guard == zero {
                write_line(&mut pages.buf[p][1], "REMOVING GUARD");
            } else {
                write_line(&mut pages.buf[p][1], "Grants veto/log");
            }
            write_line(&mut pages.buf[p][2], "on every tx");
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Guard addr:");
            if guard == zero {
                write_line(&mut pages.buf[p][1], "(none / cleared)");
                write_line(&mut pages.buf[p][2], "");
                write_line(&mut pages.buf[p][3], "");
            } else {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &guard, chain_id, resolver);
            }
            p += 1;
        }
        SafeMgmtOp::SetFallbackHandler { handler } => {
            let zero = [0u8; 20];
            write_line(&mut pages.buf[p][0], "! CHG FALLBACK");
            if handler == zero {
                write_line(&mut pages.buf[p][1], "REMOVING FB");
            } else {
                write_line(&mut pages.buf[p][1], "Runs unkn calls");
            }
            write_line(&mut pages.buf[p][2], "");
            write_line(&mut pages.buf[p][3], "> next");
            p += 1;
            write_line(&mut pages.buf[p][0], "Handler addr:");
            if handler == zero {
                write_line(&mut pages.buf[p][1], "(none / cleared)");
                write_line(&mut pages.buf[p][2], "");
                write_line(&mut pages.buf[p][3], "");
            } else {
                let [_lbl, a, b, c] = &mut pages.buf[p];
                write_addr_full_or_name(a, b, c, &handler, chain_id, resolver);
            }
            p += 1;
        }
    }
    p
}

/// Render `New thrshld: <N>` (or `! >2^16` on overflow) into one row.
fn write_threshold_row(row: &mut [u8; DISPLAY_COLS], t: &ThresholdValue) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"New thrshld: ";
    let n_pre = core::cmp::min(prefix.len(), row.len());
    row[..n_pre].copy_from_slice(&prefix[..n_pre]);
    match *t {
        ThresholdValue::Fits(n) => {
            let mut tmp = [0u8; 5];
            if let Some(width) = format_u64(n as u64, &mut tmp) {
                let start = n_pre;
                if start + width <= row.len() {
                    row[start..start + width].copy_from_slice(&tmp[..width]);
                }
            }
        }
        ThresholdValue::Overflow => {
            let suffix = b"!>2^16";
            let start = n_pre;
            let n = core::cmp::min(suffix.len(), row.len() - start);
            row[start..start + n].copy_from_slice(&suffix[..n]);
        }
    }
}

/// Render a `prev_*` linked-list pointer as one short row.
///
/// Recognises the `0x000…001` sentinel and labels it as such so
/// the user can tell the "first item" marker apart from a real
/// address that happens to start with many zeros.
fn write_prev_pointer_row(row: &mut [u8; DISPLAY_COLS], addr: &[u8; 20]) {
    *row = [b' '; DISPLAY_COLS];
    if *addr == LINKED_LIST_SENTINEL {
        let label = b"prev: SENTINEL";
        let n = core::cmp::min(label.len(), row.len());
        row[..n].copy_from_slice(&label[..n]);
        return;
    }
    let label = b"prv:0x";
    let mut p = 0;
    let n = core::cmp::min(label.len(), row.len());
    row[..n].copy_from_slice(&label[..n]);
    p += n;
    let hex = b"0123456789abcdef";
    for i in 0..2 {
        if p + 1 >= row.len() {
            return;
        }
        row[p] = hex[(addr[i] >> 4) as usize];
        row[p + 1] = hex[(addr[i] & 0x0f) as usize];
        p += 2;
    }
    if p < row.len() {
        row[p] = b'.';
        p += 1;
    }
    if p < row.len() {
        row[p] = b'.';
        p += 1;
    }
    for i in 0..2 {
        if p + 1 >= row.len() {
            return;
        }
        let b = addr[18 + i];
        row[p] = hex[(b >> 4) as usize];
        row[p + 1] = hex[(b & 0x0f) as usize];
        p += 2;
    }
}
