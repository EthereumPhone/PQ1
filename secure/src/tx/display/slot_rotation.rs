//! Standalone "ROTATE SLOT?" confirm page for `FLAG_REGISTER_SLOT`.
//!
//! When the companion sets `FLAG_REGISTER_SLOT`, the firmware emits a
//! Type 1 (`addOwnerBytes`) UserOp alongside the user's Type 2. That
//! Type 1 silently consumes one of the wallet's `MAX_BOOTSTRAP_USES`
//! bootstrap budget items on chain — so a hostile companion that always
//! sets the flag can drain the bootstrap reserve at twice the rate the
//! user thinks they're authorising.
//!
//! Closing the gap is a UI affair, not an invariant break: every Type 1
//! is already verified by the bootstrap C10 sig and bumps `bootstrapUses`
//! through the on-chain monotonic cap. We just need the trusted display
//! to surface the rotation as its own affirmative-consent step before
//! the inner-tx render runs.

use super::Pages;
use crate::ui::DISPLAY_COLS;

/// Build the one-page "ROTATE SLOT?" confirm shown before the inner-tx
/// confirm whenever `FLAG_REGISTER_SLOT` is set.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   row 0:                    (blank)
///   row 1:    ROTATE SLOT?
///   row 2:    New slot: N
///   row 3:    +bootstrap use
/// ```
///
/// `slot_index` is the firmware-side index supplied in the FLAG word
/// (always `>= 1` here — the handler refuses `register_slot && slot_index
/// == 0` upstream). Its on-chain `ownerIndex` is `slot_index + 1`, but
/// the firmware/UI/flash all key on the firmware-side index, so we keep
/// the displayed number aligned with that convention.
pub fn build_slot_rotation_pages(slot_index: u32) -> Pages {
    let mut out = Pages::empty_with_len(1);

    out.row_mut(0, 0).copy_from_slice(&[b' '; DISPLAY_COLS]);
    write_centered(out.row_mut(0, 1), b"ROTATE SLOT?");
    let mut buf = [b' '; DISPLAY_COLS];
    write_new_slot(&mut buf, slot_index);
    out.row_mut(0, 2).copy_from_slice(&buf);
    write_centered(out.row_mut(0, 3), b"+bootstrap use");

    out
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

fn write_new_slot(row: &mut [u8; DISPLAY_COLS], slot_index: u32) {
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"New slot: ";
    let mut p = 0usize;
    for &c in prefix.iter() {
        buf[p] = c;
        p += 1;
    }
    p += write_dec(&mut buf, p, slot_index as usize);
    let len = p;
    *row = [b' '; DISPLAY_COLS];
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&buf[..len]);
}

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
