//! Pixel-UI screens for the slot-rotation consent — the second painter over
//! `slot_rotation::build_slot_rotation_pages` (upstream `rotate_slot`).
//!
//! ```text
//!  ROTATE SLOT? · ROTATE (the new slot) · COST (+1 bootstrap use)
//! ```
//!
//! The handler's signer / nonce-lane / gas-lane gates follow as trailer
//! screens (`TrailerSet::Rotation`).

use super::screen_kit::{BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use pqsigner_ui_px::{Icon, Look, Screens, Weight};

/// The page count of `build_slot_rotation_pages`.
pub(crate) const LEGACY_PAGES: usize = 1;

pub(crate) const FAMILY: Family = Family {
    look: Look::plain(Icon::Rotate),
    signed: b"SLOT ROTATED",
    declined: b"ROTATION DECLINED",
};

pub(crate) fn emit(out: &mut Screens, chain_id: u64, slot_index: u32) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, chain_id, FAMILY.look);
    e.hero(b"ROTATE", b"ROTATE SLOT?")?;
    let slot = Text::new().push(b"Slot ").push_u64(u64::from(slot_index));
    if !slot.ok() {
        return Err(());
    }
    e.detail(b"ROTATE", b"ROTATE", &[(b"New signing slot", Weight::Regular), (slot.as_bytes(), Weight::Regular)], false)?;
    e.detail(
        b"COST",
        b"COST",
        &[(b"+1 bootstrap use", Weight::Regular), (b"(on-chain cap)", Weight::Regular)],
        true,
    )?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: LEGACY_PAGES,
    })
}
