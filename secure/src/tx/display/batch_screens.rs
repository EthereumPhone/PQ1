//! Pixel-UI framing for the atomic batch (`CMD_SIGN_USEROP_BATCH`, upstream
//! flows `batch/transfers`, `batch/transfers_declined`).
//!
//! Owner decision 2026-09-23 (port plan step 3): the batch keeps today's
//! gating — one ask per member, then one ask for the whole batch, and
//! nothing is signed before that last ask. Each member dialog is the
//! member's own route body with a `BATCH` screen (`BATCH SIGN` / `Tx i of
//! N`, the banner page's rows) right after its hero; between members the
//! device shows `TX i OF N CONFIRMED` (never `SIGNED`: nothing is signed
//! yet). The final dialog is the summary ask with the batch-wide trailers.

use super::batch::build_batch_banner_page;
use super::screen_kit::{BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use crate::ui::DISPLAY_COLS;
use pqsigner_ui_px::fit::{fit_tier, Region};
use pqsigner_ui_px::{Icon, Look, ScreenBuilder, Screens, Side, Weight};

/// The whole-batch ask and its endings (one declined member declines the
/// whole batch, so the caption names the batch).
pub(crate) const SUMMARY_FAMILY: Family = Family {
    look: Look::plain(Icon::Eth),
    signed: b"BATCH SIGNED",
    declined: b"BATCH DECLINED",
};

/// A member dialog wears its route's disc; declining it declines the batch.
pub(crate) fn member_family(f: Family) -> Family {
    Family {
        declined: b"BATCH DECLINED",
        ..f
    }
}

fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
    let mut e = DISPLAY_COLS;
    while e > 0 && row[e - 1] == b' ' {
        e -= 1;
    }
    let mut s = 0;
    while s < e && row[s] == b' ' {
        s += 1;
    }
    &row[s..e]
}

/// Insert the `BATCH` position screen (the banner page's two rows) right
/// after the member's hero.
pub(crate) fn insert_position(out: &mut Screens, index: usize, total: usize, look: Look) -> Result<(), ()> {
    let page = build_batch_banner_page(index, total);
    let lines = [(trimmed(&page[1]), Weight::SemiBold), (trimmed(&page[2]), Weight::Regular)];
    let tier = fit_tier(&lines, Region::Docked).ok_or(())?;
    let s = ScreenBuilder::detail(b"BATCH", look.icon, Side::Right, b"BATCH")
        .look_tint(look)
        .tier(tier)
        .line(lines[0].0, lines[0].1)
        .line(lines[1].0, lines[1].1)
        .finish()
        .map_err(|_| ())?;
    out.insert_after_hero(&s)
}

/// The summary ask: `SIGN N TXS?` and the batch size.
pub(crate) fn emit_summary(out: &mut Screens, total: usize) -> Result<BodyReceipt, ()> {
    let mut e = Emit::new(out, 0, SUMMARY_FAMILY.look);
    let ask = Text::new().push(b"SIGN ").push_u64(total as u64).push(b" TXS?");
    if !ask.ok() {
        return Err(());
    }
    e.hero(b"SIGN", ask.as_bytes())?;
    let n = Text::new().push(b"Txs in batch: ").push_u64(total as u64);
    e.detail(
        b"BATCH",
        b"BATCH",
        &[(n.as_bytes(), Weight::Regular), (b"each confirmed", Weight::Regular), (b"one signature", Weight::Regular)],
        false,
    )?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: 1,
    })
}

/// The between-members status caption (`TX i OF N CONFIRMED`, 1-based).
pub(crate) fn member_confirmed_caption(index: usize, total: usize) -> &'static [u8] {
    match (index + 1, total) {
        (1, 1) => b"TX 1 OF 1 CONFIRMED",
        (1, 2) => b"TX 1 OF 2 CONFIRMED",
        (2, 2) => b"TX 2 OF 2 CONFIRMED",
        (1, 3) => b"TX 1 OF 3 CONFIRMED",
        (2, 3) => b"TX 2 OF 3 CONFIRMED",
        (3, 3) => b"TX 3 OF 3 CONFIRMED",
        (1, 4) => b"TX 1 OF 4 CONFIRMED",
        (2, 4) => b"TX 2 OF 4 CONFIRMED",
        (3, 4) => b"TX 3 OF 4 CONFIRMED",
        (4, 4) => b"TX 4 OF 4 CONFIRMED",
        _ => b"TX CONFIRMED",
    }
}

const _: () = assert!(sphincs_tz_shared::MAX_BATCH_TXS == 4, "extend member_confirmed_caption");
