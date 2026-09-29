//! NV3007 frame geometry and the pure CASET/RASET byte builder, split out of
//! `hw/lcd_nv3007.rs` so they can be tested.
//!
//! WHY THIS FILE EXISTS (#723). `main.rs` declares `#[cfg(not(test))] mod hw;`,
//! so the whole `hw` tree is absent from every host test build — and
//! `lcd_nv3007.rs` additionally carries `#![cfg(feature = "ui-lcd")]` while
//! the host suite builds `ui-semihosting`. Four tests sat in that file
//! reporting neither pass nor fail, among them the cross-check against the
//! vendor bootloader's literal init bytes, which is the only thing tying our
//! pixel addressing to the panel the hardware actually ships with.
//!
//! **Deliberately carries no `#![cfg(...)]` header.** Inheriting the parent's
//! `ui-lcd` gate would make the mounted copy compile to nothing host-side and
//! silently re-create the hole this file closes.
//!
//! Nothing here touches SPI or GPIO: `build_set_window_bytes` is arithmetic on
//! four `u16`s. The driver mounts it and `ui_under_test` mounts it, so the
//! bytes the tests check are the bytes the firmware sends.

// ---------------------------------------------------------------------------
// Display geometry
// ---------------------------------------------------------------------------

/// Visible pixel width (X axis).
pub const FRAME_WIDTH: u16 = 142;
/// Visible pixel height (Y axis).
pub const FRAME_HEIGHT: u16 = 428;

/// X offset applied to all column-address commands. The NV3007's RAM
/// extends past the visible window; the production driver's
/// `BlockWrite()` adds `a=12` to every X coordinate. Replicated here.
pub const X_OFFSET: u16 = 12;
/// Y offset. The production driver uses `b=0`.
pub const Y_OFFSET: u16 = 0;

/// The CASET/RASET payloads for one `set_window` call.
pub struct SetWindowBytes {
    pub caset: [u8; 4],
    pub raset: [u8; 4],
}

/// Pure-logic byte builder for `set_window` — host-testable.
///
/// Moved verbatim from `hw/lcd_nv3007.rs`; no arithmetic changed.
pub fn build_set_window_bytes(x0: u16, y0: u16, x1: u16, y1: u16) -> SetWindowBytes {
    let x0 = x0 + X_OFFSET;
    let x1 = x1 + X_OFFSET;
    let y0 = y0 + Y_OFFSET;
    let y1 = y1 + Y_OFFSET;
    SetWindowBytes {
        caset: [(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8],
        raset: [(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8],
    }
}
