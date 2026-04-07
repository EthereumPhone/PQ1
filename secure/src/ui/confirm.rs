//! Multi-page transaction confirmation dialog.
//!
//! The pages are pre-rendered by `tx::display::render_pages` from a parsed
//! `Eip1559Tx`. This module just handles the navigation:
//!
//!   * tap right    → next page
//!   * tap left     → previous page
//!   * long right   → confirm
//!   * long left    → cancel

use super::{display, input, Button, Press, DISPLAY_COLS, DISPLAY_ROWS};
use crate::timeout;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ConfirmResult {
    Confirmed,
    Cancelled,
    IdleWipe,
}

/// A single page of the confirm dialog: 4 lines, 16 cols each.
pub type Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

pub fn confirm(pages: &[Page]) -> ConfirmResult {
    if pages.is_empty() {
        return ConfirmResult::Cancelled;
    }

    // ---- e2e-test fast-path ----
    //
    // Render every page (so the test harness can scrape the framebox
    // log lines if it wants to assert page content), then auto-confirm
    // without reading stdin. This is the only place the secure world
    // would block on user input during a sign request, so this single
    // bypass is enough to make every cmd_* path non-interactive.
    #[cfg(feature = "e2e-test")]
    {
        for (idx, page) in pages.iter().enumerate() {
            render_page(page, idx, pages.len());
        }
        return ConfirmResult::Confirmed;
    }

    #[cfg(not(feature = "e2e-test"))]
    {
        let mut idx: usize = 0;
        timeout::reset_activity();

        loop {
            render_page(&pages[idx], idx, pages.len());

            let mut idle = || timeout::is_idle();
            let event = match input().wait_button(&mut idle) {
                Some(ev) => ev,
                None => return ConfirmResult::IdleWipe,
            };

            timeout::reset_activity();

            match event {
                (Button::Right, Press::Short) => {
                    if idx + 1 < pages.len() {
                        idx += 1;
                    }
                }
                (Button::Left, Press::Short) => {
                    if idx > 0 {
                        idx -= 1;
                    }
                }
                (Button::Right, Press::Long) => return ConfirmResult::Confirmed,
                (Button::Left, Press::Long) => return ConfirmResult::Cancelled,
            }
        }
    }
}

fn render_page(page: &Page, idx: usize, total: usize) {
    let d = display();
    d.clear();
    for (row_idx, row) in page.iter().enumerate() {
        // SAFETY: pages are constructed from ASCII-only formatting.
        let s = unsafe { core::str::from_utf8_unchecked(row) };
        d.draw_line(row_idx, s);
    }
    // Footer indicator: "1/5" right-aligned isn't space — instead overlay on row 3.
    // We assume the page renderer leaves room or that we can append.
    // Simpler: log via secure_log.
    let _ = (idx, total);
    d.flush();
}
