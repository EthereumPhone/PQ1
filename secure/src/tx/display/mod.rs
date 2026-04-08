//! Render a parsed transaction into a fixed-size set of 4-line × 16-col
//! confirmation pages for the secure UI.
//!
//! ## Submodule layout
//!
//! Each renderer has its own file, keyed by the `TxKind` it covers.
//! Adding a new trust level / render flavour means creating a sibling
//! submodule, re-exporting its `render_*_pages` entry point from this
//! `mod.rs`, and teaching [`super::super::erc20::dispatch::TxKind`]
//! (or whichever dispatcher produces the new case) to return it. The
//! command handler in `nsc/cmd_sign.rs` then only needs one extra
//! `TxKind::* => render_*_pages(...)` match arm.
//!
//!   * [`value_transfer`]    — plain ETH transfer, no calldata
//!   * [`erc20_known`]       — decoded ERC20 call, token in the trusted DB
//!   * [`erc20_unknown`]     — decoded ERC20 call, token NOT in the DB
//!   * [`blind_sign`]        — non-empty calldata that doesn't decode
//!   * [`contract_creation`] — `tx.to.is_none()`
//!
//! [`primitives`] holds every row-level helper (hex formatting, gwei
//! formatting, `write_line`, …) so the renderers read as sequences of
//! declarative "fill row N with X" calls rather than bit-twiddling.

mod blind_sign;
mod contract_creation;
mod erc20_known;
mod erc20_unknown;
pub(super) mod primitives;
mod value_transfer;

pub use blind_sign::render_blind_sign_pages;
pub use contract_creation::render_contract_creation_pages;
pub use erc20_known::render_erc20_known_pages;
pub use erc20_unknown::render_erc20_unknown_pages;
pub use value_transfer::render_pages;

use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Maximum number of confirmation pages any renderer can produce.
///
/// Must be at least as large as the longest `render_*_pages` output:
///
///   * plain value transfer                 → 5 pages
///   * erc20_known / erc20_unknown          → 7 pages
///   * blind_sign                           → 7 pages
///   * contract_creation                    → 6 pages
///   * cowswap EIP-712 render (see
///     `crate::tx::eip712::cowswap_display`) → 10 pages
///
/// Bumping this costs `MAX_PAGES × 4 × 16 = 64` extra stack bytes per
/// page, so grow it deliberately and not speculatively.
pub const MAX_PAGES: usize = 10;

/// A buffer of up to [`MAX_PAGES`] pre-rendered confirmation pages.
///
/// Owned-by-value: every renderer returns a fresh `Pages` on the stack
/// and the caller hands `pages.as_slice()` to
/// [`crate::ui::confirm::confirm`] for the navigation loop. The buffer
/// is always allocated for the full [`MAX_PAGES`] so that only `len`
/// changes between renderers — callers must never index past `len`.
pub struct Pages {
    /// The full `MAX_PAGES`-sized page buffer. Visible only to sibling
    /// submodules under `display::` so the per-`TxKind` renderers can
    /// write directly into their own slots without going through
    /// `row_mut`/`page_mut` for every line — external callers must use
    /// [`Pages::as_slice`] instead.
    pub(super) buf: [Page; MAX_PAGES],
    pub(super) len: usize,
}

impl Pages {
    /// View the visible pages (indices `0..len`) as a slice. This is
    /// what `confirm()` consumes.
    pub fn as_slice(&self) -> &[Page] {
        &self.buf[..self.len]
    }

    /// Internal helper: zero-length `Pages` backed by a
    /// space-initialised buffer. Not exported because external
    /// consumers should not produce empty renderers.
    #[allow(dead_code)]
    fn empty() -> Self {
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len: 0,
        }
    }

    /// Construct a page bundle with exactly `len` visible pages,
    /// pre-filled with ASCII space. Used both internally by the
    /// EIP-1559 renderers in this directory and externally by the
    /// CowSwap EIP-712 renderer in
    /// `crate::tx::eip712::cowswap_display`.
    pub fn empty_with_len(len: usize) -> Self {
        assert!(len <= MAX_PAGES, "Pages::empty_with_len: len > MAX_PAGES");
        Pages {
            buf: [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; MAX_PAGES],
            len,
        }
    }

    /// Mutable access to a single row within a single page. Bounds-
    /// checked; panics on out-of-range indices (which would indicate
    /// a firmware bug since both come from compile-time constants).
    pub fn row_mut(&mut self, page: usize, row: usize) -> &mut [u8; DISPLAY_COLS] {
        assert!(page < self.len);
        assert!(row < DISPLAY_ROWS);
        &mut self.buf[page][row]
    }

    /// Mutable access to the full row array of one page. Used by
    /// renderers that need to mutate two rows of the same page
    /// simultaneously (via `split_at_mut`), which the row-at-a-time
    /// `row_mut` helper above can't express without tripping the
    /// borrow checker.
    pub fn page_mut(&mut self, page: usize) -> &mut [[u8; DISPLAY_COLS]; DISPLAY_ROWS] {
        assert!(page < self.len);
        &mut self.buf[page]
    }

    /// Renderer-local shortcut for `empty_with_len`. Kept private so
    /// the sibling submodules can `use super::Pages;` and call
    /// `Pages::with_len(...)`.
    pub(super) fn with_len(len: usize) -> Self {
        Self::empty_with_len(len)
    }
}
