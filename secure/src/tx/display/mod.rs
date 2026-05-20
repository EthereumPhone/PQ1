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
//!
//! [`primitives`] holds every row-level helper (hex formatting, gwei
//! formatting, `write_line`, …) so the renderers read as sequences of
//! declarative "fill row N with X" calls rather than bit-twiddling.

#[cfg(not(test))]
pub mod batch;
mod blind_sign;
mod eip1271;
mod erc20_known;
mod erc20_unknown;
pub mod erc7730;
pub mod erc8213;
pub(super) mod primitives;
#[cfg(not(test))]
mod safe_display;
mod slot_rotation;
mod typed_call;
mod value_transfer;

pub use blind_sign::render_blind_sign_pages;
pub use eip1271::{render_eip1271_personal_sign_pages, render_eip1271_raw32_pages};
pub use erc20_known::render_erc20_known_pages;
pub use erc20_unknown::render_erc20_unknown_pages;
#[cfg(not(test))]
pub use safe_display::render_safe_v1_pages;
pub use slot_rotation::build_slot_rotation_pages;
pub use value_transfer::render_pages;

use crate::ui::confirm::Page;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// Maximum number of confirmation pages any renderer can produce.
///
/// Must be at least as large as the longest `render_*_pages` output:
///
///   * plain value transfer                 → 6 pages
///   * erc20_known / erc20_unknown          → 8 pages
///   * blind_sign (no selector bundle)      → 9 pages
///   * blind_sign (with verified FUNCTION)  → 10 pages
///   * contract_creation                    → 8 pages
///   * cowswap EIP-712 render (see
///     `crate::tx::eip712::cowswap_display`) → 10 pages
///   * typed_call (Phase 2 calldata decode) → up to 14 pages
///     (banner + up to 6 typed args + To + Value + Chain + 2 fee
///     pages + Nonce; declines past `MAX_TYPED_ARGS_RENDERED = 6`)
///   * batch sign per-tx wrapper (see
///     `crate::tx::display::batch::wrap_pages_with_batch_banner`) →
///     same as the wrapped renderer + 1 banner page = up to 15
///   * EIP-1271 PersonalSign render →
///     5 fixed pages (banner / chain / account+slot / signer addr /
///     final confirm) + `ceil(MAX_OFFCHAIN_PERSONAL_SIGN_LEN / 48)`
///     message pages = up to 5 + ceil(700 / 48) = 5 + 15 = 20.
///
/// Bumping this costs `4 × 16 = 64` extra stack bytes per page, so
/// grow it deliberately and not speculatively.
pub const MAX_PAGES: usize = 22;

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

    /// Bump `len` by one and return the index of the newly-visible page.
    /// Returns `Err(())` when the buffer is already full; renderers map
    /// that to `RenderErr::PageBudget` and fall through to a less rich
    /// rendering ladder rung. The returned page is pre-cleared to ASCII
    /// space (matches every other allocation path).
    pub(super) fn push_blank(&mut self) -> Result<usize, ()> {
        if self.len >= MAX_PAGES {
            return Err(());
        }
        // The full MAX_PAGES buffer was zero-cleared at construction;
        // older renderers that overran past `len` via `Pages::empty()`
        // and then bumped it leave stale bytes behind. Re-clear the slot
        // here so dynamic-push renderers don't inherit prior content.
        self.buf[self.len] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
        let idx = self.len;
        self.len += 1;
        Ok(idx)
    }
}

/// Pick the right renderer for a CMD_SIGN_USEROP trusted-UI confirm.
///
/// Centralises the priority ladder — the handler stays a pure
/// orchestrator and the "which display wins when multiple trailers
/// verify" decision lives in one place:
///
///   1. v3 CoW EIP-712 (full 8-page GPv2Order breakdown from the
///      circuit-bound canonical + readable).
///   2. v1 ZK clear-sign (circuit-attested readable string + EIP-1559
///      summary pages).
///   3. Safe v1 inner-tx render (verified canonical SafeTx).
///   4. ERC-7730 descriptor (verified against the firmware-pinned
///      `ERC7730_DESCRIPTORS_ROOT`; binding cross-checked against
///      `(chain_id, to)`).
///   5. Plain value transfer (empty inner calldata).
///   6. ERC-20 with verified metadata (token name/symbol/decimals).
///   7. ERC-20 shape-only (unverified token — bare hex decode).
///   8. Typed-call selector + verified ABI walk.
///   9. Blind-sign (calldata that doesn't decode as ERC-20 / typed).
///
/// Ordering is load-bearing. In particular (1) beats (2) so a CoW
/// setPreSignature UserOp that also happens to satisfy the v1 circuit
/// renders the 8-page order, not the weaker "Pre-sign CowSwap order"
/// string. The handler's downgrade-mitigation gate enforces this
/// separately at refuse-to-sign level. (3) is above (4) so a Safe
/// `execTransaction` carrying an ERC-7730 descriptor for an inner
/// call still renders the outer Safe banner first — the descriptor
/// would be for the inner call, which the Safe renderer dispatches
/// through its own inner-tx ladder.
#[cfg(not(test))]
pub fn pick_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    v1: Option<&crate::zk::VerifiedClearSignV1>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
) -> Pages {
    if let Some(v3) = v3 {
        return match &v3.readable {
            Some(readable) => {
                crate::tx::eip712::cowswap_display::render_cowswap_pages(
                    &v3.canonical,
                    readable,
                )
            }
            None => crate::tx::eip712::cowswap_display::render_cowswap_pages_addr(
                &v3.canonical,
            ),
        };
    }
    if let Some(v1) = v1 {
        return crate::zk::render_clear_sign_pages(tx, &v1.readable, resolver);
    }
    if let Some(safe) = safe_v1 {
        // For Safe inner-tx ERC-20 rendering, only apply the outer
        // ERC-20 metadata bundle when its contract address matches the
        // inner-tx target — a Safe call carrying USDC metadata is
        // useful only if the inner `to` is in fact USDC.
        let inner_meta: Option<&crate::erc20::bundle::Erc20Metadata<'_>> = erc20.and_then(|m| {
            // Decode inner `to` from the canonical (offset 28..48 per
            // SAFE_OFF_TO). We can compare directly against m.contract.
            let inner_to: [u8; 20] = {
                let mut t = [0u8; 20];
                t.copy_from_slice(
                    &safe.canonical[sphincs_tz_shared::SAFE_OFF_TO
                        ..sphincs_tz_shared::SAFE_OFF_TO + 20],
                );
                t
            };
            if m.contract == inner_to { Some(m) } else { None }
        });
        return render_safe_v1_pages(safe, inner_meta, resolver);
    }
    if let Some(d) = erc7730 {
        match erc7730::render_erc7730_pages(tx, inner_data, d, erc20, resolver) {
            Ok(pages) => return pages,
            Err(crate::tx::erc7730_render::RenderErr::Reject(msg)) => {
                crate::ui::show_status("Sign", msg);
                // Fall through to the next ladder rung so the user
                // still sees the transaction in a less-rich form
                // (typed-call selector / blind-sign / ERC-20). The
                // banner above gives them the reason.
            }
            Err(_) => {
                // NoFormat / PageBudget — fall through silently.
            }
        }
    }
    if inner_data.is_empty() {
        return render_pages(tx, resolver);
    }
    match crate::erc20::calldata::parse_erc20_calldata(inner_data) {
        Some(call) => match erc20 {
            Some(meta) => render_erc20_known_pages(tx, &call, meta, resolver),
            None => render_erc20_unknown_pages(tx, &call, resolver),
        },
        // The verified selector → text-sig mapping (if any) is only
        // consulted when nothing else has decoded the calldata. Phase 2
        // first tries to ABI-decode the calldata against the verified
        // type list; on any parse / shape failure (or any type the
        // first cut declines) we fall through to the Phase 1 BLIND
        // SIGN flow, which itself surfaces the FUNCTION page above
        // the warning header.
        None => {
            if let Some(meta) = selector {
                if let Some(pages) =
                    typed_call::try_render_typed_call(tx, inner_data, meta, resolver)
                {
                    return pages;
                }
            }
            render_blind_sign_pages(tx, inner_data, selector, resolver)
        }
    }
}
