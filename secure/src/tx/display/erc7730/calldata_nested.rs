//! Nested-calldata recursion for the `Calldata` formatter (0x0A).
//!
//! When a top-level descriptor field is `format: calldata` (e.g., Safe
//! v1's `data` parameter on `execTransaction`), the bytes that field
//! points to are themselves an inner contract call. ERC-7730 v2 lets
//! the descriptor embed a `nestedSelector` + `nestedCallee` so the
//! renderer can fan out into a child decoding without the host having
//! to ship a second descriptor.
//!
//! Phase 4 v1 declines this and falls through to blind-sign for the
//! outer transaction. Reasons:
//!
//! 1. The seed corpus does NOT exercise nested calldata — only Safe v1
//!    uses it, and Safe rendering already lives in
//!    `tx::display::safe_display`. Pre-existing coverage.
//! 2. The renderer would need to re-extract the inner `body` (4-byte
//!    selector + ABI args), build a child `WalkerCtx`, re-enter the
//!    formatter dispatch loop, and budget pages for two banner+field
//!    levels. Capping at depth 4 (per plan) keeps stack usage bounded
//!    but the page-budget arithmetic gets non-trivial.
//! 3. The on-device IR does not currently bind a nested descriptor's
//!    selector to a second IR — `nestedSelector` only confirms the
//!    inner call's 4-byte prefix matches the outer descriptor's
//!    expectation. Full nested rendering wants a separate verified
//!    descriptor per nested level; that surface lands in Phase 5
//!    alongside the deep-types support.
//!
//! Step 3 wires this stub through the formatter dispatcher; Phase 5
//! replaces it with the recursive renderer.

use crate::tx::erc7730::FieldEntry;
use crate::tx::erc7730_render::params::ParamSet;
use crate::tx::erc7730_render::RenderErr;

use super::Pages;

pub(super) fn render(
    _field: &FieldEntry<'_>,
    _pages: &mut Pages,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    Err(RenderErr::Reject("7730 nested calldata p5"))
}
