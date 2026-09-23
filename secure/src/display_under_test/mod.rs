//! Test-only scaffold for the `secure-tx-display` slice.
//!
//! The production `tx::display` module is gated `#[cfg(not(test))]` (see
//! `secure/src/tx/mod.rs`) because the production `mod.rs` imports
//! `crate::ui::confirm::Page`, which lives behind a hardware-only path.
//! That gate keeps the entire per-renderer source tree out of the host
//! test build even though every individual renderer is pure logic.
//!
//! This scaffold:
//!
//!   * Re-declares `MAX_PAGES` and `Pages` byte-for-byte equivalent to
//!     the production definitions (see `tx/display/mod.rs`). If the
//!     production constants ever change, the [`pure_tests::
//!     positive_max_pages_matches_production`] regression test fires
//!     because it asserts the value verbatim against the source text.
//!
//!   * `#[path]`-mounts each per-renderer source file under this
//!     parallel tree. Each file's `super::primitives::*` /
//!     `super::Pages` paths then resolve to *this* scaffold's items,
//!     not the gated-out production ones, so the bodies compile and
//!     execute unchanged.
//!
//!   * Lives entirely under `#[cfg(test)]` in `main.rs`, so production
//!     builds are unaffected.
//!
//! `pick_sign_pages` (the dispatcher, now in `tx/display/dispatch.rs`)
//! IS mounted here since 2026-07-06. `cowswap_display` is test-mounted in
//! `eip712/mod.rs`. The WYSIWYS glue harness in
//! `wysiwys_dispatch_differential_tests.rs` drives the real dispatcher
//! body against the same request bytes the sign handler hashes.

// `Page`/`DISPLAY_COLS`/`DISPLAY_ROWS` are no longer used here — the mirrored
// `Pages` was replaced by a re-export of the host `pqsigner_erc7730::display`
// type, and the mounted renderers pull the constants from `crate::ui` directly.

// `Pages`/`MAX_PAGES` moved to the host crate (`pqsigner_erc7730::display`) so
// the ERC-7730 render dispatch is host-linked; re-export them here (instead of
// mirroring) so this scaffold, the still-mounted secure renderers, and the host
// render all share ONE `Pages` type. The `negative_max_pages_matches_production_
// constant` test pins the literal against the host source.
pub use pqsigner_erc7730::display::{Pages, MAX_PAGES};

/// **te-2 (Trezor-port) — canonical golden hash over a rendered `Pages`
/// grid.**
///
/// Hashes the page count then every *used* page's full row×col ASCII grid,
/// so ANY change to layout, spacing, truncation, divider placement, row
/// position, or page count changes the digest. This is the pixel-golden
/// gate's host-runnable complement for the security-critical decode-and-
/// render screens (Safe / CoW / ERC-7730): the per-substring faithfulness
/// assertions in these modules check that *specific* fields render, but a
/// full-grid golden also catches WYSIWYS regressions *elsewhere* on the
/// page (a shifted label, a dropped divider, a truncation the substring
/// check doesn't look at). The firmware `ui/golden.rs` gate covers the
/// LCD pixel-font layer for `value_transfer`; the Safe/CoW/ERC-7730 inputs
/// need host-only dbgen fixtures, so their golden gate lives here.
///
/// Intentional layout changes require re-blessing the `GOLDEN_*` constant
/// in the calling test — that explicit step is the point of a golden gate.
pub fn golden_grid_hash(pages: &Pages) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((pages.len as u32).to_be_bytes());
    for page in pages.as_slice() {
        for row in page {
            h.update(&row[..]);
        }
    }
    h.finalize().into()
}

// `primitives` was extracted to the host crate so it can be fuzzed directly;
// re-export it here (instead of `#[path]`-mounting the shim) so every mounted
// render file's `super::primitives::*` / `super::super::primitives::*` resolves
// to the same byte-writers the device build uses.
pub use pqsigner_erc7730::display::primitives;

#[path = "../tx/display/value_transfer.rs"]
pub mod value_transfer;

#[path = "../tx/display/blind_sign.rs"]
pub mod blind_sign;

#[path = "../tx/display/eip1271.rs"]
pub mod eip1271;

// Optional forced-blind raw transcript and its two request-bound receipts.
// Mount the exact production source so its 29-page golden, byte-flip, bounds,
// ordering, deadline and single-consumption tests run on the host even though
// production reachability remains feature-gated and no handler route exists.
#[path = "../tx/display/forced_blind.rs"]
pub mod forced_blind;

// UserOperation deployment/initCode consent page and receipt. Mount the real
// production source so its exact-page and fail-initialized receipt tests run
// in the host test binary.
#[path = "../tx/display/deployment.rs"]
pub mod deployment;

// Counter-sync is a trusted-display authorization surface: mount the real
// renderer so its current/target pixel-binding tests execute on the host.
#[path = "../tx/display/offchain_sync.rs"]
pub mod offchain_sync;

#[path = "../tx/display/erc20_known.rs"]
pub mod erc20_known;

#[path = "../tx/display/erc20_unknown.rs"]
pub mod erc20_unknown;

// The dispatcher-level native-value invariant (audit C-1 / H-2 / M-8).
// Mounted so its real body + regression tests run on the host even though
// the `pick_sign_pages` dispatcher that calls it is firmware-only.
#[path = "../tx/display/value_page.rs"]
pub mod value_page;

// Conditional exact display of EntryPoint v0.6's high-192 nonce key.
#[path = "../tx/display/nonce_lane.rs"]
pub mod nonce_lane;

// Unconditional exact display of the three signed UserOp gas limits (F10).
#[path = "../tx/display/userop_gas_lane.rs"]
pub mod userop_gas_lane;

#[path = "../tx/display/slot_rotation.rs"]
pub mod slot_rotation;

#[path = "../tx/display/batch.rs"]
pub mod batch;

#[path = "../tx/display/typed_call/mod.rs"]
pub mod typed_call;

// ERC-7730 / ERC-8213 renderers. Mounted alongside the other renderers
// so host tests in `erc7730_render_pure_tests.rs` can call the full
// `render_erc7730_pages` / `render_erc7730_eip712_pages` pipelines and
// assert the resulting OLED rows byte-for-byte against the strings a
// user would actually see on the device.
// The ERC-7730 render moved to the host crate; re-export it (instead of
// Mount the secure shim itself so its checked two-pass EIP-712 wrappers and
// transcript proof execute in host tests. Production reaches the same source
// through `tx::display::erc7730`.
#[path = "../tx/display/erc7730/mod.rs"]
pub mod erc7730_secure_shim;

// Re-export the host renderer and the test-mounted dispatcher's private
// contract-pass wrapper under the same sibling module shape production uses.
pub mod erc7730 {
    pub(super) use super::erc7730_secure_shim::{
        render_contract_pass_into, render_contract_proof_set_pass_into,
    };
    pub use pqsigner_erc7730::display::render::*;
}

#[path = "../tx/display/erc8213.rs"]
pub mod erc8213;

// `safe_display` IS re-mounted (2026-06-30). Its absolute `crate::tx::display::
// {Pages,primitives}` + `crate::tx::eip712::cowswap_display::*` paths now
// resolve via the `#[cfg(test)] pub(crate) use … as display` alias in
// `tx/mod.rs` and the test mount of `cowswap_display` in `eip712/mod.rs`.
// `#[allow(dead_code)]` because under the test build the binary crate's
// production callers (`pick_sign_pages`, the handlers) are gated out, so the
// public entry points would otherwise warn as unused. Render-faithfulness
// tests in `safe_display_render_pure_tests.rs`.
#[path = "../tx/display/safe_display.rs"]
#[allow(dead_code)]
pub mod safe_display;

// `safe_screens` — the pixel-UI painter over `safe_display::classify`. Host-
// mounted unconditionally (the firmware gates it behind `ui-px`) so the
// legacy-vs-screens fact differential and the per-scenario screen goldens run
// on every `cargo test`.
#[path = "../tx/display/safe_screens.rs"]
#[allow(dead_code)]
pub mod safe_screens;

#[path = "../tx/display/px_lift.rs"]
#[allow(dead_code)]
pub mod px_lift;

// The native trailer twins (`trailer_screens`) over the mounted page
// painters, so the lift's trailer proofs run against real trailer pages.
#[path = "../tx/display/trailer_screens.rs"]
#[allow(dead_code)]
pub mod trailer_screens;

// `safe_mgmt` IS re-mounted: it has no unused helpers in the host-test
// configuration, and its per-op renderers are pure-display logic that
// should be host-asserted against expected page rows.
#[path = "../tx/display/safe_mgmt.rs"]
pub mod safe_mgmt;

// The REAL `pick_sign_pages` dispatcher body (priority ladder + the
// dispatcher-level value/gas splice gates). Mounted so the WYSIWYS glue
// harness can bind "the pages the user confirms" to "the bytes the sign
// handler hashes" on the host. Inside `dispatch.rs` every sibling
// renderer is `super::`-qualified, so under this mount it calls exactly
// the renderer bodies mounted above.
#[path = "../tx/display/dispatch.rs"]
pub mod dispatch;

#[cfg(test)]
mod pure_tests;

#[cfg(test)]
mod erc7730_render_pure_tests;

#[cfg(all(test, feature = "erc7730-nested-calldata-test-fixture"))]
mod erc7730_nested_dispatch_pure_tests;

#[cfg(test)]
mod safe_mgmt_render_pure_tests;

#[cfg(test)]
mod cowswap_render_pure_tests;

#[cfg(test)]
mod safe_display_render_pure_tests;

#[cfg(test)]
mod safe_screens_render_pure_tests;

#[cfg(test)]
mod wysiwys_dispatch_differential_tests;
