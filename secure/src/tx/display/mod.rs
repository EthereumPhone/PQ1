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
mod deployment;
// The CMD_SIGN_USEROP render dispatcher (`pick_sign_pages` + its priority
// ladder). Lives in its own file so the host WYSIWYS glue harness can
// `#[path]`-mount the REAL body (`display_under_test::dispatch`); the
// production gate stays here at the declaration site.
#[cfg(not(test))]
mod dispatch;
mod eip1271;
mod erc20_known;
mod erc20_unknown;
#[cfg(feature = "erc7730-forced-blind")]
pub(crate) mod forced_blind;
mod nonce_lane;
pub mod erc7730;
pub mod erc8213;
mod offchain_sync;
pub(super) mod primitives;
#[cfg(not(test))]
mod safe_display;
/// Pixel-UI screen emitter for the Safe flow (`ui-px`): the second painter
/// over `safe_display::classify`.
#[cfg(feature = "ui-px")]
mod safe_screens;
/// The legacy-pages → screens lift and its transcript proof (`ui-px`).
#[cfg(feature = "ui-px")]
pub mod px_lift;
/// Shared building blocks of the pixel-UI screen emitters (`ui-px`).
#[cfg(feature = "ui-px")]
mod screen_kit;
/// Pixel-UI emitters for the single-UserOp routes and the rotation consent
/// (`ui-px`, port step 2), each the second painter over its page painter.
#[cfg(feature = "ui-px")]
pub(crate) mod userop_screens;
#[cfg(feature = "ui-px")]
mod value_transfer_screens;
#[cfg(feature = "ui-px")]
mod erc20_screens;
#[cfg(feature = "ui-px")]
mod blind_sign_screens;
#[cfg(feature = "ui-px")]
mod slot_rotation_screens;
/// Pixel-UI emitters for the structured routes (`ui-px`, port step 3): the
/// CoW order body (direct and Safe-wrapped), the ERC-7730 page lift, the
/// off-chain (EIP-1271) bodies and the batch framing.
#[cfg(feature = "ui-px")]
mod cowswap_screens;
#[cfg(feature = "ui-px")]
pub(crate) mod erc7730_screens;
#[cfg(feature = "ui-px")]
pub(crate) mod offchain_screens;
#[cfg(feature = "ui-px")]
pub(crate) mod batch_screens;
// The native pixel-UI twins of the handler-owned trailer pages. Always
// compiled (pure, host-testable; dead-stripped without a `ui-px` caller) so
// the sign handler's `TrailerFacts` exists on every configuration.
#[cfg(not(test))]
mod trailer_screens;
#[cfg(not(test))]
pub(crate) use trailer_screens::{TrailerFacts, TrailerSet};
#[cfg(all(not(test), feature = "ui-px"))]
pub(crate) use trailer_screens::expected_trailer_count;
#[cfg(feature = "ui-px")]
pub(crate) use dispatch::safe_route_meta;
#[cfg(not(test))]
mod safe_mgmt;
mod slot_rotation;
mod typed_call;
mod userop_gas_lane;
mod value_page;
// `pub(crate)` so the render-only golden harness (`ui::golden`) can drive the
// renderer directly; private otherwise.
pub(crate) mod value_transfer;
mod wallet_address;

pub(crate) use value_page::{
    enforce_from_page, enforce_paymaster_page, enforce_target_page, from_page_matches,
    from_page_proof, paymaster_final_set_proof, paymaster_page_proof, target_page_matches,
    target_page_proof, PAYMASTER_PAGE_CFI_EXPECTED, SIGNER_IDENTITY_PAGES,
    SIGNER_PAGE_CFI_EXPECTED, TARGET_IDENTITY_PAGES, TARGET_PAGE_CFI_EXPECTED,
};
pub(crate) use nonce_lane::{
    enforce_nonce_lane_page, nonce_lane_page_proof, NONCE_LANE_CFI_EXPECTED,
    NONZERO_NONCE_LANE_PAGES,
};
pub(crate) use deployment::{
    deployment_final_set_proof, deployment_output_binding_proof, deployment_page_proof,
    enforce_deployment_page, DeploymentConfirmContext, DeploymentConfirmReceipt,
    DEPLOYMENT_MODE_PAGES, DEPLOYMENT_PAGE_CFI_EXPECTED,
};
pub(crate) use userop_gas_lane::{
    enforce_userop_gas_page, userop_gas_final_set_proof, userop_gas_page_proof,
    USEROP_GAS_CFI_EXPECTED, USEROP_GAS_PAGES,
};
pub use blind_sign::render_blind_sign_pages;
pub use eip1271::{render_eip1271_personal_sign_pages, render_eip1271_raw32_pages};
pub(crate) use eip1271::{
    append_eip1271_context_pages, eip1271_context_final_set_proof,
    eip1271_context_page_proof, OffchainConfirmContext, OffchainConfirmReceipt,
    OFFCHAIN_CONTEXT_CFI_EXPECTED, OFFCHAIN_CONTEXT_PAGES,
};
pub use erc20_known::render_erc20_known_pages;
pub use erc20_unknown::render_erc20_unknown_pages;
#[cfg(not(test))]
pub use safe_display::{
    multisend_sign_gate, render_safe_exec_pages, render_safe_v1_pages, MultisendGate,
};
pub use offchain_sync::build_offchain_sync_pages;
pub use slot_rotation::build_slot_rotation_pages;
pub use value_transfer::render_pages;
pub use wallet_address::build_wallet_address_page;

// `Page`/`DISPLAY_COLS`/`DISPLAY_ROWS` are no longer referenced here — `Pages`
// (which used them) now lives in `pqsigner_erc7730::display`. The confirm loop
// still gets `Page` from `crate::ui::confirm`.

// `Pages`/`MAX_PAGES` moved to `pqsigner_erc7730::display` so the ERC-7730
// render dispatch can be host-linked and fuzzed (see
// `docs/erc7730-renderer-fuzzability.md` and
// `fuzz/fuzz_targets/erc7730_render_dispatch.rs`). Re-exported here so the
// ~415 direct `.buf`/`.len` accessors and the
// `Pages::{as_slice,empty_with_len,row_mut,page_mut,with_len,push_blank}`
// call sites across this display tree resolve unchanged.
//
// MAX_PAGES = 31. It must cover the longest `render_*_pages` output plus the
// mandatory full outer-signer account/address and target-contract pages and
// the conditional full 192-bit EntryPoint nonce-lane page. The worst realistic
// flow is the Safe-UI approve+presign multiSend (AddrHex legs + 3 refund pages
// + record values + batch banner + gas + ERC-8213 fingerprints + a non-zero
// `safeTxGas` page). `multisend_sign_gate` counts pages against this cap so the
// budget fails closed (refuse, never truncate).
// Grow it deliberately (4×16 = 64 stack bytes/page, ×2 transiently during the
// batch-banner wrap) — the per-flow accounting lives in git history and the
// bump rationale in the host `MAX_PAGES` doc.
pub use pqsigner_erc7730::display::{Pages, MAX_PAGES};

// `pick_sign_pages` (the CMD_SIGN_USEROP priority-ladder dispatcher) moved
// verbatim to `dispatch.rs` (2026-07-06) so the host WYSIWYS glue harness
// can `#[path]`-mount the real body — see `display_under_test::dispatch`
// and `display_under_test/wysiwys_dispatch_differential_tests.rs`.
#[cfg(not(test))]
pub(crate) use dispatch::{legacy_fee_pages_required, DispatchPageProofs};
#[cfg(not(test))]
pub use dispatch::{pick_sign_pages, pick_sign_pages_with_erc7730_evidence};
