//! Pixel trusted UI (`ui-px`): the screen-transcript confirmation loop and
//! its presenters.
//!
//! The semantic transcript (`pqsigner_ui_px::Screens`) is built and proven
//! by the sign handler (`nsc::px_confirm_safe` → `tx::display::px_lift`).
//! This module owns what happens next: navigation per DESIGN.md § Input
//! (`pqsigner_ui_px::driver::FlowDriver`), the FI-hardened consent gate, the
//! inactivity / deadline checks, and the presentation of each `(screen,
//! page)` — through the text presenter here (QEMU semihosting, `ui-capture`
//! fingerprints, and a 16×4 fallback on the legacy display) or, once the
//! rasteriser lands, the NV3007 pixel presenter.

pub mod confirm_px;
pub mod screens;
pub mod status_map;
pub mod text;
#[cfg(feature = "ui-lcd")]
pub mod assets;
#[cfg(feature = "ui-lcd")]
pub mod lcd;

pub use confirm_px::{confirm_screens_checked, PX_COMMIT_REQUIRES_SEEN_LAST};

/// The verified atlas a dialog paints with. On the NV3007 it is the view
/// `assets::verify_atlas` returned for THIS dialog; the text presenters
/// (QEMU, `ui-capture`) have no atlas and take a unit placeholder, so the
/// call shape is the same on every backend.
#[cfg(feature = "ui-lcd")]
pub type AtlasArg<'a> = &'a assets::AtlasRef;
#[cfg(not(feature = "ui-lcd"))]
pub type AtlasArg<'a> = &'a ();

/// Outcome of a pixel-UI confirm loop. The FI gate returned alongside it is
/// `OK_SENTINEL` only for `Signed`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PxOutcome {
    Signed,
    Declined,
    Cancelled,
    IdleWipe,
    DeadlineExpired,
}
