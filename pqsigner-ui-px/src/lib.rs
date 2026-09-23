//! Pixel trusted-UI substrate for the NV3007 panel (428 × 142 landscape).
//!
//! This crate is the pure-logic half of the `ui-px` feature in the secure
//! world. It owns:
//!
//! * [`screen`] — the `Screen` / `Screens` transcript: fixed-size,
//!   printable-ASCII records that the secure world builds from a verified
//!   transaction, proves byte-exactly, hashes for `ui-capture` and hands to a
//!   presenter. The record format mirrors the guarantees of
//!   `pqsigner_erc7730::display::Pages` (every byte `0x20..=0x7E`, so the
//!   `0xA5` transcript poison is unreachable), which is what lets the
//!   existing page-proof shapes (`at_matches` + exact-occurrence uniqueness)
//!   carry over unchanged.
//! * [`fit`] — the DESIGN.md "largest tier that fits" rule with baked
//!   advance widths, plus the address / hash / amount splitters. A value
//!   that does not fit is an error, never a truncation.
//!
//! Later phases add the fixed-point motion runtime, the two-button input
//! grammar, the flow driver and the strip rasteriser (see the plan in
//! `docs/ui-px/` once it lands).
//!
//! Design reference: `tools/pq-ui/pq1/DESIGN.md` (vendored, pinned in
//! `tools/pq-ui/UPSTREAM.txt`). `no_std`, no heap, no `unsafe`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// `Result<_, ()>` is the firmware-wide "refuse, reason is not data" idiom
// (`Pages::push_blank`, every `enforce_*`); the `Err` payload is deliberately
// empty so no attacker-influenced byte flows into the refusal path.
#![allow(clippy::result_unit_err, clippy::missing_errors_doc)]
// Fixed-point rasteriser / motion code narrows i64 intermediates and packs
// coverage into u8 on purpose; every such cast sits after an explicit clamp
// or a shift that bounds the range. Blanket-allowing the pedantic cast lints
// keeps the arithmetic readable.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::precedence,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod driver;
pub mod fit;
pub mod fixed;
pub mod font;
pub mod input;
#[allow(clippy::unreadable_literal, missing_docs)]
pub mod metrics_gen;
pub mod motion;
pub mod pq1a;
pub mod raster;
pub mod scene;
pub mod screen;

pub use screen::{
    exact_screen_occurrences, screen_at_matches, screen_exact, BuildErr, Icon, Kind, ResultMark,
    Screen, ScreenBuilder, Screens, Side, State, Tier, Weight, MAX_SCREENS, SCREENS_BYTES, SCREEN_BYTES,
};
