//! Pure-logic pieces of the ERC-7730 renderer that do NOT depend on the
//! display layer (`Pages`, `crate::ui::*`).
//!
//! Lives outside `tx::display::` so that host-test builds (which gate
//! out `tx::display`) can still exercise the TLV parameter parser and
//! the visibility evaluator. The UI-bound formatters / nested-calldata
//! recursor remain under `tx::display::erc7730::`.
//!
//! Surface re-exported here is `pub(crate)` — no NS-facing API.

pub mod params;
pub mod visibility;

/// Why the ERC-7730 renderer refused to take responsibility for this
/// transaction.
///
/// The priority-ladder caller in [`crate::tx::display::pick_sign_pages`]
/// inspects the variant and either surfaces a status banner (`Reject`)
/// or silently falls through (`NoFormat` / `PageBudget`).
#[derive(Debug, PartialEq, Eq)]
pub enum RenderErr {
    /// Descriptor is structurally fine but disagrees with the inbound
    /// transaction in a way that the renderer cannot paper over: a
    /// `MustMatch` value failed, a TLV blob is malformed, the walker
    /// returned an error, the inbound calldata won't decode against
    /// the format's positional schema, etc. Caller surfaces the
    /// `&'static str` reason on a `ui::show_status` banner and falls
    /// through to the next ladder rung.
    Reject(&'static str),
    /// No matching format header for the inbound `(selector |
    /// primary-type-hash[..4])`. The renderer has nothing to draw —
    /// fall through silently.
    NoFormat,
    /// Output overflowed the 22-page `Pages` budget. Fall through
    /// silently and let blind-sign cover it.
    PageBudget,
}
