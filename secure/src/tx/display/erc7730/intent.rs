//! Intent banner — page 0 of every ERC-7730 render.
//!
//! Renders the verified `owner` / `contractName` (anti-spoof: ASCII-
//! clean, truncated to 15 chars by the host pipeline) plus the
//! format's intent string ("Sign", "Wrap", "Swap", "Approve", …) into
//! a single page. The first user-visible page must make it
//! unambiguous which descriptor is in play.
//!
//! ## interpolatedIntent
//!
//! Phase 4 v1 omits `{path}` substitution. The seed corpus's intent
//! strings are all static literals ("Send", "Wrap", "Swap on Uniswap",
//! …) so there is nothing to interpolate. When a descriptor that uses
//! interpolatedIntent lands in the registry, Phase 5 wires the path-
//! lookup-and-format substitution machinery; until then, the
//! formatter dispatch loop renders interpolation tokens verbatim
//! (e.g., "Send {amount} {token}" prints with the braces still in).
//! That's intentionally ugly so a user-facing review notices.

use crate::tx::display::primitives::write_line;
use crate::tx::erc7730::{Erc7730Ir, FormatHeader};

use super::formatters::write_line_bytes;
use super::Pages;
use crate::tx::erc7730_render::RenderErr;

/// Number of pages [`render_intent_banner`] writes. Always allocates
/// at least the intent page; the `erc7730-dev-unattested` Cargo
/// feature adds a preceding "DEV UNATTESTED" warning page.
#[cfg(feature = "erc7730-dev-unattested")]
pub const INTENT_BANNER_PAGES: usize = 2;
#[cfg(not(feature = "erc7730-dev-unattested"))]
pub const INTENT_BANNER_PAGES: usize = 1;

/// Write the intent banner page. Always allocates exactly one page.
///
/// Under the `erc7730-dev-unattested` Cargo feature, allocates an
/// EXTRA preceding page with a "DEV UNATTESTED" warning row so a dev
/// confirming on a bring-up build cannot miss that the host-side
/// attestation gate was relaxed. The feature is mutually exclusive
/// with `mode-production` (compile_error in `nsc/mod.rs`), so a
/// shipped build will never render this row.
pub(super) fn render_intent_banner(
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
) -> Result<(), RenderErr> {
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let warn = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_line(pages.row_mut(warn, 0), "** DEV BUILD **");
        write_line(pages.row_mut(warn, 1), "Unattested");
        write_line(pages.row_mut(warn, 2), "descriptor");
        write_line(pages.row_mut(warn, 3), "> next");
    }

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;

    // Row 0: "Sign: <intent>" (intent is ASCII-clean, ≤ 254 B by host
    // pipeline; we trim to 16 - "Sign: ".len() = 10 chars).
    let mut row0 = [b' '; 16];
    for (i, &b) in b"Sign: ".iter().enumerate() {
        row0[i] = b;
    }
    let intent_cap = row0.len() - 6;
    let intent_take = format.intent.len().min(intent_cap);
    row0[6..6 + intent_take].copy_from_slice(&format.intent[..intent_take]);
    *pages.row_mut(p, 0) = row0;

    // Row 1: owner.
    write_line_bytes(pages.row_mut(p, 1), ir.owner);
    // Row 2: contract name.
    write_line_bytes(pages.row_mut(p, 2), ir.contract_name);
    // Row 3: "> next" navigation hint.
    write_line(pages.row_mut(p, 3), "> next");

    Ok(())
}
