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
//! The host compiler supports a constrained scalar-amount subset. It resolves
//! source placeholders to authenticated emitted field ordinals and emits a
//! max-three-reference token program. The field renderer first paints every
//! ordinary page and mints exact post-paint amount witnesses; only then may
//! [`repaint_intent_banner`] replace the static title. Derived output must fit
//! both rows completely — it never receives the static intent's `~` clipping.

use super::super::primitives::write_line;
use crate::ir::{Erc7730Ir, FormatHeader};

use super::formatters::write_line_bytes;
use super::{Page, Pages};
use crate::render::RenderErr;

/// Number of pages [`render_intent_banner`] writes. Always allocates
/// at least the intent page; the `erc7730-dev-unattested` Cargo
/// feature adds a preceding "DEV UNATTESTED" warning page.
#[cfg(feature = "erc7730-dev-unattested")]
pub const INTENT_BANNER_PAGES: usize = 2;
#[cfg(not(feature = "erc7730-dev-unattested"))]
pub const INTENT_BANNER_PAGES: usize = 1;

/// Write the intent banner. Allocates one intent page and, in an explicitly
/// acknowledged dev-unattested build, one preceding warning page.
///
/// Under the `erc7730-dev-unattested` Cargo feature, allocates an
/// EXTRA preceding page with a "DEV UNATTESTED" warning row so a dev
/// confirming on a bring-up build cannot mistake the current catalogue for
/// ERC-8176-verified provenance. No ERC-8176 verifier exists yet; production
/// rejects the dev root. The secure crate's generated provenance fences make
/// this feature mandatory for non-test dev firmware and reject it when a
/// future verified root is selected.
pub(super) fn render_intent_banner(
    pages: &mut Pages,
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    derived_intent: Option<&[u8]>,
) -> Result<usize, RenderErr> {
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let warn = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
        write_line(pages.row_mut(warn, 0), "** DEV BUILD **");
        write_line(pages.row_mut(warn, 1), "Unattested");
        write_line(pages.row_mut(warn, 2), "descriptor");
        write_line(pages.row_mut(warn, 3), "> next");
    }

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    pages.buf[p] = build_intent_page(ir, format, derived_intent);
    Ok(p)
}

/// Replace the already-reserved intent page after all referenced scalar fields
/// rendered and produced exact witnesses. The optional dev warning remains at
/// page zero; page count and visible ordering are unchanged.
pub(super) fn repaint_intent_banner(
    pages: &mut Pages,
    intent_page: usize,
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    derived_intent: &[u8],
) -> Result<(), RenderErr> {
    if derived_intent.is_empty() || derived_intent.len() > 32 {
        return Err(RenderErr::Reject("7730 bad derived intent length"));
    }
    if pages.as_slice().len() <= intent_page {
        return Err(RenderErr::Reject("7730 missing intent page"));
    }
    pages.buf[intent_page] = build_intent_page(ir, format, Some(derived_intent));
    Ok(())
}

pub(super) fn build_intent_page(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    derived_intent: Option<&[u8]>,
) -> Page {
    // The intent is the descriptor author's single most important string (the
    // flow title). The confirm page + the field pages already establish this is
    // a signing flow, so we DROP the old "Sign: " prefix — which left only 10
    // chars and chopped "Withdraw Collateral from Morpho Market" to
    // "Sign: Withdraw C" — and give the intent up to TWO rows (32 chars).
    //
    // Layout (intent is ASCII-clean, ≤ 254 B by the host pipeline):
    //   short intent (≤ 16): row0 = intent, row1 = owner, row2 = contract name;
    //   long intent  (> 16): rows 0-1 = intent (32 chars, a visible `~` in the
    //                        last cell when it runs past 32), row2 = contract
    //                        name (owner drops — the intent earns the space).
    //   row3 = "> next" nav hint (unchanged, for cross-page consistency).
    const W: usize = 16;
    // A derived intent may summarize already authenticated signed bytes, but
    // never replaces the field pages below. The only current caller override
    // is exact-zero ERC-20 approval after strict canonical decode plus a
    // chain+contract-bound metadata capability.
    let intent = derived_intent.unwrap_or(format.intent);

    let mut page = [[b' '; W]; 4];
    let r0_take = intent.len().min(W);
    page[0][..r0_take].copy_from_slice(&intent[..r0_take]);

    // `>= W`, not `> W`. At EXACTLY W the two layouts are indistinguishable to
    // anything reading the finished page: row 0 is full either way, so a
    // consumer cannot tell "the intent continues on row 1" from "row 1 is the
    // owner". `erc7730_screens::intent_text` joins rows 0+1 whenever row 0 is
    // full, which turned the 16-character `Set Account Name` plus owner `Celo`
    // into the caption `SIGN SET ACCOUNT NAMECELO?`.
    //
    // Treating "fills row 0 exactly" as the continuation case makes the layout
    // a function of the SAME predicate the consumer applies. Row 1 is then
    // simply empty, and a 16-character intent drops the owner line — the same
    // trade the `> W` branch already makes ("the intent earns the space").
    if intent.len() >= W {
        let end = intent.len().min(2 * W);
        let take = end - W;
        page[1][..take].copy_from_slice(&intent[W..end]);
        // Meaning-bearing truncation marker: the intent runs past what two rows
        // can show, so replace the last cell with `~` (never silently clip).
        if intent.len() > 2 * W {
            page[1][W - 1] = b'~';
        }
        write_line_bytes(&mut page[2], ir.contract_name);
    } else {
        write_line_bytes(&mut page[1], ir.owner);
        write_line_bytes(&mut page[2], ir.contract_name);
    }
    write_line(&mut page[3], "> next");
    page
}

/// Exact full-page comparison used for the post-publication receipt and again
/// at the secure confirmation boundary. Accumulating all differences avoids a
/// data-dependent early exit and guarantees every visible cell participates.
pub(super) fn page_exact(actual: &Page, expected: &Page) -> bool {
    let mut diff = 0u8;
    for row in 0..actual.len() {
        for col in 0..actual[row].len() {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}
