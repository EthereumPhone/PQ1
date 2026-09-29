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
use super::super::INTENT_EXTENT_MASK;
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
        pages.mark_nav(warn, 3);
    }

    let p = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    let (page, extent) = build_intent_page(ir, format, derived_intent);
    pages.buf[p] = page;
    // `build_intent_page` returns a bare `Page`, so both declarations it owes
    // the consumer are made where the page joins `pages`: the chrome it wrote
    // to row 3, and how far its intent text runs.
    pages.mark_nav(p, 3);
    extent.declare(pages, p);
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
    let (page, extent) = build_intent_page(ir, format, Some(derived_intent));
    pages.buf[intent_page] = page;
    pages.mark_nav(intent_page, 3);
    // A repaint replaces the title, so it can change the extent — an
    // interpolated intent is a different length from the static one. Re-declare
    // rather than inherit: `push_blank` cleared the byte for the FIRST paint,
    // and nothing clears it again here.
    pages.nav[intent_page] &= !INTENT_EXTENT_MASK;
    extent.declare(pages, intent_page);
    Ok(())
}

/// How far the intent text runs on the page `build_intent_page` just built.
/// Returned rather than re-derived, so the declaration and the layout come
/// from the same branch and cannot drift apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum IntentExtent {
    /// Row 0 holds the whole intent; row 1 holds the owner.
    CompleteOnRow0,
    /// Rows 0 and 1 are one unbroken string; the owner was dropped for space.
    ContinuesOnRow1,
}

impl IntentExtent {
    /// How many rows the intent text occupies, matching
    /// [`Pages::intent_rows`].
    pub(super) fn rows(self) -> usize {
        match self {
            IntentExtent::CompleteOnRow0 => 1,
            IntentExtent::ContinuesOnRow1 => 2,
        }
    }

    /// Record this extent for `page` on the transcript it was just written to.
    pub(super) fn declare(self, pages: &mut Pages, page: usize) {
        match self {
            IntentExtent::CompleteOnRow0 => pages.mark_intent_complete(page),
            IntentExtent::ContinuesOnRow1 => pages.mark_intent_continues(page),
        }
    }
}

pub(super) fn build_intent_page(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
    derived_intent: Option<&[u8]>,
) -> (Page, IntentExtent) {
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

    // `> W`. At EXACTLY W the two layouts ARE indistinguishable from the
    // finished page alone — row 0 is full either way — but the fix for that is
    // NOT to bend the layout until the consumer's guess happens to be right.
    //
    // It was, briefly (95d7831a used `>= W`), and that silently DELETED the
    // owner line from a 16-character-intent page. The owner is anti-spoof
    // material: it is how the user tells LidoDAO's descriptor from a lookalike.
    // `dbgen`'s upstream conformance test pinned exactly that transcript and
    // went red ("Claim Withdrawal" is 16 characters), which is how the loss was
    // caught. The legacy 16x4 page is a shipping surface in its own right under
    // `ui-lcd`; degrading it to simplify a pixel-adapter inference was the
    // wrong trade.
    //
    // The ambiguity is resolved where it belongs: the renderer DECLARES how far
    // the intent runs (`mark_intent_complete` / `mark_intent_continues`) and no
    // consumer infers it from the bytes. See [`Pages::intent_rows`].
    let extent = if intent.len() > W {
        IntentExtent::ContinuesOnRow1
    } else {
        IntentExtent::CompleteOnRow0
    };

    if intent.len() > W {
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
    (page, extent)
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
