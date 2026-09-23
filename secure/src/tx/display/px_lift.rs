//! The lift from the proven legacy page transcript to the pixel-UI screen
//! transcript, and the proof that binds the two.
//!
//! Three bodies share it ([`Body`]): the Safe flow (the pilot), every
//! single-UserOp route (`userop_screens`: value / contract call, ERC-20,
//! typed call, blind sign) and the slot-rotation consent. What follows
//! describes the Safe body; the others differ only in how the body is bound
//! (see [`structure_ok`]): a single-UserOp body re-runs its page painter and
//! must equal the proven body pages byte-for-byte (its `Nonce` footer page is
//! a `DETAILS` screen, not dropped), the rotation body is the one rotation
//! page.
//!
//! Under `ui-px` the Safe sign handler still builds and proves the legacy
//! `Pages` exactly as before (dispatcher, native-value / fee splice, the
//! paymaster / signer / target / nonce-lane / gas-lane / ERC-8213 / deployment
//! trailers, every `*_proof`). This module then assembles what the user
//! actually sees, with no `Legacy` (page-wrapped) record anywhere:
//!
//! ```text
//!   [0]                hero ask                        (safe_screens)
//!   [1 .. body)        Safe body details               (safe_screens)
//!   [body .. +tail)    the trailer screens, one per legacy trailer page,
//!                      each derived from the SAME page builder as the
//!                      proven page                      (trailer_screens)
//!   [last]             the returning hero (== screen 0)
//!   + `Confirm?` inserted at index 5 when the flow has ≥ 7 details
//! ```
//!
//! The legacy Safe body's own trailing confirm-footer page is the one page
//! with no screen: the design replaces it with the returning ask and the
//! auto-inserted `Confirm?`.
//!
//! [`transcript_proof`] recomputes every structural expectation from the
//! proven pages, the facts and the emitter receipts and folds them into one
//! FI sentinel: the two classifications agreed on the Safe body length, the
//! trailer tail has exactly as many screens as the handler appended pages
//! and every one of them re-derives from the facts at its index
//! (`trailer_screens::trailer_set_proof`), the returning hero is byte-equal
//! to the opening one, the `Confirm?` is where the rule puts it, no record is
//! `Legacy`, and every record is well-formed printable ASCII. A double emit
//! of body + trailers with a SHA-256 receipt between (the shape of the
//! ERC-7730 transcript proof) defends the emitters themselves against a
//! single skipped or faulted write.

use super::safe_screens::{emit_safe_exec, emit_safe_v1};
use super::screen_kit::BodyReceipt;
use super::trailer_screens::{self, TrailerFacts, TrailerReceipt};
use super::userop_screens::{self, Family, UserOpInputs};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::safe::{VerifiedSafeExec, VerifiedSafeV1};
use pqsigner_ui_px::{exact_screen_occurrences, screen_exact, Kind, Screens};
use subtle::ConstantTimeEq;

/// The legacy Safe body ends with this confirm-footer page; it is the page
/// the lift drops in favour of the returning hero.
const LEGACY_CONFIRM_FOOTER_ROW0: &[u8] = b"Long-press to";

/// The route body a dialog opens with.
pub(crate) enum Body<'a> {
    /// The verified Safe inputs the page painters classified.
    Safe {
        safe_v1: Option<&'a VerifiedSafeV1<'a>>,
        safe_exec: Option<&'a VerifiedSafeExec<'a>>,
        cow: Option<&'a VerifiedCowswapV3>,
        erc20: Option<&'a Erc20Metadata<'a>>,
        resolver: &'a NameResolver<'a>,
    },
    /// A single-UserOp route below the Safe / CoW / ERC-7730 rungs.
    UserOp(UserOpInputs<'a>),
    /// The slot-rotation consent.
    Rotation { chain_id: u64, slot_index: u32 },
}

/// Everything the content emitters consume: the route body's verified
/// inputs and the trailer facts the handler proved.
pub(crate) struct ContentInputs<'a> {
    pub(crate) body: Body<'a>,
    pub(crate) trailers: &'a TrailerFacts<'a>,
}

/// What one content emit produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContentReceipt {
    pub(crate) body: BodyReceipt,
    pub(crate) trailers: TrailerReceipt,
    /// The disc and ending captions the body chose (trailers, `Confirm?` and
    /// the endings wear it).
    pub(crate) family: Family,
}

/// SHA-256 over the visible transcript (length-prefixed).
#[must_use]
pub(crate) fn sha256_screens(screens: &Screens) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((screens.len() as u32).to_be_bytes());
    for s in screens.as_slice() {
        h.update(&s.0[..]);
    }
    h.finalize().into()
}

fn emit_once(screens: &mut Screens, inp: &ContentInputs<'_>) -> Result<ContentReceipt, ()> {
    let (body, family) = match &inp.body {
        // Same precedence as `safe::cow_binding::resolve_cow_binding` and the
        // dispatcher ladder: a verified approveHash context wins over exec.
        Body::Safe { safe_v1, safe_exec, cow, erc20, resolver } => {
            let body = if let Some(s) = safe_v1 {
                emit_safe_v1(screens, s, *cow, *erc20, resolver)?
            } else if let Some(e) = safe_exec {
                emit_safe_exec(screens, e, *cow, *erc20, resolver)?
            } else {
                return Err(());
            };
            (body, Family::SAFE)
        }
        Body::UserOp(u) => userop_screens::emit(screens, u)?,
        Body::Rotation { chain_id, slot_index } => (
            super::slot_rotation_screens::emit(screens, *chain_id, *slot_index)?,
            super::slot_rotation_screens::FAMILY,
        ),
    };
    if screens.len() != body.screens {
        return Err(());
    }
    let mut cfi = crate::fi::CfiCounter::new();
    let trailers = trailer_screens::emit_trailers(screens, inp.trailers, family.look, &mut cfi)?;
    crate::fi::scrub_sentinel_register();
    if cfi.check_into_sentinel(trailer_screens::TRAILER_CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    crate::fi::scrub_sentinel_register();
    if trailers.start != body.screens {
        return Err(());
    }
    Ok(ContentReceipt { body, trailers, family })
}

/// Emit the Safe body and the trailers TWICE into the poisoned buffer and
/// require both passes to hash identically; returns the receipt of the pass
/// left in the buffer. A skipped second pass leaves the poisoned/empty
/// buffer, whose hash cannot match the first receipt; a faulted write in
/// either pass differs.
pub(crate) fn emit_content(screens: &mut Screens, inp: &ContentInputs<'_>) -> Result<ContentReceipt, ()> {
    screens.volatile_poison_and_reset();
    if !screens.is_transcript_poisoned() {
        return Err(());
    }
    let first = emit_once(screens, inp)?;
    let first_hash = sha256_screens(screens);
    screens.volatile_poison_and_reset();
    if !screens.is_transcript_poisoned() {
        return Err(());
    }
    let second = emit_once(screens, core::hint::black_box(inp))?;
    let second_hash = sha256_screens(screens);
    let same = bool::from(first_hash.ct_eq(&second_hash))
        && first == second
        && screens.len() == second.body.screens + second.trailers.screens;
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(same)) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(second)
}

/// Append the returning hero: a byte-exact copy of screen 0.
pub(crate) fn append_returning_hero(screens: &mut Screens) -> Result<(), ()> {
    let first = *screens.as_slice().first().ok_or(())?;
    if first.kind() != Some(Kind::Hero) {
        return Err(());
    }
    screens.push(&first).map(|_| ())
}

/// Insert the design's `Confirm?` (index 5 when ≥ 7 details) with the
/// family's disc. Returns the index, if inserted.
pub(crate) fn insert_confirm(screens: &mut Screens, family: &Family) -> Result<Option<usize>, ()> {
    screens.insert_confirm_look(family.look)
}

/// The route body the handler proved is the body this emitter drew.
fn body_bound(body: &Body<'_>, pages: &Pages, body_len: usize) -> bool {
    match body {
        // The Safe body ends with the confirm footer the lift drops.
        Body::Safe { .. } => pages.buf[body_len - 1][0].starts_with(LEGACY_CONFIRM_FOOTER_ROW0),
        // The route's painter re-run equals the proven body byte-for-byte.
        Body::UserOp(u) => userop_screens::body_pages_match(pages, body_len, u),
        Body::Rotation { slot_index, .. } => {
            let want = super::slot_rotation::build_slot_rotation_pages(*slot_index);
            body_len == super::slot_rotation_screens::LEGACY_PAGES
                && want.len == body_len
                && pages.buf[0] == want.buf[0]
        }
    }
}

fn structure_ok(
    screens: &Screens,
    pages: &Pages,
    body: &Body<'_>,
    body_len: usize,
    receipt: &ContentReceipt,
    facts: &TrailerFacts<'_>,
    confirm_at: Option<usize>,
) -> bool {
    let visible = screens.as_slice();
    // The two classifications agreed, and the body sits where the emitter
    // said it does.
    if receipt.body.legacy_pages != body_len || body_len == 0 || body_len > pages.len {
        return false;
    }
    if !body_bound(body, pages, body_len) {
        return false;
    }
    // One trailer screen per trailer page the handler appended after the
    // body — the facts predict both counts.
    let tail_pages = pages.len - body_len;
    let tail = trailer_screens::expected_trailer_count(facts);
    if tail_pages != tail || receipt.trailers.screens != tail || receipt.trailers.start != receipt.body.screens {
        return false;
    }
    let expected_len = receipt.body.screens + tail + 1 + usize::from(confirm_at.is_some());
    if visible.len() != expected_len || receipt.body.screens == 0 {
        return false;
    }
    // Every record well-formed printable ASCII, and nothing page-wrapped.
    if !visible.iter().all(|s| s.is_well_formed() && s.kind() != Some(Kind::Legacy)) {
        return false;
    }
    // Opening hero, returning hero byte-equal, exactly two heroes.
    let hero = &visible[0];
    if hero.kind() != Some(Kind::Hero) || !hero.commit() {
        return false;
    }
    let last = &visible[visible.len() - 1];
    if !screen_exact(hero, last) || exact_screen_occurrences(screens, hero) != 2 {
        return false;
    }
    // Body and trailer screens (other than the hero) never arm commit; only
    // the hero pair and the Confirm? do.
    let confirms = visible.iter().filter(|s| s.kind() == Some(Kind::Confirm)).count();
    match confirm_at {
        Some(c) => {
            if confirms != 1 || c >= visible.len() || visible[c].kind() != Some(Kind::Confirm) || !visible[c].commit() {
                return false;
            }
        }
        None => {
            if confirms != 0 {
                return false;
            }
        }
    }
    let armed = visible.iter().filter(|s| s.commit()).count();
    if armed != 2 + usize::from(confirm_at.is_some()) {
        return false;
    }
    // Every trailer screen re-derives from the facts at its (shifted) index.
    crate::fi::scrub_sentinel_register();
    trailer_screens::trailer_set_proof(screens, &receipt.trailers, facts, receipt.family.look, confirm_at)
        == crate::fi::OK_SENTINEL
}

/// The lift proof as one FI sentinel: `OK_SENTINEL` iff every structural
/// expectation holds (see the module docs).
#[must_use]
#[inline(never)]
pub(crate) fn transcript_proof(
    screens: &Screens,
    pages: &Pages,
    body: &Body<'_>,
    body_len: usize,
    receipt: &ContentReceipt,
    facts: &TrailerFacts<'_>,
    confirm_at: Option<usize>,
) -> u32 {
    let ok = structure_ok(
        core::hint::black_box(screens),
        core::hint::black_box(pages),
        core::hint::black_box(body),
        core::hint::black_box(body_len),
        core::hint::black_box(receipt),
        core::hint::black_box(facts),
        core::hint::black_box(confirm_at),
    );
    crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
}
