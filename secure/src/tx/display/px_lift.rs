//! The lift from the proven legacy page transcript to the pixel-UI screen
//! transcript, and the proof that binds the two.
//!
//! Under `ui-px` the Safe sign handler still builds and proves the legacy
//! `Pages` exactly as before (dispatcher, native-value / fee splice, the
//! paymaster / signer / target / nonce-lane / gas-lane / ERC-8213 / deployment
//! trailers, every `*_proof`). This module then assembles what the user
//! actually sees:
//!
//! ```text
//!   [0]              hero ask                       (safe_screens)
//!   [1 .. body)      Safe body details              (safe_screens)
//!   [body .. +tail)  every legacy page after the Safe body, wrapped 1:1
//!                    as `Legacy` screens — byte-exact, so every trailer
//!                    proof transfers unchanged
//!   [last]           the returning hero (== screen 0)
//!   + `Confirm?` inserted at index 5 when the flow has ≥ 7 details
//! ```
//!
//! The legacy Safe body's own trailing confirm-footer page is the one page
//! NOT wrapped: the design replaces it with the returning ask and the
//! auto-inserted `Confirm?`.
//!
//! [`transcript_proof`] recomputes every structural expectation from the
//! proven pages and the emitter receipt and folds them into one FI sentinel:
//! the two classifications agreed on the Safe body length, every wrapped
//! page sits at its expected index and is unique, the returning hero is
//! byte-equal to the opening one, the `Confirm?` is where the rule puts it,
//! and every record is well-formed printable ASCII. A double emit with a
//! SHA-256 receipt between (the shape of the ERC-7730 transcript proof)
//! defends the emitter itself against a single skipped or faulted write.

use super::safe_screens::{emit_safe_exec, emit_safe_v1, SafeBodyReceipt};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::safe::{VerifiedSafeExec, VerifiedSafeV1};
use pqsigner_ui_px::{exact_screen_occurrences, screen_exact, Icon, Kind, Screen, Screens};
use subtle::ConstantTimeEq;

/// The legacy Safe body ends with this confirm-footer page; it is the page
/// the lift drops in favour of the returning hero.
const LEGACY_CONFIRM_FOOTER_ROW0: &[u8] = b"Long-press to";

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

fn emit_once(
    screens: &mut Screens,
    safe_v1: Option<&VerifiedSafeV1<'_>>,
    safe_exec: Option<&VerifiedSafeExec<'_>>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<SafeBodyReceipt, ()> {
    // Same precedence as `safe::cow_binding::resolve_cow_binding` and the
    // dispatcher ladder: a verified approveHash context wins over exec.
    if let Some(s) = safe_v1 {
        emit_safe_v1(screens, s, cow, erc20, resolver)
    } else if let Some(e) = safe_exec {
        emit_safe_exec(screens, e, cow, erc20, resolver)
    } else {
        Err(())
    }
}

/// Emit the Safe body TWICE into the poisoned buffer and require both passes
/// to hash identically; returns the receipt of the pass left in the buffer.
/// A skipped second pass leaves the poisoned/empty buffer, whose hash cannot
/// match the first receipt; a faulted write in either pass differs.
pub(crate) fn emit_safe_body(
    screens: &mut Screens,
    safe_v1: Option<&VerifiedSafeV1<'_>>,
    safe_exec: Option<&VerifiedSafeExec<'_>>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<SafeBodyReceipt, ()> {
    screens.volatile_poison_and_reset();
    if !screens.is_transcript_poisoned() {
        return Err(());
    }
    let first = emit_once(screens, safe_v1, safe_exec, cow, erc20, resolver)?;
    let first_hash = sha256_screens(screens);
    screens.volatile_poison_and_reset();
    if !screens.is_transcript_poisoned() {
        return Err(());
    }
    let second = emit_once(
        screens,
        core::hint::black_box(safe_v1),
        core::hint::black_box(safe_exec),
        core::hint::black_box(cow),
        core::hint::black_box(erc20),
        resolver,
    )?;
    let second_hash = sha256_screens(screens);
    let same = bool::from(first_hash.ct_eq(&second_hash))
        && first.screens == second.screens
        && first.legacy_pages == second.legacy_pages
        && screens.len() == second.screens;
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(same)) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(second)
}

/// Wrap every legacy page after the Safe body (`pages[body_len..]`) as a
/// `Legacy` screen, 1:1 and byte-exact. `body_len` must land exactly on the
/// legacy confirm-footer page, which is dropped. Returns the tail length.
pub(crate) fn append_legacy_tail(screens: &mut Screens, pages: &Pages, body_len: usize) -> Result<usize, ()> {
    if body_len == 0 || body_len > pages.len {
        return Err(());
    }
    if !pages.buf[body_len - 1][0].starts_with(LEGACY_CONFIRM_FOOTER_ROW0) {
        return Err(());
    }
    let mut n = 0usize;
    for page in &pages.as_slice()[body_len..] {
        screens.push_legacy(page)?;
        n += 1;
    }
    Ok(n)
}

/// Append the returning hero: a byte-exact copy of screen 0.
pub(crate) fn append_returning_hero(screens: &mut Screens) -> Result<(), ()> {
    let first = *screens.as_slice().first().ok_or(())?;
    if first.kind() != Some(Kind::Hero) {
        return Err(());
    }
    screens.push(&first).map(|_| ())
}

/// Insert the design's `Confirm?` (index 5 when ≥ 7 details) with the Safe
/// disc. Returns the index, if inserted.
pub(crate) fn insert_confirm(screens: &mut Screens) -> Result<Option<usize>, ()> {
    screens.insert_confirm(Icon::Safe)
}

/// Where an original (pre-`Confirm?`) index lands after the insertion.
fn shifted(idx: usize, confirm_at: Option<usize>) -> usize {
    match confirm_at {
        Some(c) if idx >= c => idx + 1,
        _ => idx,
    }
}

fn structure_ok(
    screens: &Screens,
    pages: &Pages,
    body_len: usize,
    receipt: &SafeBodyReceipt,
    confirm_at: Option<usize>,
) -> bool {
    let visible = screens.as_slice();
    // The two classifications agreed, and the body sits where the emitter
    // said it does.
    if receipt.legacy_pages != body_len || body_len == 0 || body_len > pages.len {
        return false;
    }
    if !pages.buf[body_len - 1][0].starts_with(LEGACY_CONFIRM_FOOTER_ROW0) {
        return false;
    }
    let tail = pages.len - body_len;
    let expected_len = receipt.screens + tail + 1 + usize::from(confirm_at.is_some());
    if visible.len() != expected_len || receipt.screens == 0 {
        return false;
    }
    // Every record well-formed printable ASCII.
    if !visible.iter().all(|s| s.is_well_formed()) {
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
    // Body screens (other than the hero) never arm commit; only the hero
    // pair and the Confirm? do.
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
    // Every wrapped trailer page at its expected index, unique.
    for j in 0..tail {
        let expected = Screen::legacy(&pages.buf[body_len + j]);
        let idx = shifted(receipt.screens + j, confirm_at);
        if idx >= visible.len() || !screen_exact(&visible[idx], &expected) {
            return false;
        }
        if exact_screen_occurrences(screens, &expected) != 1 {
            return false;
        }
    }
    // Nothing between the body and the returning hero other than the tail
    // (and the Confirm? if it landed there).
    for (i, s) in visible.iter().enumerate() {
        let is_tail_slot = (0..tail).any(|j| shifted(receipt.screens + j, confirm_at) == i);
        if s.kind() == Some(Kind::Legacy) && !is_tail_slot {
            return false;
        }
    }
    true
}

/// The lift proof as one FI sentinel: `OK_SENTINEL` iff every structural
/// expectation holds (see the module docs).
#[must_use]
#[inline(never)]
pub(crate) fn transcript_proof(
    screens: &Screens,
    pages: &Pages,
    body_len: usize,
    receipt: &SafeBodyReceipt,
    confirm_at: Option<usize>,
) -> u32 {
    let ok = structure_ok(
        core::hint::black_box(screens),
        core::hint::black_box(pages),
        core::hint::black_box(body_len),
        core::hint::black_box(receipt),
        core::hint::black_box(confirm_at),
    );
    crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
}
