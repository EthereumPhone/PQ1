//! Native pixel-UI twins of the handler-owned trailer pages — the second
//! painter of "one classification, two painters" for everything the sign
//! handler appends after a route's semantic body.
//!
//! The legacy trailers (`value_page`, `nonce_lane`, `userop_gas_lane`,
//! `erc8213`, `deployment`) are the fact source and keep every `enforce_*` /
//! `*_proof` FI gate untouched. Each screen here is derived from the SAME
//! page builder the proven page came from — the rows of that page become the
//! screen's lines (design typography, a label, a pulse on the loud ones) —
//! so a fact the page shows is on the screen by construction, never through a
//! second interpretation of the signed inputs. Addresses use the design's
//! EIP-55 two/three-line layout (the same bytes, differently wrapped).
//!
//! Slots, in page order (the dispatcher's native-value + fee splice first,
//! then the handler's own gates):
//!
//! | slot        | legacy page(s)                     | screen                     |
//! |-------------|------------------------------------|----------------------------|
//! | NativeValue | `! NATIVE <tkr>` + amount (value≠0) | detail, pulse              |
//! | MaxFee      | `Fees: max / tip` (Safe/CoW routes) | detail                     |
//! | WorstCase   | `Worst-case:`                       | detail (1–2 pages)         |
//! | Paymaster   | `! PAYMASTER SET` (when present)    | detail, pulse              |
//! | Signer      | `Signer acct #N` + address          | detail, SemiBold head      |
//! | Target      | `Target contract:` + address        | detail                     |
//! | NonceLane   | `Nonce lane key:` (lane ≠ 0)        | detail, 48 hex             |
//! | GasLane     | `Call/Verify/PreVer/Total`          | detail, 2 pages            |
//! | FpBanner    | `8213 Fingerprint` + kind           | detail, fingerprint icon   |
//! | FpDigest    | the 32-byte hash                    | value, 3 full-width lines  |
//! | Deploy      | `DEPLOY FACTORY:` + address (deploy)| detail, pulse              |
//!
//! Every slot yields exactly one screen per legacy page, so the trailer
//! screen count equals the trailer page count and the lift can bind the two
//! tails 1:1 without any `Legacy` record. Skips (value 0, no paymaster, lane
//! 0, no deploy, fee pages not required) are the page painters' own
//! decisions, recomputed here from the same facts.
//!
//! Proofs mirror the page proofs: [`trailer_screen_proof`] rebuilds one
//! slot's expected screen from the facts and requires it at its receipt
//! index exactly once (or absent, for a skip); [`trailer_set_proof`] folds
//! every slot plus the receipt's contiguity into one sentinel and is run
//! both before and after the `Confirm?` insertion.

use super::deployment::DeploymentConfirmContext;
use super::erc8213;
use super::nonce_lane;
use super::primitives::eip55_hex;
use super::userop_gas_lane;
use super::value_page;
use crate::tx::eip1559::Eip1559Tx;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_ui_px::fit::{fit_tier, layout_address, split_hash_full, AddrLines, Region};
use pqsigner_ui_px::screen::LINES_PER_PAGE;
use pqsigner_ui_px::{
    exact_screen_occurrences, screen_at_matches, Icon, Look, Screen, ScreenBuilder, Screens, Side, Weight,
};

type Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// The signed-context facts every trailer page was built from — the same
/// values the handler handed the page painters, never re-derived from the
/// pages or from companion bytes.
pub(crate) struct TrailerFacts<'a> {
    /// The display shim of the outer transaction (`value`, `chain_id`, the
    /// EIP-1559 fee fields, the aggregate gas limit).
    pub tx: &'a Eip1559Tx,
    /// Whether the dispatcher spliced the legacy fee pair for this route.
    pub legacy_fee_required: bool,
    pub paymaster_and_data_hash: &'a [u8; 32],
    pub account_index: u32,
    pub sender: &'a [u8; 20],
    pub target: &'a [u8; 20],
    /// The full Type-2 nonce (`uint192 key || uint64 sequence`).
    pub nonce: &'a [u8; 32],
    pub call_gas: &'a [u8; 32],
    pub verification_gas: &'a [u8; 32],
    pub pre_verification_gas: &'a [u8; 32],
    pub fingerprint: erc8213::Kind,
    /// The deployment context of the main confirmation; `None` on the slot
    /// rotation consent (it precedes the deployment decision).
    pub deployment: Option<&'a DeploymentConfirmContext>,
    /// Which dialog these trailers close.
    pub set: TrailerSet,
}

/// Which handler dialog the trailers belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrailerSet {
    /// The main sign confirmation: every slot, each on its own predicate.
    Sign,
    /// The slot-rotation consent: signer, nonce lane and gas lane only (the
    /// three gates the handler appends to `build_slot_rotation_pages`).
    Rotation,
}

/// The trailer slots, in page order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    NativeValue,
    MaxFee,
    WorstCase,
    Paymaster,
    Signer,
    Target,
    NonceLane,
    GasLane,
    FpBanner,
    FpDigest,
    Deploy,
}

pub(crate) const N_TRAILERS: usize = 11;
pub(crate) const SLOTS: [Slot; N_TRAILERS] = [
    Slot::NativeValue,
    Slot::MaxFee,
    Slot::WorstCase,
    Slot::Paymaster,
    Slot::Signer,
    Slot::Target,
    Slot::NonceLane,
    Slot::GasLane,
    Slot::FpBanner,
    Slot::FpDigest,
    Slot::Deploy,
];

const TRAILER_CFI_STEP: u32 = 0x7A11_5C3E;
/// One bump per slot, skipped or emitted — a whole skipped emitter leaves the
/// caller-owned counter short.
pub(crate) const TRAILER_CFI_EXPECTED: u32 = crate::cfi_expected!(
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP,
    TRAILER_CFI_STEP
);

/// What the emitter produced, for the proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TrailerReceipt {
    /// Transcript index of the first trailer screen (== the body length).
    pub(crate) start: usize,
    /// Screens appended.
    pub(crate) screens: usize,
    /// Per slot: the (unshifted) transcript index it landed at, or `None`
    /// for a proven skip.
    pub(crate) at: [Option<usize>; N_TRAILERS],
}

/// Whether a slot is present for these facts — the page painters' own skip
/// predicates, recomputed.
fn present(slot: Slot, f: &TrailerFacts<'_>) -> bool {
    if f.set == TrailerSet::Rotation {
        return match slot {
            Slot::Signer | Slot::GasLane => true,
            Slot::NonceLane => !nonce_lane::nonce_lane_is_zero(f.nonce),
            _ => false,
        };
    }
    match slot {
        Slot::NativeValue => !f.tx.value.is_zero(),
        Slot::MaxFee | Slot::WorstCase => f.legacy_fee_required,
        Slot::Paymaster => value_page::paymaster_present(f.paymaster_and_data_hash),
        Slot::Signer | Slot::Target | Slot::GasLane | Slot::FpBanner | Slot::FpDigest => true,
        Slot::NonceLane => !nonce_lane::nonce_lane_is_zero(f.nonce),
        Slot::Deploy => f.deployment.is_some_and(DeploymentConfirmContext::requested),
    }
}

/// The number of trailer screens these facts produce — and, one screen per
/// page by construction, the number of legacy trailer pages the handler
/// appended after the route body. The lift binds the two tails with it.
#[must_use]
pub(crate) fn expected_trailer_count(f: &TrailerFacts<'_>) -> usize {
    SLOTS.iter().filter(|s| present(**s, f)).count()
}

/// Detail screens alternate the disc column across the whole transcript
/// (DESIGN.md `normalize_screens`); the body puts NETWORK (index 1) on the
/// right, so odd indices are right, even indices left.
fn side_at(idx: usize) -> Side {
    if idx % 2 == 1 {
        Side::Right
    } else {
        Side::Left
    }
}

fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
    let mut n = DISPLAY_COLS;
    while n > 0 && row[n - 1] == b' ' {
        n -= 1;
    }
    &row[..n]
}

/// A page row is content unless it is empty or a `> …` navigation footer
/// (`> next`, `> verify off-dev`): instruction vocabulary the design
/// replaces with its own chevrons.
fn is_content_row(row: &[u8]) -> bool {
    !row.is_empty() && !row.starts_with(b"> ")
}

/// Up to six lines (two pages of three) with their weights.
struct Lines<'a> {
    buf: [(&'a [u8], Weight); 2 * LINES_PER_PAGE],
    n: usize,
}

impl<'a> Lines<'a> {
    const fn new() -> Self {
        Self {
            buf: [(&[], Weight::Regular); 2 * LINES_PER_PAGE],
            n: 0,
        }
    }

    fn push(&mut self, text: &'a [u8], w: Weight) -> Result<(), ()> {
        if self.n >= self.buf.len() {
            return Err(());
        }
        self.buf[self.n] = (text, w);
        self.n += 1;
        Ok(())
    }

    fn push_rows(&mut self, rows: &'a [[u8; DISPLAY_COLS]], w: Weight) -> Result<(), ()> {
        for row in rows {
            let t = trimmed(row);
            if is_content_row(t) {
                self.push(t, w)?;
            }
        }
        Ok(())
    }

    fn as_slice(&self) -> &[(&'a [u8], Weight)] {
        &self.buf[..self.n]
    }
}

/// A docked detail over `lines` (1–6, paged by three) at the largest tier
/// that fits every line. Never truncates: a line that fits no tier is `Err`.
fn detail(id: &[u8], look: Look, side: Side, label: &[u8], lines: &Lines<'_>, pulse: bool) -> Result<Screen, ()> {
    let all = lines.as_slice();
    if all.is_empty() {
        return Err(());
    }
    // The tier is fitted per page (a page stacks at most three lines) and
    // the screen takes the smaller of the two so both pages share it.
    let (p0, p1) = all.split_at(all.len().min(LINES_PER_PAGE));
    let mut tier = fit_tier(p0, Region::Docked).ok_or(())?;
    if !p1.is_empty() {
        tier = tier.min(fit_tier(p1, Region::Docked).ok_or(())?);
    }
    let mut b = ScreenBuilder::detail(id, look.icon, side, label).look_tint(look).tier(tier);
    for (i, &(text, w)) in all.iter().enumerate() {
        if i == LINES_PER_PAGE {
            b = b.next_page();
        }
        b = b.line(text, w);
    }
    if pulse {
        b = b.pulse();
    }
    b.finish().map_err(|_| ())
}

fn addr42(addr: &[u8; 20]) -> [u8; 42] {
    let mut out = [0u8; 42];
    out[0] = b'0';
    out[1] = b'x';
    out[2..].copy_from_slice(&eip55_hex(addr));
    out
}

fn addr_lines(addr: &[u8; 20]) -> AddrLines {
    layout_address(&addr42(addr))
}

/// A detail whose value is an EIP-55 address (2 or 3 design lines), with an
/// optional SemiBold head line.
fn addr_detail(
    id: &[u8],
    look: Look,
    side: Side,
    label: &[u8],
    head: Option<&[u8]>,
    addr: &[u8; 20],
    pulse: bool,
) -> Result<Screen, ()> {
    let a = addr_lines(addr);
    let mut lines = Lines::new();
    if let Some(h) = head {
        lines.push(h, Weight::SemiBold)?;
    }
    for l in a.as_slice() {
        lines.push(l.as_bytes(), Weight::Regular)?;
    }
    detail(id, look, side, label, &lines, pulse)
}

/// The two fee screens of the compact legacy fee envelope (`Fees: max / tip`
/// and `Worst-case:`), from the SAME page builder the proven fee pages came
/// from — the trailer slots on the Safe route, the route body's own fee
/// pages on every single-UserOp route. `Err` when the envelope is not exact
/// (the dispatcher's preflight already refused that case).
pub(crate) fn fee_screen(worst: bool, tx: &Eip1559Tx, look: Look, side: Side) -> Result<Screen, ()> {
    let rendered = value_page::build_legacy_fee_pages(tx);
    if !rendered.exact {
        return Err(());
    }
    let (page, id, label): (&Page, &[u8], &[u8]) = if worst {
        (&rendered.pages[1], b"WORST", b"WORST CASE")
    } else {
        (&rendered.pages[0], b"MAXFEE", b"MAX FEE")
    };
    let mut lines = Lines::new();
    lines.push_rows(page, Weight::Regular)?;
    detail(id, look, side, label, &lines, false)
}

/// The expected screen for `slot` at transcript index `idx` (unshifted),
/// `Ok(None)` for a proven skip, `Err` when the facts cannot be rendered
/// exactly (the caller refuses, exactly like the page painter would).
#[allow(clippy::too_many_lines)]
pub(crate) fn expected(slot: Slot, f: &TrailerFacts<'_>, look: Look, idx: usize) -> Result<Option<Screen>, ()> {
    if !present(slot, f) {
        return Ok(None);
    }
    let side = side_at(idx);
    let s = match slot {
        Slot::NativeValue => {
            let page: Page = value_page::build_native_value_page(&f.tx.value, f.tx.chain_id).ok_or(())?;
            let mut lines = Lines::new();
            lines.push_rows(&page, Weight::Regular)?;
            detail(b"NATIVE", look, side, b"NATIVE VALUE", &lines, true)?
        }
        Slot::MaxFee | Slot::WorstCase => fee_screen(slot == Slot::WorstCase, f.tx, look, side)?,
        Slot::Paymaster => {
            let page: Page = value_page::build_paymaster_page();
            let mut lines = Lines::new();
            lines.push_rows(&page, Weight::Regular)?;
            detail(b"PAYMSTR", look, side, b"PAYMASTER", &lines, true)?
        }
        Slot::Signer => {
            let page: Page = value_page::build_signer_identity_page(f.account_index, f.sender).ok_or(())?;
            addr_detail(b"SIGNER", look, side, b"SIGNER", Some(trimmed(&page[0])), f.sender, false)?
        }
        Slot::Target => addr_detail(b"TARGET", look, side, b"TARGET", None, f.target, false)?,
        Slot::NonceLane => {
            let page: Page = nonce_lane::build_nonce_lane_page(f.nonce);
            let mut lines = Lines::new();
            lines.push_rows(&page[1..], Weight::Regular)?;
            detail(b"LANE", look, side, b"NONCE LANE", &lines, false)?
        }
        Slot::GasLane => {
            let page: Page =
                userop_gas_lane::build_gas_lane_page(f.call_gas, f.verification_gas, f.pre_verification_gas)
                    .ok_or(())?;
            let mut lines = Lines::new();
            lines.push_rows(&page, Weight::Regular)?;
            detail(b"GASLANE", look, side, b"GAS LANE", &lines, false)?
        }
        Slot::FpBanner => {
            let pair = erc8213::build_fingerprint_pair(f.fingerprint);
            let mut lines = Lines::new();
            lines.push_rows(&pair[0], Weight::Regular)?;
            detail(b"FP8213", Look::plain(Icon::Fingerprint), side, b"ERC-8213", &lines, false)?
        }
        Slot::FpDigest => {
            let [a, b, c] = split_hash_full(f.fingerprint.hash());
            let lines = [
                (a.as_bytes(), Weight::Regular),
                (b.as_bytes(), Weight::Regular),
                (c.as_bytes(), Weight::Regular),
            ];
            let tier = fit_tier(&lines, Region::Full).ok_or(())?;
            let mut bld = ScreenBuilder::value(b"DIGEST", Icon::Fingerprint, b"DIGEST").tier(tier);
            for &(text, w) in &lines {
                bld = bld.line(text, w);
            }
            bld.finish().map_err(|_| ())?
        }
        Slot::Deploy => {
            let d = f.deployment.ok_or(())?;
            let page: Page = super::deployment::build_deployment_page(d.factory());
            addr_detail(b"DEPLOY", look, side, b"! DEPLOY", Some(trimmed(&page[0])), d.factory(), true)?
        }
    };
    Ok(Some(s))
}

/// Append every present trailer screen in slot order, bumping the
/// caller-owned CFI counter once per slot (skips included).
#[inline(never)]
pub(crate) fn emit_trailers(
    out: &mut Screens,
    f: &TrailerFacts<'_>,
    look: Look,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<TrailerReceipt, ()> {
    let start = out.len();
    let mut at = [None; N_TRAILERS];
    for (i, slot) in SLOTS.iter().enumerate() {
        let idx = out.len();
        if let Some(s) = expected(*slot, f, look, idx)? {
            out.push(&s)?;
            at[i] = Some(idx);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        cfi.bump(TRAILER_CFI_STEP);
    }
    Ok(TrailerReceipt {
        start,
        screens: out.len() - start,
        at,
    })
}

/// Where an unshifted index lands after the `Confirm?` insertion.
fn shifted(idx: usize, confirm_at: Option<usize>) -> usize {
    match confirm_at {
        Some(c) if idx >= c => idx + 1,
        _ => idx,
    }
}

/// One slot's twin of the page proofs: the expected screen, rebuilt from the
/// facts, sits at its receipt index (shifted by the `Confirm?` if one was
/// inserted) exactly once — or, for a skip, the receipt records no index.
#[inline(never)]
pub(crate) fn trailer_screen_proof(
    screens: &Screens,
    slot_i: usize,
    receipt: &TrailerReceipt,
    f: &TrailerFacts<'_>,
    look: Look,
    confirm_at: Option<usize>,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let Some(slot) = SLOTS.get(slot_i) else {
            return false;
        };
        let Some(at) = receipt.at.get(slot_i) else {
            return false;
        };
        match (at, expected(*slot, f, look, at.unwrap_or(0))) {
            (None, Ok(None)) => true,
            (Some(idx), Ok(Some(s))) => {
                core::hint::black_box(screen_at_matches(screens, shifted(*idx, confirm_at), &s))
                    && exact_screen_occurrences(screens, &s) == 1
            }
            _ => false,
        }
    })
}

/// The whole tail: contiguous receipt indices from `start`, the count the
/// facts predict, and every slot's proof.
#[inline(never)]
pub(crate) fn trailer_set_proof(
    screens: &Screens,
    receipt: &TrailerReceipt,
    f: &TrailerFacts<'_>,
    look: Look,
    confirm_at: Option<usize>,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        let mut next = receipt.start;
        let mut count = 0usize;
        for at in &receipt.at {
            if let Some(idx) = at {
                if *idx != next {
                    return false;
                }
                next += 1;
                count += 1;
            }
        }
        if count != receipt.screens || count != expected_trailer_count(f) {
            return false;
        }
        for i in 0..N_TRAILERS {
            crate::fi::scrub_sentinel_register();
            if trailer_screen_proof(screens, i, receipt, f, look, confirm_at) != crate::fi::OK_SENTINEL {
                return false;
            }
        }
        true
    })
}
