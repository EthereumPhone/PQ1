//! Pixel-UI screens for the off-chain (EIP-1271 / ERC-6492) confirmation —
//! the second painter over `eip1271::render_eip1271_personal_sign_pages` and
//! `render_eip1271_raw32_pages` (upstream flows
//! `eip1271/personal_counterfactual{,_hash}`). EIP-712 typed data goes
//! through the ERC-7730 page lift (`erc7730_screens`, `Surface::Typed`).
//!
//! ```text
//!  SIGN EIP-1271?           | SIGN BLIND HASH?          hero
//!  MODE (deployed / ! undeployed, pulse)
//!  [! BLIND RAW32, pulse]
//!  NETWORK · ACCOUNT · SIGNER | HASH (full width)
//!  MSG … (the whole message, wrapped)
//!  KEYS (used / cap, gap)
//! ```
//!
//! The message is the page painter's own byte view (printable ASCII as
//! itself, anything else `?`), wrapped at the 22 px floor and split six
//! lines to a screen — never truncated.

use super::screen_kit::{address_look, addr42, fits_at_22, BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use pqsigner_ui_px::fit::{layout_address, Line, Region};
use pqsigner_ui_px::screen::LINES_PER_PAGE;
use pqsigner_ui_px::{Icon, Look, Screens, Weight};

/// The facts both page painters take.
#[derive(Clone, Copy)]
pub(crate) struct OffchainFacts<'a> {
    pub(crate) chain_id: u64,
    pub(crate) account_index: u32,
    pub(crate) slot_index: u32,
    pub(crate) wallet: &'a [u8; 20],
    pub(crate) local_after: u64,
    pub(crate) last_userop: u64,
    pub(crate) cap: u64,
    pub(crate) deployed: bool,
}

/// Which off-chain body.
#[derive(Clone, Copy)]
pub(crate) enum OffchainBody<'a> {
    /// `personal_sign`: the raw message.
    Personal { facts: OffchainFacts<'a>, msg: &'a [u8] },
    /// RAW32: the dapp's 32-byte hash `H`.
    Raw32 { facts: OffchainFacts<'a>, hash: &'a [u8; 32] },
}

/// `personal_sign` message bytes per legacy page (3 rows × 16 columns).
const CHARS_PER_PAGE: usize = 48;

pub(crate) fn family(body: &OffchainBody<'_>) -> Family {
    match body {
        OffchainBody::Personal { facts, .. } => Family {
            look: address_look(Icon::Eth, facts.wallet),
            signed: b"EIP1271 SIGNED",
            declined: b"EIP1271 DECLINED",
        },
        OffchainBody::Raw32 { .. } => Family {
            look: Look::plain(Icon::Blind),
            signed: b"BLIND HASH SIGNED",
            declined: b"BLIND HASH DECLINED",
        },
    }
}

/// The page painter re-run (the binding witness).
pub(crate) fn render_pages(body: &OffchainBody<'_>) -> super::Pages {
    match *body {
        OffchainBody::Personal { facts: f, msg } => super::eip1271::render_eip1271_personal_sign_pages(
            f.chain_id,
            f.account_index,
            f.slot_index,
            f.wallet,
            msg,
            f.local_after,
            f.last_userop,
            f.cap,
            f.deployed,
        ),
        OffchainBody::Raw32 { facts: f, hash } => super::eip1271::render_eip1271_raw32_pages(
            f.chain_id,
            f.account_index,
            f.slot_index,
            hash,
            f.local_after,
            f.last_userop,
            f.cap,
            f.deployed,
        ),
    }
}

fn legacy_pages(body: &OffchainBody<'_>) -> usize {
    match body {
        OffchainBody::Personal { msg, .. } => 5 + msg.len().div_ceil(CHARS_PER_PAGE).max(1),
        OffchainBody::Raw32 { .. } => 6,
    }
}

/// The page painter's byte view: printable ASCII as itself, else `?`.
fn sanitise(b: u8) -> u8 {
    if (0x20..=0x7E).contains(&b) {
        b
    } else {
        b'?'
    }
}

/// Emit the whole message, wrapped at the 22 px floor (preferring a break
/// after a space or comma in the second half of a line), six lines to a
/// `MSG` screen.
fn emit_message(e: &mut Emit<'_>, msg: &[u8]) -> Result<(), ()> {
    if msg.is_empty() {
        return e.detail(b"MSG", b"MESSAGE", &[(b"(empty message)", Weight::Regular)], false);
    }
    let mut clean = [0u8; sphincs_tz_shared::MAX_OFFCHAIN_PERSONAL_SIGN_LEN];
    if msg.len() > clean.len() {
        return Err(());
    }
    for (d, s) in clean.iter_mut().zip(msg) {
        *d = sanitise(*s);
    }
    let mut rest = &clean[..msg.len()];
    let mut part = 0u64;
    while !rest.is_empty() {
        let mut lines = [Line::EMPTY; 2 * LINES_PER_PAGE];
        let mut n = 0;
        while n < lines.len() && !rest.is_empty() {
            let mut k = rest.len();
            while k > 0 && !fits_at_22(&rest[..k], Region::Docked) {
                k -= 1;
            }
            if k == 0 {
                return Err(());
            }
            if k < rest.len() {
                if let Some(b) = rest[..k].iter().rposition(|c| matches!(c, b',' | b' ')) {
                    if b + 1 >= k / 2 {
                        k = b + 1;
                    }
                }
            }
            lines[n] = Line::new(&rest[..k]).ok_or(())?;
            n += 1;
            rest = &rest[k..];
        }
        part += 1;
        let id = if part == 1 { Text::new().push(b"MSG") } else { Text::new().push(b"MSG").push_u64(part) };
        let l: [(&[u8], Weight); 2 * LINES_PER_PAGE] = core::array::from_fn(|i| (lines[i].as_bytes(), Weight::Regular));
        e.detail_multi(id.as_bytes(), b"MESSAGE", &l[..n], false)?;
    }
    Ok(())
}

fn emit_common_head(e: &mut Emit<'_>, f: &OffchainFacts<'_>) -> Result<(), ()> {
    if f.deployed {
        e.detail(
            b"MODE",
            b"DETAILS",
            &[(b"Account contract", Weight::Regular), (b"is deployed", Weight::Regular), (b"Verify on dapp", Weight::Regular)],
            false,
        )
    } else {
        // `! Undeployed sig`: a returning user whose wallet IS deployed is
        // being lied to (the budget view resets) — loud.
        e.detail(
            b"MODE",
            b"! UNDEPLOYED",
            &[(b"Account contract", Weight::Regular), (b"does not exist", Weight::Regular), (b"on chain yet", Weight::Regular)],
            true,
        )
    }
}

fn emit_account(e: &mut Emit<'_>, f: &OffchainFacts<'_>) -> Result<(), ()> {
    let acct = Text::new().push(b"Account: ").push_u64(u64::from(f.account_index));
    let slot = Text::new().push(b"Slot: ").push_u64(u64::from(f.slot_index));
    e.detail(b"ACCOUNT", b"ACCOUNT", &[(acct.as_bytes(), Weight::Regular), (slot.as_bytes(), Weight::Regular)], false)
}

fn emit_keys(e: &mut Emit<'_>, f: &OffchainFacts<'_>) -> Result<(), ()> {
    let used = Text::new().push_u64(f.local_after).push(b"/").push_u64(f.cap).push(b" keys used");
    let gap = Text::new().push(b"Gap: ").push_u64(f.local_after.saturating_sub(f.last_userop));
    if !used.ok() || !gap.ok() {
        return Err(());
    }
    e.detail(b"KEYS", b"KEYS", &[(used.as_bytes(), Weight::Regular), (gap.as_bytes(), Weight::Regular)], false)
}

/// Emit the body screens (hero first).
pub(crate) fn emit(out: &mut Screens, body: &OffchainBody<'_>, fam: Family) -> Result<BodyReceipt, ()> {
    let f = match body {
        OffchainBody::Personal { facts, .. } | OffchainBody::Raw32 { facts, .. } => facts,
    };
    let mut e = Emit::new(out, f.chain_id, fam.look);
    match body {
        OffchainBody::Personal { msg, .. } => {
            e.hero(b"SIGN", b"SIGN EIP-1271?")?;
            e.network()?;
            emit_common_head(&mut e, f)?;
            emit_account(&mut e, f)?;
            e.addr_lines(b"SIGNER", b"SIGNER", &layout_address(&addr42(f.wallet)), None)?;
            emit_message(&mut e, msg)?;
        }
        OffchainBody::Raw32 { hash, .. } => {
            e.hero(b"SIGN", b"SIGN BLIND HASH?")?;
            e.network()?;
            e.detail(
                b"BLIND",
                b"BLIND",
                &[
                    (b"! BLIND RAW32", Weight::SemiBold),
                    (b"Hash only, no text", Weight::Regular),
                    (b"Check it on the dapp", Weight::Regular),
                ],
                true,
            )?;
            emit_common_head(&mut e, f)?;
            emit_account(&mut e, f)?;
            e.word_value(b"HASH", b"HASH", hash)?;
        }
    }
    emit_keys(&mut e, f)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: legacy_pages(body),
    })
}
