//! Pixel-UI screens for the off-chain (EIP-1271 / ERC-6492) confirmation —
//! the second painter over `eip1271::render_eip1271_personal_sign_pages` and
//! `render_eip1271_raw32_pages` (upstream flows
//! `eip1271/personal_counterfactual{,_hash}`). EIP-712 typed data goes
//! through the ERC-7730 page lift (`erc7730_screens`, `Surface::Typed`).
//!
//! ```text
//!  SIGN EIP-1271?                 | SIGN BLIND HASH?          hero
//!  [! NOT TEXT, pulse]            | ! BLIND RAW32, pulse
//!  MSG … (the whole message)      | HASH (full width)
//!  MODE (deployed / ! undeployed, pulse)
//!  NETWORK · ACCOUNT · SIGNER     | NETWORK · ACCOUNT
//!  KEYS (used / cap, gap)
//! ```
//!
//! The content being signed comes first, and `Confirm?` follows it (and the
//! `MODE` screen right behind it — `screen::confirm_index`): the message or
//! the hash is read before the early exit (owner decision 2026-10-19).
//!
//! The message is shown the page painter's way (`eip1271::personal_sign_view`):
//! text — printable ASCII, each line feed starting a new line, wrapped at the
//! 22 px floor — or, for anything else, hex (8 bytes a line) behind a loud
//! `! NOT TEXT` screen. Six lines to a screen, never truncated.

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

/// Message bytes on one hex line: `0011aabb 0011aabb`.
const HEX_BYTES_PER_LINE: usize = 8;

pub(crate) fn family(body: &OffchainBody<'_>) -> Family {
    match body {
        OffchainBody::Personal { facts, .. } => Family {
            look: address_look(Icon::Eth, facts.wallet),
            signed: b"EIP1271 SIGNED",
            declined: b"EIP1271 DECLINED",
            failed: b"EIP1271 FAILED",
        },
        OffchainBody::Raw32 { .. } => Family {
            look: Look::plain(Icon::Blind),
            signed: b"BLIND HASH SIGNED",
            declined: b"BLIND HASH DECLINED",
            failed: b"BLIND HASH FAILED",
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
        // An over-budget message has no pages (the handler refuses it
        // first); 0 then fails the lift's body check.
        OffchainBody::Personal { msg, .. } => super::eip1271::personal_sign_msg_pages(msg).map_or(0, |n| 5 + n),
        OffchainBody::Raw32 { .. } => 6,
    }
}

/// Fills `MSG`, `MSG2`, … screens six lines at a time.
struct MsgScreens {
    lines: [Line; 2 * LINES_PER_PAGE],
    n: usize,
    part: u64,
    label: &'static [u8],
}

impl MsgScreens {
    fn new(label: &'static [u8]) -> Self {
        Self {
            lines: [Line::EMPTY; 2 * LINES_PER_PAGE],
            n: 0,
            part: 0,
            label,
        }
    }

    fn room(&self) -> usize {
        self.lines.len() - self.n
    }

    fn push(&mut self, e: &mut Emit<'_>, line: Line) -> Result<(), ()> {
        if self.room() == 0 {
            self.flush(e)?;
        }
        self.lines[self.n] = line;
        self.n += 1;
        Ok(())
    }

    fn flush(&mut self, e: &mut Emit<'_>) -> Result<(), ()> {
        if self.n == 0 {
            return Ok(());
        }
        self.part += 1;
        let id = if self.part == 1 { Text::new().push(b"MSG") } else { Text::new().push(b"MSG").push_u64(self.part) };
        let l: [(&[u8], Weight); 2 * LINES_PER_PAGE] = core::array::from_fn(|i| (self.lines[i].as_bytes(), Weight::Regular));
        e.detail_multi(id.as_bytes(), self.label, &l[..self.n], false)?;
        self.n = 0;
        Ok(())
    }
}

/// The length of the next screen line of `rest` (non-empty): the longest
/// prefix that fits at the 22 px floor, preferring a break after a space or
/// comma in the second half of the line. `None` when a byte has no glyph.
fn next_line_len(rest: &[u8]) -> Option<usize> {
    let mut k = rest.len();
    while k > 0 && !fits_at_22(&rest[..k], Region::Docked) {
        k -= 1;
    }
    if k == 0 {
        return None;
    }
    if k < rest.len() {
        if let Some(b) = rest[..k].iter().rposition(|c| matches!(c, b',' | b' ')) {
            if b + 1 >= k / 2 {
                k = b + 1;
            }
        }
    }
    Some(k)
}

/// The screen lines one line-feed-separated text line takes (an empty line
/// is one blank line).
fn wrapped_lines(line: &[u8]) -> Option<usize> {
    let (mut rest, mut n) = (line, 0);
    while !rest.is_empty() {
        let k = next_line_len(rest)?;
        rest = &rest[k..];
        n += 1;
    }
    Some(n.max(1))
}

/// Emit the whole message — never truncated. Text: each line feed starts a
/// new line, and a wrapped line of up to three screen lines is kept on one
/// screen (an address, a nonce) rather than split across two. Hex: a loud
/// `! NOT TEXT` screen, then 8 bytes a line.
fn emit_message(e: &mut Emit<'_>, msg: &[u8]) -> Result<(), ()> {
    if msg.len() > sphincs_tz_shared::MAX_OFFCHAIN_PERSONAL_SIGN_LEN {
        return Err(());
    }
    match super::eip1271::personal_sign_view(msg) {
        super::eip1271::MsgView::Text => {
            if msg.is_empty() {
                return e.detail(b"MSG", b"MESSAGE", &[(b"(empty message)", Weight::Regular)], false);
            }
            let mut screens = MsgScreens::new(b"MESSAGE");
            for line in msg.split(|&b| b == b'\n') {
                let n = wrapped_lines(line).ok_or(())?;
                if n <= LINES_PER_PAGE && n > screens.room() {
                    screens.flush(e)?;
                }
                if line.is_empty() {
                    screens.push(e, Line::EMPTY)?;
                }
                let mut rest = line;
                while !rest.is_empty() {
                    let k = next_line_len(rest).ok_or(())?;
                    screens.push(e, Line::new(&rest[..k]).ok_or(())?)?;
                    rest = &rest[k..];
                }
            }
            screens.flush(e)
        }
        super::eip1271::MsgView::Hex => {
            e.detail(
                b"NOTTEXT",
                b"! NOT TEXT",
                &[
                    (b"Message is not text", Weight::Regular),
                    (b"Shown as hex bytes", Weight::Regular),
                    (b"Check it on the dapp", Weight::Regular),
                ],
                true,
            )?;
            let mut screens = MsgScreens::new(b"MESSAGE HEX");
            for chunk in msg.chunks(HEX_BYTES_PER_LINE) {
                let (a, b) = chunk.split_at(chunk.len().min(HEX_BYTES_PER_LINE / 2));
                let mut t = Text::new().push_hex(a);
                if !b.is_empty() {
                    t = t.push(b" ").push_hex(b);
                }
                if !t.ok() || !fits_at_22(t.as_bytes(), Region::Docked) {
                    return Err(());
                }
                screens.push(e, Line::new(t.as_bytes()).ok_or(())?)?;
            }
            screens.flush(e)
        }
    }
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
            emit_message(&mut e, msg)?;
            emit_common_head(&mut e, f)?;
            e.network()?;
            emit_account(&mut e, f)?;
            e.addr_lines(b"SIGNER", b"SIGNER", &layout_address(&addr42(f.wallet)), None)?;
        }
        OffchainBody::Raw32 { hash, .. } => {
            e.hero(b"SIGN", b"SIGN BLIND HASH?")?;
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
            e.word_value(b"HASH", b"HASH", hash)?;
            emit_common_head(&mut e, f)?;
            e.network()?;
            emit_account(&mut e, f)?;
        }
    }
    emit_keys(&mut e, f)?;
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: legacy_pages(body),
    })
}
