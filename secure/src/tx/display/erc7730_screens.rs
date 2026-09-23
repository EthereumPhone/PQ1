//! Pixel-UI screens for an authenticated ERC-7730 render — contract calls
//! (upstream flow `erc7730/swap`) and EIP-712 typed data on the off-chain
//! path.
//!
//! The ERC-7730 renderer (`pqsigner_erc7730::display::render`, ~13k lines,
//! fifteen `FormatOp` painters) already decides what is shown and proves it:
//! the dispatcher renders it twice into one buffer and compares transcript
//! receipts, and the handler re-checks the renderer range right before the
//! confirmation. This module reads that PROVEN page range and re-lays it out
//! in the design, page for page — the facts on the screens are the facts on
//! the pages by construction, so the audited renderer is not touched (port
//! plan step 3; the planned in-renderer `Screens` sink was dropped for this
//! reason).
//!
//! ```text
//!  SIGN <INTENT>?                 hero (the intent page's own text)
//!  INTENT                         intent / owner / contract name, verbatim
//!  <field pages>                  row 0 = the field label, rows 1-3 = value
//!  NETWORK · fee pages · nonce    the renderer's envelope pages
//! ```
//!
//! Per page: navigation rows (`> next`, `1/2 > next`, `L=Cancel`, …) are
//! dropped (the design has its own chevrons); an address the page split
//! over three 16-column rows (`0x` + 14 / 16 / 10 hex) is re-joined and laid
//! out as an EIP-55 address; a row-0 label that the 16 px caps tier can
//! render in twelve cells becomes the screen label, otherwise it stays a
//! SemiBold first line. Every other row is a line, verbatim. The trailing
//! confirm page has no screen (the returning hero and `Confirm?` replace it).

use super::screen_kit::{addr42, caption_fits, wrap, BodyReceipt, Emit, Text};
use super::userop_screens::Family;
use super::Pages;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use pqsigner_ui_px::fit::{layout_address, measure_q6, Line, Region};
use pqsigner_ui_px::screen::LABEL_LEN;
use pqsigner_ui_px::{Icon, Look, Screens, Weight};

type Page = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Which ERC-7730 surface the pages came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    /// A contract call (`CMD_SIGN_USEROP`): the disc is hashed from the
    /// target contract.
    Contract,
    /// EIP-712 typed data (`CMD_SIGN_OFFCHAIN`): hashed from the verifying
    /// contract.
    Typed,
}

/// The family for a render against `contract` (target or verifying
/// contract): the ether mark on the placeholder ramp hashed from its EIP-55
/// address, like the design reference's `erc7730/swap`.
pub(crate) fn family(surface: Surface, contract: &[u8; 20]) -> Family {
    let look = Look {
        icon: Icon::Eth,
        tint: Some(pqsigner_ui_px::placeholder_ramp(&addr42(contract))),
    };
    match surface {
        Surface::Contract => Family {
            look,
            signed: b"TRANSACTION SIGNED",
            declined: b"TRANSACTION DECLINED",
        },
        Surface::Typed => Family {
            look,
            signed: b"MESSAGE SIGNED",
            declined: b"MESSAGE DECLINED",
        },
    }
}

fn trimmed(row: &[u8; DISPLAY_COLS]) -> &[u8] {
    let mut n = DISPLAY_COLS;
    while n > 0 && row[n - 1] == b' ' {
        n -= 1;
    }
    let mut s = 0;
    while s < n && row[s] == b' ' {
        s += 1;
    }
    &row[s..n]
}

/// Instruction vocabulary the design replaces with its own chevrons and
/// hold grammar.
pub(crate) fn is_nav_row(row: &[u8]) -> bool {
    row.starts_with(b"> ")
        || row.ends_with(b"> next")
        || row.ends_with(b"> sign")
        || matches!(
            row,
            b"L=Cancel" | b"R=Confirm" | b"Long-press:" | b"Long-press to" | b"L cancel/R sign" | b"Long-right" | b"to confirm"
        )
}

/// The renderer's final confirm page (`append_confirm_page`): nothing but
/// navigation.
pub(crate) fn is_confirm_page(page: &Page) -> bool {
    page.iter().all(|r| {
        let t = trimmed(r);
        t.is_empty() || is_nav_row(t)
    })
}

fn is_hex(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_hexdigit)
}

/// `write_addr_full`'s three rows: `0x` + 14 hex / 16 hex / 10 hex.
fn joined_address(a: &[u8], b: &[u8], c: &[u8]) -> Option<[u8; 42]> {
    if a.len() == 16 && a.starts_with(b"0x") && is_hex(&a[2..]) && b.len() == 16 && is_hex(b) && c.len() == 10 && is_hex(c)
    {
        let mut out = [0u8; 42];
        out[..16].copy_from_slice(a);
        out[16..32].copy_from_slice(b);
        out[32..].copy_from_slice(c);
        Some(out)
    } else {
        None
    }
}

/// `text` upper-cased into a screen label, when it renders there (twelve
/// cells, the 16 px caps tier).
fn as_label(text: &[u8]) -> Option<([u8; LABEL_LEN], usize)> {
    if text.is_empty() || text.len() > LABEL_LEN {
        return None;
    }
    let mut up = [0u8; LABEL_LEN];
    for (d, s) in up.iter_mut().zip(text) {
        *d = s.to_ascii_uppercase();
    }
    measure_q6(&up[..text.len()], 16, true, 0).map(|_| (up, text.len()))
}

/// Up to six design lines assembled from one page.
struct PageLines {
    lines: [Line; 6],
    weights: [Weight; 6],
    n: usize,
}

impl PageLines {
    fn push(&mut self, text: &[u8], w: Weight) -> Result<(), ()> {
        if self.n >= self.lines.len() {
            return Err(());
        }
        self.lines[self.n] = Line::new(text).ok_or(())?;
        self.weights[self.n] = w;
        self.n += 1;
        Ok(())
    }
}

/// Lay out the content rows `rows` (row 0 label excluded when it became the
/// screen label) as lines, re-joining split addresses.
fn page_lines(rows: &[&[u8]], head: Option<&[u8]>) -> Result<PageLines, ()> {
    let mut out = PageLines {
        lines: [Line::EMPTY; 6],
        weights: [Weight::Regular; 6],
        n: 0,
    };
    if let Some(h) = head {
        out.push(h, Weight::SemiBold)?;
    }
    let mut i = 0;
    while i < rows.len() {
        if i + 2 < rows.len() {
            if let Some(addr) = joined_address(rows[i], rows[i + 1], rows[i + 2]) {
                for l in layout_address(&addr).as_slice() {
                    out.push(l.as_bytes(), Weight::Regular)?;
                }
                i += 3;
                continue;
            }
        }
        out.push(rows[i], Weight::Regular)?;
        i += 1;
    }
    Ok(out)
}

/// The intent text the intent page shows: row 0 alone for a short intent
/// (< 16 cells); a long one continues on row 1 unbroken
/// (`build_intent_page`), so rows 0 + 1 join. `None` when row 1 carries the
/// `~` overflow marker (the page itself could not show it all).
fn intent_text(intent: &Page) -> Option<([u8; 2 * DISPLAY_COLS], usize, usize)> {
    let r0 = trimmed(&intent[0]);
    let r1 = trimmed(&intent[1]);
    let mut out = [0u8; 2 * DISPLAY_COLS];
    if r0.len() < DISPLAY_COLS {
        out[..r0.len()].copy_from_slice(r0);
        Some((out, r0.len(), 1))
    } else if !r1.contains(&b'~') {
        out[..r0.len()].copy_from_slice(r0);
        out[r0.len()..r0.len() + r1.len()].copy_from_slice(r1);
        Some((out, r0.len() + r1.len(), 2))
    } else {
        None
    }
}

/// The `SIGN <INTENT>?` caption from the intent page, when its text is
/// unambiguous and renders on the hero band; otherwise a fixed ask.
fn hero_caption(intent: &Page) -> Text {
    if let Some((text, n, _)) = intent_text(intent) {
        let t = Text::new().push(b"SIGN ").push(&text[..n]).push(b"?");
        if t.ok() {
            let mut up = [0u8; 32];
            let b = t.as_bytes();
            for (d, s) in up.iter_mut().zip(b) {
                *d = s.to_ascii_uppercase();
            }
            let upper = Text::new().push(&up[..b.len()]);
            if upper.ok() && caption_fits(upper.as_bytes()) {
                return upper;
            }
        }
    }
    Text::new().push(b"CONFIRM CLEAR SIGN?")
}

/// The INTENT screen: the intent (joined like the caption, wrapped) in
/// SemiBold, then the page's remaining rows (owner / contract name).
fn emit_intent(e: &mut Emit<'_>, intent: &Page) -> Result<(), ()> {
    let mut l: [(&[u8], Weight); 6] = [(&[], Weight::Regular); 6];
    let mut n = 0;
    let (text, len, used) = intent_text(intent).unwrap_or(([0u8; 2 * DISPLAY_COLS], 0, 0));
    let wrapped;
    if used > 0 {
        wrapped = wrap(&text[..len], Region::Docked).ok_or(())?;
        for line in wrapped.as_slice() {
            *l.get_mut(n).ok_or(())? = (line.as_bytes(), Weight::SemiBold);
            n += 1;
        }
    }
    for (r, row) in intent.iter().enumerate().skip(used) {
        let t = trimmed(row);
        if t.is_empty() || is_nav_row(t) {
            continue;
        }
        *l.get_mut(n).ok_or(())? = (t, if r == 0 { Weight::SemiBold } else { Weight::Regular });
        n += 1;
    }
    e.detail_multi(b"INTENT", b"INTENT", &l[..n], false)
}

fn page_id(i: usize) -> Text {
    Text::new().push(b"F").push_u64(i as u64)
}

/// Emit the screens for the proven ERC-7730 page range
/// `pages[start..start + body_len]` (its last page is the renderer's confirm
/// page).
pub(crate) fn emit(out: &mut Screens, pages: &Pages, start: usize, body_len: usize, chain_id: u64, fam: Family) -> Result<BodyReceipt, ()> {
    let end = start.checked_add(body_len).ok_or(())?;
    if body_len < 2 || end > pages.len || !is_confirm_page(&pages.buf[end - 1]) {
        return Err(());
    }
    let body = &pages.buf[start..end - 1];
    let mut e = Emit::new(out, chain_id, fam.look);
    // The optional dev-build warning precedes the intent page.
    let intent_at = usize::from(trimmed(&body[0][0]) == b"** DEV BUILD **");
    let intent = body.get(intent_at).ok_or(())?;
    e.hero(b"SIGN", hero_caption(intent).as_bytes())?;
    let mut skip_next = false;
    for (i, page) in body.iter().enumerate() {
        if core::mem::take(&mut skip_next) {
            continue;
        }
        // A 32-byte word the renderer split over a `1/2` / `2/2` page pair
        // (same label row) is ONE two-page screen: the pager keeps the order.
        // Likewise the envelope's full 256-bit UserOp nonce: three hex rows
        // under `Nonce (hex):`, the fourth alone on the next page.
        if i > intent_at && trimmed(&page[0]) == b"Nonce (hex):" {
            if let Some(next) = body.get(i + 1) {
                let tail = trimmed(&next[0]);
                if tail.len() == DISPLAY_COLS && is_hex(tail) && next[1..3].iter().all(|r| trimmed(r).is_empty()) {
                    let p0 = [
                        (trimmed(&page[1]), Weight::Regular),
                        (trimmed(&page[2]), Weight::Regular),
                        (trimmed(&page[3]), Weight::Regular),
                    ];
                    e.detail_two_pages(b"NONCE", b"NONCE (HEX)", &p0, &[(tail, Weight::Regular)], false)?;
                    skip_next = true;
                    continue;
                }
            }
        }
        if i > intent_at && trimmed(&page[3]) == b"1/2 > next" {
            if let Some(next) = body.get(i + 1) {
                if trimmed(&next[3]) == b"2/2 > next" && next[0] == page[0] {
                    let l0 = trimmed(&page[0]);
                    let label = as_label(l0.strip_suffix(b":").unwrap_or(l0));
                    let (lbl, head): (&[u8], Option<&[u8]>) = match &label {
                        Some((up, n)) => (&up[..*n], None),
                        None => (b"", Some(l0)),
                    };
                    let mut p0: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
                    let mut p1: [(&[u8], Weight); 3] = [(&[], Weight::Regular); 3];
                    let mut n0 = 0;
                    if let Some(h) = head {
                        p0[0] = (h, Weight::SemiBold);
                        n0 = 1;
                    }
                    for r in &page[1..3] {
                        let t = trimmed(r);
                        if !t.is_empty() {
                            *p0.get_mut(n0).ok_or(())? = (t, Weight::Regular);
                            n0 += 1;
                        }
                    }
                    let mut n1 = 0;
                    for r in &next[1..3] {
                        let t = trimmed(r);
                        if !t.is_empty() {
                            p1[n1] = (t, Weight::Regular);
                            n1 += 1;
                        }
                    }
                    e.detail_two_pages(page_id(i).as_bytes(), lbl, &p0[..n0], &p1[..n1], false)?;
                    skip_next = true;
                    continue;
                }
            }
        }
        let mut rows: [&[u8]; DISPLAY_ROWS] = [&[]; DISPLAY_ROWS];
        let mut n = 0;
        let mut row0_is_label = false;
        for (r, row) in page.iter().enumerate() {
            let t = trimmed(row);
            if t.is_empty() || is_nav_row(t) {
                continue;
            }
            if r == 0 {
                row0_is_label = true;
            }
            rows[n] = t;
            n += 1;
        }
        let rows = &rows[..n];
        if rows.is_empty() {
            return Err(());
        }
        if i < intent_at {
            let lines = page_lines(&rows[1..], None)?;
            let l: [(&[u8], Weight); 6] = core::array::from_fn(|k| (lines.lines[k].as_bytes(), lines.weights[k]));
            e.detail(b"DEV", b"! DEV BUILD", &l[..lines.n], true)?;
            continue;
        }
        if i == intent_at {
            emit_intent(&mut e, page)?;
            continue;
        }
        // The renderer's `Network:` page is the design's NETWORK screen
        // (the chain line from the same id).
        if row0_is_label && rows[0] == b"Network:" {
            e.network()?;
            continue;
        }
        let (label, head, rest): (Option<([u8; LABEL_LEN], usize)>, Option<&[u8]>, &[&[u8]]) = if row0_is_label {
            match as_label(rows[0].strip_suffix(b":").unwrap_or(rows[0])) {
                Some(l) => (Some(l), None, &rows[1..]),
                None => (None, Some(rows[0]), &rows[1..]),
            }
        } else {
            (None, None, rows)
        };
        let label: &[u8] = match &label {
            Some((up, n)) => &up[..*n],
            None => b"",
        };
        let lines = page_lines(rest, head)?;
        if lines.n == 0 {
            // A label with no value rows: the label is the content.
            let only = [(rows[0], Weight::SemiBold)];
            e.detail(page_id(i).as_bytes(), b"", &only, false)?;
            continue;
        }
        let l: [(&[u8], Weight); 6] = core::array::from_fn(|k| (lines.lines[k].as_bytes(), lines.weights[k]));
        e.detail_multi(page_id(i).as_bytes(), label, &l[..lines.n], false)?;
    }
    Ok(BodyReceipt {
        screens: e.n,
        legacy_pages: body_len,
    })
}
