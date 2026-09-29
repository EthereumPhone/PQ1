//! Shared building blocks of the pixel-UI screen emitters (`*_screens.rs`).
//!
//! Every family emitter paints the facts its page painter already decided
//! as design screens (`tools/pq-ui/pq1/DESIGN.md`): a hero ask, docked
//! details (label + 1–3 lines at the largest tier that fits), full-width
//! value screens for 32-byte words. This module holds what they share — the
//! [`Emit`] cursor, the amount exactness policies of the page painters as
//! strings, the address / chain / nonce text builders and the width-aware
//! wrap — lifted out of the Safe emitter unchanged, so the Safe family
//! (`Look::SAFE`) renders byte-identically.
//!
//! Nothing here truncates: a value that fits no tier is `Err(())`, which
//! every caller turns into a refusal to sign.

use super::primitives::{
    amount_is_exact_at_fraction_digits, chain_name, eip55_hex, exact_fraction_digits, format_u64,
    formatted_collapses_to_zero, known_native_ticker, NATIVE_DISPLAY_FRACTION_DIGITS,
};
use crate::names::NameResolver;
use crate::tx::eip1559::U256;
use pqsigner_ui_px::fit::{
    fit_tier, layout_amount, layout_name_over_address, measure_q6, split_hash_full, AddrLines, Line,
    Region,
};
use pqsigner_ui_px::screen::LINES_PER_PAGE;
use pqsigner_ui_px::{Icon, Look, Screen, ScreenBuilder, Screens, Side, Tier, Weight};

/// What a body emitter produced, for the lift's cross-checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyReceipt {
    /// Screens appended (the opening hero included; the returning hero and
    /// the auto-inserted `Confirm?` are the lift's business).
    pub(crate) screens: usize,
    /// The legacy page count the emitter's own classification predicts for
    /// the route body. The lift requires it to equal the body the page
    /// painter actually produced, so the two classifications provably agree.
    pub(crate) legacy_pages: usize,
}

// ---------------------------------------------------------------------------
// Emitter cursor
// ---------------------------------------------------------------------------

pub(crate) struct Emit<'s> {
    pub(crate) out: &'s mut Screens,
    pub(crate) n: usize,
    pub(crate) side: Side,
    pub(crate) chain_id: u64,
    pub(crate) look: Look,
}

impl<'s> Emit<'s> {
    pub(crate) fn new(out: &'s mut Screens, chain_id: u64, look: Look) -> Self {
        Self {
            out,
            n: 0,
            side: Side::Left,
            chain_id,
            look,
        }
    }

    pub(crate) fn push(&mut self, s: Screen) -> Result<(), ()> {
        self.out.push(&s)?;
        self.n += 1;
        Ok(())
    }

    /// The opening hero ask (index 0); the next detail (NETWORK) docks right.
    pub(crate) fn hero(&mut self, id: &[u8], ask: &[u8]) -> Result<(), ()> {
        let s = ScreenBuilder::hero(id, self.look.icon, ask)
            .look_tint(self.look)
            .finish()
            .map_err(|_| ())?;
        self.push(s)?;
        self.side = Side::Right;
        Ok(())
    }

    /// `NETWORK`: the chain mark and the chain line, no label.
    pub(crate) fn network(&mut self) -> Result<(), ()> {
        let chain = chain_line(self.chain_id);
        self.detail_look(
            b"NETWORK",
            Look::plain(Icon::Chain),
            b"",
            &[(chain.as_bytes(), Weight::Regular)],
            false,
        )
    }

    /// Detail screens alternate the disc column (DESIGN.md `normalize_screens`).
    pub(crate) fn next_side(&mut self) -> Side {
        let s = self.side;
        self.side = match s {
            Side::Left => Side::Right,
            _ => Side::Left,
        };
        s
    }

    pub(crate) fn detail(&mut self, id: &[u8], label: &[u8], lines: &[(&[u8], Weight)], pulse: bool) -> Result<(), ()> {
        self.detail_look(id, self.look, label, lines, pulse)
    }

    pub(crate) fn detail_icon(
        &mut self,
        id: &[u8],
        icon: Icon,
        label: &[u8],
        lines: &[(&[u8], Weight)],
        pulse: bool,
    ) -> Result<(), ()> {
        self.detail_look(id, Look::plain(icon), label, lines, pulse)
    }

    pub(crate) fn detail_look(
        &mut self,
        id: &[u8],
        look: Look,
        label: &[u8],
        lines: &[(&[u8], Weight)],
        pulse: bool,
    ) -> Result<(), ()> {
        let tier = fit_tier(lines, Region::Docked).ok_or(())?;
        let side = self.next_side();
        let mut b = ScreenBuilder::detail(id, look.icon, side, label).look_tint(look).tier(tier);
        for &(text, w) in lines {
            b = b.line(text, w);
        }
        if pulse {
            b = b.pulse();
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A docked detail over 1–6 lines, paged by three; both pages share the
    /// smaller of their fitted tiers.
    pub(crate) fn detail_multi(&mut self, id: &[u8], label: &[u8], lines: &[(&[u8], Weight)], pulse: bool) -> Result<(), ()> {
        if lines.is_empty() || lines.len() > 2 * LINES_PER_PAGE {
            return Err(());
        }
        if lines.len() <= LINES_PER_PAGE {
            return self.detail(id, label, lines, pulse);
        }
        let (p0, p1) = lines.split_at(LINES_PER_PAGE);
        let tier = fit_tier(p0, Region::Docked).ok_or(())?.min(fit_tier(p1, Region::Docked).ok_or(())?);
        let side = self.next_side();
        let mut b = ScreenBuilder::detail(id, self.look.icon, side, label).look_tint(self.look).tier(tier);
        for (i, &(text, w)) in lines.iter().enumerate() {
            if i == LINES_PER_PAGE {
                b = b.next_page();
            }
            b = b.line(text, w);
        }
        if pulse {
            b = b.pulse();
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A docked detail over two explicit pages (1–3 lines each); both
    /// pages share the smaller of their fitted tiers.
    pub(crate) fn detail_two_pages(
        &mut self,
        id: &[u8],
        label: &[u8],
        p0: &[(&[u8], Weight)],
        p1: &[(&[u8], Weight)],
        pulse: bool,
    ) -> Result<(), ()> {
        if p0.is_empty() || p1.is_empty() || p0.len() > LINES_PER_PAGE || p1.len() > LINES_PER_PAGE {
            return Err(());
        }
        let tier = fit_tier(p0, Region::Docked).ok_or(())?.min(fit_tier(p1, Region::Docked).ok_or(())?);
        let side = self.next_side();
        let mut b = ScreenBuilder::detail(id, self.look.icon, side, label).look_tint(self.look).tier(tier);
        for &(text, w) in p0 {
            b = b.line(text, w);
        }
        b = b.next_page();
        for &(text, w) in p1 {
            b = b.line(text, w);
        }
        if pulse {
            b = b.pulse();
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A docked detail whose one value turns two pages (a 32-byte word).
    pub(crate) fn detail_paged(&mut self, id: &[u8], label: &[u8], pages: &[[Line; 2]; 2]) -> Result<(), ()> {
        let p0 = [(pages[0][0].as_bytes(), Weight::Regular), (pages[0][1].as_bytes(), Weight::Regular)];
        let p1 = [(pages[1][0].as_bytes(), Weight::Regular), (pages[1][1].as_bytes(), Weight::Regular)];
        let t0 = fit_tier(&p0, Region::Docked).ok_or(())?;
        let t1 = fit_tier(&p1, Region::Docked).ok_or(())?;
        let tier = t0.min(t1);
        let side = self.next_side();
        let s = ScreenBuilder::detail(id, self.look.icon, side, label)
            .look_tint(self.look)
            .tier(tier)
            .line(p0[0].0, Weight::Regular)
            .line(p0[1].0, Weight::Regular)
            .next_page()
            .line(p1[0].0, Weight::Regular)
            .line(p1[1].0, Weight::Regular)
            .finish()
            .map_err(|_| ())?;
        self.push(s)
    }

    /// Full-width value screen (disc parked off-panel).
    pub(crate) fn value(&mut self, id: &[u8], label: &[u8], lines: &[(&[u8], Weight)]) -> Result<(), ()> {
        let tier = fit_tier(lines, Region::Full).ok_or(())?;
        let mut b = ScreenBuilder::value(id, self.look.icon, label).look_tint(self.look).tier(tier);
        for &(text, w) in lines {
            b = b.line(text, w);
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A 32-byte word as one full-width value screen (3 lines at 22).
    pub(crate) fn word_value(&mut self, id: &[u8], label: &[u8], word: &[u8; 32]) -> Result<(), ()> {
        let [a, b, c] = split_hash_full(word);
        self.value(
            id,
            label,
            &[
                (a.as_bytes(), Weight::Regular),
                (b.as_bytes(), Weight::Regular),
                (c.as_bytes(), Weight::Regular),
            ],
        )
    }

    /// An address detail: resolved name (SemiBold, when it fits) over the
    /// two EIP-55 address halves.
    pub(crate) fn addr(&mut self, id: &[u8], label: &[u8], addr: &[u8; 20], resolver: &NameResolver<'_>) -> Result<(), ()> {
        let addr42 = addr42(addr);
        let na = layout_name_over_address(resolver.lookup(self.chain_id, addr), &addr42);
        match na.name {
            Some(name) => self.detail(
                id,
                label,
                &[
                    (name.as_bytes(), Weight::SemiBold),
                    (na.addr.lines[0].as_bytes(), Weight::Regular),
                    (na.addr.lines[1].as_bytes(), Weight::Regular),
                ],
                false,
            ),
            None => self.addr_lines(id, label, &na.addr, None),
        }
    }

    /// A docked address (2 or 3 lines), optionally headed by a fixed
    /// `SemiBold` label line (only when the address takes two lines).
    pub(crate) fn addr_lines(&mut self, id: &[u8], label: &[u8], a: &AddrLines, head: Option<&[u8]>) -> Result<(), ()> {
        let l = a.as_slice();
        match (head, l.len()) {
            (Some(h), 2) => self.detail(
                id,
                label,
                &[(h, Weight::SemiBold), (l[0].as_bytes(), Weight::Regular), (l[1].as_bytes(), Weight::Regular)],
                false,
            ),
            (_, 2) => self.detail(
                id,
                label,
                &[(l[0].as_bytes(), Weight::Regular), (l[1].as_bytes(), Weight::Regular)],
                false,
            ),
            _ => self.detail(
                id,
                label,
                &[
                    (l[0].as_bytes(), Weight::Regular),
                    (l[1].as_bytes(), Weight::Regular),
                    (l[2].as_bytes(), Weight::Regular),
                ],
                false,
            ),
        }
    }

    /// An amount detail: number + unit on one line when a one-line tier
    /// fits, else number / unit.
    pub(crate) fn amount(&mut self, id: &[u8], label: &[u8], amt: &Amount, pulse: bool) -> Result<(), ()> {
        let lay = layout_amount(amt.digits(), amt.unit(), Region::Docked).map_err(|_| ())?;
        if lay.n == 1 {
            self.detail(id, label, &[(lay.lines[0].as_bytes(), Weight::Regular)], pulse)
        } else {
            self.detail(
                id,
                label,
                &[(lay.lines[0].as_bytes(), Weight::Regular), (lay.lines[1].as_bytes(), Weight::Regular)],
                pulse,
            )
        }
    }
}

pub(crate) fn addr42(addr: &[u8; 20]) -> [u8; 42] {
    let mut out = [0u8; 42];
    out[0] = b'0';
    out[1] = b'x';
    out[2..].copy_from_slice(&eip55_hex(addr));
    out
}

// ---------------------------------------------------------------------------
// Amount formatting — the page painters' exactness policies as strings
// ---------------------------------------------------------------------------

/// A formatted amount: decimal digits (no unit) and the unit label.
pub(crate) struct Amount {
    digits: [u8; 96],
    n: usize,
    unit: [u8; 40],
    unit_len: usize,
}

impl Amount {
    pub(crate) fn digits(&self) -> &[u8] {
        &self.digits[..self.n.min(96)]
    }

    pub(crate) fn unit(&self) -> &[u8] {
        &self.unit[..self.unit_len.min(40)]
    }

    pub(crate) fn new(value: &U256, decimals: u32, frac: u32, unit: &[u8]) -> Option<Self> {
        let mut a = Self {
            digits: [0u8; 96],
            n: 0,
            unit: [0u8; 40],
            unit_len: 0,
        };
        a.n = value.format_decimal(decimals, frac, false, &mut a.digits)?;
        if unit.len() > a.unit.len() {
            return None;
        }
        a.unit[..unit.len()].copy_from_slice(unit);
        a.unit_len = unit.len();
        Some(a)
    }
}

/// `write_native_amount_two_rows`' policy: a known chain shows the stable
/// six-decimal ticker form when exact, else the exact integer in `wei`; an
/// unknown chain shows the exact integer as `raw`.
pub(crate) fn native_amount(value: &U256, chain_id: u64) -> Option<Amount> {
    match known_native_ticker(chain_id) {
        None => Amount::new(value, 0, 0, b"raw"),
        Some(unit) => {
            if amount_is_exact_at_fraction_digits(value, 18, NATIVE_DISPLAY_FRACTION_DIGITS) {
                if let Some(a) = Amount::new(value, 18, NATIVE_DISPLAY_FRACTION_DIGITS, unit) {
                    if !formatted_collapses_to_zero(value, a.digits()) {
                        return Some(a);
                    }
                }
            }
            Amount::new(value, 0, 0, b"wei")
        }
    }
}

/// `write_native_derived_amount_two_rows`' policy: a derived bound may widen
/// the fraction (6..=18) before the exact-wei fallback.
pub(crate) fn native_derived_amount(value: &U256, chain_id: u64) -> Option<Amount> {
    let Some(unit) = known_native_ticker(chain_id) else {
        return native_amount(value, chain_id);
    };
    if let Some(frac) = exact_fraction_digits(value, 18, NATIVE_DISPLAY_FRACTION_DIGITS, 18) {
        if let Some(a) = Amount::new(value, 18, frac, unit) {
            if !formatted_collapses_to_zero(value, a.digits()) {
                return Some(a);
            }
        }
    }
    native_amount(value, chain_id)
}

/// `write_token_amount_two_rows`' policy: six fractional digits widened up
/// to 18 to stay exact, else the signed integer in labelled base units.
pub(crate) fn token_amount(value: &U256, decimals: u8, symbol: &[u8]) -> Option<Amount> {
    if let Some(frac) = exact_fraction_digits(value, u32::from(decimals), 6, 18) {
        if let Some(a) = Amount::new(value, u32::from(decimals), frac, symbol) {
            if !formatted_collapses_to_zero(value, a.digits()) {
                return Some(a);
            }
        }
    }
    let mut base = [0u8; 40];
    const PREFIX: &[u8] = b"base ";
    if PREFIX.len() + symbol.len() > base.len() {
        return None;
    }
    base[..PREFIX.len()].copy_from_slice(PREFIX);
    base[PREFIX.len()..PREFIX.len() + symbol.len()].copy_from_slice(symbol);
    Amount::new(value, 0, 0, &base[..PREFIX.len() + symbol.len()])
}

/// A verified token amount in the representation its page painter chose
/// (`write_token_amount_two_rows`): the widened exact fraction, or — when
/// that did not fit the page — the integer in labelled base units. `None`
/// where the page could not render it exactly (the dispatcher refused).
pub(crate) fn token_amount_as_page(value: &U256, meta: &crate::erc20::bundle::Erc20Metadata<'_>) -> Option<Amount> {
    use super::primitives::{write_token_amount_two_rows, AmountFit};
    use crate::ui::DISPLAY_COLS;
    let mut r1 = [b' '; DISPLAY_COLS];
    let mut r2 = [b' '; DISPLAY_COLS];
    if write_token_amount_two_rows(&mut r1, &mut r2, value, meta) != AmountFit::Full {
        return None;
    }
    let base = r1.windows(5).chain(r2.windows(5)).any(|w| w == b"base ");
    if base {
        let mut unit = [0u8; 40];
        const PREFIX: &[u8] = b"base ";
        if PREFIX.len() + meta.symbol.len() > unit.len() {
            return None;
        }
        unit[..PREFIX.len()].copy_from_slice(PREFIX);
        unit[PREFIX.len()..PREFIX.len() + meta.symbol.len()].copy_from_slice(meta.symbol);
        Amount::new(value, 0, 0, &unit[..PREFIX.len() + meta.symbol.len()])
    } else {
        token_amount(value, meta.decimals, meta.symbol)
    }
}

/// Raw integer in `units` for a token with no verified metadata.
pub(crate) fn raw_units(value: &U256) -> Option<Amount> {
    Amount::new(value, 0, 0, b"units")
}

// ---------------------------------------------------------------------------
// Small text builders
// ---------------------------------------------------------------------------

/// Fixed-capacity ASCII scratch line.
pub(crate) struct Text {
    buf: [u8; 32],
    n: usize,
}

impl Text {
    pub(crate) const fn new() -> Self {
        Self { buf: [b' '; 32], n: 0 }
    }

    /// Append; `ok()` turns false if anything did not fit (callers that
    /// build a value — not a fixed label — must check it).
    pub(crate) fn push(mut self, s: &[u8]) -> Self {
        if self.n > self.buf.len() {
            return self;
        }
        let room = self.buf.len().saturating_sub(self.n);
        let k = s.len().min(room);
        self.buf[self.n..self.n + k].copy_from_slice(&s[..k]);
        self.n += k;
        if k < s.len() {
            self.n = usize::MAX;
        }
        self
    }

    pub(crate) fn push_u64(self, v: u64) -> Self {
        let mut tmp = [0u8; 20];
        let n = format_u64(v, &mut tmp).unwrap_or(0);
        self.push(&tmp[..n])
    }

    pub(crate) fn push_hex(mut self, bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            if self.n > self.buf.len() {
                break;
            }
            if self.n + 2 > self.buf.len() {
                self.n = usize::MAX;
                break;
            }
            self.buf[self.n] = HEX[usize::from(b >> 4)];
            self.buf[self.n + 1] = HEX[usize::from(b & 0x0F)];
            self.n += 2;
        }
        self
    }

    /// Everything pushed fitted.
    pub(crate) fn ok(&self) -> bool {
        self.n <= self.buf.len()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.n.min(self.buf.len())]
    }
}

/// `on Sepolia` for a named chain, `Chain 11155111` otherwise (the numeric
/// id stays the ground truth when there is no advisory name).
pub(crate) fn chain_line(chain_id: u64) -> Text {
    let name = chain_name(chain_id).as_bytes();
    if name == b"(unknown chain)" || name.len() < 3 {
        Text::new().push(b"Chain ").push_u64(chain_id)
    } else {
        Text::new().push(b"on ").push(&name[1..name.len() - 1])
    }
}

// ---------------------------------------------------------------------------
// Width-aware wrap and caption fit
// ---------------------------------------------------------------------------

/// Up to six wrapped lines.
pub(crate) struct Wrapped {
    pub(crate) lines: [Line; 2 * LINES_PER_PAGE],
    pub(crate) n: usize,
}

impl Wrapped {
    pub(crate) fn as_slice(&self) -> &[Line] {
        &self.lines[..self.n.min(self.lines.len())]
    }
}

pub(crate) fn fits_at_22(text: &[u8], region: Region) -> bool {
    text.len() <= region.chars(Tier::T22)
        && measure_q6(text, 22, false, 0).is_some_and(|w| w <= region.width_px() * 64)
}

/// Break `text` into the fewest lines that each fit `region` at the 22 tier
/// (the floor), preferring a break after `,` / `(` / space in the second
/// half of a line. `None` when a byte has no glyph or more than six lines
/// are needed — never a truncation.
pub(crate) fn wrap(text: &[u8], region: Region) -> Option<Wrapped> {
    let mut w = Wrapped {
        lines: [Line::EMPTY; 2 * LINES_PER_PAGE],
        n: 0,
    };
    let mut rest = text;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        if w.n >= w.lines.len() {
            return None;
        }
        // Longest prefix that fits.
        let mut k = rest.len();
        while k > 0 && !fits_at_22(&rest[..k], region) {
            k -= 1;
        }
        if k == 0 {
            return None;
        }
        if k < rest.len() {
            if let Some(b) = rest[..k].iter().rposition(|c| matches!(c, b',' | b'(' | b' ')) {
                if b + 1 >= k / 2 {
                    k = b + 1;
                }
            }
        }
        w.lines[w.n] = Line::new(&rest[..k])?;
        w.n += 1;
        rest = &rest[k..];
    }
    Some(w)
}

/// Whether `caption` renders on the hero band: every byte has a glyph in
/// the 18 px caps tier and the tracked width fits the panel.
pub(crate) fn caption_fits(caption: &[u8]) -> bool {
    use pqsigner_ui_px::screen::CAPTION_LEN;
    caption.len() <= CAPTION_LEN
        && measure_q6(caption, 18, false, 32).is_some_and(|w| w <= Region::Full.width_px() * 64)
}

/// The DESIGN.md look for a token by its verified symbol: logo art for the
/// tokens the atlas carries, the ether mark on the mono body for ETH /
/// WETH, otherwise the ether mark on the placeholder ramp hashed from the
/// symbol (`components.token_defaults`).
pub(crate) fn token_look(symbol: &[u8]) -> Look {
    match symbol {
        b"USDC" => Look::plain(Icon::Usdc),
        b"USDT" => Look::plain(Icon::Usdt),
        b"DAI" => Look::plain(Icon::Dai),
        b"ETH" | b"WETH" => Look::plain(Icon::Eth),
        _ => Look {
            icon: Icon::Eth,
            tint: Some(pqsigner_ui_px::placeholder_ramp(symbol)),
        },
    }
}

/// The look for a value the device only knows by its address (an unknown
/// token, an undecoded call's target): the placeholder ramp hashed from the
/// EIP-55 address string, like the design reference.
pub(crate) fn address_look(icon: Icon, addr: &[u8; 20]) -> Look {
    Look {
        icon,
        tint: Some(pqsigner_ui_px::placeholder_ramp(&addr42(addr))),
    }
}
