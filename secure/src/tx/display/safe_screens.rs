//! Pixel-UI screen emitter for the Safe sign flow — the second painter of
//! "one classification, two painters".
//!
//! `safe_display.rs` classifies a SafeTx once ([`super::safe_display::classify`])
//! and paints 16×4 pages from the decisions. This module paints the SAME
//! decisions as design screens (`pqsigner_ui_px::Screen`, see
//! `tools/pq-ui/pq1/DESIGN.md`): a hero ask, docked details with a label
//! and 1–3 value lines at the largest tier that fits, full-width value
//! screens for 32-byte words, and the returning hero the handler appends.
//!
//! Every signed fact the legacy pages show is shown here too — the host
//! differential test walks the legacy page text and requires every address,
//! amount, nonce and hex word to appear in the screen text verbatim. Where
//! the legacy layout truncated (short-form addresses on dividers and the
//! CoW banner, 16 of 32 data-hash bytes, appData prefix/suffix) the screens
//! show the full value. Nothing here truncates: a value that fits no tier
//! makes the whole emit `Err(())`, which the handler turns into a refusal.
//!
//! Amount formatting reuses the exactness policies of the page painters
//! (`primitives::{exact_fraction_digits, known_native_ticker}` + the
//! zero-collapse guard), so a value the legacy path renders exactly is
//! rendered exactly here — and the same base-unit fallbacks apply.

use super::primitives::{
    amount_is_exact_at_fraction_digits, chain_name, eip55_hex, exact_fraction_digits, format_u64,
    formatted_collapses_to_zero, known_native_ticker, native_ticker, NATIVE_DISPLAY_FRACTION_DIGITS,
};
use super::safe_display::{
    classify, multisend_record_semantics, presign_unique_idx, u64_be_tail, InnerKind,
    SafeRenderFlavour, SafeRenderInput, SafeSemantics, GAS_USED_CEILING,
};
use super::safe_mgmt::{SafeMgmtOp, ThresholdValue};
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::U256;
use crate::tx::eip712::cowswap::{CowLeg, VerifiedCowswapV3};
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::{self, MsRecordIter};
use crate::tx::eip712::safe::{decode_canonical, SafeTx, VerifiedSafeExec, VerifiedSafeV1};
use pqsigner_ui_px::fit::{
    fit_tier, layout_address, layout_amount, layout_name_over_address, split_hash_full,
    split_word_docked, AddrLines, Line, Region,
};
use pqsigner_ui_px::{Icon, Screen, ScreenBuilder, Screens, Side, Weight};
use sphincs_tz_shared::GPV2_VAULT_RELAYER_ADDRESS;

/// What the emitter produced, for the handler's cross-checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SafeBodyReceipt {
    /// Screens appended (the opening hero included; the returning hero and
    /// the auto-inserted `Confirm?` are the lift's business).
    pub(crate) screens: usize,
    /// The legacy page count [`classify`] computed (header + refund +
    /// safeTxGas + inner + confirm footer). The handler requires this to
    /// equal the number of pages the legacy renderer actually produced for
    /// the Safe body, so the two classifications provably agree.
    pub(crate) legacy_pages: usize,
}

/// Emit the screens for a verified `safe_v1` (approveHash) trailer.
pub(crate) fn emit_safe_v1(
    out: &mut Screens,
    safe: &VerifiedSafeV1<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<SafeBodyReceipt, ()> {
    let tx = decode_canonical(&safe.canonical).unwrap_or(SafeTx {
        chain_id: 0,
        safe_address: [0u8; 20],
        to: [0u8; 20],
        value: [0u8; 32],
        data_hash: [0u8; 32],
        operation: 0,
        safe_tx_gas: [0u8; 32],
        base_gas: [0u8; 32],
        gas_price: [0u8; 32],
        gas_token: [0u8; 20],
        refund_receiver: [0u8; 20],
        nonce: [0u8; 32],
    });
    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ApproveHash { nonce: tx.nonce },
        chain_id: tx.chain_id,
        safe_address: tx.safe_address,
        to: tx.to,
        operation: tx.operation,
        value: tx.value,
        raw_data: safe.raw_data,
        data_hash: tx.data_hash,
        gas_price: tx.gas_price,
        gas_token: tx.gas_token,
        refund_receiver: tx.refund_receiver,
        base_gas: tx.base_gas,
        safe_tx_gas: tx.safe_tx_gas,
    };
    emit_inner(out, &input, cow, erc20, resolver)
}

/// Emit the screens for a verified `execTransaction(...)` UserOp.
pub(crate) fn emit_safe_exec(
    out: &mut Screens,
    exec: &VerifiedSafeExec<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<SafeBodyReceipt, ()> {
    let d = &exec.decoded;
    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ExecTransaction,
        chain_id: exec.chain_id,
        safe_address: exec.safe_address,
        to: d.to,
        operation: d.operation,
        value: d.value,
        raw_data: d.data,
        data_hash: keccak(d.data),
        gas_price: d.gas_price,
        gas_token: d.gas_token,
        refund_receiver: d.refund_receiver,
        base_gas: d.base_gas,
        safe_tx_gas: d.safe_tx_gas,
    };
    emit_inner(out, &input, cow, erc20, resolver)
}

/// Screens the emitter will produce for these semantics — the screen-domain
/// twin of `inner_kind_page_count` + `safe_fixed_overhead_pages`, kept in
/// lockstep so the self-check at the end of [`emit_inner`] catches a dropped
/// or duplicated screen.
pub(crate) fn expected_body_screens(sem: &SafeSemantics<'_>) -> usize {
    1 /* hero */ + 1 /* network */ + 1 /* safe acct */ + 1 /* tx info */
        + if sem.refund_active { 3 } else { 0 }
        + usize::from(sem.show_inner_eth)
        + usize::from(sem.show_safe_tx_gas)
        + inner_kind_screens(&sem.inner_kind)
}

fn inner_kind_screens(kind: &InnerKind<'_>) -> usize {
    match kind {
        InnerKind::EmptyCall => 1,
        InnerKind::PlainEth => 2,
        InnerKind::Erc20Known(call) => 4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
        InnerKind::Erc20Unknown(call) => 4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. })),
        InnerKind::SafeMgmt(op) => mgmt_screens(op),
        InnerKind::CowswapPresign(v3) => 1 + cow_body_screens(&v3.sell, &v3.buy),
        InnerKind::UnknownSafeSelf | InnerKind::Blind => 4,
        // Per-record totals are counted while emitting (the record walk is
        // the only place the per-record kinds exist); the emitter's counter
        // is reconciled against `count_multisend_screens` instead.
        InnerKind::MultiSend { .. } => 0,
    }
}

fn mgmt_screens(op: &SafeMgmtOp) -> usize {
    match op {
        SafeMgmtOp::AddOwnerWithThreshold { .. } => 2,
        SafeMgmtOp::RemoveOwner { .. } => 3,
        SafeMgmtOp::SwapOwner { .. } => 2,
        SafeMgmtOp::ChangeThreshold { .. } => 1,
        SafeMgmtOp::EnableModule { .. }
        | SafeMgmtOp::DisableModule { .. }
        | SafeMgmtOp::SetGuard { .. }
        | SafeMgmtOp::SetFallbackHandler { .. } => 2,
    }
}

fn leg_screens(leg: &CowLeg) -> usize {
    match leg {
        CowLeg::Decoded { .. } => 1,
        CowLeg::AddrHex => 2,
    }
}

fn cow_body_screens(sell: &CowLeg, buy: &CowLeg) -> usize {
    leg_screens(sell) + leg_screens(buy) + 1 /* receiver */ + 1 /* expires */ + 1 /* fee */ + 1 /* sources */ + 1 /* appData */
}

// ---------------------------------------------------------------------------
// Emitter state
// ---------------------------------------------------------------------------

struct Emit<'s> {
    out: &'s mut Screens,
    n: usize,
    side: Side,
    chain_id: u64,
}

impl Emit<'_> {
    fn push(&mut self, s: Screen) -> Result<(), ()> {
        self.out.push(&s)?;
        self.n += 1;
        Ok(())
    }

    /// Detail screens alternate the disc column (DESIGN.md `normalize_screens`).
    fn next_side(&mut self) -> Side {
        let s = self.side;
        self.side = match s {
            Side::Left => Side::Right,
            _ => Side::Left,
        };
        s
    }

    fn detail(&mut self, id: &[u8], label: &[u8], lines: &[(&[u8], Weight)], pulse: bool) -> Result<(), ()> {
        self.detail_icon(id, Icon::Safe, label, lines, pulse)
    }

    fn detail_icon(
        &mut self,
        id: &[u8],
        icon: Icon,
        label: &[u8],
        lines: &[(&[u8], Weight)],
        pulse: bool,
    ) -> Result<(), ()> {
        let tier = fit_tier(lines, Region::Docked).ok_or(())?;
        let side = self.next_side();
        let mut b = ScreenBuilder::detail(id, icon, side, label).tier(tier);
        for &(text, w) in lines {
            b = b.line(text, w);
        }
        if pulse {
            b = b.pulse();
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A docked detail whose one value turns two pages (a 32-byte word).
    fn detail_paged(&mut self, id: &[u8], label: &[u8], pages: &[[Line; 2]; 2]) -> Result<(), ()> {
        let p0 = [(pages[0][0].as_bytes(), Weight::Regular), (pages[0][1].as_bytes(), Weight::Regular)];
        let p1 = [(pages[1][0].as_bytes(), Weight::Regular), (pages[1][1].as_bytes(), Weight::Regular)];
        let t0 = fit_tier(&p0, Region::Docked).ok_or(())?;
        let t1 = fit_tier(&p1, Region::Docked).ok_or(())?;
        let tier = t0.min(t1);
        let side = self.next_side();
        let s = ScreenBuilder::detail(id, Icon::Safe, side, label)
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
    fn value(&mut self, id: &[u8], label: &[u8], lines: &[(&[u8], Weight)]) -> Result<(), ()> {
        let tier = fit_tier(lines, Region::Full).ok_or(())?;
        let mut b = ScreenBuilder::value(id, Icon::Safe, label).tier(tier);
        for &(text, w) in lines {
            b = b.line(text, w);
        }
        self.push(b.finish().map_err(|_| ())?)
    }

    /// A 32-byte word as one full-width value screen (3 lines at 22).
    fn word_value(&mut self, id: &[u8], label: &[u8], word: &[u8; 32]) -> Result<(), ()> {
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
    fn addr(&mut self, id: &[u8], label: &[u8], addr: &[u8; 20], resolver: &NameResolver<'_>) -> Result<(), ()> {
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
    fn addr_lines(&mut self, id: &[u8], label: &[u8], a: &AddrLines, head: Option<&[u8]>) -> Result<(), ()> {
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
    fn amount(&mut self, id: &[u8], label: &[u8], amt: &Amount, pulse: bool) -> Result<(), ()> {
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

fn addr42(addr: &[u8; 20]) -> [u8; 42] {
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
struct Amount {
    digits: [u8; 96],
    n: usize,
    unit: [u8; 40],
    unit_len: usize,
}

impl Amount {
    fn digits(&self) -> &[u8] {
        &self.digits[..self.n.min(96)]
    }

    fn unit(&self) -> &[u8] {
        &self.unit[..self.unit_len.min(40)]
    }

    fn new(value: &U256, decimals: u32, frac: u32, unit: &[u8]) -> Option<Self> {
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
fn native_amount(value: &U256, chain_id: u64) -> Option<Amount> {
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
fn native_derived_amount(value: &U256, chain_id: u64) -> Option<Amount> {
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
fn token_amount(value: &U256, decimals: u8, symbol: &[u8]) -> Option<Amount> {
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

/// Raw integer in `units` for a token with no verified metadata.
fn raw_units(value: &U256) -> Option<Amount> {
    Amount::new(value, 0, 0, b"units")
}

// ---------------------------------------------------------------------------
// Small text builders
// ---------------------------------------------------------------------------

/// Fixed-capacity ASCII scratch line.
struct Text {
    buf: [u8; 32],
    n: usize,
}

impl Text {
    const fn new() -> Self {
        Self { buf: [b' '; 32], n: 0 }
    }

    fn push(mut self, s: &[u8]) -> Self {
        let room = self.buf.len().saturating_sub(self.n);
        let k = s.len().min(room);
        self.buf[self.n..self.n + k].copy_from_slice(&s[..k]);
        self.n += k;
        self
    }

    fn push_u64(self, v: u64) -> Self {
        let mut tmp = [0u8; 20];
        let n = format_u64(v, &mut tmp).unwrap_or(0);
        self.push(&tmp[..n])
    }

    fn push_hex(mut self, bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            if self.n + 2 > self.buf.len() {
                break;
            }
            self.buf[self.n] = HEX[usize::from(b >> 4)];
            self.buf[self.n + 1] = HEX[usize::from(b & 0x0F)];
            self.n += 2;
        }
        self
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.n]
    }
}

/// `on Sepolia` for a named chain, `Chain 11155111` otherwise (the numeric
/// id stays the ground truth when there is no advisory name).
fn chain_line(chain_id: u64) -> Text {
    let name = chain_name(chain_id).as_bytes();
    if name == b"(unknown chain)" || name.len() < 3 {
        Text::new().push(b"Chain ").push_u64(chain_id)
    } else {
        Text::new().push(b"on ").push(&name[1..name.len() - 1])
    }
}

fn nonce_line(nonce_be: &[u8; 32]) -> Text {
    let (n, overflow) = u64_be_tail(nonce_be);
    if overflow {
        Text::new().push(b"Nonce: >2^64")
    } else {
        Text::new().push(b"Nonce: ").push_u64(n)
    }
}

fn threshold_line(t: &ThresholdValue) -> Text {
    match *t {
        ThresholdValue::Fits(n) => Text::new().push(b"Threshold: ").push_u64(u64::from(n)),
        ThresholdValue::Overflow => Text::new().push(b"Threshold: >64k"),
    }
}

const LINKED_LIST_SENTINEL: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 0x01;
    a
};

// ---------------------------------------------------------------------------
// The body
// ---------------------------------------------------------------------------

fn emit_inner(
    out: &mut Screens,
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<SafeBodyReceipt, ()> {
    let sem = classify(input, cow, erc20)?;
    let start = out.len();
    let mut e = Emit {
        out,
        n: 0,
        side: Side::Left,
        chain_id: input.chain_id,
    };

    // ── Hero ────────────────────────────────────────────────────────
    let (hero_id, ask): (&[u8], &[u8]) = match input.flavour {
        SafeRenderFlavour::ApproveHash { .. } => (b"APPROVE", b"APPROVE SAFE TX?"),
        SafeRenderFlavour::ExecTransaction => (b"EXECUTE", b"EXECUTE SAFE TX?"),
    };
    e.push(ScreenBuilder::hero(hero_id, Icon::Safe, ask).finish().map_err(|_| ())?)?;

    // ── NETWORK (chain mark, no label) ──────────────────────────────
    let chain = chain_line(input.chain_id);
    e.side = Side::Right;
    e.detail_icon(b"NETWORK", Icon::Chain, b"", &[(chain.as_bytes(), Weight::Regular)], false)?;

    // ── SAFE ACCT ───────────────────────────────────────────────────
    e.addr(b"SAFEACCT", b"SAFE ACCT", &input.safe_address, resolver)?;

    // ── TX INFO: nonce / execute-now + honest op row ────────────────
    let first = match input.flavour {
        SafeRenderFlavour::ApproveHash { nonce } => nonce_line(&nonce),
        SafeRenderFlavour::ExecTransaction => Text::new().push(b"Execute now"),
    };
    let (op, op_loud) = if input.operation == 0 {
        (Text::new().push(b"Op: Call"), false)
    } else if let InnerKind::MultiSend { count, .. } = &sem.inner_kind {
        (Text::new().push(b"Op: MultiSend x").push_u64(*count as u64), false)
    } else {
        (Text::new().push(b"! Op: DELEGATE"), true)
    };
    e.detail(
        b"TXINFO",
        b"TX INFO",
        &[(first.as_bytes(), Weight::Regular), (op.as_bytes(), Weight::Regular)],
        op_loud,
    )?;

    // ── Refund block (3 screens) ────────────────────────────────────
    if sem.refund_active {
        if input.gas_token.iter().all(|&b| b == 0) {
            let t = Text::new().push(native_ticker(input.chain_id)).push(b" (native)");
            e.detail(b"REFUNDTK", b"REFUND TOKEN", &[(t.as_bytes(), Weight::Regular)], true)?;
        } else {
            e.addr(b"REFUNDTK", b"REFUND TOKEN", &input.gas_token, resolver)?;
        }
        let (base_u64, base_overflow) = u64_be_tail(&input.base_gas);
        let gas_units = base_u64.saturating_add(GAS_USED_CEILING);
        let (worst, mul_overflow) = U256(input.gas_price).saturating_mul_u64(gas_units);
        if base_overflow || mul_overflow {
            e.detail(
                b"REFUNDMX",
                b"REFUND MAX",
                &[(b"!HUGE", Weight::Regular), (b"(refuse)", Weight::Regular), (b"at 30M gas est", Weight::Regular)],
                true,
            )?;
        } else {
            let amt = if input.gas_token.iter().all(|&b| b == 0) {
                native_derived_amount(&worst, input.chain_id)
            } else if let Some(m) = erc20.filter(|m| m.contract == input.gas_token) {
                token_amount(&worst, m.decimals, m.symbol)
            } else {
                raw_units(&worst)
            }
            .ok_or(())?;
            let lay = layout_amount(amt.digits(), amt.unit(), Region::Docked).map_err(|_| ())?;
            let disclosure: &[u8] = b"at 30M gas est";
            if lay.n == 1 {
                e.detail(
                    b"REFUNDMX",
                    b"REFUND MAX",
                    &[(lay.lines[0].as_bytes(), Weight::Regular), (disclosure, Weight::Regular)],
                    true,
                )?;
            } else {
                e.detail(
                    b"REFUNDMX",
                    b"REFUND MAX",
                    &[
                        (lay.lines[0].as_bytes(), Weight::Regular),
                        (lay.lines[1].as_bytes(), Weight::Regular),
                        (disclosure, Weight::Regular),
                    ],
                    true,
                )?;
            }
        }
        if input.refund_receiver.iter().all(|&b| b == 0) {
            e.detail(
                b"REFUNDTO",
                b"REFUND TO",
                &[(b"tx.origin", Weight::Regular), (b"whoever executes", Weight::Regular)],
                false,
            )?;
        } else {
            e.addr(b"REFUNDTO", b"REFUND TO", &input.refund_receiver, resolver)?;
        }
    }

    // ── Inner ETH the Safe forwards (non-inline kinds) ──────────────
    let inner_value = U256(input.value);
    if sem.show_inner_eth {
        let amt = native_amount(&inner_value, input.chain_id).ok_or(())?;
        e.amount(b"SAFEVAL", b"SAFE VALUE", &amt, false)?;
    }

    // ── safeTxGas ───────────────────────────────────────────────────
    if sem.show_safe_tx_gas {
        let (units, overflow) = u64_be_tail(&input.safe_tx_gas);
        let g = if overflow {
            Text::new().push(b"!HUGE (>u64)")
        } else {
            Text::new().push_u64(units).push(b" gas")
        };
        e.detail(
            b"SAFETXG",
            b"SAFETX GAS",
            &[(g.as_bytes(), Weight::Regular), (b"inner may no-op", Weight::Regular)],
            true,
        )?;
    }

    // ── Inner call ──────────────────────────────────────────────────
    let expected_inner = match &sem.inner_kind {
        InnerKind::MultiSend { count, .. } => {
            emit_multisend(&mut e, input, *count, cow, erc20, resolver)?
        }
        kind => {
            let ctx = InnerCtx {
                to: input.to,
                value: inner_value,
                data: input.raw_data,
                data_hash: input.data_hash,
                erc20,
            };
            let before = e.n;
            emit_inner_kind(&mut e, kind, &ctx, resolver)?;
            let produced = e.n - before;
            if produced != inner_kind_screens(kind) {
                return Err(());
            }
            produced
        }
    };

    // ── Screen-accounting self-check ────────────────────────────────
    let expected = expected_body_screens(&sem) + expected_inner
        - inner_kind_screens(&sem.inner_kind);
    if e.n != expected || e.out.len() != start + e.n {
        return Err(());
    }
    Ok(SafeBodyReceipt {
        screens: e.n,
        legacy_pages: sem.total_pages,
    })
}

struct InnerCtx<'a> {
    to: [u8; 20],
    value: U256,
    data: &'a [u8],
    data_hash: [u8; 32],
    erc20: Option<&'a Erc20Metadata<'a>>,
}

/// Emit every record of a multiSend batch: divider (`RECORD i/N` + full
/// target), value screen when the kind does not show it inline, then the
/// record's classified screens. Returns the screens emitted.
fn emit_multisend<'a>(
    e: &mut Emit<'_>,
    input: &SafeRenderInput<'a>,
    count: usize,
    cow: Option<&'a VerifiedCowswapV3>,
    erc20: Option<&'a Erc20Metadata<'a>>,
    resolver: &NameResolver<'_>,
) -> Result<usize, ()> {
    let before = e.n;
    let packed = multi_send::decode_multisend(input.raw_data).map_err(|_| ())?;
    let presign_idx = presign_unique_idx(input.raw_data);
    let mut idx = 0usize;
    let mut expected = 0usize;
    for rec in MsRecordIter::new(packed) {
        let rec = rec.map_err(|_| ())?;
        let sem = multisend_record_semantics(input, cow, erc20, presign_idx, idx, rec);
        // Divider: position + FULL target address (the legacy divider showed
        // 6 of 20 bytes; the classified screens repeat it, but full here too).
        let id = Text::new().push(b"RECORD").push_u64(idx as u64 + 1);
        let label = Text::new().push(b"RECORD ").push_u64(idx as u64 + 1).push(b"/").push_u64(count as u64);
        e.addr(id.as_bytes(), label.as_bytes(), &sem.rec.to, resolver)?;
        expected += 1;
        let value = U256(sem.rec.value);
        if sem.needs_value_page {
            let amt = native_amount(&value, input.chain_id).ok_or(())?;
            let id = Text::new().push(b"RECVAL").push_u64(idx as u64 + 1);
            e.amount(id.as_bytes(), b"REC VALUE", &amt, false)?;
            expected += 1;
        }
        let ctx = InnerCtx {
            to: sem.rec.to,
            value,
            data: sem.rec.data,
            data_hash: keccak(sem.rec.data),
            erc20: sem.meta,
        };
        let k_before = e.n;
        emit_inner_kind(e, &sem.kind, &ctx, resolver)?;
        if e.n - k_before != inner_kind_screens(&sem.kind) {
            return Err(());
        }
        expected += inner_kind_screens(&sem.kind);
        idx += 1;
    }
    if idx != count || e.n - before != expected {
        return Err(());
    }
    Ok(expected)
}

fn emit_inner_kind(
    e: &mut Emit<'_>,
    kind: &InnerKind<'_>,
    ctx: &InnerCtx<'_>,
    resolver: &NameResolver<'_>,
) -> Result<(), ()> {
    match kind {
        InnerKind::EmptyCall => e.addr(b"EMPTYCAL", b"EMPTY CALL", &ctx.to, resolver),
        InnerKind::PlainEth => {
            e.addr(b"TO", b"TO", &ctx.to, resolver)?;
            let amt = native_amount(&ctx.value, e.chain_id).ok_or(())?;
            e.amount(b"SEND", b"SEND", &amt, false)
        }
        InnerKind::Erc20Known(call) => {
            let meta = ctx.erc20.ok_or(())?;
            emit_erc20(e, call, Some(meta), ctx, resolver)
        }
        InnerKind::Erc20Unknown(call) => emit_erc20(e, call, None, ctx, resolver),
        InnerKind::Blind => {
            e.detail(
                b"BLINDSGN",
                b"BLIND SIGN",
                &[(b"Can not decode data", Weight::Regular), (b"Confirm on dapp", Weight::Regular)],
                true,
            )?;
            e.addr(b"TO", b"TO", &ctx.to, resolver)?;
            emit_calldata(e, ctx)
        }
        InnerKind::UnknownSafeSelf => {
            e.detail(
                b"UNKNOWOP",
                b"UNKNOWN OP",
                &[(b"Self-call to Safe", Weight::Regular), (b"Verify off-device", Weight::Regular)],
                true,
            )?;
            e.addr(b"TO", b"TO", &ctx.to, resolver)?;
            emit_calldata(e, ctx)
        }
        InnerKind::SafeMgmt(op) => emit_mgmt(e, op, resolver),
        InnerKind::CowswapPresign(v3) => {
            let kind_line: &[u8] = if v3.canonical[168] == 0 { b"SELL order" } else { b"BUY order" };
            e.detail(
                b"COWORDER",
                b"COW ORDER",
                &[(kind_line, Weight::Regular), (b"owner: this Safe", Weight::Regular)],
                false,
            )?;
            emit_cow_body(e, v3)
        }
        InnerKind::MultiSend { .. } => Err(()),
    }
}

/// `CALLDATA` (selector + length) then the full 32-byte data hash.
fn emit_calldata(e: &mut Emit<'_>, ctx: &InnerCtx<'_>) -> Result<(), ()> {
    let sel = if ctx.data.len() >= 4 {
        Text::new().push(b"Function: 0x").push_hex(&ctx.data[..4])
    } else {
        Text::new().push(b"Function: 0x").push_hex(ctx.data)
    };
    let len = Text::new().push(b"Data: ").push_u64(ctx.data.len() as u64).push(b" B");
    e.detail(
        b"CALLDATA",
        b"CALL DATA",
        &[(sel.as_bytes(), Weight::Regular), (len.as_bytes(), Weight::Regular)],
        false,
    )?;
    e.word_value(b"DATAHASH", b"DATA HASH", &ctx.data_hash)
}

fn emit_erc20(
    e: &mut Emit<'_>,
    call: &Erc20Call,
    meta: Option<&Erc20Metadata<'_>>,
    ctx: &InnerCtx<'_>,
    resolver: &NameResolver<'_>,
) -> Result<(), ()> {
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. }
        | Erc20Call::TransferFrom { amount, .. }
        | Erc20Call::Approve { amount, .. } => *amount,
    };
    let unlimited = matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount);
    let verb: &[u8] = match call {
        Erc20Call::Transfer { .. } => b"SEND",
        Erc20Call::TransferFrom { .. } => b"PULL",
        Erc20Call::Approve { .. } => b"APPROVE",
    };
    match meta {
        Some(m) => {
            // AMOUNT (labelled by the verb) then the verified token name.
            if unlimited {
                e.detail(b"AMOUNT", verb, &[(b"unlimited", Weight::Regular)], false)?;
            } else {
                let amt = token_amount(&amount, m.decimals, m.symbol).ok_or(())?;
                e.amount(b"AMOUNT", verb, &amt, false)?;
            }
            let name_fits = fit_tier(&[(m.name, Weight::SemiBold)], Region::Docked).is_some();
            if name_fits && !m.name.is_empty() {
                e.detail(b"TOKEN", b"TOKEN", &[(m.name, Weight::SemiBold)], false)?;
            } else {
                // A name that fits no tier is advisory metadata; the
                // contract screen below is the fact. Keep the screen count
                // exact with the symbol instead.
                e.detail(b"TOKEN", b"TOKEN", &[(m.symbol, Weight::Regular)], false)?;
            }
        }
        None => {
            e.detail(
                b"UNVERIF",
                b"UNVERIFIED",
                &[(b"ERC-20 call", Weight::Regular), (b"token unknown", Weight::Regular)],
                true,
            )?;
            if unlimited {
                e.value(b"RAWAMT", b"RAW AMOUNT", &[(b"unlimited", Weight::Regular)])?;
            } else {
                let amt = raw_units(&amount).ok_or(())?;
                let lay = layout_amount(amt.digits(), amt.unit(), Region::Full).map_err(|_| ())?;
                if lay.n == 1 {
                    e.value(b"RAWAMT", b"RAW AMOUNT", &[(lay.lines[0].as_bytes(), Weight::Regular)])?;
                } else {
                    e.value(
                        b"RAWAMT",
                        b"RAW AMOUNT",
                        &[(lay.lines[0].as_bytes(), Weight::Regular), (lay.lines[1].as_bytes(), Weight::Regular)],
                    )?;
                }
            }
        }
    }
    if let Erc20Call::TransferFrom { from, .. } = call {
        e.addr(b"FROM", b"FROM", from, resolver)?;
    }
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } | Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    match call {
        Erc20Call::Approve { .. } if recipient == GPV2_VAULT_RELAYER_ADDRESS => {
            // Verified human label against the rodata constant.
            let a = layout_address(&addr42(&recipient));
            e.addr_lines(b"SPENDER", b"SPENDER", &a, Some(b"CoW VaultRelayer"))?;
        }
        Erc20Call::Approve { .. } => e.addr(b"SPENDER", b"SPENDER", &recipient, resolver)?,
        _ => e.addr(b"TO", b"TO", &recipient, resolver)?,
    }
    e.addr(b"CONTRACT", b"CONTRACT", &ctx.to, resolver)
}

fn emit_mgmt(e: &mut Emit<'_>, op: &SafeMgmtOp, resolver: &NameResolver<'_>) -> Result<(), ()> {
    let signers = |e: &mut Emit<'_>, t: &ThresholdValue| -> Result<(), ()> {
        let line = threshold_line(t);
        match *t {
            ThresholdValue::Fits(1) => e.detail(
                b"SIGNERS",
                b"SIGNERS",
                &[(line.as_bytes(), Weight::Regular), (b"! MULTISIG OFF", Weight::Regular)],
                true,
            ),
            ThresholdValue::Fits(0) => e.detail(
                b"SIGNERS",
                b"SIGNERS",
                &[(line.as_bytes(), Weight::Regular), (b"! THRESHOLD 0", Weight::Regular)],
                true,
            ),
            _ => e.detail(b"SIGNERS", b"SIGNERS", &[(line.as_bytes(), Weight::Regular)], false),
        }
    };
    let prev = |e: &mut Emit<'_>, id: &[u8], label: &[u8], p: &[u8; 20]| -> Result<(), ()> {
        if *p == LINKED_LIST_SENTINEL {
            e.detail(id, label, &[(b"SENTINEL", Weight::Regular), (b"(list start)", Weight::Regular)], false)
        } else {
            e.addr(id, label, p, resolver)
        }
    };
    match *op {
        SafeMgmtOp::AddOwnerWithThreshold { new_owner, new_threshold } => {
            e.addr(b"NEW", b"NEW OWNER", &new_owner, resolver)?;
            signers(e, &new_threshold)
        }
        SafeMgmtOp::RemoveOwner { prev_owner, owner, new_threshold } => {
            e.addr(b"REMOVING", b"REMOVING", &owner, resolver)?;
            prev(e, b"PREVPTR", b"PREV PTR", &prev_owner)?;
            signers(e, &new_threshold)
        }
        SafeMgmtOp::SwapOwner { old_owner, new_owner, .. } => {
            e.addr(b"OLD", b"OLD OWNER", &old_owner, resolver)?;
            e.addr(b"NEW", b"NEW OWNER", &new_owner, resolver)
        }
        SafeMgmtOp::ChangeThreshold { new_threshold } => signers(e, &new_threshold),
        SafeMgmtOp::EnableModule { module } => {
            e.detail(
                b"ENABLE",
                b"ENABLE",
                &[(b"Grants exec auth", Weight::Regular), (b"to module address", Weight::Regular)],
                true,
            )?;
            e.addr(b"MODULE", b"MODULE", &module, resolver)
        }
        SafeMgmtOp::DisableModule { module, .. } => {
            e.detail(b"DISABLE", b"DISABLE", &[(b"Module loses", Weight::Regular), (b"exec auth", Weight::Regular)], false)?;
            e.addr(b"MODULE", b"MODULE", &module, resolver)
        }
        SafeMgmtOp::SetGuard { guard } => {
            let zero = [0u8; 20];
            let l1: &[u8] = if guard == zero { b"Removing guard" } else { b"Grants veto/log" };
            e.detail(b"GUARD", b"GUARD", &[(l1, Weight::Regular), (b"on every tx", Weight::Regular)], true)?;
            if guard == zero {
                e.detail(b"GUARDADR", b"GUARD ADDR", &[(b"none / cleared", Weight::Regular)], false)
            } else {
                e.addr(b"GUARDADR", b"GUARD ADDR", &guard, resolver)
            }
        }
        SafeMgmtOp::SetFallbackHandler { handler } => {
            let zero = [0u8; 20];
            let l1: &[u8] = if handler == zero { b"Removing fallback" } else { b"Runs unknown calls" };
            e.detail(b"FALLBACK", b"FALLBACK", &[(l1, Weight::Regular)], true)?;
            if handler == zero {
                e.detail(b"HANDLER", b"HANDLER", &[(b"none / cleared", Weight::Regular)], false)
            } else {
                e.addr(b"HANDLER", b"HANDLER", &handler, resolver)
            }
        }
    }
}

// CoW canonical offsets (mirror `cowswap_display.rs`).
const OFF_SELL_TOKEN: usize = 8;
const OFF_BUY_TOKEN: usize = 28;
const OFF_RECEIVER: usize = 48;
const OFF_SELL_AMOUNT: usize = 68;
const OFF_BUY_AMOUNT: usize = 100;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_VALID_TO: usize = 164;
const OFF_KIND: usize = 168;
const OFF_PARTIAL: usize = 169;
const OFF_SELL_TOKEN_BAL: usize = 170;
const OFF_BUY_TOKEN_BAL: usize = 171;
const OFF_APP_DATA: usize = 172;

fn word_at(c: &[u8; 204], off: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w.copy_from_slice(&c[off..off + 32]);
    w
}

fn addr_at(c: &[u8; 204], off: usize) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&c[off..off + 20]);
    a
}

fn emit_cow_leg(e: &mut Emit<'_>, c: &[u8; 204], leg: &CowLeg, sell: bool) -> Result<(), ()> {
    let kind = c[OFF_KIND];
    let (tok_off, amt_off) = if sell { (OFF_SELL_TOKEN, OFF_SELL_AMOUNT) } else { (OFF_BUY_TOKEN, OFF_BUY_AMOUNT) };
    let amount = U256(word_at(c, amt_off));
    // Sell-order: sell exactly / buy at least; buy-order: sell at most / buy exactly.
    let label: &[u8] = match (kind, sell) {
        (0, true) => b"SELL",
        (0, false) => b"BUY MIN",
        (_, true) => b"SELL MAX",
        (_, false) => b"BUY",
    };
    match leg {
        CowLeg::Decoded { decimals, symbol, symbol_len, .. } => {
            let amt = token_amount(&amount, *decimals, &symbol[..usize::from(*symbol_len)]).ok_or(())?;
            let id: &[u8] = if sell { b"SELL" } else { b"BUY" };
            e.amount(id, label, &amt, false)
        }
        CowLeg::AddrHex => {
            let a = layout_address(&addr42(&addr_at(c, tok_off)));
            let (id_tok, id_amt, lbl_tok): (&[u8], &[u8], &[u8]) = if sell {
                (b"SELLTOK", b"SELLAMT", b"SELL TOKEN")
            } else {
                (b"BUYTOK", b"BUYAMT", b"BUY TOKEN")
            };
            e.addr_lines(id_tok, lbl_tok, &a, None)?;
            e.word_value(id_amt, label, &amount.0)
        }
    }
}

fn emit_cow_body(e: &mut Emit<'_>, v3: &VerifiedCowswapV3) -> Result<(), ()> {
    let c = &v3.canonical;
    emit_cow_leg(e, c, &v3.sell, true)?;
    emit_cow_leg(e, c, &v3.buy, false)?;
    // Receiver: zero routes proceeds to the uid owner (= this Safe).
    let receiver = addr_at(c, OFF_RECEIVER);
    if receiver == [0u8; 20] {
        e.detail(b"RECEIVER", b"RECEIVER", &[(b"= the Safe", Weight::Regular)], false)?;
    } else {
        let a = layout_address(&addr42(&receiver));
        e.addr_lines(b"RECEIVER", b"RECEIVER", &a, None)?;
    }
    let valid_to = u32::from_be_bytes([c[OFF_VALID_TO], c[OFF_VALID_TO + 1], c[OFF_VALID_TO + 2], c[OFF_VALID_TO + 3]]);
    let exp = Text::new().push(b"unix ").push_u64(u64::from(valid_to));
    let partial: &[u8] = if c[OFF_PARTIAL] == 0 { b"Partial: no" } else { b"Partial: yes" };
    e.detail(b"EXPIRES", b"EXPIRES", &[(exp.as_bytes(), Weight::Regular), (partial, Weight::Regular)], false)?;
    // Fee in the sell token, full magnitude (a huge fee is a drain).
    let fee = U256(word_at(c, OFF_FEE_AMOUNT));
    let fee_amt = match &v3.sell {
        CowLeg::Decoded { decimals, symbol, symbol_len, .. } => token_amount(&fee, *decimals, &symbol[..usize::from(*symbol_len)]),
        CowLeg::AddrHex => raw_units(&fee),
    }
    .ok_or(())?;
    e.amount(b"FEE", b"FEE (SELL)", &fee_amt, false)?;
    let src: &[u8] = match c[OFF_SELL_TOKEN_BAL] {
        0 => b"sell: erc20",
        1 => b"sell: external",
        2 => b"sell: internal",
        _ => b"sell: ?",
    };
    let dst: &[u8] = match c[OFF_BUY_TOKEN_BAL] {
        0 => b"buy: erc20",
        1 => b"buy: internal",
        _ => b"buy: ?",
    };
    e.detail(b"SOURCES", b"SOURCES", &[(src, Weight::Regular), (dst, Weight::Regular)], false)?;
    let app = word_at(c, OFF_APP_DATA);
    e.detail_paged(b"APPDATA", b"APP DATA", &split_word_docked(&app))
}
