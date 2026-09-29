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

use super::primitives::native_ticker;
use super::screen_kit::{
    addr42, chain_line, native_amount, native_derived_amount, raw_units, token_amount, BodyReceipt, Emit, Text,
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
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::{self, MsRecordIter};
use crate::tx::eip712::safe::{decode_canonical, SafeTx, VerifiedSafeExec, VerifiedSafeV1};
use pqsigner_ui_px::fit::{fit_tier, layout_address, layout_amount, Region};
use pqsigner_ui_px::{Icon, Look, ScreenBuilder, Screens, Side, Weight};
use sphincs_tz_shared::GPV2_VAULT_RELAYER_ADDRESS;

/// What the emitter produced, for the handler's cross-checks. `legacy_pages`
/// is the page count [`classify`] computed (header + refund + safeTxGas +
/// inner + confirm footer); the handler requires it to equal the number of
/// pages the legacy renderer actually produced for the Safe body.
pub(crate) type SafeBodyReceipt = BodyReceipt;

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
        InnerKind::CowswapPresign(v3) => 1 + super::cowswap_screens::order_body_screens(&v3.sell, &v3.buy),
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
    let mut e = Emit::new(out, input.chain_id, Look::SAFE);

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
            super::cowswap_screens::emit_order_body(e, v3, Some(b"= the Safe"))
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

