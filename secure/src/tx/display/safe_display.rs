//! Trust level — Safe-multisig `approveHash` clear-sign.
//!
//! Rendered when the gateway receives a `safe_v1` trailer that has
//! passed every cross-check in
//! `crate::tx::eip712::safe::verify_and_bind_trailer`. At that point
//! the firmware has cryptographically-bound `(canonical SafeTx,
//! raw_data)` so the renderer can show the inner transaction's
//! semantic content alongside the Safe-level metadata that distinguish
//! "approving a Safe tx" from "calling something directly".
//!
//! Page layout (variable, capped at [`super::MAX_PAGES`]):
//!
//! ```text
//!   0: "Approve Safe TX"     1: "Safe:"             2: "SafeTx #N"
//!      Chain: <n>                <addr full>            Op: Call
//!      <chain name>              <addr full>            <inner kind hint>
//!      > next                    <addr full>            > next
//!
//!   refund (3 pages, only when a gas refund is configured — i.e. any of
//!          gasPrice / gasToken / refundReceiver is non-zero):
//!          A: "! GAS REFUND" + "Safe pays in:" + token (addr or "ETH")
//!          B: "Refund up to:" + worst-case (CEILING+baseGas)*gasPrice at
//!             full token magnitude (CEILING over-approximates the runtime
//!             gasUsed). This single total bounds every drain vector and
//!             vanishes to 0 only when the worst-case debit is truly
//!             negligible — so no drain can hide behind it.
//!          C: "Refund to:"   + refundReceiver (full addr, or "tx.origin")
//!          The total debit is (gasUsed+baseGas)*gasPrice with gasUsed
//!          runtime; B shows the worst-case bound. A *token* refund has no
//!          on-chain gasPrice cap, so without B an attacker could move the
//!          Safe's whole balance "as gas" behind an amount-less screen
//!          (audit 2026-06-19).
//!
//!   inner-native (1 page, only when SafeTx `value != 0` and the inner kind
//!          is not PlainEth/EmptyCall): "Safe value:" + chain-native amount. The
//!          PlainEth branch shows the value inline instead.
//!
//!   N..M: inner-tx pages (one of):
//!         * plain native transfer (2 pages: "Inner to" + "Send <ticker>")
//!         * ERC-20 known        (4 pages: header + recipient + amount + contract)
//!         * ERC-20 unknown      (4 pages: same shape, no symbol)
//!         * Safe-mgmt           (1..3 pages, per-op intent banner;
//!                                see [`super::safe_mgmt`]). Fires
//!                                when `canonical.to == safe_address`
//!                                and selector matches one of the
//!                                eight Safe v1.3.0+ singleton ops.
//!         * CoW presign         (7 or 9 pages: "CowSwap order / for
//!                                this Safe" context banner + the v3
//!                                order body from
//!                                `crate::tx::eip712::cowswap_display`.
//!                                Fires only when the handler verified
//!                                a CoW v3 trailer against the SafeTx
//!                                inner calldata with owner = the Safe;
//!                                see `safe::cow_binding`).
//!         * multiSend batch     (per record: 1 divider page "MSend rec
//!                                i/N" + target, an explicit value page
//!                                when the record forwards ETH a kind
//!                                doesn't show inline, then the
//!                                record's own pages through the SAME
//!                                per-kind arms above — incl. the CoW
//!                                presign body on the v3-bound record.
//!                                Fires only for an allowlisted
//!                                `MultiSendCallOnly` DELEGATECALL; see
//!                                `safe::multi_send`).
//!         * unknown Safe op     (3 pages: "Unknown Safe op" + Inner-to + selector/hash)
//!         * proven-unknown blind-sign (3 pages: "Unknown call" + "Inner to" + selector/hash)
//!
//!   last: "L=Cancel"
//!         "R=Confirm"
//! ```
//!
//! The `Op:` row is honest: `Op: Call` for operation 0, `Op: MultiSend`
//! for the allowlisted DELEGATECALL batch (the only operation-1 shape
//! the verifiers in `crate::tx::eip712::safe::{verify, exec_decode}`
//! let through), and a loud `! Op: DELEGATE` for the impossible-state
//! remainder, which renders as blind-sign.

use super::primitives::{
    format_u64, write_addr_full_or_name, write_calldata_hash_rows, write_chain, write_data_len_row,
    write_erc20_header, write_gas, write_line, write_native_amount_two_rows,
    write_native_currency_row, write_native_derived_amount_two_rows, write_selector_row,
    write_token_amount_two_rows, write_token_name, AmountFit,
};
use super::safe_mgmt::{
    classify_safe_mgmt, page_count as safe_mgmt_page_count, render_safe_mgmt_pages, SafeMgmtOp,
};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::calldata::{is_unlimited_amount, parse_erc20_calldata, Erc20Call};
use crate::names::NameResolver;
use crate::tx::eip1559::U256;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::cowswap_display::{
    append_order_body_pages, order_body_page_count, order_kind_label,
};
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::{
    self, classify_record_kind, record_needs_value_page, MsRecord, MsRecordIter, MsRecordKind,
};
use crate::tx::eip712::safe::{
    decode_canonical, safe_inner_is_cow_presign, SafeTx, VerifiedSafeExec, VerifiedSafeV1,
};
use crate::ui::DISPLAY_COLS;
use sphincs_tz_shared::GPV2_VAULT_RELAYER_ADDRESS;

/// Number of fixed Safe-level header pages rendered before the inner-tx
/// pages and the trailing confirm page.
const SAFE_HEADER_PAGES: usize = 3;

/// FI-robust "must this signed-value page be shown?" decision.
///
/// Returns `true` (SHOW) unless `safe_to_skip` is proven true through a
/// Hamming-distant sentinel double-evaluation (`fi::check_true_into_sentinel`
/// + `black_box`). A single glitch on the `safe_to_skip` predicate therefore
/// cannot turn a fund-bearing page from SHOW into SKIP — it can only fail
/// *towards* showing the page. This is the Safe-surface analogue of
/// `value_page::enforce_native_value_page`'s skip gate, and is shared by the
/// renderer AND the budget gate so a fault in either path defaults to the
/// safe (show / over-count) direction (audit 2026-06-27 — HIGH: the
/// inner-ETH / refund / safeTxGas page presence was previously a bare
/// `.iter().any()` boolean, single-fault-skippable like the pre-fix
/// native-value gate).
fn must_show_unless_robustly_skippable(safe_to_skip: bool) -> bool {
    crate::fi::check_true_into_sentinel(|| core::hint::black_box(safe_to_skip))
        != crate::fi::OK_SENTINEL
}

/// True when EVERY byte of `field` is zero — the "robustly absent" predicate
/// fed to [`must_show_unless_robustly_skippable`]. Kept as one helper so the
/// renderer and the gate test field-presence identically (no divergence).
fn all_zero(field: &[u8]) -> bool {
    field.iter().all(|&b| b == 0)
}

const CFI_SAFE_ROUTE_A: u32 = 0x6D13_A9C4;
const CFI_SAFE_ROUTE_B: u32 = 0xB72C_5E91;
const CFI_SAFE_ROUTE_VERDICT: u32 = 0x2A96_D347;
const CFI_SAFE_ROUTE_PUBLISH: u32 = 0xC53B_18ED;
const CFI_SAFE_ROUTE_EXPECTED: u32 = crate::cfi_expected!(
    CFI_SAFE_ROUTE_A,
    CFI_SAFE_ROUTE_B,
    CFI_SAFE_ROUTE_VERDICT,
    CFI_SAFE_ROUTE_PUBLISH,
);

/// Four-byte selector used by the omission filter. Short/empty calldata is
/// deliberately zero-padded instead of bypassing the query.
fn omission_selector(data: &[u8]) -> [u8; 4] {
    let mut selector = [0u8; 4];
    let n = core::cmp::min(data.len(), selector.len());
    selector[..n].copy_from_slice(&data[..n]);
    selector
}

/// Is a Bloom-positive tuple independently pinned by the native ERC-20
/// decoder? Metadata is a capability produced by the Merkle verifier, but it
/// is useful for this exemption only when it describes THIS contract on THIS
/// chain and the calldata passes the strict standard-ERC-20 ABI decoder.
fn exact_erc20_call_is_pinned(
    chain_id: u64,
    target: &[u8; 20],
    data: &[u8],
    erc20: Option<&Erc20Metadata<'_>>,
) -> bool {
    erc20.is_some_and(|meta| {
        meta.chain_id == chain_id
            && meta.contract == *target
            && parse_erc20_calldata(data).is_some()
    })
}

/// One complete route + exact-tuple pass over the Safe inner surface.
///
/// A direct `CALL` checks `(chain,to,zero-padded selector)`. An accepted
/// canonical `MultiSendCallOnly` checks EVERY record tuple, irrespective of
/// display classification. A Bloom-positive tuple fails closed unless its
/// semantics are independently pinned by exact Merkle-verified ERC-20
/// metadata plus strict calldata decoding, or it is the exact CoW presign
/// call/record already verified and bound by the CoW pipeline. Any non-CALL
/// direct route, claimed-but-malformed MultiSend, record parse error, or count
/// mismatch also fails closed.
#[inline(never)]
fn safe_inner_calls_unknown_once(
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
) -> bool {
    match multi_send::multisend_verdict(input.operation, &input.to, input.raw_data) {
        multi_send::MsVerdict::NotMultiSend => {
            if input.operation != 0 {
                return false;
            }
            let selector = omission_selector(input.raw_data);
            let catalogued = pqsigner_erc7730::known_calls::may_contain(
                crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
                input.chain_id,
                &input.to,
                &selector,
            );
            !catalogued
                || exact_erc20_call_is_pinned(input.chain_id, &input.to, input.raw_data, erc20)
                || (cow.is_some() && safe_inner_is_cow_presign(&input.to, input.raw_data))
        }
        multi_send::MsVerdict::Reject(_) => false,
        multi_send::MsVerdict::Accept(summary) => {
            let Ok(packed) = multi_send::decode_multisend(input.raw_data) else {
                return false;
            };
            let mut seen = 0usize;
            for record in MsRecordIter::new(packed) {
                let Ok(record) = record else {
                    return false;
                };
                if record.operation != 0 {
                    return false;
                }
                let selector = omission_selector(record.data);
                if pqsigner_erc7730::known_calls::may_contain(
                    crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
                    input.chain_id,
                    &record.to,
                    &selector,
                ) {
                    let erc20_pinned =
                        exact_erc20_call_is_pinned(input.chain_id, &record.to, record.data, erc20);
                    // `cow: Some` is supplied only after the v3 verifier has
                    // bound the order to the unique presign record's bytes and
                    // Safe owner. Re-derive the unique index and the exact
                    // target/selector predicate here so a different record
                    // cannot borrow that capability.
                    let cow_pinned = cow.is_some()
                        && summary.presign_claims == 1
                        && summary.presign_idx == seen
                        && safe_inner_is_cow_presign(&record.to, record.data);
                    if !erc20_pinned && !cow_pinned {
                        return false;
                    }
                }
                seen += 1;
            }
            seen != 0 && seen == summary.record_count
        }
    }
}

/// FI-hardened proof that every direct Safe inner call / canonical MultiSend
/// record is either absent from the firmware-pinned ERC-7730 catalogue or is
/// independently pinned by an exact native ERC-20 / bound-CoW capability.
///
/// The caller owns and FAIL-initializes both output slot and CFI transcript.
/// This non-inlined boundary recomputes routing, strict record parsing, and all
/// exact Bloom tuples independently on sides A/B around a randomized gap, then
/// volatile-publishes only their conjunction. Skipping the whole call leaves
/// the caller's two final gates rejecting.
#[inline(never)]
fn prove_safe_inner_calls_unknown(
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    verdict_out: &mut u32,
    cfi: &mut crate::fi::CfiCounter,
) {
    let permitted_a = safe_inner_calls_unknown_once(input, cow, erc20);
    cfi.bump(CFI_SAFE_ROUTE_A);
    crate::fi::wait_random();
    let permitted_b = safe_inner_calls_unknown_once(
        core::hint::black_box(input),
        core::hint::black_box(cow),
        core::hint::black_box(erc20),
    );
    cfi.bump(CFI_SAFE_ROUTE_B);
    let verdict = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(permitted_a) && core::hint::black_box(permitted_b)
    });
    cfi.bump(CFI_SAFE_ROUTE_VERDICT);
    // SAFETY: unique valid mutable reference supplied by the caller. Volatile
    // publication prevents substituting the proof's SSA value for either
    // independent caller readback.
    unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    cfi.bump(CFI_SAFE_ROUTE_PUBLISH);
}

/// SafeTx refund is configured when ANY of `gasPrice` / `gasToken` /
/// `refundReceiver` is non-zero. One source of truth for the renderer and
/// the budget gate.
fn refund_is_active(
    gas_price: &[u8; 32],
    gas_token: &[u8; 20],
    refund_receiver: &[u8; 20],
) -> bool {
    must_show_unless_robustly_skippable(
        all_zero(gas_price) && all_zero(gas_token) && all_zero(refund_receiver),
    )
}

fn erc20_call_amount_is_exactly_renderable(call: &Erc20Call, meta: &Erc20Metadata<'_>) -> bool {
    let amount = match call {
        Erc20Call::Transfer { amount, .. }
        | Erc20Call::TransferFrom { amount, .. }
        | Erc20Call::Approve { amount, .. } => amount,
    };
    (matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(amount))
        || super::primitives::token_amount_is_exactly_renderable(amount, meta)
}

/// Pre-publication exactness proof for every native or metadata-scaled legacy
/// amount and the signed SafeTx gas limit. It walks the same strict ERC-20 and
/// MultiSend decoders used by classification and executes the real painters
/// into scratch rows. Unknown tokens remain on the raw-integer path;
/// authenticated decimals, native values, and gas limits may never authorize
/// a lossy marker.
fn legacy_values_are_exactly_renderable(
    input: &SafeRenderInput<'_>,
    erc20: Option<&Erc20Metadata<'_>>,
) -> bool {
    if !all_zero(&input.safe_tx_gas) {
        let (units, overflow) = u64_be_tail(&input.safe_tx_gas);
        let mut gas_row = [b' '; DISPLAY_COLS];
        if overflow || !write_gas(&mut gas_row, units) {
            return false;
        }
    }

    let inner_value = U256(input.value);
    if !inner_value.is_zero()
        && !super::primitives::native_amount_is_exactly_renderable(&inner_value, input.chain_id)
    {
        return false;
    }

    // Safe gas refund amount. Native refunds use the signed chain's pinned
    // native policy; token refunds use address-matched authenticated metadata.
    if refund_is_active(&input.gas_price, &input.gas_token, &input.refund_receiver) {
        let native_refund = all_zero(&input.gas_token);
        let token_meta = erc20.filter(|meta| meta.contract == input.gas_token);
        if native_refund || token_meta.is_some() {
            let (base_gas, base_overflow) = u64_be_tail(&input.base_gas);
            let Some(gas_units) = base_gas.checked_add(GAS_USED_CEILING) else {
                return false;
            };
            let (worst, mul_overflow) = U256(input.gas_price).saturating_mul_u64(gas_units);
            if base_overflow || mul_overflow {
                return false;
            }

            if native_refund {
                let mut row1 = [b' '; DISPLAY_COLS];
                let mut row2 = [b' '; DISPLAY_COLS];
                if write_native_derived_amount_two_rows(
                    &mut row1,
                    &mut row2,
                    &worst,
                    input.chain_id,
                ) != AmountFit::Full
                {
                    return false;
                }
            } else if let Some(meta) = token_meta {
                if !super::primitives::token_amount_is_exactly_renderable(&worst, meta) {
                    return false;
                }
            }
        }
    }

    if multi_send::is_multisend_claim(input.operation, &input.to, input.raw_data) {
        let Ok(packed) = multi_send::decode_multisend(input.raw_data) else {
            return false;
        };
        for record in MsRecordIter::new(packed) {
            let Ok(record) = record else {
                return false;
            };
            let value = U256(record.value);
            if !value.is_zero()
                && !super::primitives::native_amount_is_exactly_renderable(&value, input.chain_id)
            {
                return false;
            }
            let Some(meta) = erc20.filter(|meta| meta.contract == record.to) else {
                continue;
            };
            if let Some(call) = parse_erc20_calldata(record.data) {
                if !erc20_call_amount_is_exactly_renderable(&call, meta) {
                    return false;
                }
            }
        }
        return true;
    }

    let Some(meta) = erc20.filter(|meta| meta.contract == input.to) else {
        return true;
    };
    parse_erc20_calldata(input.raw_data)
        .map(|call| erc20_call_amount_is_exactly_renderable(&call, meta))
        .unwrap_or(true)
}

/// Fixed (non-inner-tx, non-inner-ETH) Safe overhead page count:
/// header(3) + refund(0|3) + safeTxGas(0|1) + trailing confirm(1).
///
/// The SINGLE source of truth shared by `render_safe_pages_inner`'s
/// `total_pages` and `multisend_sign_gate`'s `fixed`, so the count the gate
/// approves and the count the renderer produces can never diverge (a
/// divergence is what would otherwise drive the renderer's page-accounting
/// refusal / the historic silent `min(.., MAX_PAGES)` truncation).
fn safe_fixed_overhead_pages(refund_active: bool, safe_tx_gas_active: bool) -> usize {
    SAFE_HEADER_PAGES + if refund_active { 3 } else { 0 } + usize::from(safe_tx_gas_active) + 1
    // trailing confirm page
}

/// Over-approximation of the runtime `gasUsed` term used to bound the Safe
/// gas-refund worst-case `(gasUsed + baseGas) * gasPrice` on the refund
/// magnitude page. The on-chain `gasUsed` is not a signed field, so the
/// trusted display cannot show an exact refund; it shows an upper bound
/// using this ceiling (the Ethereum-mainnet block gas limit, a
/// representative cap). For a legitimate refund this over-states the debit
/// (hence the "up to" label); on chains with a higher block limit it is no
/// longer a strict maximum but still scales with — and stays large for —
/// any real drain. See the refund-page comment in `render_safe_pages_inner`.
pub(super) const GAS_USED_CEILING: u64 = 30_000_000;

/// Which Safe flow the render is being driven from. Used to pick the
/// banner string on page 0 and decide what to show on the metadata page
/// (approveHash carries a SafeTx nonce in the canonical; execTransaction
/// only sees the SafeTx nonce on-chain at execution time).
#[derive(Copy, Clone)]
pub(super) enum SafeRenderFlavour {
    /// `approveHash(bytes32)` — the firmware re-derived the SafeTx hash
    /// from the trailer's canonical and bound it to the calldata
    /// argument. The user is approving the hash now; the Safe will
    /// execute it later once threshold approvals collect.
    ApproveHash { nonce: [u8; 32] },
    /// `execTransaction(...)` — the wallet is the EOA-equivalent
    /// triggering the Safe to execute. SafeTx fields come from the
    /// calldata directly (no separate trailer). Nonce is determined
    /// by the Safe's storage at execution time and is not visible
    /// to the firmware. Refund fields (gasPrice / gasToken /
    /// refundReceiver) ride in [`SafeRenderInput`] for both flavours,
    /// so the renderer surfaces them identically regardless of flow.
    ExecTransaction,
}

/// Normalised input to the shared Safe rendering body. Approve-hash and
/// exec-transaction both reduce to the same display surface: chain, Safe
/// address, op + inner-kind hint, inner-tx pages, confirm.
pub(super) struct SafeRenderInput<'a> {
    pub(super) flavour: SafeRenderFlavour,
    pub(super) chain_id: u64,
    pub(super) safe_address: [u8; 20],
    pub(super) to: [u8; 20],
    /// SafeTx operation byte. `0` = Call. `1` = DelegateCall — only
    /// reachable for an allowlisted MultiSendCallOnly batch (the
    /// verifiers' operation gates refuse everything else); rendered as
    /// `Op: MultiSend` with per-record pages. Anything else on this
    /// field is an impossible state rendered as a loud `! Op: DELEGATE`.
    pub(super) operation: u8,
    pub(super) value: [u8; 32],
    pub(super) raw_data: &'a [u8],
    /// keccak256(raw_data). For approveHash this comes from the
    /// canonical (already byte-equal to keccak256(raw_data) by the
    /// verifier's bind step); for exec we compute it here so the
    /// blind-sign branches can still surface it.
    pub(super) data_hash: [u8; 32],
    /// SafeTx refund parameters. All three are folded into the signed
    /// `safeTxHash` (EIP-712 struct hash) but are NOT otherwise visible
    /// in the inner-tx semantics, so the renderer must surface them
    /// explicitly: when `gasPrice > 0` the Safe pays
    /// `(gasUsed + baseGas) * gasPrice` of `gasToken` (or ETH when
    /// `gasToken == 0`) to `refundReceiver` (or `tx.origin` when
    /// `refundReceiver == 0`). A *token* refund has no on-chain cap on
    /// `gasPrice`, so an attacker who hides these fields can drain the
    /// Safe's entire balance of a chosen ERC-20 behind a benign-looking
    /// inner call. See `docs/companion/safe-multisig-clear-sign.md`.
    pub(super) gas_price: [u8; 32],
    pub(super) gas_token: [u8; 20],
    pub(super) refund_receiver: [u8; 20],
    /// SafeTx `baseGas` (signed, EIP-712 struct field). The refund debit is
    /// `(gasUsed + baseGas) * gasPrice`; `baseGas` is uncapped, so an
    /// attacker can drain via a huge `baseGas` with a tiny `gasPrice` (which
    /// would make the per-gas RATE page look benign). We therefore also
    /// render the `baseGas * gasPrice` base component so that drain vector
    /// is visible (audit 2026-06-19, hardened after adversarial review).
    pub(super) base_gas: [u8; 32],
    /// SafeTx `safeTxGas` (signed, EIP-712 struct field, canonical word 4).
    /// It bounds the gas forwarded to the inner call; crucially, Safe's
    /// `require(success || safeTxGas != 0 || gasPrice != 0)` means a NON-ZERO
    /// `safeTxGas` lets `execTransaction` SUCCEED — burning the nonce and
    /// paying any refund — even when the inner call runs out of gas and
    /// reverts. A hidden non-zero `safeTxGas` therefore lets the displayed
    /// inner action ("transfer 100 USDC") silently no-op while the user
    /// believes it executed: a WYSIWYS integrity gap. Surfaced on its own
    /// page whenever non-zero (audit 2026-06-26).
    pub(super) safe_tx_gas: [u8; 32],
}

/// Render a verified `safe_v1` trailer.
///
/// `tx_chain_id` is the outer UserOp's chain id — already cross-checked
/// against `canonical.chain_id` by the verifier, so passing either is
/// equivalent. We use the canonical's value for display-correctness.
/// `erc20` is the optional Merkle-verified ERC-20 metadata bundle from
/// the *outer* trailer chain; we apply it to the inner-tx's `to` only
/// when the addresses match (a Safe inner call to USDC carries the
/// metadata for USDC, not for the Safe contract).
/// `cow` is the optional CoW v3 order the handler verified against this
/// SafeTx's inner calldata (owner = the Safe) — when present, the
/// inner-tx pages become the full order intent instead of blind-sign.
pub fn render_safe_v1_pages(
    safe: &VerifiedSafeV1<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, ()> {
    // The verifier already proved the canonical decodes; mirror that
    // success here without re-erroring (a fresh `Err` would only fire
    // if the trailer parser was bypassed, which is impossible).
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
    render_safe_pages_inner(&input, cow, erc20, resolver)
}

/// Render a verified `execTransaction(...)` UserOp.
///
/// Mirrors `render_safe_v1_pages` but for the direct-execution flow:
/// the wallet is acting as the EOA that calls `execTransaction` on a
/// Safe, carrying co-signers' approvals in the function's `signatures`
/// argument. SafeTx fields come from the decoded calldata; the SafeTx
/// nonce is *not* visible (the Safe reads it from storage at execution
/// time), so the metadata page surfaces an "(execute now)" row in place
/// of the approve-hash nonce.
///
/// `erc20` follows the same address-match rule as the approveHash path:
/// we apply outer-trailer metadata only when its contract address
/// matches the decoded inner `to`. The decoded `signatures` blob is
/// left intentionally undisplayed — it is multi-owner content and
/// surfacing it would only add noise to the on-device confirm.
/// `cow` mirrors [`render_safe_v1_pages`]: a CoW v3 order verified
/// against the decoded SafeTx inner calldata with owner = the Safe.
pub fn render_safe_exec_pages(
    exec: &VerifiedSafeExec<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, ()> {
    let d = &exec.decoded;
    // The verifier proved `operation` is either 0 (Call) or an
    // allowlisted MultiSendCallOnly DELEGATECALL; the Op row + record
    // routing key off the byte. Compute the data hash for the
    // blind-sign / unknown-Safe-op branches that show it.
    let data_hash = keccak(d.data);
    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ExecTransaction,
        chain_id: exec.chain_id,
        safe_address: exec.safe_address,
        to: d.to,
        operation: d.operation,
        value: d.value,
        raw_data: d.data,
        data_hash,
        gas_price: d.gas_price,
        gas_token: d.gas_token,
        refund_receiver: d.refund_receiver,
        base_gas: d.base_gas,
        safe_tx_gas: d.safe_tx_gas,
    };
    render_safe_pages_inner(&input, cow, erc20, resolver)
}

/// Shared rendering body for both approveHash and execTransaction.
///
/// Returns `Err(())` — mapped by the dispatcher to a refuse-to-sign — when
/// the page budget is exceeded or the page-accounting self-check fails. It
/// NEVER silently truncates: a page that renders a signed value (inner ETH,
/// gas refund, a multiSend record) must either be shown or the signature
/// refused (audit 2026-06-27 — fail-closed replacement for the historic
/// `min(total_pages, MAX_PAGES)` clamp).
fn render_safe_pages_inner(
    input: &SafeRenderInput<'_>,
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Result<Pages, ()> {
    // Local field aliases to keep the existing rendering body readable.
    // We deliberately preserve the names the previous monolithic
    // function used (`tx.to`, `safe.raw_data`, …) so the diff stays
    // small.
    let tx = SafeTxFields {
        chain_id: input.chain_id,
        safe_address: input.safe_address,
        to: input.to,
        value: input.value,
        data_hash: input.data_hash,
    };
    let safe = SafeRawData {
        raw_data: input.raw_data,
    };

    let SafeSemantics {
        inner_kind,
        refund_active,
        show_inner_eth,
        show_safe_tx_gas,
        total_pages,
    } = classify(input, cow, erc20)?;
    let inner_value = U256(tx.value);
    let mut pages = Pages::with_len(total_pages);

    // ── Page 0: banner + chain ──────────────────────────────────────
    let banner = match input.flavour {
        SafeRenderFlavour::ApproveHash { .. } => "Approve Safe TX",
        SafeRenderFlavour::ExecTransaction => "Execute Safe TX",
    };
    write_line(&mut pages.buf[0][0], banner);
    {
        let [_banner, id, continuation_or_name, _foot] = &mut pages.buf[0];
        write_chain(id, continuation_or_name, tx.chain_id);
    }
    write_line(&mut pages.buf[0][3], "> next");

    // ── Page 1: Safe address (full) ─────────────────────────────────
    write_line(&mut pages.buf[1][0], "Safe:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[1];
        write_addr_full_or_name(a, b, c, &tx.safe_address, tx.chain_id, resolver);
    }

    // ── Page 2: Safe-level metadata (flavour-specific top row + op +
    //          inner-kind hint) ──────────────────────────────────────
    match input.flavour {
        SafeRenderFlavour::ApproveHash { nonce } => {
            write_safe_nonce_row(&mut pages.buf[2][0], &nonce);
        }
        SafeRenderFlavour::ExecTransaction => {
            // No SafeTx nonce visible from calldata — the Safe reads it
            // from storage at execution time. Surface the flow so the
            // user can tell this apart from an approveHash render at a
            // glance.
            write_line(&mut pages.buf[2][0], "(execute now)");
        }
    }
    // Honest Op row: `Call` for operation 0; `MultiSend` for the
    // allowlisted DELEGATECALL batch the record pages decode; a loud
    // `! Op: DELEGATE` for the impossible-state remainder (operation 1
    // that the verifiers should have refused — render falls to Blind).
    let op_row = if input.operation == 0 {
        "Op: Call"
    } else if matches!(inner_kind, InnerKind::MultiSend { .. }) {
        "Op: MultiSend"
    } else {
        "! Op: DELEGATE"
    };
    write_line(&mut pages.buf[2][1], op_row);
    match &inner_kind {
        InnerKind::MultiSend { count, .. } => {
            write_msend_hint_row(&mut pages.buf[2][2], *count);
        }
        kind => write_inner_kind_hint(&mut pages.buf[2][2], kind, tx.chain_id),
    }
    write_line(&mut pages.buf[2][3], "> next");

    // ── Optional refund pages: gasToken + refundReceiver ────────────
    //
    // Rendered for BOTH flavours when any refund field is set. The user
    // is paying `(gasUsed + baseGas) * gasPrice` in `gasToken` (ETH when
    // `gasToken == 0`) to `refundReceiver`. We cannot decode the exact
    // amount (it depends on runtime gas usage), but the *token* and the
    // *recipient* are the WYSIWYS-critical facts: a token refund has no
    // on-chain gasPrice cap, so without these pages an attacker could
    // drain the Safe's full balance of a chosen ERC-20 to themselves
    // behind a benign-looking inner call.
    let mut next_page = SAFE_HEADER_PAGES;
    if refund_active {
        // Page A: banner + the token the refund is paid in.
        if input.gas_token.iter().all(|&b| b == 0) {
            write_line(&mut pages.buf[next_page][0], "! GAS REFUND");
            write_line(&mut pages.buf[next_page][1], "Safe pays in:");
            write_native_currency_row(&mut pages.buf[next_page][2], b"", tx.chain_id, b" (native)");
            write_line(&mut pages.buf[next_page][3], "> next");
        } else {
            // Token refund (no on-chain gasPrice cap) — show the FULL token
            // address, resolver-aware, so the user can actually recognise
            // "wait, that's my USDC". The old `write_short_addr` showed only
            // 6 of 20 bytes AND skipped the name DB, defeating that exact
            // purpose: a draining refund denominated in a chosen ERC-20 could
            // pass for a worthless-token refund because the user could read
            // neither the full address nor the token's name (audit
            // 2026-06-26). Mirrors the full-address treatment of the refund
            // recipient (page C) and every other contract/recipient address
            // on this surface. Still ONE page — the 40-hex / resolved name
            // occupies rows 1-3 — so the 3-page refund budget and the
            // `multisend_sign_gate` lockstep are unchanged.
            write_line(&mut pages.buf[next_page][0], "! REFUND TOKEN:");
            let [_lbl, a, b, c] = &mut pages.buf[next_page];
            write_addr_full_or_name(a, b, c, &input.gas_token, tx.chain_id, resolver);
        }
        next_page += 1;

        // Page B: the WORST-CASE refund magnitude (audit 2026-06-19;
        // hardened across two adversarial review rounds).
        //
        // On-chain the Safe pays `(gasUsed + baseGas) * gasPrice` of
        // `gasToken` to `refundReceiver`. `gasUsed` is a RUNTIME quantity,
        // attacker-influenced via the inner call but BOUNDED by the block
        // gas limit (`GAS_USED_CEILING`); `baseGas` and `gasPrice` are
        // signed and uncapped. We therefore render the worst-case TOTAL
        //
        //     (GAS_USED_CEILING + baseGas) * gasPrice
        //
        // at full token magnitude. This is the right number to show because
        // it equals the largest the refund debit can be, so it vanishes to
        // "0.000000" ONLY when the actual worst-case debit is itself a
        // negligible sub-unit amount — no real drain can hide behind it.
        //
        // Earlier attempts failed here: the `baseGas*gasPrice` FLOOR read
        // "0" when an attacker set `baseGas = 0` and drained via `gasUsed`;
        // and a per-gas RATE (`gasPrice` scaled by the token's decimals)
        // rounded a 15-token gasUsed-driven drain to "0.000000" because the
        // rate is divided by `10^decimals`. The TOTAL has neither flaw.
        //
        // `gasUsed` is over-approximated by a fixed ceiling rather than the
        // exact runtime value, so for a legitimate refund this page shows an
        // upper bound (labelled "up to"); a token gas-refund is rare and
        // always worth scrutinising, so a conservative ceiling is the safe
        // direction. On chains whose block limit exceeds the ceiling the
        // bound is still large for any real drain (it scales with the
        // drain), just not a strict maximum.
        write_line(&mut pages.buf[next_page][0], "Refund up to:");
        {
            // baseGas + ceiling, reduced to u64 (a baseGas beyond u64 makes
            // the worst case astronomically large → handled as overflow).
            let (base_u64, base_overflow) = u64_be_tail(&input.base_gas);
            let gas_units = base_u64.saturating_add(GAS_USED_CEILING);
            let (worst, mul_overflow) = U256(input.gas_price).saturating_mul_u64(gas_units);
            let huge = base_overflow || mul_overflow;
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            if huge {
                // Exceeds 2^256 — unrenderable but unmistakably enormous.
                // Fail loud; never a misleading small number.
                write_line(r1, "!HUGE");
                write_line(r2, "(refuse)");
                write_line(foot, "@30M gas est");
            } else {
                // gasToken == 0 → ETH (18 dec). gasToken matching the
                // address-checked inner bundle → its decimals + symbol.
                // Otherwise the raw integer in base units. Overflow paints a
                // loud banner rather than dropping the high-order digits.
                let fit = if input.gas_token.iter().all(|&b| b == 0) {
                    write_native_derived_amount_two_rows(r1, r2, &worst, tx.chain_id)
                } else if let Some(m) = erc20.filter(|m| m.contract == input.gas_token) {
                    write_token_amount_two_rows(r1, r2, &worst, m)
                } else {
                    let units = Erc20Metadata {
                        chain_id: 0,
                        contract: [0u8; 20],
                        decimals: 0,
                        name: &[],
                        symbol: b"units",
                    };
                    write_token_amount_two_rows(r1, r2, &worst, &units)
                };
                write_line(
                    foot,
                    match fit {
                        // Footer doubles as the gas-ceiling disclosure so the
                        // "up to" is honest about its assumption.
                        AmountFit::Full => "@30M gas est",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
        }
        next_page += 1;

        // Page C: who receives the refund (full address, resolver-aware).
        write_line(&mut pages.buf[next_page][0], "Refund to:");
        if input.refund_receiver.iter().all(|&b| b == 0) {
            write_line(&mut pages.buf[next_page][1], "tx.origin");
            write_line(&mut pages.buf[next_page][2], "(whoever execs)");
            write_line(&mut pages.buf[next_page][3], "> next");
        } else {
            let [_lbl, a, b, c] = &mut pages.buf[next_page];
            write_addr_full_or_name(a, b, c, &input.refund_receiver, tx.chain_id, resolver);
        }
        next_page += 1;
    }

    // ── Optional inner-ETH page ─────────────────────────────────────
    //
    // The PlainEth branch already shows the value inline; for every
    // other inner kind a non-zero SafeTx `value` is otherwise invisible.
    if show_inner_eth {
        write_line(&mut pages.buf[next_page][0], "Safe value:");
        {
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            let fit = write_native_amount_two_rows(r1, r2, &inner_value, tx.chain_id);
            write_line(
                foot,
                match fit {
                    AmountFit::Full => "> next",
                    AmountFit::Overflow => "!AMOUNT OVERFLOW",
                },
            );
        }
        next_page += 1;
    }

    // ── Optional safeTxGas page ─────────────────────────────────────
    //
    // `safeTxGas` is signed into the safeTxHash but is invisible in the
    // inner-tx semantics. A non-zero value lets `execTransaction` succeed
    // even if the inner call runs out of gas (Safe's
    // `require(success || safeTxGas != 0 || gasPrice != 0)`), so the inner
    // action can silently no-op while the nonce is burned and any refund is
    // paid. Surface it whenever non-zero (audit 2026-06-26).
    if show_safe_tx_gas {
        write_line(&mut pages.buf[next_page][0], "SafeTx gas:");
        {
            let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
            let (units, overflow) = u64_be_tail(&input.safe_tx_gas);
            if overflow {
                // > u64 gas is absurd; never misrepresent it as a small value.
                write_line(r1, "!HUGE (>u64)");
            } else {
                let _ = write_gas(r1, units);
            }
            // Why it matters: a non-zero safeTxGas can let the inner call
            // silently fail while the outer Safe tx still succeeds.
            write_line(r2, "inner may no-op");
            write_line(foot, "> next");
        }
        next_page += 1;
    }

    // ── Inner-tx pages ──────────────────────────────────────────────
    //
    // Single-call SafeTxs render exactly one classified inner; a
    // multiSend renders divider + (optional value page) + classified
    // pages PER RECORD through the same `append_inner_kind_pages` body
    // — one render implementation for both shapes.
    match &inner_kind {
        InnerKind::MultiSend { count, .. } => {
            next_page =
                append_multisend_pages(&mut pages, next_page, input, *count, cow, erc20, resolver);
        }
        kind => {
            let ctx = InnerRenderCtx {
                chain_id: tx.chain_id,
                safe_address: tx.safe_address,
                to: tx.to,
                value: inner_value,
                data: safe.raw_data,
                data_hash: tx.data_hash,
                erc20,
                resolver,
            };
            next_page = append_inner_kind_pages(&mut pages, next_page, kind, &ctx);
        }
    }

    // ── Page-accounting self-check (WYSIWYS class backstop) ─────────
    //
    // Every page that was COUNTED into `total_pages` must have been
    // WRITTEN: the inner-tx appenders advance `next_page` by exactly the
    // page count `inner_kind_page_count` reported, the fixed/refund/value/
    // gas pages were spliced above, and the trailing confirm page occupies
    // the final slot — so the invariant is `next_page + 1 == total_pages`.
    //
    // If it ever fails, the renderer produced fewer (or more) pages than it
    // counted — i.e. a page that renders a signed value was dropped, or a
    // gate/renderer page-count divergence slipped through. Rather than show
    // a buffer with a hidden value we refuse to sign. This is the generic
    // net that closes the whole "signed-but-not-shown via a dropped page"
    // class, independent of any single presence flag being right
    // (audit 2026-06-27).
    if next_page + 1 != total_pages {
        return Err(());
    }

    // ── Final: confirm prompt ───────────────────────────────────────
    write_line(&mut pages.buf[next_page][0], "Long-press to");
    write_line(&mut pages.buf[next_page][1], "");
    write_line(&mut pages.buf[next_page][2], "L=Cancel");
    write_line(&mut pages.buf[next_page][3], "R=Confirm");

    Ok(pages)
}


/// The Safe display decisions, computed ONCE and consumed by every painter.
///
/// "One classification, two painters": the legacy 16×4 page renderer
/// ([`render_safe_pages_inner`]) and the pixel-UI screen emitter
/// (`safe_screens`) must never disagree about what a SafeTx *is* — which
/// inner kind it carries, whether the refund / inner-ETH / safeTxGas pages
/// are due — so those decisions, together with every FI gate that guards
/// them, live here and nowhere else. `total_pages` is the legacy page count
/// (including the trailing confirm page) that the pixel path cross-checks
/// against the legacy renderer's actual output.
pub(super) struct SafeSemantics<'a> {
    pub(super) inner_kind: InnerKind<'a>,
    pub(super) refund_active: bool,
    pub(super) show_inner_eth: bool,
    pub(super) show_safe_tx_gas: bool,
    pub(super) total_pages: usize,
}

/// Classify a normalised Safe render input. Runs the legacy exactness gate,
/// the FI-hardened unknown-call proof with its two final reject gates, the
/// FI-robust refund / inner-ETH / safeTxGas presence decisions, the inner
/// kind ladder and the page budget. `Err(())` means refuse to sign.
pub(super) fn classify<'a>(
    input: &SafeRenderInput<'_>,
    cow: Option<&'a VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
) -> Result<SafeSemantics<'a>, ()> {
    let legacy_amounts_exact = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(legacy_values_are_exactly_renderable(input, erc20))
    });
    crate::fi::scrub_sentinel_register();
    if legacy_amounts_exact != crate::fi::OK_SENTINEL {
        return Err(());
    }

    // Safe cannot consume an ERC-7730 proof for its inner call yet. Before
    // classification, prove that the exact direct tuple OR every exact
    // canonical-MultiSend record tuple is absent from the pinned catalogue,
    // except for the two native paths whose semantics are independently
    // pinned: exact Merkle ERC-20 metadata + strict ABI decode, or the exact
    // CoW presign call/record already verified and bound by the v3 pipeline.
    // Display classification itself is intentionally irrelevant: an ERC-721
    // `approve` that merely looks like ERC-20 still requires its descriptor.
    let mut unknown_verdict_slot = 0u32;
    // SAFETY: unique caller-owned local. Volatile FAIL materialization must
    // survive LTO; skipping the non-inlined proof call leaves this rejecting.
    unsafe {
        core::ptr::write_volatile(&mut unknown_verdict_slot, crate::fi::FAIL_SENTINEL);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let mut unknown_cfi = crate::fi::CfiCounter::new();
    prove_safe_inner_calls_unknown(
        input,
        cow,
        erc20,
        &mut unknown_verdict_slot,
        &mut unknown_cfi,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    // Final reject gate A: independently materialize the volatile proof and
    // caller-owned CFI transcript. No `?` propagation is load-bearing here.
    // SAFETY: the proof's unique mutable borrow ended before this readback.
    let unknown_verdict_a = unsafe { core::ptr::read_volatile(&unknown_verdict_slot) };
    let unknown_cfi_verdict_a = unknown_cfi.check_into_sentinel(CFI_SAFE_ROUTE_EXPECTED);
    let unknown_all_ok_a = unknown_verdict_a == crate::fi::OK_SENTINEL
        && unknown_cfi_verdict_a == crate::fi::OK_SENTINEL;
    crate::fi::scrub_sentinel_register();
    let unknown_gate_a =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_a));
    crate::fi::scrub_sentinel_register();
    if unknown_gate_a != crate::fi::OK_SENTINEL {
        return Err(());
    }

    crate::fi::wait_random();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Final reject gate B: re-read live evidence after an independent gap.
    // SAFETY: same initialized caller-owned local, with no intervening write.
    let unknown_verdict_b = unsafe { core::ptr::read_volatile(&unknown_verdict_slot) };
    let unknown_cfi_verdict_b = unknown_cfi.check_into_sentinel(CFI_SAFE_ROUTE_EXPECTED);
    let unknown_all_ok_b = unknown_verdict_b == crate::fi::OK_SENTINEL
        && unknown_cfi_verdict_b == crate::fi::OK_SENTINEL;
    crate::fi::scrub_sentinel_register();
    let unknown_gate_b =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_b));
    crate::fi::scrub_sentinel_register();
    if unknown_gate_b != crate::fi::OK_SENTINEL {
        return Err(());
    }

    // Refund-risk pages are added for BOTH approveHash and
    // execTransaction whenever the SafeTx configures a gas refund.
    // Safe pays `(gasUsed + baseGas) * gasPrice` of `gasToken` (ETH when
    // `gasToken == 0`) to `refundReceiver` (`tx.origin` when zero). The
    // on-chain trigger is `gasPrice > 0`; a *token* refund has no
    // gasPrice cap, so a hidden refund is a full-ERC-20-balance drain
    // channel dressed up behind a benign inner call. We surface it
    // whenever any refund field is set — a non-zero gasToken /
    // refundReceiver with gasPrice 0 is anomalous enough to show too.
    // Two pages: banner + gasToken, then the full refundReceiver address.
    // FI-robust: defaults to SHOW unless all three refund fields are
    // provably zero (see `must_show_unless_robustly_skippable`). A hidden
    // *token* refund is a full-ERC-20-balance drain channel, so a single
    // fault must never be able to skip these pages.
    let refund_active =
        refund_is_active(&input.gas_price, &input.gas_token, &input.refund_receiver);

    // Decide inner-tx flavor up-front so we can size the page count.
    // ERC-20 calldata renders as `Erc20Known` only when metadata is
    // *both* present and address-matches the inner `to`; otherwise we
    // fall back to `Erc20Unknown` (still readable shape, just no
    // symbol/decimals).
    //
    // Safe self-calls (`tx.to == tx.safe_address`) are routed to the
    // Safe-mgmt decoder first: a positive classification yields a
    // per-op intent banner; an unrecognised selector falls into the
    // loud "Unknown Safe op" blind-sign branch so the user can tell
    // it apart from a generic opaque inner call.
    let inner_value = U256(input.value);
    // An allowlisted MultiSendCallOnly DELEGATECALL renders per-record
    // pages (the verdict gate in the handlers already enforced the hard
    // rules + the page budget). The claim predicate is the SAME
    // `multi_send::is_multisend_claim` the verifiers' operation gates
    // and the CoW-binding resolver use, so verify, gate and render
    // cannot disagree about what counts as a multiSend. A claim that
    // fails to decode here is an impossible state (the gate refused it)
    // and falls to the loud blind branch under a `! Op: DELEGATE` row —
    // fail-safe, never fail-rich.
    //
    // Otherwise, a handler-verified CoW v3 order takes the inner slot
    // outright — the v3 pipeline already byte-bound the canonical to
    // this SafeTx's raw_data (digest/validTo) and to the Safe address
    // (uid owner). The predicate re-check is defensive only: if the
    // dispatcher ever paired a `cow` with a non-presign inner call
    // (logic bug, memory fault), we ignore it and fall through to the
    // normal ladder, which lands on the loud blind-sign page.
    let inner_kind = if multi_send::is_multisend_claim(input.operation, &input.to, input.raw_data) {
        let cow_body = safe_cow_pages(cow);
        let count = multi_send::summarize(input.raw_data)
            .map(|s| s.record_count)
            .unwrap_or(0);
        match multi_send::records_pages_total(input.raw_data, &input.safe_address, cow_body) {
            Some(total) if count > 0 => InnerKind::MultiSend {
                count,
                inner_pages: total,
            },
            _ => InnerKind::Blind,
        }
    } else {
        match cow {
            Some(v3) if safe_inner_is_cow_presign(&input.to, input.raw_data) => {
                InnerKind::CowswapPresign(v3)
            }
            _ => {
                if input.to == input.safe_address && !input.raw_data.is_empty() {
                    match classify_safe_mgmt(input.raw_data) {
                        Some(op) => InnerKind::SafeMgmt(op),
                        None => InnerKind::UnknownSafeSelf,
                    }
                } else {
                    match classify_inner(input.raw_data, &inner_value) {
                        InnerKind::Erc20Known(call) if erc20.is_some() => {
                            InnerKind::Erc20Known(call)
                        }
                        InnerKind::Erc20Known(call) => InnerKind::Erc20Unknown(call),
                        other => other,
                    }
                }
            }
        }
    };

    let inner_pages = inner_kind_page_count(&inner_kind);
    // The refund block is 3 pages when configured (token + worst-case refund
    // MAGNITUDE + recipient, audit 2026-06-19); that count now lives in the
    // shared `safe_fixed_overhead_pages` so the renderer and the budget gate
    // cannot disagree about it.
    //
    // Inner SafeTx `value` (native currency the Safe forwards to `to`)
    // is shown inline only by the PlainEth branch. For every other inner
    // kind a non-zero value would otherwise be invisible even though it
    // is bound into the signed safeTxHash, so splice a dedicated page.
    // FI-robust: defaults to SHOW unless the inner value is provably zero or
    // the value is already rendered inline (PlainEth / EmptyCall). The
    // inner native value the Safe forwards to `to` is committed into the signed
    // safeTxHash and is gated ONLY here — the dispatcher's
    // `enforce_native_value_page` covers the *outer* UserOp value, not this
    // one — so a single-fault skip would hide an ETH drain (audit 2026-06-27).
    let inline_value_kind = matches!(inner_kind, InnerKind::PlainEth | InnerKind::EmptyCall);
    let show_inner_eth =
        must_show_unless_robustly_skippable(inner_value.is_zero() || inline_value_kind);
    let inner_eth_pages = usize::from(show_inner_eth);
    // safeTxGas page (audit 2026-06-26): shown whenever non-zero — it is
    // signed into the safeTxHash but invisible in the inner-tx semantics,
    // and a non-zero value lets the inner call silently fail while the outer
    // tx still succeeds (see `SafeRenderInput::safe_tx_gas`). Kept in
    // lockstep with the `multisend_sign_gate` `fixed` term so the budget gate
    // REFUSES (rather than truncates) any multiSend whose total would
    // overflow MAX_PAGES.
    // FI-robust (same rationale): a hidden non-zero safeTxGas lets the inner
    // call silently no-op while the nonce is burned and any refund paid.
    let show_safe_tx_gas = must_show_unless_robustly_skippable(all_zero(&input.safe_tx_gas));
    let total_pages =
        safe_fixed_overhead_pages(refund_active, show_safe_tx_gas) + inner_eth_pages + inner_pages;
    // Fail CLOSED, never truncate: a page that renders a signed value must be
    // shown or the signature refused. The old `min(total_pages, MAX_PAGES)`
    // silently dropped trailing pages (records) when the gate/renderer page
    // counts diverged — exactly the signed-but-not-shown class this audit
    // closes (2026-06-27). `multisend_sign_gate` already refuses over-budget
    // multiSends up front; this is the renderer-local backstop for every
    // Safe shape (single-call included), so the WYSIWYS guarantee no longer
    // rests solely on the external gate.
    if total_pages > super::MAX_PAGES {
        return Err(());
    }
    Ok(SafeSemantics {
        inner_kind,
        refund_active,
        show_inner_eth,
        show_safe_tx_gas,
        total_pages,
    })
}

// ---------------------------------------------------------------------------
// Handler-facing multiSend gate
// ---------------------------------------------------------------------------

/// Verdict of [`multisend_sign_gate`].
pub enum MultisendGate {
    /// The Safe context's inner call is not a claimed multiSend —
    /// nothing for this gate to do.
    NotMultiSend,
    /// Claimed multiSend that must refuse to sign: a hard-rule
    /// violation (malformed framing, record op != 0, record cap, ≥2
    /// presign claims) or a trusted-display page-budget overflow.
    /// Handlers show `("Safe sign", reason)` and return
    /// `InvalidPointer` — a DELEGATECALL payload has no degraded
    /// render.
    Reject(&'static str),
    /// Decodes under every hard rule and fits the page budget.
    Ok,
}

/// One shared accept/refuse decision for a verified Safe context whose
/// inner call claims an allowlisted multiSend — called by BOTH the
/// single-tx and batch handlers so the two cannot drift.
///
/// `reserved_pages` is the handler-specific page overhead outside this
/// renderer: the dispatcher's native-value page (1 when the outer
/// UserOp `value != 0`), the mandatory signer and target-address pages, the
/// two ERC-8213 fingerprint pages, and the batch banner (batch handler only).
///
/// The budget arithmetic mirrors `render_safe_pages_inner` exactly:
/// [`safe_fixed_overhead_pages`] (header + refund + SafeTx-gas + confirm),
/// the optional SafeTx-value page, the per-record total from
/// `multi_send::records_pages_total`, and `reserved_pages`.
pub fn multisend_sign_gate(
    safe_v1: Option<&VerifiedSafeV1<'_>>,
    safe_exec: Option<&VerifiedSafeExec<'_>>,
    cow: Option<&VerifiedCowswapV3>,
    reserved_pages: usize,
) -> MultisendGate {
    // Same precedence as `safe::cow_binding::resolve_cow_binding`:
    // a verified approveHash context wins over exec.
    let (operation, to, raw, safe_address, refund_active, safe_value_nonzero, safe_tx_gas_nonzero) =
        if let Some(s) = safe_v1 {
            let Ok(tx) = decode_canonical(&s.canonical) else {
                // The verifier proved the canonical decodes; stay
                // fail-safe if this is ever reached.
                return MultisendGate::Reject("msend canonical");
            };
            (
                tx.operation,
                tx.to,
                s.raw_data,
                tx.safe_address,
                // SAME FI-robust flags + helpers the renderer uses, so the
                // gate's `fixed` and the renderer's `total_pages` cannot
                // diverge (and a fault biases both toward over-counting →
                // refuse, the fail-closed direction).
                refund_is_active(&tx.gas_price, &tx.gas_token, &tx.refund_receiver),
                must_show_unless_robustly_skippable(all_zero(&tx.value)),
                must_show_unless_robustly_skippable(all_zero(&tx.safe_tx_gas)),
            )
        } else if let Some(e) = safe_exec {
            let d = &e.decoded;
            (
                d.operation,
                d.to,
                d.data,
                e.safe_address,
                refund_is_active(&d.gas_price, &d.gas_token, &d.refund_receiver),
                must_show_unless_robustly_skippable(all_zero(&d.value)),
                must_show_unless_robustly_skippable(all_zero(&d.safe_tx_gas)),
            )
        } else {
            return MultisendGate::NotMultiSend;
        };

    match multi_send::multisend_verdict(operation, &to, raw) {
        multi_send::MsVerdict::NotMultiSend => return MultisendGate::NotMultiSend,
        multi_send::MsVerdict::Reject(reason) => return MultisendGate::Reject(reason),
        multi_send::MsVerdict::Accept(_) => {}
    }

    // Page budget — refuse instead of truncating: a record the user
    // never saw is exactly the attack class this feature closes.
    let cow_body = safe_cow_pages(cow);
    let Some(inner_pages) = multi_send::records_pages_total(raw, &safe_address, cow_body) else {
        return MultisendGate::Reject("msend malformed");
    };
    // Shared overhead helper (header + refund + safeTxGas + confirm) — the
    // SAME function the renderer's `total_pages` uses — plus the inner-ETH
    // page, so the gate counts exactly what the renderer will produce.
    let fixed = safe_fixed_overhead_pages(refund_active, safe_tx_gas_nonzero)
        + usize::from(safe_value_nonzero);
    if fixed + inner_pages + reserved_pages > super::MAX_PAGES {
        return MultisendGate::Reject("msend too long");
    }
    MultisendGate::Ok
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lightweight view of the SafeTx fields the renderer needs. Lets the
/// shared body keep its `tx.foo` references after the refactor without
/// dragging the full canonical decode into the exec path.
struct SafeTxFields {
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    value: [u8; 32],
    data_hash: [u8; 32],
}

/// Twin of [`SafeTxFields`] for the raw inner-call payload. Borrows
/// from the gateway's TOCTOU snapshot (approveHash) or the inner_data
/// snapshot (exec).
struct SafeRawData<'a> {
    raw_data: &'a [u8],
}

pub(super) enum InnerKind<'a> {
    EmptyCall,
    PlainEth,
    Erc20Known(Erc20Call),
    Erc20Unknown(Erc20Call),
    /// Inner call targets `safe_address` and decoded as one of the
    /// recognised Safe-native owner/module/guard/fallback ops.
    SafeMgmt(SafeMgmtOp),
    /// Inner call is `setPreSignature` on GPv2Settlement and the
    /// handler verified a CoW v3 trailer against it (orderUid digest /
    /// validTo bound to `raw_data`, uid owner == the Safe). Renders
    /// the full order intent via the shared cowswap_display body.
    CowswapPresign(&'a VerifiedCowswapV3),
    /// Inner call targets `safe_address` but the selector is not in the
    /// recognised Safe-native set — loud blind-sign with an explicit
    /// "Unknown Safe op" warning, but only after the ERC-7730 filter proves
    /// the tuple unknown.
    UnknownSafeSelf,
    /// Allowlisted `MultiSendCallOnly` DELEGATECALL batch: every packed
    /// record renders its own divider + classified pages through
    /// [`append_multisend_pages`]. `inner_pages` is the exact total
    /// from `multi_send::records_pages_total` (same per-kind counts the
    /// handlers' page-budget gate used).
    MultiSend {
        count: usize,
        inner_pages: usize,
    },
    Blind,
}

/// Paint a one-line semantic hint about the inner tx, e.g.
/// `"Inner: ERC-20"`. The plain-native arm derives its ticker from the
/// signed chain id, so a BSC Safe transfer says `"Inner: BNB"` rather than
/// the ambiguous `"Inner: native"` (or, worse, a hard-coded ETH label).
fn write_inner_kind_hint(row: &mut [u8; DISPLAY_COLS], kind: &InnerKind<'_>, chain_id: u64) {
    match kind {
        InnerKind::PlainEth => write_native_currency_row(row, b"Inner: ", chain_id, b""),
        InnerKind::EmptyCall => write_line(row, "(empty call)"),
        InnerKind::Erc20Known(_) => write_line(row, "Inner: ERC-20"),
        InnerKind::Erc20Unknown(_) => write_line(row, "Inner: ERC-20?"),
        InnerKind::SafeMgmt(_) => write_line(row, "Inner: Safe mgmt"),
        InnerKind::CowswapPresign(_) => write_line(row, "Inner: CoW order"),
        InnerKind::UnknownSafeSelf => write_line(row, "! Unkn self-call"),
        // The MultiSend hint carries the record count and is written by
        // `write_msend_hint_row` instead; this arm is a fallback.
        InnerKind::MultiSend { .. } => write_line(row, "Inner: MultiSend"),
        InnerKind::Blind => write_line(row, "! Inner: opaque"),
    }
}

#[cfg(test)]
mod inner_kind_hint_tests {
    use super::*;

    const WETH: [u8; 20] = [
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9,
        0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ];
    const WETH_DEPOSIT: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];

    fn render_input<'a>(to: [u8; 20], operation: u8, raw_data: &'a [u8]) -> SafeRenderInput<'a> {
        SafeRenderInput {
            flavour: SafeRenderFlavour::ExecTransaction,
            chain_id: 1,
            safe_address: [0x5a; 20],
            to,
            operation,
            value: [0u8; 32],
            raw_data,
            data_hash: keccak(raw_data),
            gas_price: [0u8; 32],
            gas_token: [0u8; 20],
            refund_receiver: [0u8; 20],
            base_gas: [0u8; 32],
            safe_tx_gas: [0u8; 32],
        }
    }

    fn be_u128(value: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn pages_contain(pages: &Pages, needle: &[u8]) -> bool {
        pages.buf[..pages.len]
            .iter()
            .flatten()
            .any(|row| row.windows(needle.len()).any(|window| window == needle))
    }

    #[test]
    fn plain_native_hint_uses_signed_chain_ticker() {
        let mut bsc = [b' '; DISPLAY_COLS];
        write_inner_kind_hint(&mut bsc, &InnerKind::PlainEth, 56);
        assert_eq!(&bsc[..10], b"Inner: BNB");
        assert!(!bsc.windows(3).any(|w| w == b"ETH"));

        let mut unknown = [b' '; DISPLAY_COLS];
        write_inner_kind_hint(&mut unknown, &InnerKind::PlainEth, u64::MAX);
        assert_eq!(&unknown[..13], b"Inner: NATIVE");
    }

    #[test]
    fn direct_opaque_known_weth_deposit_refuses() {
        let resolver = NameResolver::new();
        let known = render_input(WETH, 0, &WETH_DEPOSIT);
        assert!(
            render_safe_pages_inner(&known, None, None, &resolver).is_err(),
            "Safe wrapper must not bypass the known WETH deposit proof requirement"
        );

        // Non-vacuity: an actually-unknown selector on the same target keeps
        // the loud opaque Safe review available.
        let unknown_data = [0xde, 0xad, 0xbe, 0xef];
        let unknown = render_input(WETH, 0, &unknown_data);
        assert!(render_safe_pages_inner(&unknown, None, None, &resolver).is_ok());
    }

    #[test]
    fn safe_tx_gas_must_fit_the_exact_painter_before_pages_escape() {
        let resolver = NameResolver::new();
        let unknown_data = [0xde, 0xad, 0xbe, 0xef];

        let mut exact = render_input(WETH, 0, &unknown_data);
        exact.safe_tx_gas[24..].copy_from_slice(&999_999_999u64.to_be_bytes());
        assert!(legacy_values_are_exactly_renderable(&exact, None));
        assert!(render_safe_pages_inner(&exact, None, None, &resolver).is_ok());

        let mut lossy = render_input(WETH, 0, &unknown_data);
        lossy.safe_tx_gas[24..].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        assert!(!legacy_values_are_exactly_renderable(&lossy, None));
        assert!(
            render_safe_pages_inner(&lossy, None, None, &resolver).is_err(),
            "distinct signed SafeTx gas values must not collapse to the same !OVF page"
        );
    }

    #[test]
    fn direct_safe_native_value_uses_exact_wei_fallback_or_refuses_overwide() {
        let resolver = NameResolver::new();
        let unknown_data = [0xde, 0xad, 0xbe, 0xef];

        for raw_data in [&[][..], &unknown_data[..]] {
            let mut exact = render_input([0x44; 20], 0, raw_data);
            exact.value = be_u128(1_000_000_000_000_000_000);
            assert!(legacy_values_are_exactly_renderable(&exact, None));
            let exact_pages =
                render_safe_pages_inner(&exact, None, None, &resolver).expect("1 ETH is exact");

            let mut one_wei = render_input([0x44; 20], 0, raw_data);
            one_wei.value = be_u128(1);
            assert!(legacy_values_are_exactly_renderable(&one_wei, None));
            let one_wei_pages = render_safe_pages_inner(&one_wei, None, None, &resolver)
                .expect("1 wei uses the exact base-unit fallback");
            assert!(pages_contain(&one_wei_pages, b"wei"));

            let mut adjacent = render_input([0x44; 20], 0, raw_data);
            adjacent.value = be_u128(1_000_000_000_000_000_001);
            assert!(legacy_values_are_exactly_renderable(&adjacent, None));
            let adjacent_pages = render_safe_pages_inner(&adjacent, None, None, &resolver)
                .expect("1 ETH + 1 wei uses the exact base-unit fallback");
            assert!(pages_contain(&adjacent_pages, b"wei"));
            assert_ne!(exact_pages.buf, one_wei_pages.buf);
            assert_ne!(exact_pages.buf, adjacent_pages.buf);
            assert_ne!(one_wei_pages.buf, adjacent_pages.buf);

            let mut next_exact = render_input([0x44; 20], 0, raw_data);
            next_exact.value = be_u128(1_000_001_000_000_000_000);
            assert!(legacy_values_are_exactly_renderable(&next_exact, None));
            let next_pages = render_safe_pages_inner(&next_exact, None, None, &resolver)
                .expect("the next exact six-decimal step remains available");
            assert_ne!(exact_pages.buf, next_pages.buf);

            let mut overwide = render_input([0x44; 20], 0, raw_data);
            overwide.value = [0xff; 32];
            assert!(!legacy_values_are_exactly_renderable(&overwide, None));
            assert!(
                render_safe_pages_inner(&overwide, None, None, &resolver).is_err(),
                "an overwide native value must refuse before any Safe pages escape"
            );
        }
    }

    #[test]
    fn native_refund_bound_widens_exactly_or_refuses_before_pages_escape() {
        let resolver = NameResolver::new();
        let unknown_data = [0xde, 0xad, 0xbe, 0xef];

        let mut exact = render_input([0x44; 20], 0, &unknown_data);
        exact.gas_price = be_u128(100_000);
        assert!(legacy_values_are_exactly_renderable(&exact, None));
        let exact_pages =
            render_safe_pages_inner(&exact, None, None, &resolver).expect("3e12 wei is exact");

        let mut adjacent = render_input([0x44; 20], 0, &unknown_data);
        adjacent.gas_price = be_u128(100_001);
        assert!(legacy_values_are_exactly_renderable(&adjacent, None));
        let adjacent_pages = render_safe_pages_inner(&adjacent, None, None, &resolver)
            .expect("the derived bound may widen to remain exact");
        assert_ne!(exact_pages.buf, adjacent_pages.buf);

        let mut next_exact = render_input([0x44; 20], 0, &unknown_data);
        next_exact.gas_price = be_u128(200_000);
        assert!(legacy_values_are_exactly_renderable(&next_exact, None));
        let next_pages = render_safe_pages_inner(&next_exact, None, None, &resolver)
            .expect("the next exact native refund bound remains available");
        assert_ne!(exact_pages.buf, next_pages.buf);

        // Realistic Safe settings: a 1-gwei refund with nonzero baseGas must
        // not be rejected merely because the derived upper bound needs nine
        // fractional digits. A one-wei gas-price delta must also remain exact
        // and visibly distinct (the painter may use its raw-wei fallback).
        let mut ordinary = render_input([0x44; 20], 0, &unknown_data);
        ordinary.base_gas = be_u128(43_776);
        ordinary.gas_price = be_u128(1_000_000_000);
        assert!(legacy_values_are_exactly_renderable(&ordinary, None));
        let ordinary_pages = render_safe_pages_inner(&ordinary, None, None, &resolver)
            .expect("ordinary nonzero-baseGas refund remains available");

        let mut dusty = render_input([0x44; 20], 0, &unknown_data);
        dusty.base_gas = be_u128(43_776);
        dusty.gas_price = be_u128(1_000_000_001);
        assert!(legacy_values_are_exactly_renderable(&dusty, None));
        let dusty_pages = render_safe_pages_inner(&dusty, None, None, &resolver)
            .expect("raw-wei fallback keeps an adjacent refund bound exact");
        assert_ne!(ordinary_pages.buf, dusty_pages.buf);

        let mut raw_fit = render_input([0x44; 20], 0, &unknown_data);
        raw_fit.chain_id = 4_242_424_242;
        raw_fit.gas_price = be_u128(100_000_000_000_000_000_000);
        assert!(legacy_values_are_exactly_renderable(&raw_fit, None));
        assert!(
            render_safe_pages_inner(&raw_fit, None, None, &resolver).is_ok(),
            "a 28-digit unknown-chain raw refund bound must fit"
        );

        let mut raw_wide = render_input([0x44; 20], 0, &unknown_data);
        raw_wide.chain_id = 4_242_424_242;
        raw_wide.gas_price = be_u128(1_000_000_000_000_000_000_000);
        assert!(!legacy_values_are_exactly_renderable(&raw_wide, None));
        assert!(
            render_safe_pages_inner(&raw_wide, None, None, &resolver).is_err(),
            "a 29-digit unknown-chain raw refund bound must refuse"
        );
    }

    #[test]
    fn multisend_native_values_are_exact_on_inline_and_dedicated_pages() {
        use crate::tx::eip712::safe::multi_send::test_util::{encode_multisend, pack_record};

        let resolver = NameResolver::new();
        let multisend = sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0];
        let exact_value = be_u128(1_000_000_000_000_000_000);
        let adjacent_value = be_u128(1_000_000_000_000_000_001);

        for record_data in [&[][..], &[0xde, 0xad, 0xbe, 0xef][..]] {
            let exact_packed = pack_record(0, &[0x44; 20], &exact_value, record_data);
            let exact_calldata = encode_multisend(&exact_packed);
            let exact = render_input(multisend, 1, &exact_calldata);
            assert!(legacy_values_are_exactly_renderable(&exact, None));
            let exact_pages = render_safe_pages_inner(&exact, None, None, &resolver)
                .expect("exact record values remain available");

            let adjacent_packed = pack_record(0, &[0x44; 20], &adjacent_value, record_data);
            let adjacent_calldata = encode_multisend(&adjacent_packed);
            let adjacent = render_input(multisend, 1, &adjacent_calldata);
            assert!(legacy_values_are_exactly_renderable(&adjacent, None));
            let adjacent_pages = render_safe_pages_inner(&adjacent, None, None, &resolver)
                .expect("record values share the exact base-unit fallback");
            assert!(pages_contain(&adjacent_pages, b"wei"));
            assert_ne!(exact_pages.buf, adjacent_pages.buf);
        }

        let overwide_value = [0xff; 32];
        let overwide_packed = pack_record(0, &[0x44; 20], &overwide_value, &[]);
        let overwide_calldata = encode_multisend(&overwide_packed);
        let overwide = render_input(multisend, 1, &overwide_calldata);
        assert!(!legacy_values_are_exactly_renderable(&overwide, None));
        assert!(
            render_safe_pages_inner(&overwide, None, None, &resolver).is_err(),
            "an overwide record value must refuse the entire Safe batch"
        );
    }

    #[test]
    fn unknown_chain_multisend_native_values_use_exact_raw_width() {
        use crate::tx::eip712::safe::multi_send::test_util::{encode_multisend, pack_record};

        let resolver = NameResolver::new();
        let multisend = sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0];

        let one_packed = pack_record(0, &[0x44; 20], &be_u128(1), &[]);
        let one_calldata = encode_multisend(&one_packed);
        let mut one = render_input(multisend, 1, &one_calldata);
        one.chain_id = 4_242_424_242;
        assert!(legacy_values_are_exactly_renderable(&one, None));
        let one_pages =
            render_safe_pages_inner(&one, None, None, &resolver).expect("raw one must fit");

        let two_packed = pack_record(0, &[0x44; 20], &be_u128(2), &[]);
        let two_calldata = encode_multisend(&two_packed);
        let mut two = render_input(multisend, 1, &two_calldata);
        two.chain_id = 4_242_424_242;
        assert!(legacy_values_are_exactly_renderable(&two, None));
        let two_pages =
            render_safe_pages_inner(&two, None, None, &resolver).expect("raw two must fit");
        assert_ne!(one_pages.buf, two_pages.buf);

        let fit_value = be_u128(10u128.pow(28) - 1);
        let fit_packed = pack_record(0, &[0x44; 20], &fit_value, &[]);
        let fit_calldata = encode_multisend(&fit_packed);
        let mut fit = render_input(multisend, 1, &fit_calldata);
        fit.chain_id = 4_242_424_242;
        assert!(legacy_values_are_exactly_renderable(&fit, None));
        assert!(render_safe_pages_inner(&fit, None, None, &resolver).is_ok());

        let wide_value = be_u128(10u128.pow(28));
        let wide_packed = pack_record(0, &[0x44; 20], &wide_value, &[]);
        let wide_calldata = encode_multisend(&wide_packed);
        let mut wide = render_input(multisend, 1, &wide_calldata);
        wide.chain_id = 4_242_424_242;
        assert!(!legacy_values_are_exactly_renderable(&wide, None));
        assert!(
            render_safe_pages_inner(&wide, None, None, &resolver).is_err(),
            "a raw value wider than the real two-row painter must refuse"
        );
    }

    #[test]
    fn multisend_opaque_known_weth_deposit_record_refuses() {
        use crate::tx::eip712::safe::multi_send::test_util::{encode_multisend, pack_record};

        let packed = pack_record(0, &WETH, &[0u8; 32], &WETH_DEPOSIT);
        let calldata = encode_multisend(&packed);
        let input = render_input(
            sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0],
            1,
            &calldata,
        );
        let resolver = NameResolver::new();
        assert!(
            render_safe_pages_inner(&input, None, None, &resolver).is_err(),
            "a known opaque record must refuse the entire MultiSend"
        );

        // Non-vacuity: an unknown opaque record still reaches the loud record
        // pages, proving the gate is membership-based rather than a blanket
        // ban on Safe multiSend opacity.
        let unknown_data = [0xde, 0xad, 0xbe, 0xef];
        let unknown_packed = pack_record(0, &[0x44; 20], &[0u8; 32], &unknown_data);
        let unknown_calldata = encode_multisend(&unknown_packed);
        let unknown = render_input(
            sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0],
            1,
            &unknown_calldata,
        );
        assert!(render_safe_pages_inner(&unknown, None, None, &resolver).is_ok());
    }
}

/// Content pages for one classified inner (no divider / value pages —
/// those are multiSend-record concerns counted by the caller). Must
/// stay in lockstep with `multi_send::record_content_pages`, which the
/// handlers' page-budget gate uses for the same per-kind counts: the
/// MultiSend arm's total here IS `records_pages_total` (shared fn), and
/// each non-MultiSend arm's literal mirrors its `record_content_pages`
/// arm — a divergence would show as blank or truncated pages in the
/// QEMU multiSend e2e scenarios.
/// Body + context-banner page count for a Safe-wrapped CoW presign.
/// Each leg is 2 pages in both modes, so the body is a constant 8 and
/// this returns 9 regardless of whether `cow` is present; the absent
/// case still computes it via the AddrHex legs for symmetry.
pub(super) fn safe_cow_pages(cow: Option<&VerifiedCowswapV3>) -> usize {
    use crate::tx::eip712::cowswap::CowLeg;
    1 + cow.map_or(
        order_body_page_count(&CowLeg::AddrHex, &CowLeg::AddrHex),
        |v| order_body_page_count(&v.sell, &v.buy),
    )
}

pub(super) fn inner_kind_page_count(kind: &InnerKind<'_>) -> usize {
    match kind {
        InnerKind::EmptyCall => 1,
        InnerKind::PlainEth => 2,
        // 4 = header + recipient + amount + contract; +1 for the
        // transferFrom `From (debited)` page (kept in lockstep with
        // `append_erc20_tail_pages` and `multi_send::record_content_pages`).
        InnerKind::Erc20Known(call) | InnerKind::Erc20Unknown(call) => {
            4 + usize::from(matches!(call, Erc20Call::TransferFrom { .. }))
        }
        InnerKind::SafeMgmt(op) => safe_mgmt_page_count(op),
        // Context banner + the shared CoW order body (constant 8 pages).
        InnerKind::CowswapPresign(v3) => safe_cow_pages(Some(v3)),
        InnerKind::UnknownSafeSelf => 3,
        InnerKind::MultiSend { inner_pages, .. } => *inner_pages,
        InnerKind::Blind => 3,
    }
}

/// Everything one inner render needs, scoped so a multiSend record and
/// a single-call SafeTx flow through the same arm bodies. `data_hash`
/// is the bound SafeTx data hash for the single-call shape and
/// `keccak(record.data)` for a record (the record bytes sit inside the
/// data_hash-bound blob, so the recompute is honest).
struct InnerRenderCtx<'a, 'r> {
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    value: U256,
    data: &'a [u8],
    data_hash: [u8; 32],
    erc20: Option<&'a Erc20Metadata<'a>>,
    resolver: &'a NameResolver<'r>,
}

/// Append the pages for one classified inner (a single-call SafeTx's
/// inner call, or one multiSend record). Returns the next free page.
///
/// The arm bodies are the former inline match in
/// `render_safe_pages_inner`, parameterised over [`InnerRenderCtx`] —
/// behaviour for single-call SafeTxs is unchanged.
fn append_inner_kind_pages(
    pages: &mut Pages,
    start: usize,
    kind: &InnerKind<'_>,
    ctx: &InnerRenderCtx<'_, '_>,
) -> usize {
    let mut next_page = start;
    match kind {
        InnerKind::EmptyCall => {
            // P_n: "Empty call to:" + the FULL target address (rows 1-3),
            // resolver-aware. An empty call still triggers `to`'s
            // receive()/fallback(), and `to` is a signed field, so it must be
            // shown in full like every other inner `to`. EmptyCall was the one
            // inner kind that never repeated `to` in full — the old
            // `write_short_addr` showed 6 of 20 bytes and skipped the name DB
            // (audit 2026-06-26), violating the per-record divider's own
            // "ERC-20 / blind / mgmt pages repeat it in full" invariant. Stays
            // ONE page (the 40-hex / resolved name fills rows 1-3), so
            // `inner_kind_page_count` / `record_content_pages` (= 1) and the
            // multiSend page-budget lockstep are unchanged.
            write_line(&mut pages.buf[next_page][0], "Empty call to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
        }
        InnerKind::PlainEth => {
            // P_n: "Inner to:" + addr full
            write_line(&mut pages.buf[next_page][0], "Inner to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // P_n+1: chain-native send + amount.
            write_native_currency_row(&mut pages.buf[next_page][0], b"Send ", ctx.chain_id, b":");
            {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_native_amount_two_rows(r1, r2, &ctx.value, ctx.chain_id);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
            next_page += 1;
        }
        InnerKind::Erc20Known(call) => {
            let meta = ctx
                .erc20
                .expect("InnerKind::Erc20Known implies erc20 metadata present");
            // P_n: "Send/Approve SYM" + token name + native-ETH warn + "> next"
            write_erc20_header(&mut pages.buf[next_page][0], call, meta);
            write_token_name(&mut pages.buf[next_page][1], meta);
            if !ctx.value.is_zero() {
                write_native_currency_row(
                    &mut pages.buf[next_page][2],
                    b"! native ",
                    ctx.chain_id,
                    b"!",
                );
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            next_page = append_erc20_tail_pages(pages, next_page, call, Some(meta), ctx);
        }
        InnerKind::Erc20Unknown(call) => {
            // P_n: "ERC-20 call" / "(unverified)" + native-ETH warn + "> next"
            write_line(&mut pages.buf[next_page][0], "ERC-20 call");
            write_line(&mut pages.buf[next_page][1], "(unverified)");
            if !ctx.value.is_zero() {
                write_native_currency_row(
                    &mut pages.buf[next_page][2],
                    b"! native ",
                    ctx.chain_id,
                    b"!",
                );
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            next_page = append_erc20_tail_pages(pages, next_page, call, None, ctx);
        }
        InnerKind::Blind => {
            // P_n: loud banner
            write_line(&mut pages.buf[next_page][0], "! BLIND SIGN");
            write_line(&mut pages.buf[next_page][1], "Unknown call");
            write_line(&mut pages.buf[next_page][2], "Verify on dapp");
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // P_n+1: "Inner to:" + addr (full)
            write_line(&mut pages.buf[next_page][0], "Inner to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // P_n+2: selector + data length + first/last data-hash bytes
            write_selector_row(&mut pages.buf[next_page][0], ctx.data);
            write_data_len_row(&mut pages.buf[next_page][1], ctx.data.len());
            // Reuse the "calldata hash" 2-row layout but spread it
            // over rows 2 + 3 so we surface the inner data's keccak
            // (which `ctx.data_hash` already commits to via the bind).
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &ctx.data_hash);
            }
            next_page += 1;
        }
        InnerKind::SafeMgmt(op) => {
            next_page = render_safe_mgmt_pages(
                pages,
                next_page,
                op,
                ctx.chain_id,
                &ctx.safe_address,
                ctx.resolver,
            );
        }
        InnerKind::CowswapPresign(v3) => {
            // P_n: context banner — the load-bearing linkage page. The
            // user must understand that the order shown on the next
            // pages is owned by (sells the funds of) THIS Safe, not the
            // wallet. The short-form Safe address lets them eyeball it
            // against the full-address page 1 without flipping back.
            write_line(&mut pages.buf[next_page][0], "CowSwap order");
            write_line(&mut pages.buf[next_page][1], "for this Safe:");
            write_short_addr(&mut pages.buf[next_page][2], &ctx.safe_address);
            // Surface the sell/buy direction on the context banner; the
            // per-leg labels in the body restate it but this keeps it
            // visible up-front (the direct flow shows it on page 0).
            write_line(
                &mut pages.buf[next_page][3],
                order_kind_label(&v3.canonical),
            );
            next_page += 1;
            // P_n+1..: the shared CoW order body. Zero receiver renders
            // as "(= the Safe)" — GPv2 routes proceeds to the uid owner,
            // which the handler verified is this Safe.
            next_page = append_order_body_pages(
                pages,
                next_page,
                &v3.canonical,
                &v3.sell,
                &v3.buy,
                Some("(= the Safe)"),
            );
        }
        InnerKind::UnknownSafeSelf => {
            // Loud variant of Blind that distinguishes "self-call to the
            // Safe contract with an unrecognised selector" from a generic
            // opaque inner call. The user sees the extra warning row and
            // can refuse if the dapp didn't ask for a Safe-mgmt op.
            write_line(&mut pages.buf[next_page][0], "! UNKNOWN SAFE OP");
            write_line(&mut pages.buf[next_page][1], "Self-call to Safe");
            write_line(&mut pages.buf[next_page][2], "Verify off-device");
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // Inner `to` (= Safe address; rendered full so a name in the
            // names bundle still lights up).
            write_line(&mut pages.buf[next_page][0], "Inner to (Safe):");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
            }
            next_page += 1;
            // Selector + data length + bound data-hash (matches the
            // Blind branch's last page so the user can compare on-device).
            write_selector_row(&mut pages.buf[next_page][0], ctx.data);
            write_data_len_row(&mut pages.buf[next_page][1], ctx.data.len());
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &ctx.data_hash);
            }
            next_page += 1;
        }
        InnerKind::MultiSend { .. } => {
            // Unreachable: the caller routes MultiSend through
            // `append_multisend_pages` (records never classify as
            // MultiSend — `classify_record_kind` has no such arm, so
            // there is no recursion either). Render nothing.
            debug_assert!(false, "MultiSend must not reach append_inner_kind_pages");
        }
    }
    next_page
}

/// Shared recipient/amount/contract tail (3 pages) for the two ERC-20
/// flavours — `meta = Some` renders decimals + symbol, `None` renders
/// the raw hex amount. The label page above differs per flavour and
/// stays at the call sites.
fn append_erc20_tail_pages(
    pages: &mut Pages,
    start: usize,
    call: &Erc20Call,
    meta: Option<&Erc20Metadata<'_>>,
    ctx: &InnerRenderCtx<'_, '_>,
) -> usize {
    let mut next_page = start;
    // From (debited account) — transferFrom only. The `from` is a signed
    // calldata operand that names a THIRD-PARTY account being pulled (not
    // the wallet/Safe), so it gets its own page; hiding it is the same
    // WYSIWYS gap closed on the direct ERC-20 renderers (audit 2026-06-18).
    // This +1 page for transferFrom is mirrored by `inner_kind_page_count`
    // and `multi_send::record_content_pages` so the multiSend page-budget
    // gate stays exact.
    if let Erc20Call::TransferFrom { from, .. } = call {
        write_line(&mut pages.buf[next_page][0], "From (debited):");
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, from, ctx.chain_id, ctx.resolver);
        next_page += 1;
    }
    // Recipient/spender (full address). An `approve` whose spender is
    // the pinned CoW vault relayer gets a verified human label — the
    // equality is against the rodata constant, not companion data.
    let recipient: [u8; 20] = match call {
        Erc20Call::Transfer { to, .. } => *to,
        Erc20Call::TransferFrom { to, .. } => *to,
        Erc20Call::Approve { spender, .. } => *spender,
    };
    let recipient_label: &str = match call {
        Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
        Erc20Call::Approve { .. } if recipient == GPV2_VAULT_RELAYER_ADDRESS => "CoW VaultRelayer",
        Erc20Call::Approve { .. } => "Spender:",
    };
    write_line(&mut pages.buf[next_page][0], recipient_label);
    {
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, &recipient, ctx.chain_id, ctx.resolver);
    }
    next_page += 1;
    // Amount (with unlimited-approve guard).
    let amount: U256 = match call {
        Erc20Call::Transfer { amount, .. } => *amount,
        Erc20Call::TransferFrom { amount, .. } => *amount,
        Erc20Call::Approve { amount, .. } => *amount,
    };
    match meta {
        Some(meta) => {
            write_line(&mut pages.buf[next_page][0], "Amount:");
            if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
                write_line(&mut pages.buf[next_page][1], "unlimited");
                write_line(&mut pages.buf[next_page][2], "");
                write_line(&mut pages.buf[next_page][3], "> next");
            } else {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_token_amount_two_rows(r1, r2, &amount, meta);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
        }
        None => {
            // Raw amount, decimals unknown. Render the FULL integer
            // magnitude (no decimals, "units" suffix) with a loud overflow
            // banner — NEVER a middle-truncated hex that hides the
            // magnitude (audit 2026-06-23 — Safe-inner unverified-ERC-20
            // amount magnitude-hiding drain). The companion can force this
            // `meta == None` arm for ANY token by withholding the optional
            // ERC-20 metadata trailer, so the old head-7/tail-6 hex (bytes
            // 7..26 dropped) let a benign-looking `0x000…0064` tail hide a
            // huge transfer the wallet/Safe was signing. This mirrors the
            // top-level `erc20_unknown` renderer (full decimal, loud
            // overflow) and the refund-page unknown-token treatment.
            write_line(&mut pages.buf[next_page][0], "Raw amount:");
            if matches!(call, Erc20Call::Approve { .. }) && is_unlimited_amount(&amount) {
                write_line(&mut pages.buf[next_page][1], "unlimited");
                write_line(&mut pages.buf[next_page][2], "");
                write_line(&mut pages.buf[next_page][3], "> next");
            } else {
                let units = Erc20Metadata {
                    chain_id: 0,
                    contract: [0u8; 20],
                    decimals: 0,
                    name: &[],
                    symbol: b"units",
                };
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_token_amount_two_rows(r1, r2, &amount, &units);
                write_line(
                    foot,
                    match fit {
                        AmountFit::Full => "> next",
                        AmountFit::Overflow => "!AMOUNT OVERFLOW",
                    },
                );
            }
        }
    }
    next_page += 1;
    // Contract (full address) — anti-spoof.
    write_line(&mut pages.buf[next_page][0], "Contract:");
    {
        let [_lbl, a, b, c] = &mut pages.buf[next_page];
        write_addr_full_or_name(a, b, c, &ctx.to, ctx.chain_id, ctx.resolver);
    }
    next_page += 1;
    next_page
}

/// One multiSend record with its display decisions, as both painters see it.
pub(super) struct MsRecordSem<'a> {
    pub(super) idx: usize,
    pub(super) rec: MsRecord<'a>,
    pub(super) kind: InnerKind<'a>,
    pub(super) needs_value_page: bool,
    pub(super) meta: Option<&'a Erc20Metadata<'a>>,
}

/// The record the verified CoW order is bound to (unique presign claim) —
/// the same selection the resolver made, re-derived from the same bytes.
pub(super) fn presign_unique_idx(raw_data: &[u8]) -> Option<usize> {
    multi_send::summarize(raw_data)
        .ok()
        .filter(|s| s.presign_claims == 1)
        .map(|s| s.presign_idx)
}

/// Classify one decoded multiSend record exactly as the legacy painter does:
/// metadata applies per record by address match (the single-call rule), and
/// the CoW order renders ONLY on the record the handler verified the v3
/// trailer against (unique presign claim); any other pairing is an
/// impossible state that falls to the loud blind pages, never fail-rich.
pub(super) fn multisend_record_semantics<'a>(
    input: &SafeRenderInput<'a>,
    cow: Option<&'a VerifiedCowswapV3>,
    erc20: Option<&'a Erc20Metadata<'a>>,
    presign_unique_idx: Option<usize>,
    idx: usize,
    rec: MsRecord<'a>,
) -> MsRecordSem<'a> {
    let value = U256(rec.value);
    let raw_kind = classify_record_kind(&rec.to, value.is_zero(), rec.data, &input.safe_address);
    let needs_value_page = record_needs_value_page(&raw_kind, value.is_zero());
    let meta = erc20.filter(|m| m.contract == rec.to);
    let kind: InnerKind<'a> = match raw_kind {
        MsRecordKind::EmptyCall => InnerKind::EmptyCall,
        MsRecordKind::PlainEth => InnerKind::PlainEth,
        MsRecordKind::Erc20(call) if meta.is_some() => InnerKind::Erc20Known(call),
        MsRecordKind::Erc20(call) => InnerKind::Erc20Unknown(call),
        MsRecordKind::SafeMgmt(op) => InnerKind::SafeMgmt(op),
        MsRecordKind::UnknownSafeSelf => InnerKind::UnknownSafeSelf,
        MsRecordKind::CowPresignClaim => match (cow, presign_unique_idx) {
            (Some(v3), Some(pi)) if pi == idx => InnerKind::CowswapPresign(v3),
            _ => InnerKind::Blind,
        },
        MsRecordKind::Blind => InnerKind::Blind,
    };
    MsRecordSem {
        idx,
        rec,
        kind,
        needs_value_page,
        meta,
    }
}

/// Render every record of an allowlisted multiSend batch: divider page
/// ("MSend rec i/N" + target), an explicit value page for any record
/// that forwards ETH without showing it inline, then the record's
/// classified pages via [`append_inner_kind_pages`].
fn append_multisend_pages<'a>(
    pages: &mut Pages,
    start: usize,
    input: &SafeRenderInput<'a>,
    count: usize,
    cow: Option<&'a VerifiedCowswapV3>,
    erc20: Option<&'a Erc20Metadata<'a>>,
    resolver: &NameResolver<'_>,
) -> usize {
    let mut p = start;
    let Ok(packed) = multi_send::decode_multisend(input.raw_data) else {
        // Unreachable post-gate; the classification block already fell
        // to Blind for undecodable claims.
        return p;
    };
    let presign_idx = presign_unique_idx(input.raw_data);
    let mut idx = 0usize;
    for rec in MsRecordIter::new(packed) {
        // Decode errors are unreachable post-gate (summarize already
        // walked every record); stop cleanly rather than render a
        // half-decoded batch.
        let Ok(rec) = rec else { break };
        let sem = multisend_record_semantics(input, cow, erc20, presign_idx, idx, rec);
        write_msend_divider_page(pages, p, idx, count, &sem.rec.to);
        p += 1;
        let value = U256(sem.rec.value);
        if sem.needs_value_page {
            write_record_value_page(pages, p, &value, input.chain_id);
            p += 1;
        }
        let ctx = InnerRenderCtx {
            chain_id: input.chain_id,
            safe_address: input.safe_address,
            to: sem.rec.to,
            value,
            data: sem.rec.data,
            data_hash: keccak(sem.rec.data),
            erc20: sem.meta,
            resolver,
        };
        p = append_inner_kind_pages(pages, p, &sem.kind, &ctx);
        idx += 1;
    }
    p
}

/// Divider page before each multiSend record: position, target address
/// (short form — ERC-20 / blind / mgmt pages repeat it in full).
fn write_msend_divider_page(
    pages: &mut Pages,
    page: usize,
    idx: usize,
    count: usize,
    to: &[u8; 20],
) {
    {
        let row = &mut pages.buf[page][0];
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"MSend rec ";
        row[..prefix.len()].copy_from_slice(prefix);
        // `idx` is 0-based; show 1-based "i/N". Both bounded to one
        // digit by MULTISEND_MAX_RECORDS (6).
        row[prefix.len()] = b'1' + (idx as u8);
        row[prefix.len() + 1] = b'/';
        row[prefix.len() + 2] = b'0' + (count as u8);
    }
    write_line(&mut pages.buf[page][1], "to:");
    write_short_addr(&mut pages.buf[page][2], to);
    write_line(&mut pages.buf[page][3], "> next");
}

/// Dedicated value page for a multiSend record whose kind doesn't show its
/// forwarded native currency inline — mirrors the SafeTx-level value page.
fn write_record_value_page(pages: &mut Pages, page: usize, value: &U256, chain_id: u64) {
    write_line(&mut pages.buf[page][0], "Record value:");
    let [_lbl, r1, r2, foot] = &mut pages.buf[page];
    let fit = write_native_amount_two_rows(r1, r2, value, chain_id);
    write_line(
        foot,
        match fit {
            AmountFit::Full => "> next",
            AmountFit::Overflow => "!AMOUNT OVERFLOW",
        },
    );
}

/// Page-2 hint row for the multiSend flow: "Inner: MSend xN".
fn write_msend_hint_row(row: &mut [u8; DISPLAY_COLS], count: usize) {
    *row = [b' '; DISPLAY_COLS];
    let prefix = b"Inner: MSend x";
    row[..prefix.len()].copy_from_slice(prefix);
    // Bounded to one digit by MULTISEND_MAX_RECORDS (6).
    row[prefix.len()] = b'0' + (count as u8).min(9);
}

// The returned `InnerKind` never borrows from the arguments — the
// lifetime parameter only exists for the `CowswapPresign` variant,
// which this classifier never produces (the caller selects it from the
// handler-verified `cow` before consulting the ladder).
fn classify_inner<'a>(raw_data: &[u8], value: &U256) -> InnerKind<'a> {
    if raw_data.is_empty() {
        if value.is_zero() {
            InnerKind::EmptyCall
        } else {
            InnerKind::PlainEth
        }
    } else {
        match parse_erc20_calldata(raw_data) {
            Some(call) => {
                // We can't decide here whether the metadata is going
                // to be present (the caller passes it separately and
                // also has to address-match it). Default to
                // `Erc20Known` and let the renderer fall back if the
                // metadata is absent or mismatched. Mismatch handling
                // happens in `pick_sign_pages` (the caller suppresses
                // the metadata when contracts don't align).
                InnerKind::Erc20Known(call)
            }
            None => InnerKind::Blind,
        }
    }
}

/// Wrap [`super::primitives::write_nonce_row`]'s u64 path: SafeTx
/// nonces are uint256s on-chain, but in practice they fit in a u64
/// for the foreseeable future. If the high 24 bytes are non-zero we
/// fall back to a hex-tail render so the user knows it overflowed.
fn write_safe_nonce_row(row: &mut [u8; DISPLAY_COLS], nonce_be: &[u8; 32]) {
    // Check if the upper 24 bytes are zero so we can render as decimal.
    let high_nonzero = nonce_be[..24].iter().any(|&b| b != 0);
    if !high_nonzero {
        let n = u64::from_be_bytes([
            nonce_be[24],
            nonce_be[25],
            nonce_be[26],
            nonce_be[27],
            nonce_be[28],
            nonce_be[29],
            nonce_be[30],
            nonce_be[31],
        ]);
        // Use our own label so this can't be confused with the inner-tx
        // `write_nonce_row` "Nonce:" — but keep it short. On a 16-column row
        // "SafeTx Nonce: " (14 cols) left only 2 columns for digits, so any
        // nonce >= 100 (i.e. essentially every active Safe, whose nonce
        // increments per executed tx) rendered as the "!O" overflow marker and
        // the user could not read it to cross-check against the dApp. "SafeTx #"
        // (8 cols) leaves 8 digit columns (up to 99_999_999) — more than any
        // realistic Safe nonce; anything larger still falls to the loud marker.
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"SafeTx #";
        let n_pre = core::cmp::min(prefix.len(), row.len());
        row[..n_pre].copy_from_slice(&prefix[..n_pre]);
        let mut tmp = [0u8; 20];
        if let Some(width) = format_u64(n, &mut tmp) {
            let start = n_pre;
            if start + width <= row.len() {
                row[start..start + width].copy_from_slice(&tmp[..width]);
            } else {
                // overflow marker
                let _ = write_overflow_marker(row, n_pre);
            }
        } else {
            let _ = write_overflow_marker(row, n_pre);
        }
    } else {
        // Pathological: nonce > u64::MAX. Render as
        // "SafeTx N: >2^64" which is unmistakable.
        let prefix = b"SafeTx N: >2^64";
        *row = [b' '; DISPLAY_COLS];
        let n = core::cmp::min(prefix.len(), row.len());
        row[..n].copy_from_slice(&prefix[..n]);
    }
}

/// Decode the low 8 bytes of a 32-byte big-endian uint as a `u64`.
/// Returns `(value, overflowed)` with `overflowed == true` (and `value ==
/// u64::MAX`) when the high 24 bytes are non-zero — i.e. the operand
/// exceeds `u64::MAX`. Used for the `baseGas * gasPrice` base-cost page via
/// [`U256::saturating_mul_u64`]; a `baseGas` beyond `u64` makes the cost
/// astronomically large, which the caller renders as a loud `!HUGE`.
pub(super) fn u64_be_tail(be: &[u8; 32]) -> (u64, bool) {
    let high_nonzero = be[..24].iter().any(|&b| b != 0);
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&be[24..32]);
    if high_nonzero {
        (u64::MAX, true)
    } else {
        (u64::from_be_bytes(tail), false)
    }
}

fn write_overflow_marker(row: &mut [u8; DISPLAY_COLS], pos: usize) -> usize {
    let marker = b"!OVF";
    let space = row.len().saturating_sub(pos);
    let n = core::cmp::min(marker.len(), space);
    row[pos..pos + n].copy_from_slice(&marker[..n]);
    pos + n
}

/// Render the first 4 + last 4 bytes of an address into a single
/// 16-column row: "0xAABBCCDD..EEFFAABB" — 2+8+2+8 = 20 chars,
/// truncated to 16 by dropping the trailing 4 hex chars when needed.
/// This is a one-row alternative to [`write_addr_full_or_name`] for
/// pages that only have a single line to spare.
fn write_short_addr(row: &mut [u8; DISPLAY_COLS], addr: &[u8; 20]) {
    *row = [b' '; DISPLAY_COLS];
    row[0] = b'0';
    row[1] = b'x';
    let hex = b"0123456789abcdef";
    // First 3 bytes
    for i in 0..3 {
        row[2 + i * 2] = hex[(addr[i] >> 4) as usize];
        row[2 + i * 2 + 1] = hex[(addr[i] & 0x0f) as usize];
    }
    row[8] = b'.';
    row[9] = b'.';
    // Last 3 bytes
    for i in 0..3 {
        let b = addr[17 + i];
        row[10 + i * 2] = hex[(b >> 4) as usize];
        row[10 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
}

// `write_raw_uint_two_rows` (head-7/tail-6 hex of a 32-byte amount) was
// removed 2026-06-23: it hid the middle 19 bytes of the signed amount, a
// magnitude-hiding WYSIWYS drain on the unverified-ERC-20 path. The
// "Raw amount:" page now renders the full integer magnitude via
// `write_token_amount_two_rows` with a loud overflow fallback (see the
// `meta == None` arm of `append_erc20_tail_pages`).
