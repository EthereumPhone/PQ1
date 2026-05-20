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
//! Page layout (variable, capped at `MAX_PAGES = 10`):
//!
//! ```text
//!   0: "Approve Safe TX"     1: "Safe:"             2: "SafeTx Nonce: N"
//!      Chain: <n>                <addr full>            Op: Call
//!      <chain name>              <addr full>            <inner kind hint>
//!      > next                    <addr full>            > next
//!
//!   3..N: inner-tx pages (one of):
//!         * plain ETH transfer  (2 pages: "Inner to" + "Send ETH")
//!         * ERC-20 known        (4 pages: header + recipient + amount + contract)
//!         * ERC-20 unknown      (4 pages: same shape, no symbol)
//!         * Safe-mgmt           (1..3 pages, per-op intent banner;
//!                                see [`super::safe_mgmt`]). Fires
//!                                when `canonical.to == safe_address`
//!                                and selector matches one of the
//!                                eight Safe v1.3.0+ singleton ops.
//!         * unknown Safe op     (3 pages: "Unknown Safe op" + Inner-to + selector/hash)
//!         * blind-sign          (3 pages: "Unknown call" + "Inner to" + selector/hash)
//!
//!   last: "L=Cancel"
//!         "R=Confirm"
//! ```
//!
//! DelegateCall is rejected upstream in
//! `crate::tx::eip712::safe::verify_and_bind_trailer`, so this
//! renderer always shows `Op: Call`.

use super::primitives::{
    chain_name, format_u64, write_addr_full_or_name, write_calldata_hash_rows, write_chain,
    write_data_len_row, write_erc20_header, write_eth_two_rows, write_line, write_selector_row,
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
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::{decode_canonical, SafeTx, VerifiedSafeExec, VerifiedSafeV1};
use crate::ui::DISPLAY_COLS;

/// Number of fixed Safe-level header pages rendered before the inner-tx
/// pages and the trailing confirm page.
const SAFE_HEADER_PAGES: usize = 3;

/// Which Safe flow the render is being driven from. Used to pick the
/// banner string on page 0 and decide what to show on the metadata page
/// (approveHash carries a SafeTx nonce in the canonical; execTransaction
/// only sees the SafeTx nonce on-chain at execution time).
#[derive(Copy, Clone)]
enum SafeRenderFlavour {
    /// `approveHash(bytes32)` — the firmware re-derived the SafeTx hash
    /// from the trailer's canonical and bound it to the calldata
    /// argument. The user is approving the hash now; the Safe will
    /// execute it later once threshold approvals collect.
    ApproveHash { nonce: [u8; 32] },
    /// `execTransaction(...)` — the wallet is the EOA-equivalent
    /// triggering the Safe to execute. SafeTx fields come from the
    /// calldata directly (no separate trailer). Nonce is determined
    /// by the Safe's storage at execution time and is not visible
    /// to the firmware.
    ExecTransaction { gas_price: [u8; 32] },
}

/// Normalised input to the shared Safe rendering body. Approve-hash and
/// exec-transaction both reduce to the same display surface: chain, Safe
/// address, op + inner-kind hint, inner-tx pages, confirm.
struct SafeRenderInput<'a> {
    flavour: SafeRenderFlavour,
    chain_id: u64,
    safe_address: [u8; 20],
    to: [u8; 20],
    value: [u8; 32],
    raw_data: &'a [u8],
    /// keccak256(raw_data). For approveHash this comes from the
    /// canonical (already byte-equal to keccak256(raw_data) by the
    /// verifier's bind step); for exec we compute it here so the
    /// blind-sign branches can still surface it.
    data_hash: [u8; 32],
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
pub fn render_safe_v1_pages(
    safe: &VerifiedSafeV1<'_>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
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
        value: tx.value,
        raw_data: safe.raw_data,
        data_hash: tx.data_hash,
    };
    render_safe_pages_inner(&input, erc20, resolver)
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
pub fn render_safe_exec_pages(
    exec: &VerifiedSafeExec<'_>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
    let d = &exec.decoded;
    // The verifier already proved `operation == 0`; the bind branch
    // forbids DelegateCall, so callers that reach this function are
    // safe to treat as `Op: Call`. Compute the data hash for the
    // blind-sign / unknown-Safe-op branches that show it.
    let data_hash = keccak(d.data);
    let input = SafeRenderInput {
        flavour: SafeRenderFlavour::ExecTransaction {
            gas_price: d.gas_price,
        },
        chain_id: exec.chain_id,
        safe_address: exec.safe_address,
        to: d.to,
        value: d.value,
        raw_data: d.data,
        data_hash,
    };
    render_safe_pages_inner(&input, erc20, resolver)
}

/// Shared rendering body for both approveHash and execTransaction.
fn render_safe_pages_inner(
    input: &SafeRenderInput<'_>,
    erc20: Option<&Erc20Metadata<'_>>,
    resolver: &NameResolver<'_>,
) -> Pages {
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

    // Refund-risk warning page is added only on the execTransaction path
    // when `gas_price != 0`. Safe's refund mechanism pays the executor
    // back `(safeTxGas + baseGas) * gasPrice` in `gasToken` (or ETH if
    // `gasToken == 0`), so a non-zero gasPrice is a real value flow the
    // user should see.
    let refund_warning = matches!(
        input.flavour,
        SafeRenderFlavour::ExecTransaction { gas_price }
            if gas_price.iter().any(|&b| b != 0)
    );

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
    let inner_value = U256(tx.value);
    let inner_kind = if tx.to == tx.safe_address && !safe.raw_data.is_empty() {
        match classify_safe_mgmt(safe.raw_data) {
            Some(op) => InnerKind::SafeMgmt(op),
            None => InnerKind::UnknownSafeSelf,
        }
    } else {
        match classify_inner(safe.raw_data, &inner_value) {
            InnerKind::Erc20Known(call) if erc20.is_some() => InnerKind::Erc20Known(call),
            InnerKind::Erc20Known(call) => InnerKind::Erc20Unknown(call),
            other => other,
        }
    };
    let inner_pages = match &inner_kind {
        InnerKind::PlainEth => 2,
        InnerKind::EmptyCall => 1,
        InnerKind::Erc20Known(_) | InnerKind::Erc20Unknown(_) => 4,
        InnerKind::SafeMgmt(op) => safe_mgmt_page_count(op),
        InnerKind::UnknownSafeSelf => 3,
        InnerKind::Blind => 3,
    };
    let refund_pages = if refund_warning { 1 } else { 0 };
    let total_pages = SAFE_HEADER_PAGES + refund_pages + inner_pages + 1; // +1 = confirm
    let total_pages = core::cmp::min(total_pages, super::MAX_PAGES);
    let mut pages = Pages::with_len(total_pages);

    // ── Page 0: banner + chain ──────────────────────────────────────
    let banner = match input.flavour {
        SafeRenderFlavour::ApproveHash { .. } => "Approve Safe TX",
        SafeRenderFlavour::ExecTransaction { .. } => "Execute Safe TX",
    };
    write_line(&mut pages.buf[0][0], banner);
    write_chain(&mut pages.buf[0][1], tx.chain_id);
    write_line(&mut pages.buf[0][2], chain_name(tx.chain_id));
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
        SafeRenderFlavour::ExecTransaction { .. } => {
            // No SafeTx nonce visible from calldata — the Safe reads it
            // from storage at execution time. Surface the flow so the
            // user can tell this apart from an approveHash render at a
            // glance.
            write_line(&mut pages.buf[2][0], "(execute now)");
        }
    }
    write_line(&mut pages.buf[2][1], "Op: Call");
    write_line(&mut pages.buf[2][2], inner_kind_hint(&inner_kind));
    write_line(&mut pages.buf[2][3], "> next");

    // ── Optional page 3: refund-risk warning (exec only, gasPrice>0) ─
    let mut next_page = SAFE_HEADER_PAGES;
    if refund_warning {
        // The user is paying the executor `(safeTxGas + baseGas) * gasPrice`
        // in `gasToken` (ETH when `gasToken == 0`). Most modern Safes set
        // `gasPrice = 0`, so flagging the rare non-zero case loudly is
        // proportional. We don't decode the amount — it depends on the
        // executor's actual gas usage which the firmware can't know.
        write_line(&mut pages.buf[next_page][0], "! GAS REFUND");
        write_line(&mut pages.buf[next_page][1], "Safe pays exec");
        write_line(&mut pages.buf[next_page][2], "gasPrice != 0");
        write_line(&mut pages.buf[next_page][3], "> next");
        next_page += 1;
    }

    // ── Inner-tx pages ──────────────────────────────────────────────
    match inner_kind {
        InnerKind::EmptyCall => {
            // P_n: "Inner: empty call" / "Inner to:" / addr-summary / "> next"
            write_line(&mut pages.buf[next_page][0], "Inner: empty");
            write_line(&mut pages.buf[next_page][1], "(no calldata)");
            // Use a compact name+truncated-hex form by writing just one
            // row's worth of address. The full address is on the next
            // page if we had room, but for the empty-call case we save
            // a page.
            write_short_addr(&mut pages.buf[next_page][2], &tx.to);
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
        }
        InnerKind::PlainEth => {
            // P_n: "Inner to:" + addr full
            write_line(&mut pages.buf[next_page][0], "Inner to:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &tx.to, tx.chain_id, resolver);
            }
            next_page += 1;
            // P_n+1: "Send ETH:" + amount
            write_line(&mut pages.buf[next_page][0], "Send ETH:");
            {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                let fit = write_eth_two_rows(r1, r2, &inner_value);
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
            let meta = erc20.expect("InnerKind::Erc20Known implies erc20 metadata present");
            // P_n: "Send/Approve SYM" + token name + native-ETH warn + "> next"
            write_erc20_header(&mut pages.buf[next_page][0], &call, meta);
            write_token_name(&mut pages.buf[next_page][1], meta);
            if !inner_value.is_zero() {
                write_line(&mut pages.buf[next_page][2], "! native ETH!");
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // P_n+1: recipient/spender (full address)
            let recipient_label: &str = match call {
                Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
                Erc20Call::Approve { .. } => "Spender:",
            };
            write_line(&mut pages.buf[next_page][0], recipient_label);
            let recipient: [u8; 20] = match call {
                Erc20Call::Transfer { to, .. } => to,
                Erc20Call::TransferFrom { to, .. } => to,
                Erc20Call::Approve { spender, .. } => spender,
            };
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &recipient, tx.chain_id, resolver);
            }
            next_page += 1;
            // P_n+2: amount (with unlimited-approve guard)
            write_line(&mut pages.buf[next_page][0], "Amount:");
            let amount: U256 = match call {
                Erc20Call::Transfer { amount, .. } => amount,
                Erc20Call::TransferFrom { amount, .. } => amount,
                Erc20Call::Approve { amount, .. } => amount,
            };
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
            next_page += 1;
            // P_n+3: contract (full address) — anti-spoof
            write_line(&mut pages.buf[next_page][0], "Contract:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &tx.to, tx.chain_id, resolver);
            }
            next_page += 1;
        }
        InnerKind::Erc20Unknown(call) => {
            // P_n: "ERC-20 call" / "(unverified)" + native-ETH warn + "> next"
            write_line(&mut pages.buf[next_page][0], "ERC-20 call");
            write_line(&mut pages.buf[next_page][1], "(unverified)");
            if !inner_value.is_zero() {
                write_line(&mut pages.buf[next_page][2], "! native ETH!");
            }
            write_line(&mut pages.buf[next_page][3], "> next");
            next_page += 1;
            // P_n+1: recipient/spender (full)
            let recipient_label: &str = match call {
                Erc20Call::Transfer { .. } | Erc20Call::TransferFrom { .. } => "Recipient:",
                Erc20Call::Approve { .. } => "Spender:",
            };
            write_line(&mut pages.buf[next_page][0], recipient_label);
            let recipient: [u8; 20] = match call {
                Erc20Call::Transfer { to, .. } => to,
                Erc20Call::TransferFrom { to, .. } => to,
                Erc20Call::Approve { spender, .. } => spender,
            };
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &recipient, tx.chain_id, resolver);
            }
            next_page += 1;
            // P_n+2: raw amount (no decimals known)
            write_line(&mut pages.buf[next_page][0], "Raw amount:");
            let amount_u256: U256 = match call {
                Erc20Call::Transfer { amount, .. } => amount,
                Erc20Call::TransferFrom { amount, .. } => amount,
                Erc20Call::Approve { amount, .. } => amount,
            };
            // Render the amount as a hex tail across two rows so the
            // user can compare against a dapp's hex (no decimals
            // available without a verified metadata entry).
            {
                let [_lbl, r1, r2, foot] = &mut pages.buf[next_page];
                write_raw_uint_two_rows(r1, r2, &amount_u256);
                write_line(foot, "> next");
            }
            next_page += 1;
            // P_n+3: contract (full)
            write_line(&mut pages.buf[next_page][0], "Contract:");
            {
                let [_lbl, a, b, c] = &mut pages.buf[next_page];
                write_addr_full_or_name(a, b, c, &tx.to, tx.chain_id, resolver);
            }
            next_page += 1;
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
                write_addr_full_or_name(a, b, c, &tx.to, tx.chain_id, resolver);
            }
            next_page += 1;
            // P_n+2: selector + data length + first/last data-hash bytes
            write_selector_row(&mut pages.buf[next_page][0], safe.raw_data);
            write_data_len_row(&mut pages.buf[next_page][1], safe.raw_data.len());
            // Reuse the "calldata hash" 2-row layout but spread it
            // over rows 2 + 3 so we surface the inner data's keccak
            // (which `tx.data_hash` already commits to via the bind).
            // Show the data_hash, not a recompute, since the bind
            // proves they're equal.
            //
            // 2 rows = label "Data hash:" doesn't fit; just paint the
            // hash directly.
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &tx.data_hash);
            }
            next_page += 1;
        }
        InnerKind::SafeMgmt(op) => {
            next_page = render_safe_mgmt_pages(
                &mut pages,
                next_page,
                &op,
                tx.chain_id,
                &tx.safe_address,
                resolver,
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
                write_addr_full_or_name(a, b, c, &tx.to, tx.chain_id, resolver);
            }
            next_page += 1;
            // Selector + data length + bound data-hash (matches the
            // Blind branch's last page so the user can compare on-device).
            write_selector_row(&mut pages.buf[next_page][0], safe.raw_data);
            write_data_len_row(&mut pages.buf[next_page][1], safe.raw_data.len());
            {
                let [_a, _b, r1, r2] = &mut pages.buf[next_page];
                write_calldata_hash_rows(r1, r2, &tx.data_hash);
            }
            next_page += 1;
        }
    }

    // ── Final: confirm prompt ───────────────────────────────────────
    if next_page < total_pages {
        write_line(&mut pages.buf[next_page][0], "Long-press to");
        write_line(&mut pages.buf[next_page][1], "");
        write_line(&mut pages.buf[next_page][2], "L=Cancel");
        write_line(&mut pages.buf[next_page][3], "R=Confirm");
    }

    pages
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

enum InnerKind {
    EmptyCall,
    PlainEth,
    Erc20Known(Erc20Call),
    Erc20Unknown(Erc20Call),
    /// Inner call targets `safe_address` and decoded as one of the
    /// recognised Safe-native owner/module/guard/fallback ops.
    SafeMgmt(SafeMgmtOp),
    /// Inner call targets `safe_address` but the selector is not in
    /// the recognised Safe-native set — loud blind-sign with an
    /// explicit "Unknown Safe op" warning so the user can tell this
    /// apart from a generic opaque call.
    UnknownSafeSelf,
    Blind,
}

/// Produce a one-line semantic hint about the inner tx, e.g.
/// `"Inner: ERC-20"`. Bounded to 16 ASCII columns.
fn inner_kind_hint(kind: &InnerKind) -> &'static str {
    match kind {
        InnerKind::EmptyCall => "(empty call)",
        InnerKind::PlainEth => "Inner: ETH xfer",
        InnerKind::Erc20Known(_) => "Inner: ERC-20",
        InnerKind::Erc20Unknown(_) => "Inner: ERC-20?",
        InnerKind::SafeMgmt(_) => "Inner: Safe mgmt",
        InnerKind::UnknownSafeSelf => "! Unkn self-call",
        InnerKind::Blind => "! Inner: opaque",
    }
}

fn classify_inner(raw_data: &[u8], value: &U256) -> InnerKind {
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
        // Reuse the existing nonce-row primitive but with our own
        // label so it reads "SafeTx Nonce: N" rather than "Nonce: N".
        // We can't reuse write_nonce_row's prefix, so format here.
        *row = [b' '; DISPLAY_COLS];
        let prefix = b"SafeTx Nonce: ";
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

fn write_overflow_marker(
    row: &mut [u8; DISPLAY_COLS],
    pos: usize,
) -> usize {
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

/// Render a U256 hex tail across two rows: row1 = "0x" + first 7 bytes,
/// row2 = ".. " + last 6 bytes. Used for the unverified-token "raw
/// amount" page where we don't know the decimals. Mirrors the calldata
/// hash 2-row layout for visual consistency.
fn write_raw_uint_two_rows(
    row1: &mut [u8; DISPLAY_COLS],
    row2: &mut [u8; DISPLAY_COLS],
    value: &U256,
) {
    *row1 = [b' '; DISPLAY_COLS];
    *row2 = [b' '; DISPLAY_COLS];
    let hex = b"0123456789abcdef";
    row1[0] = b'0';
    row1[1] = b'x';
    for i in 0..7 {
        let b = value.0[i];
        row1[2 + i * 2] = hex[(b >> 4) as usize];
        row1[2 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
    row2[0] = b'.';
    row2[1] = b'.';
    row2[2] = b'.';
    row2[3] = b' ';
    for i in 0..6 {
        let b = value.0[26 + i];
        row2[4 + i * 2] = hex[(b >> 4) as usize];
        row2[4 + i * 2 + 1] = hex[(b & 0x0f) as usize];
    }
}

