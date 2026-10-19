//! `CMD_SIGN_OFFCHAIN` kinds 4 (`OFFCHAIN_KIND_SAFE_TX`) and 5
//! (`OFFCHAIN_KIND_COW_ORDER`): clear-signed EIP-712 typed data whose
//! meaning the firmware already decodes on the UserOp path.
//!
//!   * **SafeTx** — this wallet co-signs a Safe transaction off-chain as an
//!     owner. The payload carries the on-chain `approveHash` trailer encoding
//!     (canonical SafeTx + raw inner data), plus optional ERC-20 / CoW / name
//!     evidence for the inner call. The device recomputes `safeTxHash`
//!     (Safe ≥ v1.3.0 domain) and renders the Safe transaction with the same
//!     classifier and painters as the approveHash route.
//!   * **CoW order** — this wallet signs a `GPv2Order` with CoW's `eip1271`
//!     scheme (owner = this wallet). The payload is the on-chain CoW order
//!     trailer encoding; the device recomputes the order digest under the
//!     GPv2Settlement domain and renders the order.
//!
//! **The signed value is unchanged from RAW32.** Both sign
//! `replay_safe_hash(chain, wallet, H)` where `H` is the EIP-712 digest the
//! device recomputed from the bytes it renders — byte-identical to what
//! `OFFCHAIN_KIND_RAW32` signs when a companion passes the same `H`. Only the
//! display changes: the user sees the transaction / order instead of a blind
//! hash. The companion's hash is never used.
//!
//! This module owns the kind-specific half (parse → double verify →
//! render → confirm → post-confirm re-derivation → receipt). The common half
//! of `cmd_sign_offchain::run` — the page-123 gap/cap gate before, the
//! confirmation-authority gate, FI-hardened C10 sign, verify-before-release
//! and the durable counter bump after — is shared with every other kind.
//! Both kinds refuse an undeployed wallet before this runs (neither Safe's
//! `checkSignatures` nor GPv2Settlement unwraps ERC-6492).

use sphincs_tz_shared::{
    NscStatus, MAX_SLOT_USES, OFFCHAIN_KIND_COW_ORDER, OFFCHAIN_KIND_SAFE_TX,
    OFFCHAIN_MAX_NAME_BUNDLES, OFFCHAIN_NAME_BUNDLE_MAX_LEN,
};
use subtle::ConstantTimeEq;

use crate::tx::display::erc8213::Kind as FpKind;
use crate::tx::display::{OffchainConfirmContext, OffchainConfirmReceipt, Pages};
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::safe::VerifiedSafeV1;

// The proto mirrors of the name-bundle limits (proto has no dependencies).
const _: () = assert!(OFFCHAIN_NAME_BUNDLE_MAX_LEN == crate::names::MAX_NAME_BUNDLE_LEN);
const _: () = assert!(OFFCHAIN_MAX_NAME_BUNDLES == crate::names::MAX_NAME_BUNDLES);

/// What a confirmed structured request hands back to the common half.
pub(super) struct Confirmed {
    pub(super) hash_to_sign: [u8; 32],
    pub(super) wallet_addr: [u8; 20],
    /// The pixel UI ran the confirmation (and so owns the signing film).
    pub(super) px_owns_ending: bool,
}

/// The wallet's CREATE2 proxy address (the EIP-712 `verifyingContract` of
/// the replay-safe nesting): bootstrap cache, else derive and cache.
fn wallet_address(account_index: u32, entropy: &[u8; 32]) -> [u8; 20] {
    let cached = super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
    let (pk_seed, pk_root) = match cached {
        Some(pair) => pair,
        None => {
            crate::ui::show_progress("C10 keygen", 0);
            let (c10_sk, pk_seed_32, pk_root_32) =
                crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                    entropy,
                    account_index,
                    |p| crate::ui::show_progress("C10 keygen", p),
                );
            drop(c10_sk); // ZeroizeOnDrop wipes sk_seed.
            super::state::with_state(|s| {
                s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
            });
            (pk_seed_32, pk_root_32)
        }
    };
    crate::aa::eip1271::proxy_address(&pk_seed, &pk_root)
}

/// Sentinel gate over one bool, double-evaluated across a randomized gap.
fn gate(ok: bool) -> bool {
    crate::fi::scrub_sentinel_register();
    let a = crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok));
    crate::fi::wait_random();
    let b = crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok));
    crate::fi::scrub_sentinel_register();
    a == crate::fi::OK_SENTINEL && b == crate::fi::OK_SENTINEL
}

/// The two independent verifier runs agree on every published fact.
fn safe_pair_equal(a: &(VerifiedSafeV1<'_>, [u8; 32]), b: &(VerifiedSafeV1<'_>, [u8; 32])) -> bool {
    bool::from(a.0.canonical.ct_eq(&b.0.canonical))
        && a.0.raw_data.len() == b.0.raw_data.len()
        && bool::from(a.0.raw_data.ct_eq(b.0.raw_data))
        && bool::from(a.1.ct_eq(&b.1))
}

fn cow_pair_equal(a: &(VerifiedCowswapV3, [u8; 32]), b: &(VerifiedCowswapV3, [u8; 32])) -> bool {
    bool::from(a.0.canonical.ct_eq(&b.0.canonical))
        && a.0.sell.is_decoded() == b.0.sell.is_decoded()
        && a.0.buy.is_decoded() == b.0.buy.is_decoded()
        && bool::from(a.1.ct_eq(&b.1))
}

/// Append the handler-owned suffix (ERC-8213 fingerprint of `H`, then the
/// off-chain context) and prove each insertion. Returns the two insertion
/// indices for the final-set proofs.
fn append_suffix(
    pages: &mut Pages,
    fp: FpKind,
    ctx: &OffchainConfirmContext,
) -> Result<(usize, usize), &'static str> {
    use crate::tx::display::erc8213;
    let fp_before = pages.len;
    let mut fp_cfi = crate::fi::CfiCounter::new();
    if erc8213::append_fingerprint_page(pages, fp, &mut fp_cfi).is_err() {
        return Err("fp unshown");
    }
    crate::fi::scrub_sentinel_register();
    let fp_cfi_verdict = fp_cfi.check_into_sentinel(erc8213::FINGERPRINT_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let fp_page_verdict = erc8213::fingerprint_page_proof(pages, fp_before, fp);
    if fp_cfi_verdict != crate::fi::OK_SENTINEL || fp_page_verdict != crate::fi::OK_SENTINEL {
        return Err("fp incomplete");
    }
    let ctx_before = pages.len;
    let mut ctx_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::append_eip1271_context_pages(pages, ctx, &mut ctx_cfi).is_err() {
        return Err("context unshown");
    }
    crate::fi::scrub_sentinel_register();
    let ctx_cfi_verdict = ctx_cfi.check_into_sentinel(crate::tx::display::OFFCHAIN_CONTEXT_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let ctx_page_verdict = crate::tx::display::eip1271_context_page_proof(pages, ctx_before, ctx);
    if ctx_cfi_verdict != crate::fi::OK_SENTINEL || ctx_page_verdict != crate::fi::OK_SENTINEL {
        return Err("context incomplete");
    }
    Ok((fp_before, ctx_before))
}

/// Final-set proofs of the suffix, immediately before the confirmation.
fn suffix_final_proofs(
    pages: &Pages,
    fp: FpKind,
    fp_before: usize,
    ctx: &OffchainConfirmContext,
    ctx_before: usize,
) -> Result<(), &'static str> {
    crate::fi::scrub_sentinel_register();
    if crate::tx::display::erc8213::fingerprint_final_set_proof(pages, fp_before, fp) != crate::fi::OK_SENTINEL {
        return Err("fp changed");
    }
    crate::fi::scrub_sentinel_register();
    if crate::tx::display::eip1271_context_final_set_proof(pages, ctx_before, ctx) != crate::fi::OK_SENTINEL {
        return Err("context changed");
    }
    Ok(())
}

/// The kind-specific half of a kind-4 / kind-5 request. On `Ok` the user
/// confirmed and `receipt` holds the one confirmation for exactly the
/// returned `(wallet_addr, hash_to_sign)` plus the caller's counters; on
/// `Err` the `NscStatus` to return (nothing was signed or written).
///
/// # Safety
/// Called only from `cmd_sign_offchain::run` under the single-threaded,
/// non-reentrant dispatcher, with `px_scratch` the disjoint tail of the
/// shared snapshot buffer.
#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn confirm(
    kind: u8,
    payload: &[u8],
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    account_deployed: bool,
    new_count: u64,
    last_userop: u64,
    entropy: &[u8; 32],
    px_scratch: &mut [u8],
    receipt: &mut OffchainConfirmReceipt,
) -> Result<Confirmed, u32> {
    // Belt for the §4 gate in the caller: never on an undeployed wallet.
    if !account_deployed {
        crate::ui::show_status("EIP-1271", "struct needs deploy");
        return Err(NscStatus::InvalidPointer as u32);
    }
    #[cfg(not(feature = "ui-px"))]
    let _ = &px_scratch;
    let refuse = |reason: &'static str| -> u32 {
        crate::ui::show_status("Sign refused", reason);
        NscStatus::InternalError as u32
    };

    match kind {
        OFFCHAIN_KIND_SAFE_TX => {
            let frame = match pqsigner_aa::offchain_header::parse_safe_tx_frame(payload) {
                Ok(f) => f,
                Err(e) => {
                    crate::ui::show_status("Safe sign", e.status_str());
                    return Err(NscStatus::InvalidPointer as u32);
                }
            };
            // ── Double verify: two independent runs, every fact equal ──
            let a = crate::tx::eip712::safe::verify_offchain_safe_tx(frame.safe_bundle, chain_id);
            crate::fi::wait_random();
            let b = crate::tx::eip712::safe::verify_offchain_safe_tx(
                core::hint::black_box(frame.safe_bundle),
                core::hint::black_box(chain_id),
            );
            let (verified, safe_tx_hash) = match (a, b) {
                (Some(a), Some(b)) if gate(safe_pair_equal(&a, &b)) => a,
                _ => {
                    crate::ui::show_status("Safe sign", "safe tx invalid");
                    return Err(NscStatus::InvalidPointer as u32);
                }
            };
            // ── Evidence for the inner call ──
            let erc20 = if frame.erc20.is_empty() {
                None
            } else {
                crate::erc20::bundle::verify_erc20_bundle(frame.erc20)
            };
            let meta = crate::tx::display::safe_route_meta(chain_id, Some(&verified), None, erc20.as_ref());
            let wallet_addr = wallet_address(account_index, entropy);
            let bind = crate::tx::eip712::safe::resolve_cow_binding(&[], &wallet_addr, Some(&verified), None);
            let cow = if bind.via_safe {
                if frame.cow.is_empty() {
                    crate::ui::show_status("CoW sign", "v3 required");
                    return Err(NscStatus::InvalidPointer as u32);
                }
                let v = crate::tx::eip712::cowswap::verify_and_bind_trailer(
                    frame.cow,
                    bind.calldata,
                    chain_id,
                    &bind.owner,
                );
                if !gate(v.is_some()) {
                    crate::ui::show_status("CoW sign", "v3 required");
                    return Err(NscStatus::InvalidPointer as u32);
                }
                v
            } else {
                if !frame.cow.is_empty() {
                    crate::ui::show_status("CoW sign", "cow unexpected");
                    return Err(NscStatus::InvalidPointer as u32);
                }
                None
            };
            let reserved = pqsigner_erc7730::display::erc8213_contract::FINGERPRINT_PAGES
                + crate::tx::display::OFFCHAIN_CONTEXT_PAGES;
            if let crate::tx::display::MultisendGate::Reject(reason) =
                crate::tx::display::multisend_sign_gate(Some(&verified), None, cow.as_ref(), reserved)
            {
                crate::ui::show_status("Safe sign", reason);
                return Err(NscStatus::InvalidPointer as u32);
            }
            let mut resolver = crate::names::NameResolver::new();
            for bundle in frame.names.iter().take(frame.names_count) {
                if let Some(m) = crate::names::verify_name_bundle(bundle) {
                    resolver.push(m);
                }
            }
            // ── The signed value: RAW32's nesting of the recomputed H ──
            let hash_to_sign = crate::aa::eip1271::replay_safe_hash(chain_id, &wallet_addr, &safe_tx_hash);
            let ctx = OffchainConfirmContext::new(
                kind,
                chain_id,
                account_index,
                slot_index,
                wallet_addr,
                account_deployed,
                new_count,
                last_userop,
                MAX_SLOT_USES,
                hash_to_sign,
            );
            // ── Render + suffix + confirm ──
            let Ok(mut pages) = crate::tx::display::render_safe_offchain_pages(&verified, cow.as_ref(), meta, &resolver)
            else {
                return Err(refuse("render refused"));
            };
            let fp = FpKind::SafeTxHash(safe_tx_hash);
            let (fp_before, ctx_before) = append_suffix(&mut pages, fp, &ctx).map_err(refuse)?;
            suffix_final_proofs(&pages, fp, fp_before, &ctx, ctx_before).map_err(refuse)?;
            #[cfg(feature = "ui-px")]
            let px = px_route(
                px_scratch,
                &pages,
                crate::tx::display::px_lift::Body::SafeOffchain {
                    safe: &verified,
                    cow: cow.as_ref(),
                    erc20: meta,
                    resolver: &resolver,
                },
                fp,
                &ctx,
            );
            #[cfg(not(feature = "ui-px"))]
            let px: PxOutcome = None;
            let px_owns_ending = run_confirm(px, &pages)?;
            finish(receipt, &ctx, kind, payload, chain_id, &safe_tx_hash, &hash_to_sign, wallet_addr, px_owns_ending)
        }
        OFFCHAIN_KIND_COW_ORDER => {
            let frame = match pqsigner_aa::offchain_header::parse_cow_order_frame(payload) {
                Ok(f) => f,
                Err(e) => {
                    crate::ui::show_status("CoW sign", e.status_str());
                    return Err(NscStatus::InvalidPointer as u32);
                }
            };
            let a = crate::tx::eip712::cowswap::verify_offchain_cow_order(frame.canonical, frame.sell, frame.buy, chain_id);
            crate::fi::wait_random();
            let b = crate::tx::eip712::cowswap::verify_offchain_cow_order(
                core::hint::black_box(frame.canonical),
                core::hint::black_box(frame.sell),
                core::hint::black_box(frame.buy),
                core::hint::black_box(chain_id),
            );
            let (v3, digest) = match (a, b) {
                (Some(a), Some(b)) if gate(cow_pair_equal(&a, &b)) => a,
                _ => {
                    crate::ui::show_status("CoW sign", "order invalid");
                    return Err(NscStatus::InvalidPointer as u32);
                }
            };
            // Every signed amount must render exactly; refuse rather than
            // show a lossy one.
            if !gate(crate::tx::eip712::cowswap_display::amounts_are_exactly_renderable(
                &v3.canonical,
                &v3.sell,
                &v3.buy,
            )) {
                return Err(refuse("cow amount"));
            }
            let wallet_addr = wallet_address(account_index, entropy);
            let hash_to_sign = crate::aa::eip1271::replay_safe_hash(chain_id, &wallet_addr, &digest);
            let ctx = OffchainConfirmContext::new(
                kind,
                chain_id,
                account_index,
                slot_index,
                wallet_addr,
                account_deployed,
                new_count,
                last_userop,
                MAX_SLOT_USES,
                hash_to_sign,
            );
            let mut pages =
                crate::tx::eip712::cowswap_display::render_cowswap_offchain_pages(&v3.canonical, &v3.sell, &v3.buy);
            let fp = FpKind::Eip712Final(digest);
            let (fp_before, ctx_before) = append_suffix(&mut pages, fp, &ctx).map_err(refuse)?;
            suffix_final_proofs(&pages, fp, fp_before, &ctx, ctx_before).map_err(refuse)?;
            #[cfg(feature = "ui-px")]
            let px = px_route(
                px_scratch,
                &pages,
                crate::tx::display::px_lift::Body::CowOffchain { v3: &v3 },
                fp,
                &ctx,
            );
            #[cfg(not(feature = "ui-px"))]
            let px: PxOutcome = None;
            let px_owns_ending = run_confirm(px, &pages)?;
            finish(receipt, &ctx, kind, payload, chain_id, &digest, &hash_to_sign, wallet_addr, px_owns_ending)
        }
        _ => Err(NscStatus::InternalError as u32),
    }
}

/// Post-confirm FI: an independent second parse + verify of the snapshot
/// payload (`tx::eip712::offchain_structured`, the host-tested definition
/// of the signed value) must reproduce the `H` that was shown and the value
/// that was confirmed — one fault anywhere in the pre-confirm derivation
/// cannot reach the receipt. Then the one receipt.
#[allow(clippy::too_many_arguments)]
fn finish(
    receipt: &mut OffchainConfirmReceipt,
    ctx: &OffchainConfirmContext,
    kind: u8,
    payload: &[u8],
    chain_id: u64,
    h_shown: &[u8; 32],
    hash_to_sign: &[u8; 32],
    wallet_addr: [u8; 20],
    px_owns_ending: bool,
) -> Result<Confirmed, u32> {
    use crate::tx::eip712::offchain_structured::{structured_digest, structured_signed_value};
    let h_again = structured_digest(
        core::hint::black_box(kind),
        core::hint::black_box(payload),
        core::hint::black_box(chain_id),
    );
    let signed_again = structured_signed_value(
        core::hint::black_box(kind),
        core::hint::black_box(payload),
        core::hint::black_box(chain_id),
        core::hint::black_box(&wallet_addr),
    );
    let same = match (h_again, signed_again) {
        (Some(h), Some(v)) => bool::from(h.ct_eq(h_shown)) && bool::from(v.ct_eq(hash_to_sign)),
        _ => false,
    };
    if !gate(same) {
        super::zeroize_sensitive_state();
        crate::ui::show_status("Sign refused", "fi tampered");
        return Err(NscStatus::InternalError as u32);
    }
    if receipt.record_confirmed(ctx).is_err() {
        super::zeroize_sensitive_state();
        return Err(NscStatus::UserRejected as u32);
    }
    Ok(Confirmed {
        hash_to_sign: *hash_to_sign,
        wallet_addr,
        px_owns_ending,
    })
}

type PxOutcome = Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>>;

/// Route the confirmation through the pixel UI when `ui-px` is on (`None` =
/// the page dialog).
#[cfg(feature = "ui-px")]
fn px_route(
    scratch: &mut [u8],
    pages: &Pages,
    body: crate::tx::display::px_lift::Body<'_>,
    fp: FpKind,
    ctx: &OffchainConfirmContext,
) -> PxOutcome {
    Some(super::cmd_sign_offchain::px_offchain_confirm(scratch, pages, body, fp, None, Some(ctx)))
}

/// Run the dialog and map its answer; `Ok(px_owns_ending)` only on an
/// affirmative, sentinel-checked confirmation.
fn run_confirm(px: PxOutcome, pages: &Pages) -> Result<bool, u32> {
    use crate::ui::confirm::{confirm_checked, ConfirmResult};
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    let px_route = px.is_some();
    let (cr, cr_verdict) = match px {
        Some(Ok(r)) => r,
        Some(Err(reason)) => {
            crate::ui::show_status("Sign refused", reason);
            return Err(NscStatus::InternalError as u32);
        }
        None => confirm_checked(pages.as_slice()),
    };
    match cr {
        ConfirmResult::Confirmed => {
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::fi::scrub_sentinel_register();
                if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
                    super::zeroize_sensitive_state();
                    crate::ui::show_status("Sign refused", "px atlas");
                    return Err(NscStatus::InternalError as u32);
                }
                crate::fi::scrub_sentinel_register();
            }
        }
        ConfirmResult::Cancelled => {
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Declined);
                return Err(NscStatus::UserRejected as u32);
            }
            crate::ui::show_status("Cancelled", "");
            return Err(NscStatus::UserRejected as u32);
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return Err(NscStatus::IdleWipe as u32);
        }
    }
    // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail closed.
    if cr_verdict != crate::fi::OK_SENTINEL {
        super::zeroize_sensitive_state();
        return Err(NscStatus::UserRejected as u32);
    }
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    return Ok(px_route);
    #[cfg(not(all(feature = "ui-px", feature = "ui-lcd")))]
    Ok(false)
}
