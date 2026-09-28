//! Dispatcher-level native-ETH `value` invariant (audit C-1 / H-2 / M-8).
//!
//! The outer UserOp `value` is signed verbatim into
//! `executeWithOffchainCount(ownerIndex, count, target, value, data)`, but
//! several renderers historically surfaced only token / inner-tx semantics
//! and never the native ETH — so a malicious companion could display a
//! benign token transfer while signing an ETH-draining `call{value}` to an
//! attacker contract.
//!
//! Rather than trust each renderer to opt in, EVERY sign confirm funnels
//! through [`enforce_native_value_page`] (called by
//! [`super::pick_sign_pages`]): when `value != 0` it appends a dedicated,
//! loud value page. A future renderer physically cannot forget it, and the
//! append-only transition cannot shift or overwrite an already-proved page.
//!
//! Lives in its own file (not `mod.rs`) so the host-test scaffold
//! (`crate::display_under_test`) can `#[path]`-mount it and exercise the
//! real body — `mod.rs`'s `pick_sign_pages` dispatcher pulls in
//! firmware-only deps and is gated `#[cfg(not(test))]`.

use super::primitives;
use super::Pages;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

/// SHA-256("") — the sentinel the companion sends for an absent
/// `paymasterAndData` (mirrors `crate::aa::userop::SHA256_EMPTY`; copied
/// here so the host-test `#[path]` mount of this file does not pull in the
/// `aa` crate). Used by [`enforce_paymaster_page`] to decide presence.
const SHA256_OF_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// One mandatory full signer-identity page per confirmation set.
pub(crate) const SIGNER_IDENTITY_PAGES: usize = 1;
/// One mandatory full target-contract page per transaction confirmation.
pub(crate) const TARGET_IDENTITY_PAGES: usize = 1;
/// One conditional native-value page when the signed value is non-zero.
pub(crate) const NATIVE_VALUE_PAGES: usize = 1;
/// The legacy friendly fee envelope is an atomic two-page suffix.
pub(crate) const LEGACY_FEE_PAGES: usize = primitives::LEGACY_FEE_PAGE_COUNT;
/// One conditional warning page when the UserOp carries a paymaster.
pub(crate) const PAYMASTER_PAGES: usize = 1;

const SIGNER_PAGE_CFI_STEP: u32 = 0xA4D1_73C9;
pub(crate) const SIGNER_PAGE_CFI_EXPECTED: u32 = crate::cfi_expected!(SIGNER_PAGE_CFI_STEP);
const TARGET_PAGE_CFI_STEP: u32 = 0x6B2E_91F5;
pub(crate) const TARGET_PAGE_CFI_EXPECTED: u32 = crate::cfi_expected!(TARGET_PAGE_CFI_STEP);
const NATIVE_VALUE_CFI_STEP: u32 = 0xD83A_4C27;
pub(crate) const NATIVE_VALUE_CFI_EXPECTED: u32 = crate::cfi_expected!(NATIVE_VALUE_CFI_STEP);
const LEGACY_FEE_CFI_STEP: u32 = 0x39F6_BD81;
pub(crate) const LEGACY_FEE_CFI_EXPECTED: u32 = crate::cfi_expected!(LEGACY_FEE_CFI_STEP);
const PAYMASTER_PAGE_CFI_STEP: u32 = 0xC52D_8E73;
pub(crate) const PAYMASTER_PAGE_CFI_EXPECTED: u32 = crate::cfi_expected!(PAYMASTER_PAGE_CFI_STEP);

type SignerIdentityPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];
type TargetIdentityPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];
type NativeValuePage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];
type PaymasterPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

/// Append the mandatory UserOp signer page after all already-rendered pages.
///
/// `account_index` selects a distinct mnemonic-derived wallet, while `sender`
/// is the CREATE2 address independently derived and companion-bound in the
/// secure handler. Both are signed-context facts: omitting them lets a hostile
/// companion reuse otherwise identical intent pages while signing from a
/// different account. "Signer" is deliberate: a Safe or `transferFrom` call
/// may debit an address other than this outer PQ wallet, so labelling it
/// "From" would create a second trusted-display ambiguity. The address is
/// rendered in full EIP-55 form across all three remaining rows; no name
/// substitution or truncated fingerprint is permitted.
///
/// The page is unconditional and fails closed. A full page buffer or an
/// out-of-range account index returns `Err(())`, and every UserOp caller maps
/// that to a refusal before confirmation/signing.
#[inline(never)]
pub(crate) fn enforce_from_page(
    pages: &mut Pages,
    account_index: u32,
    sender: &[u8; 20],
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    let page = build_signer_identity_page(account_index, sender).ok_or(())?;
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(SIGNER_PAGE_CFI_STEP);
    Ok(())
}

/// Exact all-64-byte readback predicate for the handler's FI completion gate.
pub(crate) fn from_page_matches(
    pages: &Pages,
    page_index: usize,
    account_index: u32,
    sender: &[u8; 20],
) -> bool {
    let Some(expected) = build_signer_identity_page(account_index, sender) else {
        return false;
    };
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    page_exact(actual, &expected)
}

/// FI-hardened completion proof for [`enforce_from_page`].
///
/// The caller records `prior_len`, invokes the non-inlined inserter, scrubs the
/// ABI sentinel register, then requires this function to return
/// [`crate::fi::OK_SENTINEL`]. Skipping the insert leaves the length/page check
/// false; skipping this proof after the scrub leaves a non-OK return register.
#[inline(never)]
pub(crate) fn from_page_proof(
    pages: &Pages,
    prior_len: usize,
    account_index: u32,
    sender: &[u8; 20],
) -> u32 {
    let Some(expected) = build_signer_identity_page(account_index, sender) else {
        return crate::fi::FAIL_SENTINEL;
    };
    let Some(expected_len) = prior_len.checked_add(SIGNER_IDENTITY_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && from_page_matches(pages, prior_len, account_index, sender)
            && exact_page_occurrences(pages, &expected) == 1
    })
}

pub(crate) fn build_signer_identity_page(account_index: u32, sender: &[u8; 20]) -> Option<SignerIdentityPage> {
    // The wire field is exactly eight bits. Recheck at the display boundary so
    // a faulted flag decode cannot paint a truncated/aliased account number.
    if account_index > 255 {
        return None;
    }
    const PREFIX: &[u8] = b"Signer acct #";
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    let mut digits = [0u8; 3];
    let n = primitives::format_u64(u64::from(account_index), &mut digits)?;
    if PREFIX.len() + n > DISPLAY_COLS {
        return None;
    }
    page[0][..PREFIX.len()].copy_from_slice(PREFIX);
    page[0][PREFIX.len()..PREFIX.len() + n].copy_from_slice(&digits[..n]);
    let [_label, a, b, c] = &mut page;
    primitives::write_addr_full(a, b, c, sender);
    Some(page)
}

/// Append the mandatory full target-contract page.
///
/// ERC-7730 intent pages can otherwise consume the whole semantic surface
/// without showing the outer call target. A descriptor is bound to the target
/// in secure world, but that cryptographic binding does not tell the user which
/// contract will receive the signed call. The raw EIP-55 address is therefore
/// always shown for each single transaction / batch member, independent of the
/// selected semantic renderer or name database.
#[inline(never)]
pub(crate) fn enforce_target_page(
    pages: &mut Pages,
    target: &[u8; 20],
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    let page = build_target_identity_page(target);
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(TARGET_PAGE_CFI_STEP);
    Ok(())
}

/// Exact all-64-byte readback predicate for the mandatory target page.
pub(crate) fn target_page_matches(pages: &Pages, page_index: usize, target: &[u8; 20]) -> bool {
    let expected = build_target_identity_page(target);
    let Some(actual) = pages.as_slice().get(page_index) else {
        return false;
    };
    page_exact(actual, &expected)
}

/// FI-hardened completion proof for [`enforce_target_page`].
///
/// Callers record `prior_len` after the signer proof, invoke the non-inlined
/// inserter, scrub the sentinel register, then require this independent
/// length/full-page recomputation to return `OK_SENTINEL`.
#[inline(never)]
pub(crate) fn target_page_proof(pages: &Pages, prior_len: usize, target: &[u8; 20]) -> u32 {
    let Some(expected_len) = prior_len.checked_add(TARGET_IDENTITY_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    let expected = build_target_identity_page(target);
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && target_page_matches(pages, prior_len, target)
            && exact_page_occurrences(pages, &expected) == 1
    })
}

pub(crate) fn build_target_identity_page(target: &[u8; 20]) -> TargetIdentityPage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    page[0].copy_from_slice(b"Target contract:");
    let [_label, a, b, c] = &mut page;
    primitives::write_addr_full(a, b, c, target);
    page
}

/// Append a loud native-ETH `value` page to an already-rendered page set
/// when `value != 0`, reporting whether the WYSIWYS invariant holds.
///
/// The page lands exactly at the caller-recorded prior length. Two hardening
/// properties (audit 2026-06-18 — native-value
/// WYSIWYS gate), because the outer UserOp `value` is signed verbatim into
/// `executeWithOffchainCount(...)` and forwarded on chain via
/// `target.call{value: value}(data)` — so hiding it is an ETH drain behind
/// a benign confirm (the same class as audit C-1 / H-2 / M-8):
///
///   * **FI-hardened skip decision.** The dangerous outcome is *skipping*
///     the value page on a non-zero value. The skip path is therefore
///     gated on a Hamming-distant sentinel proof that `value == 0`
///     (`fi::check_true_into_sentinel` double-evaluates the predicate with
///     `wait_random` between, then commits the verdict to a volatile
///     sentinel). A single fault that tries to force the skip on a
///     non-zero value cannot produce `OK_SENTINEL`, so control falls
///     through to the mandatory append — matching the FI bar every other
///     sign-path gate already meets. A bare `if value.is_zero()` was one
///     instruction-skip away from dropping the page.
///   * **Fails CLOSED on a full page buffer.** If `value != 0` and the
///     page cannot be appended (`pages.len == MAX_PAGES`), returns
///     `Err(())` so the caller REFUSES to sign rather than release a
///     signature over ETH the user never saw. The old code silently
///     skipped on a false assumption ("every renderer that reaches
///     `MAX_PAGES` already shows the value"), which is untrue for the
///     dynamically-grown ERC-7730 calldata renderer (`6 + N_visible`
///     pages): a future ≥18-visible-field payable descriptor would have
///     dropped the value page with no fault at all. Refusing is the
///     dispatcher-level analogue of the multiSend gate's "refuse rather
///     than truncate" rule.
///
/// Returns `Ok(())` when the invariant holds (value robustly zero, or the
/// loud page was appended) and `Err(())` when a mandatory value page could
/// not be appended — the caller must map that to a refuse-to-sign. The
/// `Result` is `#[must_use]` by construction, so `pick_sign_pages`'s `?`
/// can never silently drop the refusal.
#[inline(never)]
pub(super) fn enforce_native_value_page(
    pages: &mut Pages,
    value: &U256,
    chain_id: u64,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    // Skip ONLY on a sentinel-robust proof that `value == 0`. `black_box`
    // keeps the two internal evaluations of the predicate from collapsing
    // into one (F-1). Any other outcome — value non-zero, or a glitched
    // zero-check — flows to the mandatory splice below.
    let may_skip = crate::fi::check_true_into_sentinel(|| core::hint::black_box(value.is_zero()));
    if may_skip == crate::fi::OK_SENTINEL {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        cfi.bump(NATIVE_VALUE_CFI_STEP);
        return Ok(());
    }
    // value is non-zero (or the zero-check was faulted): an exact native-value
    // page is MANDATORY. Reconstruct it before reserving a slot so a value with
    // no exact bounded representation fails closed without mutating the page
    // set or CFI receipt. The later `push_blank` likewise fails atomically on a
    // full buffer.
    let page = build_native_value_page(value, chain_id).ok_or(())?;
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(NATIVE_VALUE_CFI_STEP);
    Ok(())
}

pub(crate) fn build_native_value_page(value: &U256, chain_id: u64) -> Option<NativeValuePage> {
    if !primitives::native_amount_is_exactly_renderable(value, chain_id) {
        return None;
    }
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    primitives::write_native_currency_row(&mut page[0], b"! NATIVE ", chain_id, b"");
    let [_lbl, r1, r2, foot] = &mut page;
    let fit = primitives::write_native_amount_two_rows(r1, r2, value, chain_id);
    if fit != primitives::AmountFit::Full {
        return None;
    }
    primitives::write_line(foot, "> next");
    Some(page)
}

/// Exact completed-skip proof for the compact zero-value path.
#[inline(never)]
pub(super) fn native_value_skip_proof(pages: &Pages, prior_len: usize, value: &U256) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(value.is_zero()) && core::hint::black_box(pages.len == prior_len)
    })
}

/// Exact transition/content/uniqueness proof for the conditional native page.
#[inline(never)]
pub(super) fn native_value_page_proof(
    pages: &Pages,
    prior_len: usize,
    value: &U256,
    chain_id: u64,
) -> u32 {
    if value.is_zero() {
        return native_value_skip_proof(pages, prior_len, value);
    }
    let Some(expected_len) = prior_len.checked_add(NATIVE_VALUE_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    let Some(expected) = build_native_value_page(value, chain_id) else {
        return crate::fi::FAIL_SENTINEL;
    };
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && page_at_matches(pages, prior_len, &expected)
            && exact_page_occurrences(pages, &expected) == 1
    })
}

/// Recheck the native-value invariant after later handler-owned appends.
#[inline(never)]
pub(super) fn native_value_final_set_proof(
    pages: &Pages,
    prior_len: usize,
    value: &U256,
    chain_id: u64,
) -> u32 {
    let Some(expected) = build_native_value_page(value, chain_id) else {
        return crate::fi::FAIL_SENTINEL;
    };
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(value.is_zero()) {
            core::hint::black_box(pages.len >= prior_len)
                && exact_page_occurrences(pages, &expected) == 0
        } else {
            prior_len
                .checked_add(NATIVE_VALUE_PAGES)
                .is_some_and(|minimum_len| {
                    core::hint::black_box(pages.len >= minimum_len)
                        && page_at_matches(pages, prior_len, &expected)
                        && exact_page_occurrences(pages, &expected) == 1
                })
        }
    })
}

/// Append the two standard gas/fee pages (identical to value_transfer pages
/// 3-4) as one atomic suffix.
///
/// Called by [`super::pick_sign_pages`] for the Safe / CoW / ERC-7730
/// surfaces, which — unlike every other renderer — do not emit gas pages
/// of their own. The five EntryPoint v0.6 fee fields are committed to by
/// the UserOp signature and the wallet pays the EntryPoint prefund out of
/// its own native ETH; hiding them is a fee-bomb drain behind a benign
/// confirm (audit 2026-06-19 — the WYSIWYS sibling of the native-value
/// gate above).
///
/// Unlike [`enforce_native_value_page`] there is no skip-on-zero decision
/// (gas is shown unconditionally, matching every other renderer), so there
/// is no FI skip gate to harden here. The only failure mode is a full page
/// buffer, which FAILS CLOSED: the check is performed up-front so the
/// append is atomic (never a single orphaned gas page) and the caller maps
/// `Err(())` to a refuse-to-sign.
#[inline(never)]
pub(super) fn enforce_gas_pages(
    pages: &mut Pages,
    tx: &Eip1559Tx,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    // Atomic budget check: both pages or neither.
    let prior_len = pages.len;
    let Some(expected_len) = prior_len.checked_add(LEGACY_FEE_PAGES) else {
        return Err(());
    };
    if expected_len > super::MAX_PAGES {
        return Err(());
    }
    let rendered = build_legacy_fee_pages(tx);
    if !rendered.exact {
        return Err(());
    }
    let [first, second] = rendered.pages;
    let first_idx = pages.push_blank()?;
    if first_idx != prior_len {
        pages.len = prior_len;
        return Err(());
    }
    pages.buf[first_idx] = first;
    let second_idx = match pages.push_blank() {
        Ok(idx) if idx == prior_len + 1 => idx,
        _ => {
            pages.buf[first_idx] = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
            pages.len = prior_len;
            return Err(());
        }
    };
    pages.buf[second_idx] = second;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(LEGACY_FEE_CFI_STEP);
    Ok(())
}

pub(crate) fn build_legacy_fee_pages(tx: &Eip1559Tx) -> primitives::LegacyFeeRender {
    primitives::build_legacy_fee_pages(
        &tx.max_fee_per_gas,
        &tx.max_priority_fee_per_gas,
        tx.gas_limit,
        tx.chain_id,
    )
}

/// Exact two-page length/content/adjacency/uniqueness completion proof.
#[inline(never)]
pub(super) fn legacy_fee_pages_proof(pages: &Pages, prior_len: usize, tx: &Eip1559Tx) -> u32 {
    let Some(expected_len) = prior_len.checked_add(LEGACY_FEE_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    let rendered = build_legacy_fee_pages(tx);
    if !rendered.exact {
        return crate::fi::FAIL_SENTINEL;
    }
    let [first, second] = rendered.pages;
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len == expected_len)
            && page_at_matches(pages, prior_len, &first)
            && page_at_matches(pages, prior_len + 1, &second)
            && exact_page_occurrences(pages, &first) == 1
            && exact_page_occurrences(pages, &second) == 1
    })
}

/// Recheck the legacy fee pair after later handler-owned appends.
#[inline(never)]
pub(super) fn legacy_fee_pages_final_set_proof(
    pages: &Pages,
    prior_len: usize,
    tx: &Eip1559Tx,
) -> u32 {
    let Some(minimum_len) = prior_len.checked_add(LEGACY_FEE_PAGES) else {
        return crate::fi::FAIL_SENTINEL;
    };
    let rendered = build_legacy_fee_pages(tx);
    if !rendered.exact {
        return crate::fi::FAIL_SENTINEL;
    }
    let [first, second] = rendered.pages;
    crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(pages.len >= minimum_len)
            && page_at_matches(pages, prior_len, &first)
            && page_at_matches(pages, prior_len + 1, &second)
            && exact_page_occurrences(pages, &first) == 1
            && exact_page_occurrences(pages, &second) == 1
    })
}

/// Append a loud "! PAYMASTER SET" page when the UserOp carries a
/// non-empty `paymasterAndData` field, reporting whether the WYSIWYS
/// invariant holds.
///
/// **STATUS — no paymaster product flow; completion parity hardened
/// 2026-07-17.** The 2026-06-27/28 owner decision that PQ1 does not ship a
/// paymaster-using companion remains unchanged. The warning was retained as
/// belt-and-suspenders hardening; it now has the same caller-owned completion
/// receipt and exact final-set proof as the mandatory value/fee pages. This is
/// assurance parity, not authorization for companion paymaster support.
///
/// The EntryPoint v0.6 `paymasterAndData` is committed to by the UserOp
/// signature (its digest is folded into `compute_sphincs_digest_v06`),
/// but the firmware only ever receives `sha256(paymasterAndData)` over the
/// wire — it cannot show *which* paymaster, only that one is present. A
/// paymaster materially changes the transaction's economics: gas is paid by
/// the sponsor instead of the wallet's native ETH, and a *token* paymaster's
/// `postOp` debits the user in ERC-20 tokens. A malicious companion can
/// route an otherwise-benign UserOp through a paymaster the user previously
/// approved, draining tokens as "gas" behind a confirm whose only fee page
/// ("Worst-case: X ETH") actively misdirects. Hiding the paymaster is
/// therefore the same signed-but-not-shown class as the native-value gate
/// above (audit 2026-06-27).
///
/// `paymaster_and_data_hash` is the on-wire `sha256(paymasterAndData)`
/// (the companion sends [`SHA256_OF_EMPTY`] when no paymaster is set), and
/// presence is recomputed from those bytes *inside* the sentinel closure so
/// a single glitch on one comparison cannot force the skip. Two hardening
/// properties mirror [`enforce_native_value_page`]:
///
///   * **FI-hardened skip decision.** The dangerous outcome is *skipping*
///     the warning when a paymaster IS present, so the skip path is gated on
///     a Hamming-distant sentinel proof that the hash equals the empty-bytes
///     hash. A single fault that tries to force the skip on a present
///     paymaster cannot produce `OK_SENTINEL`, so control falls through to
///     the mandatory append.
///   * **Fails CLOSED on a full page buffer.** If a paymaster is present and
///     the page cannot be appended (`pages.len == MAX_PAGES`), returns
///     `Err(())` so the caller REFUSES to sign rather than release a
///     signature over a sponsor the user never saw.
///
/// Returns `Ok(())` when the invariant holds (no paymaster, or the loud page
/// was appended) and `Err(())` when a mandatory page could not be appended.
/// The caller must pair success with [`PAYMASTER_PAGE_CFI_EXPECTED`] and
/// [`paymaster_page_proof`]; a skipped whole call therefore cannot masquerade
/// as the legitimate absent-paymaster path.
#[inline(never)]
pub(crate) fn enforce_paymaster_page(
    pages: &mut Pages,
    paymaster_and_data_hash: &[u8; 32],
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    // Skip ONLY on a sentinel-robust proof that the hash is the empty-bytes
    // hash (no paymaster). Recompute the byte compare inside the closure (it
    // is double-evaluated, `black_box`'d to defeat CSE) so a glitch on a
    // single load/compare cannot mask a present paymaster. Any other
    // outcome — non-empty hash, or a glitched compare — flows to the
    // mandatory append below.
    let may_skip = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(*paymaster_and_data_hash == SHA256_OF_EMPTY)
    });
    if may_skip == crate::fi::OK_SENTINEL {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        cfi.bump(PAYMASTER_PAGE_CFI_STEP);
        return Ok(());
    }
    // Paymaster present (or the absence-check was faulted): a loud page is
    // MANDATORY. Append it without moving prior pages; `?` fails CLOSED when the
    // buffer is full so the caller refuses to sign instead of hiding the
    // sponsor.
    let page = build_paymaster_page();
    let idx = pages.push_blank()?;
    pages.buf[idx] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(PAYMASTER_PAGE_CFI_STEP);
    Ok(())
}

/// The page painters' presence predicate for the paymaster warning.
pub(crate) fn paymaster_present(paymaster_and_data_hash: &[u8; 32]) -> bool {
    *paymaster_and_data_hash != SHA256_OF_EMPTY
}

pub(crate) fn build_paymaster_page() -> PaymasterPage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    primitives::write_line(&mut page[0], "! PAYMASTER SET");
    primitives::write_line(&mut page[1], "Gas sponsored");
    primitives::write_line(&mut page[2], "may debit tokens");
    primitives::write_line(&mut page[3], "> next");
    page
}

/// Exact completed-skip or one-page transition proof for the paymaster gate.
#[inline(never)]
pub(crate) fn paymaster_page_proof(
    pages: &Pages,
    prior_len: usize,
    paymaster_and_data_hash: &[u8; 32],
) -> u32 {
    let expected = build_paymaster_page();
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(*paymaster_and_data_hash == SHA256_OF_EMPTY) {
            core::hint::black_box(pages.len == prior_len)
                && exact_page_occurrences(pages, &expected) == 0
        } else {
            prior_len
                .checked_add(PAYMASTER_PAGES)
                .is_some_and(|expected_len| {
                    core::hint::black_box(pages.len == expected_len)
                        && page_at_matches(pages, prior_len, &expected)
                        && exact_page_occurrences(pages, &expected) == 1
                })
        }
    })
}

/// Recheck the paymaster warning against the complete confirmation transcript.
#[inline(never)]
pub(crate) fn paymaster_final_set_proof(
    pages: &Pages,
    prior_len: usize,
    paymaster_and_data_hash: &[u8; 32],
) -> u32 {
    let expected = build_paymaster_page();
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(*paymaster_and_data_hash == SHA256_OF_EMPTY) {
            core::hint::black_box(pages.len >= prior_len)
                && exact_page_occurrences(pages, &expected) == 0
        } else {
            prior_len
                .checked_add(PAYMASTER_PAGES)
                .is_some_and(|minimum_len| {
                    core::hint::black_box(pages.len >= minimum_len)
                        && page_at_matches(pages, prior_len, &expected)
                        && exact_page_occurrences(pages, &expected) == 1
                })
        }
    })
}

fn page_exact(
    actual: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS],
    expected: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS],
) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

fn page_at_matches(
    pages: &Pages,
    page_index: usize,
    expected: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS],
) -> bool {
    pages
        .as_slice()
        .get(page_index)
        .is_some_and(|actual| page_exact(actual, expected))
}

fn exact_page_occurrences(pages: &Pages, expected: &[[u8; DISPLAY_COLS]; DISPLAY_ROWS]) -> usize {
    pages
        .as_slice()
        .iter()
        .filter(|actual| page_exact(actual, expected))
        .count()
}

/// WYSIWYS per-flow address-match gate for the DIRECT ERC-20 render path
/// (audit 2026-06-28 — `v1_ms` metadata mis-attribution).
///
/// `crate::tx::display::pick_sign_pages_inner` reaches its direct ERC-20
/// branch only when NO Safe / CoW / v1 context verified — i.e. the wallet
/// itself is `msg.sender` and `tx.to` IS the token being called. The only
/// legitimate metadata attribution there is therefore `meta.contract ==
/// tx.to`.
///
/// The handler supplies only Merkle+chain-verified metadata. The dispatcher
/// then grants it independently per selected surface: verified Safe execution
/// facts for Safe, signed tokenPath resolution for ERC-7730, and this exact
/// outer-target equality for direct ERC-20. A `transfer` to token Y must never
/// render with token T's name/symbol/decimals merely because another surface
/// could legitimately use T.
///
/// Returns `true` only when the bundle's contract equals the call target,
/// so the caller can fall back to the raw `erc20_unknown` render on any
/// mismatch (including the no-target contract-creation shape). This is the
/// direct-path gate is deliberately local to the branch that consumes it.
#[must_use]
pub(crate) fn direct_erc20_meta_matches(
    meta_contract: &[u8; 20],
    tx_to: Option<&[u8; 20]>,
) -> bool {
    tx_to.is_some_and(|to| meta_contract == to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_signer(pages: &mut Pages, account_index: u32, sender: &[u8; 20]) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_from_page(pages, account_index, sender, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(SIGNER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn append_target(pages: &mut Pages, target: &[u8; 20]) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_target_page(pages, target, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(TARGET_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn append_native(pages: &mut Pages, value: &U256, chain_id: u64) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_native_value_page(pages, value, chain_id, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn append_legacy_fees(pages: &mut Pages, tx: &Eip1559Tx) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_gas_pages(pages, tx, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(LEGACY_FEE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn append_paymaster(pages: &mut Pages, paymaster_and_data_hash: &[u8; 32]) {
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_paymaster_page(pages, paymaster_and_data_hash, &mut cfi).unwrap();
        assert_eq!(
            cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    fn one_wei() -> U256 {
        let mut v = [0u8; 32];
        v[31] = 1;
        U256(v)
    }

    fn u256_from_u128(value: u128) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    fn one_native() -> U256 {
        u256_from_u128(1_000_000_000_000_000_000)
    }

    fn power_of_ten(exponent: u32) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        for _ in 0..exponent {
            let mut carry = 0u16;
            for byte in bytes.iter_mut().rev() {
                let product = u16::from(*byte) * 10 + carry;
                *byte = product as u8;
                carry = product >> 8;
            }
            assert_eq!(carry, 0, "test power must remain inside U256");
        }
        U256(bytes)
    }

    fn gwei(n: u64) -> U256 {
        // n * 1e9 wei, fits a u64 for any realistic gas price.
        let wei = (n as u128) * 1_000_000_000u128;
        let mut v = [0u8; 32];
        v[16..32].copy_from_slice(&wei.to_be_bytes());
        U256(v)
    }

    fn fee_tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: gwei(2),
            max_fee_per_gas: gwei(50),
            gas_limit: 21_000,
            to: Some([0x11u8; 20]),
            value: U256::zero(),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
            userop_fields: None,
        }
    }

    #[test]
    fn from_page_shows_account_and_full_derived_address() {
        let sender = [0xabu8; 20];
        let mut pages = Pages::with_len(2);
        primitives::write_line(pages.row_mut(0, 0), "Sign transfer?");
        primitives::write_line(pages.row_mut(1, 3), "R=Confirm");

        append_signer(&mut pages, 255, &sender);
        assert_eq!(pages.len, 3);
        assert_eq!(&pages.buf[2][0], b"Signer acct #255");

        // The identity page uses the exact full-address primitive: 0x + all
        // 40 EIP-55 nibbles across rows 1..=3, never a short address/name.
        let mut expected = [[b' '; DISPLAY_COLS]; 3];
        let [a, b, c] = &mut expected;
        primitives::write_addr_full(a, b, c, &sender);
        assert_eq!(&pages.buf[2][1..4], &expected);

        // Existing banner/confirm content is preserved byte-for-byte.
        assert_eq!(&pages.buf[0][0][..14], b"Sign transfer?");
        assert_eq!(&pages.buf[1][3][..9], b"R=Confirm");
    }

    #[test]
    fn account_flip_changes_confirmed_from_page() {
        let sender = [0x42u8; 20];
        let mut account_zero = Pages::with_len(1);
        let mut account_one = Pages::with_len(1);
        append_signer(&mut account_zero, 0, &sender);
        append_signer(&mut account_one, 1, &sender);
        assert_ne!(
            account_zero.buf[1], account_one.buf[1],
            "changing only account_index must change trusted-display bytes"
        );
        assert_eq!(&account_zero.buf[1][0][..14], b"Signer acct #0");
        assert_eq!(&account_one.buf[1][0][..14], b"Signer acct #1");
        assert!(from_page_matches(&account_zero, 1, 0, &sender));
        assert!(!from_page_matches(&account_zero, 1, 1, &sender));
    }

    #[test]
    fn every_sender_byte_is_bound_into_the_signer_page() {
        let sender = [0x42u8; 20];
        let mut pages = Pages::with_len(1);
        append_signer(&mut pages, 7, &sender);
        assert!(from_page_matches(&pages, 1, 7, &sender));
        for i in 0..sender.len() {
            let mut changed = sender;
            changed[i] ^= 1;
            assert!(!from_page_matches(&pages, 1, 7, &changed));
        }
    }

    #[test]
    fn signer_page_completion_proof_fails_before_or_after_corruption() {
        let sender = [0x24u8; 20];
        let mut pages = Pages::with_len(1);
        assert_ne!(
            from_page_proof(&pages, 1, 3, &sender),
            crate::fi::OK_SENTINEL
        );
        append_signer(&mut pages, 3, &sender);
        assert_eq!(
            from_page_proof(&pages, 1, 3, &sender),
            crate::fi::OK_SENTINEL
        );
        pages.buf[1][2][7] ^= 1;
        assert_ne!(
            from_page_proof(&pages, 1, 3, &sender),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn target_page_follows_signer_and_shows_full_address() {
        let sender = [0x11u8; 20];
        let target = [0xabu8; 20];
        let mut pages = Pages::with_len(1);
        append_signer(&mut pages, 4, &sender);
        append_target(&mut pages, &target);

        assert_eq!(pages.len, 3);
        assert_eq!(&pages.buf[1][0][..14], b"Signer acct #4");
        assert_eq!(&pages.buf[2][0], b"Target contract:");
        let mut expected = [[b' '; DISPLAY_COLS]; 3];
        let [a, b, c] = &mut expected;
        primitives::write_addr_full(a, b, c, &target);
        assert_eq!(&pages.buf[2][1..4], &expected);
        assert!(target_page_matches(&pages, 2, &target));
    }

    #[test]
    fn target_flip_changes_page_and_completion_proof_is_fail_closed() {
        let sender = [0x22u8; 20];
        let target = [0x44u8; 20];
        let mut pages = Pages::with_len(1);
        append_signer(&mut pages, 0, &sender);
        let before = pages.len;
        assert_ne!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
        append_target(&mut pages, &target);
        assert_eq!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
        for i in 0..target.len() {
            let mut changed = target;
            changed[i] ^= 1;
            assert!(!target_page_matches(&pages, 2, &changed));
            assert_ne!(
                target_page_proof(&pages, before, &changed),
                crate::fi::OK_SENTINEL
            );
        }
        pages.buf[2][3][9] ^= 1;
        assert_ne!(
            target_page_proof(&pages, before, &target),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn target_page_full_buffer_fails_closed() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_target_page(&mut pages, &[0x55u8; 20], &mut cfi).is_err());
        assert_eq!(pages.len, super::super::MAX_PAGES);
    }

    #[test]
    fn from_page_full_buffer_and_bad_account_fail_closed() {
        let sender = [0x11u8; 20];
        let mut full = Pages::with_len(super::super::MAX_PAGES);
        let mut full_cfi = crate::fi::CfiCounter::new();
        assert!(enforce_from_page(&mut full, 0, &sender, &mut full_cfi).is_err());
        assert_eq!(full.len, super::super::MAX_PAGES);

        let mut bad_account = Pages::with_len(1);
        let mut bad_cfi = crate::fi::CfiCounter::new();
        assert!(enforce_from_page(&mut bad_account, 256, &sender, &mut bad_cfi).is_err());
        assert_eq!(bad_account.len, 1, "invalid account must not add a page");
    }

    /// Audit C-1 regression. The invariant is applied uniformly to the
    /// final page set regardless of which renderer (TxKind) produced it,
    /// so a single test over a synthetic banner+body+confirm set proves
    /// the per-TxKind guarantee: a non-zero `value` always yields a loud
    /// append-only suffix page.
    #[test]
    fn nonzero_value_appends_loud_value_page_without_touching_prefix() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "! Unknown token");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        append_native(&mut pages, &one_native(), 1);
        assert_eq!(pages.len, 4, "a value page must be inserted");
        // Banner stays first; the loud value page is appended.
        assert_eq!(&pages.buf[0][0][..15], b"! Unknown token");
        assert_eq!(&pages.buf[3][0][..12], b"! NATIVE ETH");
        // The complete original prefix remains untouched.
        assert_eq!(&pages.buf[2][2][..8], b"L=Cancel");
    }

    #[test]
    fn nonzero_value_page_uses_chain_native_ticker() {
        let mut pages = Pages::with_len(2);
        append_native(&mut pages, &one_native(), 56);
        assert_eq!(&pages.buf[2][0][..12], b"! NATIVE BNB");
        let rows = &pages.buf[2];
        assert!(rows.iter().all(|row| !row.windows(3).any(|w| w == b"ETH")));
    }

    /// Audit 2026-06-28 regression — `v1_ms` metadata mis-attribution.
    /// On the DIRECT ERC-20 render path the bundle metadata may only be
    /// applied when its contract matches the call target. A bundle for
    /// token T (e.g. routed via a bogus `safe_v1` multiSend record) must
    /// NOT be applied to a `transfer` whose `tx.to` is the unrelated token
    /// Y — otherwise the OLED would show "Send <T.symbol>" with T's
    /// decimals for a transfer of Y.
    #[test]
    fn direct_erc20_meta_gate_rejects_mismatched_contract() {
        let token_y = [0xAAu8; 20]; // the real call target
        let token_t = [0xBBu8; 20]; // the bundle's (mis-attributed) token
                                    // Mismatch → reject (renderer falls back to erc20_unknown).
        assert!(!direct_erc20_meta_matches(&token_t, Some(&token_y)));
    }

    /// Positive: a legitimate direct ERC-20 call (bundle contract == the
    /// call target) is accepted, so the rich `erc20_known` render still
    /// fires for honest transfers.
    #[test]
    fn direct_erc20_meta_gate_accepts_matching_contract() {
        let token = [0xCDu8; 20];
        assert!(direct_erc20_meta_matches(&token, Some(&token)));
    }

    /// A contract-creation / no-`to` shape can never match a token bundle,
    /// so the gate declines (fail-safe to raw render) rather than panicking
    /// or accepting a bundle for a `None` target.
    #[test]
    fn direct_erc20_meta_gate_rejects_absent_target() {
        let token = [0x01u8; 20];
        assert!(!direct_erc20_meta_matches(&token, None));
    }

    /// A near-miss (single trailing byte differs) is still a mismatch —
    /// the compare is full-width, not a truncated prefix.
    #[test]
    fn direct_erc20_meta_gate_is_full_width() {
        let mut a = [0x42u8; 20];
        let mut b = [0x42u8; 20];
        a[19] = 0x00;
        b[19] = 0x01;
        assert!(!direct_erc20_meta_matches(&a, Some(&b)));
    }

    /// A zero `value` must NOT add a page (no spurious "0 ETH" page), and
    /// reports `Ok` (invariant holds — nothing to show).
    #[test]
    fn zero_value_adds_no_page() {
        let mut pages = Pages::with_len(3);
        append_native(&mut pages, &U256::zero(), 1);
        assert_eq!(pages.len, 3);
    }

    /// Audit 2026-06-18 regression — FAIL CLOSED. A non-zero `value` that
    /// cannot be spliced because the renderer already filled the page
    /// budget must return `Err(())` (caller refuses to sign), NOT silently
    /// drop the loud ETH page. Pages are left unchanged so nothing
    /// confirmable hides the value.
    #[test]
    fn nonzero_value_full_buffer_fails_closed() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let before = pages.len;
        let before_buf = pages.buf;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(
            enforce_native_value_page(&mut pages, &one_native(), 1, &mut cfi).is_err(),
            "non-zero value on a full buffer must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced or dropped");
        assert_eq!(
            pages.buf, before_buf,
            "failure must be byte-for-byte atomic"
        );
        assert_ne!(
            cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "a failed append must not publish the native-value CFI receipt"
        );
    }

    /// A non-zero value with exactly one free slot must splice the loud
    /// page (the common case for the short value-hiding renderers, which
    /// never approach the cap).
    #[test]
    fn nonzero_value_with_room_splices_and_reports_ok() {
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        append_native(&mut pages, &one_native(), 1);
        assert_eq!(pages.len, super::super::MAX_PAGES);
        assert_eq!(
            &pages.buf[super::super::MAX_PAGES - 1][0][..12],
            b"! NATIVE ETH"
        );
    }

    #[test]
    fn known_native_value_page_accepts_scaled_and_exact_wei_forms() {
        let values = [
            one_native(),
            u256_from_u128(1_000_001_000_000_000_000), // 1.000001 native
            one_wei(),
            u256_from_u128(1_000_000_000_000_000_001), // exact wei fallback
        ];
        for chain_id in [1, 56] {
            for value in values {
                let mut pages = marker_pages(2);
                let prior_len = pages.len;
                append_native(&mut pages, &value, chain_id);
                assert_eq!(
                    native_value_page_proof(&pages, prior_len, &value, chain_id),
                    crate::fi::OK_SENTINEL
                );
                assert_eq!(
                    native_value_final_set_proof(&pages, prior_len, &value, chain_id),
                    crate::fi::OK_SENTINEL
                );
            }
        }
    }

    #[test]
    fn one_wei_and_one_native_plus_one_wei_have_distinct_confirmed_pages() {
        let cases = [
            one_wei(),
            one_native(),
            u256_from_u128(1_000_000_000_000_000_001),
        ];
        let mut confirmed = [[[b' '; DISPLAY_COLS]; DISPLAY_ROWS]; 3];

        for (index, value) in cases.iter().enumerate() {
            let mut pages = marker_pages(2);
            let prior_len = pages.len;
            append_native(&mut pages, value, 1);
            assert_eq!(
                native_value_page_proof(&pages, prior_len, value, 1),
                crate::fi::OK_SENTINEL
            );
            assert_eq!(
                native_value_final_set_proof(&pages, prior_len, value, 1),
                crate::fi::OK_SENTINEL
            );
            confirmed[index] = pages.buf[prior_len];
        }

        assert_eq!(&confirmed[0][1][..1], b"1");
        assert_eq!(&confirmed[0][2][..3], b"wei");
        assert_eq!(&confirmed[1][1][..12], b"1.000000 ETH");
        assert_eq!(&confirmed[2][1], b"1000000000000000");
        assert_eq!(&confirmed[2][2][..7], b"001 wei");
        assert_ne!(confirmed[0], confirmed[1]);
        assert_ne!(confirmed[1], confirmed[2]);
        assert_ne!(confirmed[0], confirmed[2]);
    }

    #[test]
    fn exact_but_overwide_known_native_value_refuses_atomically() {
        // 10^60 base units is divisible by 10^12, so it passes the precision
        // gate, but its 43-digit native-unit representation cannot fit the two
        // value rows. This isolates the width/overflow half of the policy.
        let overwide_exact = power_of_ten(60);
        assert!(primitives::amount_is_exact_at_fraction_digits(
            &overwide_exact,
            18,
            primitives::NATIVE_DISPLAY_FRACTION_DIGITS,
        ));
        let mut pages = marker_pages(2);
        let before_len = pages.len;
        let before_buf = pages.buf;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_native_value_page(&mut pages, &overwide_exact, 1, &mut cfi).is_err());
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
        assert_ne!(
            cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            native_value_page_proof(&pages, before_len, &overwide_exact, 1),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            native_value_final_set_proof(&pages, before_len, &overwide_exact, 1),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn unknown_chain_raw_value_stays_exact_and_overwide_raw_refuses() {
        const UNKNOWN_CHAIN: u64 = 4_242_424_242;
        let mut exact_pages = marker_pages(2);
        let exact_prior = exact_pages.len;
        append_native(&mut exact_pages, &one_wei(), UNKNOWN_CHAIN);
        assert_eq!(
            native_value_page_proof(&exact_pages, exact_prior, &one_wei(), UNKNOWN_CHAIN),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(&exact_pages.buf[exact_prior][1][..1], b"1");
        assert_eq!(&exact_pages.buf[exact_prior][2][..3], b"raw");

        let overwide = U256([0xff; 32]);
        let mut refused = marker_pages(2);
        let before_len = refused.len;
        let before_buf = refused.buf;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(
            enforce_native_value_page(&mut refused, &overwide, UNKNOWN_CHAIN, &mut cfi).is_err()
        );
        assert_eq!(refused.len, before_len);
        assert_eq!(refused.buf, before_buf);
        assert_ne!(
            cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            native_value_page_proof(&refused, before_len, &overwide, UNKNOWN_CHAIN),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            native_value_final_set_proof(&refused, before_len, &overwide, UNKNOWN_CHAIN),
            crate::fi::OK_SENTINEL
        );
    }

    /// Audit 2026-06-19 — gas/fee WYSIWYS splice. The two gas pages are
    /// appended after the renderer's existing pages, so a
    /// Safe/CoW confirm can no longer hide the signed maxFeePerGas / gas
    /// limits. Banner stays first, confirm stays last.
    #[test]
    fn gas_pages_form_append_only_suffix() {
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "Sign CowSwap?");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        append_legacy_fees(&mut pages, &fee_tx());
        assert_eq!(pages.len, 5, "two gas pages must be inserted");
        // Original prefix is unchanged; fee pages form the new suffix.
        assert_eq!(&pages.buf[0][0][..13], b"Sign CowSwap?");
        assert_eq!(&pages.buf[2][2][..8], b"L=Cancel");
        assert_eq!(&pages.buf[3][0][..15], b"Fees: max / tip");
        assert_eq!(&pages.buf[4][0][..11], b"Worst-case:");
    }

    #[test]
    fn unknown_chain_gas_pages_are_raw_exact_and_proven() {
        let mut tx = fee_tx();
        tx.chain_id = 4_242_424_242;
        tx.max_fee_per_gas = u256_from_u128(30_000_000_001);
        tx.max_priority_fee_per_gas = u256_from_u128(1_234_567_890);
        tx.gas_limit = 30_000_000;

        let mut pages = marker_pages(3);
        let prior_len = pages.len;
        append_legacy_fees(&mut pages, &tx);
        assert_eq!(pages.len, prior_len + LEGACY_FEE_PAGES);
        assert_eq!(&pages.buf[prior_len][0][..15], b"Base: max / tip");
        assert_eq!(&pages.buf[prior_len][1][..11], b"30000000001");
        assert_eq!(&pages.buf[prior_len][2][..10], b"1234567890");
        assert_eq!(&pages.buf[prior_len + 1][0], b"Worst-case/base:");
        assert_eq!(
            legacy_fee_pages_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );

        pages.push_blank().unwrap();
        assert_eq!(
            legacy_fee_pages_final_set_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );
        pages.buf[prior_len][1][0] ^= 1;
        assert_ne!(
            legacy_fee_pages_final_set_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn unknown_chain_inexact_fee_suffix_refuses_atomically() {
        let mut tx = fee_tx();
        tx.chain_id = 4_242_424_242;
        tx.max_fee_per_gas = u256_from_u128(10_000_000_000_000_000);
        tx.max_priority_fee_per_gas = u256_from_u128(1);
        tx.gas_limit = 21_000;

        let mut pages = marker_pages(3);
        let before_len = pages.len;
        let before_buf = pages.buf;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_gas_pages(&mut pages, &tx, &mut cfi).is_err());
        assert_eq!(pages.len, before_len);
        assert_eq!(pages.buf, before_buf);
        assert_ne!(
            cfi.check_into_sentinel(LEGACY_FEE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            legacy_fee_pages_proof(&pages, before_len, &tx),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            legacy_fee_pages_final_set_proof(&pages, before_len, &tx),
            crate::fi::OK_SENTINEL
        );
    }

    /// FAIL CLOSED + ATOMIC. With fewer than two free slots the gas splice
    /// must refuse (caller refuses to sign) and leave the page set
    /// untouched — never a single orphaned gas page hiding the other.
    #[test]
    fn gas_pages_insufficient_room_fails_closed_atomically() {
        // Exactly one free slot — not enough for the two-page splice.
        let mut pages = Pages::with_len(super::super::MAX_PAGES - 1);
        let before = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(
            enforce_gas_pages(&mut pages, &fee_tx(), &mut cfi).is_err(),
            "fewer than two free slots must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced (atomic)");
    }

    /// Audit 2026-06-27 — paymaster WYSIWYS. A present paymaster appends
    /// a loud page so the user can never authorise a
    /// sponsored UserOp (whose token-paymaster may debit ERC-20 for "gas")
    /// without seeing it.
    #[test]
    fn paymaster_present_appends_loud_page() {
        let present = [0x11u8; 32]; // any non-empty-bytes hash
        let mut pages = Pages::with_len(3);
        primitives::write_line(pages.row_mut(0, 0), "Send ETH?");
        primitives::write_line(pages.row_mut(2, 2), "L=Cancel");
        let prior_len = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_paymaster_page(&mut pages, &present, &mut cfi).is_ok());
        assert_eq!(
            cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            paymaster_page_proof(&pages, prior_len, &present),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(pages.len, 4, "a paymaster page must be inserted");
        assert_eq!(&pages.buf[0][0][..9], b"Send ETH?");
        assert_eq!(&pages.buf[3][0][..15], b"! PAYMASTER SET");
        assert_eq!(&pages.buf[2][2][..8], b"L=Cancel");
    }

    /// Absent paymaster (hash == SHA-256("")) must add no page and report Ok.
    #[test]
    fn paymaster_absent_adds_no_page() {
        let mut pages = Pages::with_len(3);
        let prior_len = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_paymaster_page(&mut pages, &SHA256_OF_EMPTY, &mut cfi).is_ok());
        assert_eq!(
            cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            paymaster_page_proof(&pages, prior_len, &SHA256_OF_EMPTY),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(pages.len, 3);
    }

    /// FAIL CLOSED. A present paymaster that cannot be spliced because the
    /// renderer already filled the budget must return `Err(())` (caller
    /// refuses to sign), never silently drop the warning.
    #[test]
    fn paymaster_present_full_buffer_fails_closed() {
        let present = [0x11u8; 32];
        let mut pages = Pages::with_len(super::super::MAX_PAGES);
        let before = pages.len;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(
            enforce_paymaster_page(&mut pages, &present, &mut cfi).is_err(),
            "present paymaster on a full buffer must fail closed"
        );
        assert_eq!(pages.len, before, "no page may be spliced or dropped");
        assert_ne!(
            cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn paymaster_skip_append_and_final_set_require_cfi_and_exact_content() {
        let present = [0x23u8; 32];

        // The absent shape is structurally valid even if the whole enforcer
        // call were skipped; the independent caller-owned CFI distinguishes
        // that fault from a completed legitimate skip.
        let mut absent = Pages::with_len(2);
        let absent_prior = absent.len;
        let mut absent_cfi = crate::fi::CfiCounter::new();
        assert_eq!(
            paymaster_page_proof(&absent, absent_prior, &SHA256_OF_EMPTY),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            absent_cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        enforce_paymaster_page(&mut absent, &SHA256_OF_EMPTY, &mut absent_cfi).unwrap();
        assert_eq!(
            absent_cfi.check_into_sentinel(PAYMASTER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        absent.push_blank().unwrap();
        assert_eq!(
            paymaster_final_set_proof(&absent, absent_prior, &SHA256_OF_EMPTY),
            crate::fi::OK_SENTINEL
        );

        let mut appended = Pages::with_len(2);
        let appended_prior = appended.len;
        let mut appended_cfi = crate::fi::CfiCounter::new();
        enforce_paymaster_page(&mut appended, &present, &mut appended_cfi).unwrap();
        assert_eq!(
            paymaster_page_proof(&appended, appended_prior, &present),
            crate::fi::OK_SENTINEL
        );
        appended.push_blank().unwrap();
        assert_eq!(
            paymaster_final_set_proof(&appended, appended_prior, &present),
            crate::fi::OK_SENTINEL
        );
        appended.buf[appended_prior][2][4] ^= 1;
        assert_ne!(
            paymaster_final_set_proof(&appended, appended_prior, &present),
            crate::fi::OK_SENTINEL
        );

        let mut wrong_index = Pages::with_len(2);
        let wrong_prior = wrong_index.len;
        append_paymaster(&mut wrong_index, &present);
        wrong_index.buf.swap(0, wrong_prior);
        assert_ne!(
            paymaster_page_proof(&wrong_index, wrong_prior, &present),
            crate::fi::OK_SENTINEL
        );

        let mut duplicate = Pages::with_len(2);
        let duplicate_prior = duplicate.len;
        append_paymaster(&mut duplicate, &present);
        duplicate.buf[0] = duplicate.buf[duplicate_prior];
        assert_ne!(
            paymaster_page_proof(&duplicate, duplicate_prior, &present),
            crate::fi::OK_SENTINEL
        );

        let mut absent_injection = Pages::with_len(2);
        let absent_injection_prior = absent_injection.len;
        absent_injection.buf[0] = build_paymaster_page();
        assert_ne!(
            paymaster_page_proof(&absent_injection, absent_injection_prior, &SHA256_OF_EMPTY,),
            crate::fi::OK_SENTINEL
        );
    }

    fn marker_pages(len: usize) -> Pages {
        let mut pages = Pages::with_len(len);
        for page_index in 0..len {
            let marker = 0x40u8.wrapping_add(page_index as u8);
            for row in &mut pages.buf[page_index] {
                row.fill(marker);
            }
        }
        pages
    }

    #[test]
    fn every_value_page_producer_preserves_a_unique_marker_prefix() {
        let sender = [0x21; 20];
        let target = [0x32; 20];
        let present_paymaster = [0x43; 32];

        let mut signer = marker_pages(4);
        let signer_before = signer.buf;
        append_signer(&mut signer, 7, &sender);
        assert_eq!(&signer.buf[..4], &signer_before[..4]);

        let mut target_pages = marker_pages(4);
        let target_before = target_pages.buf;
        append_target(&mut target_pages, &target);
        assert_eq!(&target_pages.buf[..4], &target_before[..4]);

        let mut native = marker_pages(4);
        let native_before = native.buf;
        append_native(&mut native, &one_native(), 1);
        assert_eq!(&native.buf[..4], &native_before[..4]);

        let mut fees = marker_pages(4);
        let fees_before = fees.buf;
        append_legacy_fees(&mut fees, &fee_tx());
        assert_eq!(&fees.buf[..4], &fees_before[..4]);

        let mut paymaster = marker_pages(4);
        let paymaster_before = paymaster.buf;
        append_paymaster(&mut paymaster, &present_paymaster);
        assert_eq!(&paymaster.buf[..4], &paymaster_before[..4]);
    }

    #[test]
    fn exact_fit_succeeds_and_overfull_cfi_receipts_stay_short() {
        let sender = [0x11; 20];
        let target = [0x22; 20];

        let mut signer = marker_pages(super::super::MAX_PAGES - 1);
        append_signer(&mut signer, 1, &sender);
        assert_eq!(signer.len, super::super::MAX_PAGES);

        let mut target_pages = marker_pages(super::super::MAX_PAGES - 1);
        append_target(&mut target_pages, &target);
        assert_eq!(target_pages.len, super::super::MAX_PAGES);

        let mut native = marker_pages(super::super::MAX_PAGES - 1);
        append_native(&mut native, &one_native(), 1);
        assert_eq!(native.len, super::super::MAX_PAGES);

        let mut fees = marker_pages(super::super::MAX_PAGES - LEGACY_FEE_PAGES);
        append_legacy_fees(&mut fees, &fee_tx());
        assert_eq!(fees.len, super::super::MAX_PAGES);

        let mut full = marker_pages(super::super::MAX_PAGES);
        let full_before = full.buf;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        assert!(enforce_from_page(&mut full, 1, &sender, &mut signer_cfi).is_err());
        assert_eq!(full.buf, full_before);
        assert_ne!(
            signer_cfi.check_into_sentinel(SIGNER_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn signer_and_target_proofs_reject_wrong_index_duplicate_and_corruption() {
        let sender = [0x51; 20];
        let target = [0x62; 20];
        let mut pages = marker_pages(3);

        let signer_prior = pages.len;
        append_signer(&mut pages, 9, &sender);
        assert_eq!(
            from_page_proof(&pages, signer_prior, 9, &sender),
            crate::fi::OK_SENTINEL
        );
        pages.buf[0] = pages.buf[signer_prior];
        assert_ne!(
            from_page_proof(&pages, signer_prior, 9, &sender),
            crate::fi::OK_SENTINEL,
            "a second exact signer page must fail uniqueness"
        );
        pages.buf[0].fill([b'X'; DISPLAY_COLS]);
        pages.buf.swap(1, signer_prior);
        assert_ne!(
            from_page_proof(&pages, signer_prior, 9, &sender),
            crate::fi::OK_SENTINEL,
            "the right page at the wrong index must fail"
        );

        let mut target_pages = marker_pages(3);
        let target_prior = target_pages.len;
        append_target(&mut target_pages, &target);
        assert_eq!(
            target_page_proof(&target_pages, target_prior, &target),
            crate::fi::OK_SENTINEL
        );
        target_pages.buf[target_prior][2][5] ^= 1;
        assert_ne!(
            target_page_proof(&target_pages, target_prior, &target),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn native_skip_and_append_require_both_completion_cfi_and_exact_proof() {
        let zero = U256::zero();
        let mut skipped = marker_pages(2);
        let skipped_prior = skipped.len;
        let mut skip_cfi = crate::fi::CfiCounter::new();
        assert_eq!(
            native_value_skip_proof(&skipped, skipped_prior, &zero),
            crate::fi::OK_SENTINEL,
            "the structural skip alone cannot prove the enforcer ran"
        );
        assert_ne!(
            skip_cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        enforce_native_value_page(&mut skipped, &zero, 1, &mut skip_cfi).unwrap();
        assert_eq!(
            skip_cfi.check_into_sentinel(NATIVE_VALUE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            native_value_page_proof(&skipped, skipped_prior, &zero, 1),
            crate::fi::OK_SENTINEL
        );

        let mut appended = marker_pages(2);
        let append_prior = appended.len;
        append_native(&mut appended, &one_native(), 1);
        assert_eq!(
            native_value_page_proof(&appended, append_prior, &one_native(), 1),
            crate::fi::OK_SENTINEL
        );
        appended.buf[append_prior][1][0] ^= 1;
        assert_ne!(
            native_value_page_proof(&appended, append_prior, &one_native(), 1),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn legacy_fee_pair_is_atomic_exact_and_recheckable_after_suffix_appends() {
        let tx = fee_tx();
        let mut pages = marker_pages(3);
        let before = pages.buf;
        let prior_len = pages.len;
        append_legacy_fees(&mut pages, &tx);
        assert_eq!(&pages.buf[..prior_len], &before[..prior_len]);
        assert_eq!(
            legacy_fee_pages_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );
        pages.push_blank().unwrap();
        assert_eq!(
            legacy_fee_pages_final_set_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );
        pages.buf[prior_len + 1][0][0] ^= 1;
        assert_ne!(
            legacy_fee_pages_final_set_proof(&pages, prior_len, &tx),
            crate::fi::OK_SENTINEL
        );

        let mut insufficient = marker_pages(super::super::MAX_PAGES - 1);
        let insufficient_before = insufficient.buf;
        let mut cfi = crate::fi::CfiCounter::new();
        assert!(enforce_gas_pages(&mut insufficient, &tx, &mut cfi).is_err());
        assert_eq!(insufficient.len, super::super::MAX_PAGES - 1);
        assert_eq!(insufficient.buf, insufficient_before);
        assert_ne!(
            cfi.check_into_sentinel(LEGACY_FEE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn legacy_shift_symbol_has_zero_references_in_confirmation_modules() {
        let needle = concat!("insert_", "blank");
        for source in [
            include_str!("value_page.rs"),
            include_str!("nonce_lane.rs"),
            include_str!("dispatch.rs"),
            include_str!("mod.rs"),
        ] {
            assert!(!source.contains(needle));
        }
    }
}
