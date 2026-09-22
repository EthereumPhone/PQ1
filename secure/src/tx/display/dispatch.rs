//! `pick_sign_pages` — the CMD_SIGN_USEROP trusted-UI render dispatcher.
//!
//! Extracted verbatim from `tx/display/mod.rs` (2026-07-06) into its own
//! file so the WYSIWYS glue harness can `#[path]`-mount the REAL body on
//! the host (see `crate::display_under_test::dispatch` and
//! `display_under_test/wysiwys_dispatch_differential_tests.rs`). Every
//! sibling-renderer reference is `super::`-qualified so the body resolves
//! identically under both parents:
//!
//!   * production: `super` = `crate::tx::display` (this directory's
//!     `mod.rs`, which declares `mod dispatch;` under `cfg(not(test))`),
//!   * host tests: `super` = `crate::display_under_test` (the scaffold,
//!     which mounts the same per-renderer source files).
//!
//! No logic change — the function bodies are byte-identical to the
//! pre-extraction `mod.rs` versions apart from the path qualification.

const UNSET_PAGE_INDEX: usize = usize::MAX;

/// No ERC-7730 contract renderer won the dispatch priority ladder. This is
/// distinct from every renderer transcript state.
const INTENT_REQUIREMENT_NONE: u32 = 0xF00F_5AA5;
const INTENT_CFI_FAIL_INITIALIZED: u32 = 0x2A17_C4E9;
const INTENT_CFI_REQUIREMENT_CLASSIFIED: u32 = 0xB4C2_196D;
const TRANSCRIPT_CFI_FIRST_RECEIPT_RECORDED: u32 = 0x49D8_E3B2;
const TRANSCRIPT_CFI_BUFFER_RESET: u32 = 0x963A_5C71;
const TRANSCRIPT_CFI_SECOND_RENDER_VERIFIED: u32 = 0x6BC5_A38E;
const TRANSCRIPT_CFI_NONE_RECORDED: u32 = 0xD14E_72A9;
const TRANSCRIPT_CFI_ERC7730_EXPECTED: u32 = crate::cfi_expected!(
    INTENT_CFI_FAIL_INITIALIZED,
    INTENT_CFI_REQUIREMENT_CLASSIFIED,
    TRANSCRIPT_CFI_FIRST_RECEIPT_RECORDED,
    TRANSCRIPT_CFI_BUFFER_RESET,
    TRANSCRIPT_CFI_SECOND_RENDER_VERIFIED,
);
const TRANSCRIPT_CFI_NONE_EXPECTED: u32 = crate::cfi_expected!(
    INTENT_CFI_FAIL_INITIALIZED,
    INTENT_CFI_REQUIREMENT_CLASSIFIED,
    TRANSCRIPT_CFI_NONE_RECORDED,
);

const _: () = {
    use pqsigner_erc7730::display::render::{
        INTENT_PUBLICATION_INTERPOLATED, INTENT_PUBLICATION_STATIC, INTENT_PUBLICATION_UNPUBLISHED,
    };
    assert!((INTENT_REQUIREMENT_NONE ^ INTENT_PUBLICATION_UNPUBLISHED).count_ones() >= 16);
    assert!((INTENT_REQUIREMENT_NONE ^ INTENT_PUBLICATION_STATIC).count_ones() >= 16);
    assert!((INTENT_REQUIREMENT_NONE ^ INTENT_PUBLICATION_INTERPOLATED).count_ones() >= 16);
};

/// Secure-world view of one complete renderer transcript. `expected_state` is
/// classified from the authenticated descriptor and dispatch priority without
/// consulting the renderer receipt. The receipt comes from the first full
/// render; displayed pages come from a fresh second render into the same buffer.
struct Erc7730TranscriptProof {
    expected_state: u32,
    nested_commitment: Option<[u8; 32]>,
    receipt: pqsigner_erc7730::display::render::ContractTranscriptReceipt,
    start_index: usize,
    cfi: crate::fi::CfiCounter,
}

impl Erc7730TranscriptProof {
    const fn new() -> Self {
        Self {
            expected_state: pqsigner_erc7730::display::render::INTENT_PUBLICATION_UNPUBLISHED,
            nested_commitment: None,
            receipt: pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished(),
            start_index: UNSET_PAGE_INDEX,
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    #[inline(never)]
    fn fail_initialize(&mut self) {
        // SAFETY: every pointer is derived from this unique mutable borrow.
        // Volatile stores keep the fail state materialized if a later proof
        // call is fault-skipped under LTO.
        unsafe {
            core::ptr::write_volatile(
                &mut self.expected_state,
                pqsigner_erc7730::display::render::INTENT_PUBLICATION_UNPUBLISHED,
            );
            core::ptr::write_volatile(&mut self.nested_commitment, None);
            core::ptr::write_volatile(
                &mut self.receipt,
                pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished(),
            );
            core::ptr::write_volatile(&mut self.start_index, UNSET_PAGE_INDEX);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(INTENT_CFI_FAIL_INITIALIZED);
    }

    #[inline]
    fn range_matches(
        &self,
        receipt: &pqsigner_erc7730::display::render::ContractTranscriptReceipt,
        pages: &super::Pages,
        start: usize,
    ) -> bool {
        match self.nested_commitment.as_ref() {
            Some(commitment) => receipt.range_matches_with_nested(pages, start, commitment),
            None => receipt.range_matches(pages, start),
        }
    }

    /// Record the first full render only after independently classified state,
    /// count, and exact range all agree. The CFI bump is operation-local.
    #[inline(never)]
    fn record_first_receipt(
        &mut self,
        receipt: &pqsigner_erc7730::display::render::ContractTranscriptReceipt,
        pages: &super::Pages,
    ) -> Result<(), ()> {
        let valid = receipt.state_code() == self.expected_state
            && matches!(
                self.expected_state,
                pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC
                    | pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED
            )
            && self.range_matches(receipt, pages, 0);
        let verdict = crate::fi::check_true_into_sentinel(|| core::hint::black_box(valid));
        if verdict != crate::fi::OK_SENTINEL {
            return Err(());
        }
        // SAFETY: unique mutable borrow. The receipt/start stores are volatile
        // so a skipped publication cannot inherit a permissive prior frame.
        unsafe {
            core::ptr::write_volatile(&mut self.receipt, *receipt);
            core::ptr::write_volatile(&mut self.start_index, 0);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(TRANSCRIPT_CFI_FIRST_RECEIPT_RECORDED);
        Ok(())
    }

    /// Destroy the first render in-place and grant the reset CFI step only
    /// after all fixed-capacity bytes and the visible length read back as the
    /// poison state.
    #[inline(never)]
    fn poison_for_second_render(&mut self, pages: &mut super::Pages) -> Result<(), ()> {
        pages.volatile_poison_and_reset();
        let verdict = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(pages.is_transcript_poisoned())
        });
        if verdict != crate::fi::OK_SENTINEL {
            return Err(());
        }
        self.cfi.bump(TRANSCRIPT_CFI_BUFFER_RESET);
        Ok(())
    }

    /// Compare the independently rendered second receipt and displayed pages
    /// against the first receipt. The caller owns and fail-initializes the
    /// verdict slot, so skipping this function cannot grant authority.
    #[inline(never)]
    fn verify_second_render(
        &mut self,
        second: &pqsigner_erc7730::display::render::ContractTranscriptReceipt,
        pages: &super::Pages,
        verdict_out: &mut u32,
    ) {
        let comparison = self.receipt.exact_match(second)
            && second.state_code() == self.expected_state
            && self.range_matches(second, pages, 0);
        let comparison_verdict =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(comparison));
        if comparison_verdict != crate::fi::OK_SENTINEL {
            return;
        }
        self.cfi.bump(TRANSCRIPT_CFI_SECOND_RENDER_VERIFIED);
        let final_verdict = self.proof(pages);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: unique caller-owned output slot, already materialized FAIL.
        unsafe { core::ptr::write_volatile(verdict_out, final_verdict) };
    }

    /// Complete the distinct no-ERC-7730 route. No fake empty transcript can
    /// satisfy a static/interpolated requirement.
    #[inline(never)]
    fn finish_route(&mut self) -> Result<(), ()> {
        match self.expected_state {
            INTENT_REQUIREMENT_NONE => {
                if self.receipt
                    != pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished()
                    || self.nested_commitment.is_some()
                    || self.start_index != UNSET_PAGE_INDEX
                {
                    return Err(());
                }
                self.cfi.bump(TRANSCRIPT_CFI_NONE_RECORDED);
                Ok(())
            }
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC
            | pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED => {
                if self.receipt.state_code() != self.expected_state || self.start_index != 0 {
                    return Err(());
                }
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn is_pristine(&self) -> bool {
        self.expected_state == pqsigner_erc7730::display::render::INTENT_PUBLICATION_UNPUBLISHED
            && self.receipt
                == pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished()
            && self.nested_commitment.is_none()
            && self.start_index == UNSET_PAGE_INDEX
    }

    fn shift_index(&mut self, by: usize) -> Result<(), ()> {
        if self.start_index != UNSET_PAGE_INDEX {
            self.start_index = self.start_index.checked_add(by).ok_or(())?;
        }
        Ok(())
    }

    /// CFI + independently classified state + exact protected-range check.
    #[inline(never)]
    fn proof(&self, pages: &super::Pages) -> u32 {
        let expected_cfi = if self.expected_state == INTENT_REQUIREMENT_NONE {
            TRANSCRIPT_CFI_NONE_EXPECTED
        } else {
            TRANSCRIPT_CFI_ERC7730_EXPECTED
        };
        let cfi = self.cfi.check_into_sentinel(expected_cfi);
        crate::fi::scrub_sentinel_register();
        let content_ok = match self.expected_state {
            INTENT_REQUIREMENT_NONE => {
                self.start_index == UNSET_PAGE_INDEX
                    && self.nested_commitment.is_none()
                    && self.receipt
                        == pqsigner_erc7730::display::render::ContractTranscriptReceipt::unpublished(
                        )
            }
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC
            | pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED => {
                self.receipt.state_code() == self.expected_state
                    && self.start_index != UNSET_PAGE_INDEX
                    && self.range_matches(&self.receipt, pages, self.start_index)
            }
            _ => false,
        };
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(cfi == crate::fi::OK_SENTINEL)
                && core::hint::black_box(content_ok)
        })
    }
}

/// Caller-owned receipts for dispatcher-appended native-value and legacy-fee
/// pages. The secure handler keeps this object alive until the final confirm
/// boundary, so skipping the dispatcher enforcer, its immediate proof, or the
/// later complete-set recheck leaves an independently observable failure.
pub(crate) struct DispatchPageProofs {
    native_prior_len: usize,
    legacy_fee_prior_len: usize,
    native_cfi: crate::fi::CfiCounter,
    legacy_fee_cfi: crate::fi::CfiCounter,
    erc7730_transcript: Erc7730TranscriptProof,
}

impl DispatchPageProofs {
    pub(crate) const fn new() -> Self {
        Self {
            native_prior_len: UNSET_PAGE_INDEX,
            legacy_fee_prior_len: UNSET_PAGE_INDEX,
            native_cfi: crate::fi::CfiCounter::new(),
            legacy_fee_cfi: crate::fi::CfiCounter::new(),
            erc7730_transcript: Erc7730TranscriptProof::new(),
        }
    }

    /// Materialize all dispatcher-owned fail states before any renderer can
    /// publish pages. Required even though [`Self::new`] is also fail-safe:
    /// the intent CFI step detects a skipped initialization call.
    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        self.erc7730_transcript.fail_initialize();
    }

    /// Test-only view of the exact receipt and nested commitment retained by
    /// the production dispatcher. This keeps behavior tests on the real
    /// dispatcher while adding no firmware-visible inspection surface.
    #[cfg(all(test, feature = "erc7730-nested-calldata-test-fixture"))]
    pub(crate) fn erc7730_transcript_for_test(
        &self,
    ) -> (
        pqsigner_erc7730::display::render::ContractTranscriptReceipt,
        Option<[u8; 32]>,
    ) {
        (
            self.erc7730_transcript.receipt,
            self.erc7730_transcript.nested_commitment,
        )
    }

    /// Simulate a post-render fault in the retained nested commitment. The
    /// final production proof must turn this into a refusal.
    #[cfg(all(test, feature = "erc7730-nested-calldata-test-fixture"))]
    pub(crate) fn corrupt_erc7730_nested_commitment_for_test(&mut self) {
        if let Some(commitment) = self.erc7730_transcript.nested_commitment.as_mut() {
            commitment[0] ^= 1;
        }
    }

    fn is_pristine(&self) -> bool {
        self.native_prior_len == UNSET_PAGE_INDEX
            && self.legacy_fee_prior_len == UNSET_PAGE_INDEX
            && self.erc7730_transcript.is_pristine()
    }

    /// Account for a caller-owned prefix wrapper (the batch banner) that is
    /// constructed after dispatch. A skipped or wrong shift makes the final
    /// exact-index proof fail closed.
    pub(crate) fn shift_indices(&mut self, by: usize) -> Result<(), ()> {
        self.native_prior_len = self.native_prior_len.checked_add(by).ok_or(())?;
        if self.legacy_fee_prior_len != UNSET_PAGE_INDEX {
            self.legacy_fee_prior_len = self.legacy_fee_prior_len.checked_add(by).ok_or(())?;
        }
        self.erc7730_transcript.shift_index(by)?;
        Ok(())
    }

    /// Final-boundary CFI/content/uniqueness recheck after every later append.
    #[inline(never)]
    pub(crate) fn final_set_proof(
        &self,
        pages: &super::Pages,
        tx: &crate::tx::eip1559::Eip1559Tx,
        legacy_fee_required: bool,
        verdict_out: &mut u32,
    ) {
        let native_cfi = self
            .native_cfi
            .check_into_sentinel(super::value_page::NATIVE_VALUE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let native_pages = super::value_page::native_value_final_set_proof(
            pages,
            self.native_prior_len,
            &tx.value,
            tx.chain_id,
        );
        crate::fi::scrub_sentinel_register();
        let legacy_cfi = self
            .legacy_fee_cfi
            .check_into_sentinel(if legacy_fee_required {
                super::value_page::LEGACY_FEE_CFI_EXPECTED
            } else {
                crate::fi::CfiCounter::INIT_VALUE
            });
        crate::fi::scrub_sentinel_register();
        let legacy_pages = if legacy_fee_required {
            super::value_page::legacy_fee_pages_final_set_proof(
                pages,
                self.legacy_fee_prior_len,
                tx,
            )
        } else {
            crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(self.legacy_fee_prior_len == UNSET_PAGE_INDEX)
            })
        };
        crate::fi::scrub_sentinel_register();
        let erc7730_transcript = self.erc7730_transcript.proof(pages);
        let all_ok = native_cfi == crate::fi::OK_SENTINEL
            && native_pages == crate::fi::OK_SENTINEL
            && legacy_cfi == crate::fi::OK_SENTINEL
            && legacy_pages == crate::fi::OK_SENTINEL
            && erc7730_transcript == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        let verdict = crate::fi::check_true_into_sentinel(|| core::hint::black_box(all_ok));
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: caller supplied a unique live output slot. It initializes the
        // slot to FAIL before this call, so skipping this entire function never
        // authorizes confirmation via a stale return register.
        unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    }
}

/// Safe/CoW renderers omit the legacy friendly fee envelope; all other
/// renderer branches already produce it themselves.
#[must_use]
pub(crate) const fn legacy_fee_pages_required(
    cow_present: bool,
    safe_v1_present: bool,
    safe_exec_present: bool,
) -> bool {
    cow_present || safe_v1_present || safe_exec_present
}

/// Whether the winning route paints fees with the compact legacy rows.
///
/// Native CoW/Safe routes win over ERC-7730 and receive the dispatcher-owned
/// legacy suffix. With no higher-priority route, an authenticated ERC-7730
/// descriptor owns its exact fee envelope and must be judged by that renderer,
/// not by the narrower legacy layout.
#[must_use]
const fn legacy_fee_preflight_required(
    cow_present: bool,
    safe_v1_present: bool,
    safe_exec_present: bool,
    erc7730_present: bool,
) -> bool {
    legacy_fee_pages_required(cow_present, safe_v1_present, safe_exec_present) || !erc7730_present
}

/// Independently determine what the winning dispatch route requires from the
/// renderer. This deliberately reparses the selected authenticated format's
/// parameter TLVs and never consults a renderer transcript receipt.
#[inline(never)]
fn classify_intent_requirement(
    cow_present: bool,
    safe_v1_present: bool,
    safe_exec_present: bool,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    inner_data: &[u8],
    proof: &mut Erc7730TranscriptProof,
) -> Result<(), ()> {
    let requirement = if cow_present || safe_v1_present || safe_exec_present {
        INTENT_REQUIREMENT_NONE
    } else if let Some(descriptor) = erc7730 {
        let selector: [u8; 4] = inner_data.get(..4).ok_or(())?.try_into().map_err(|_| ())?;
        let format = descriptor
            .ir
            .find_format_by_selector(&selector)
            .map_err(|_| ())?
            .ok_or(())?;
        let mut enrolled = false;
        for (ordinal, field) in format.fields().enumerate() {
            let field = field.map_err(|_| ())?;
            let params = pqsigner_erc7730::render::params::parse(&descriptor.ir, field.param_off)
                .map_err(|_| ())?;
            if params.interpolated_intent.is_some() {
                if ordinal != 0 || enrolled {
                    return Err(());
                }
                enrolled = true;
            }
        }
        if enrolled {
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED
        } else {
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC
        }
    } else {
        if expected_nested.is_some() {
            return Err(());
        }
        INTENT_REQUIREMENT_NONE
    };

    let nested_commitment = if requirement == INTENT_REQUIREMENT_NONE {
        None
    } else {
        expected_nested.map(crate::tx::erc7730::nested_binding_commitment)
    };

    // SAFETY: unique mutable borrow. The classifier publishes both authority
    // dimensions into the caller-owned fail-in state; skipping this call
    // leaves the state, nested commitment, and CFI counter non-authoritative.
    unsafe {
        core::ptr::write_volatile(&mut proof.expected_state, requirement);
        core::ptr::write_volatile(&mut proof.nested_commitment, nested_commitment);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    proof.cfi.bump(INTENT_CFI_REQUIREMENT_CLASSIFIED);
    Ok(())
}

/// Backward-compatible descriptor-only dispatcher retained for the existing
/// host differential corpus. Production handlers use
/// [`pick_sign_pages_with_erc7730_evidence`] so nested authority cannot be
/// reconstructed from a descriptor without its complete rooted proof set.
#[allow(clippy::too_many_arguments)]
pub fn pick_sign_pages(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    proofs: &mut DispatchPageProofs,
) -> Result<super::Pages, ()> {
    pick_sign_pages_impl(
        tx,
        inner_data,
        device_signer,
        v3,
        safe_v1,
        safe_exec,
        erc7730,
        None,
        None,
        erc20,
        selector,
        resolver,
        proofs,
    )
}

/// Production proof-set-aware contract dispatcher. `expected_nested` is the
/// exact binding already derived and FI-proven by the secure handler. The
/// renderer independently re-derives it on both passes and the transcript
/// proof selects V1 or nested V2 framing from that expectation.
#[allow(clippy::too_many_arguments)]
pub fn pick_sign_pages_with_erc7730_evidence(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedProofSet<'_>>,
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    proofs: &mut DispatchPageProofs,
) -> Result<super::Pages, ()> {
    let descriptor = erc7730.map(|set| &set.outer.descriptor);
    pick_sign_pages_impl(
        tx,
        inner_data,
        device_signer,
        v3,
        safe_v1,
        safe_exec,
        descriptor,
        erc7730,
        expected_nested,
        erc20,
        selector,
        resolver,
        proofs,
    )
}

/// Pick the right renderer for a CMD_SIGN_USEROP trusted-UI confirm.
///
/// Centralises the priority ladder — the handler stays a pure
/// orchestrator and the "which display wins when multiple trailers
/// verify" decision lives in one place:
///
///   1. Native CoW EIP-712 (full GPv2Order breakdown from the
///      secure-world-decoded canonical order).
///   2. Safe v1 inner-tx render (verified canonical SafeTx).
///   3. ERC-7730 descriptor (verified against the firmware-pinned
///      `ERC7730_DESCRIPTORS_ROOT`; binding cross-checked against
///      `(chain_id, to)`).
///   4. Known-call omission filter: a registry-known/Bloom-positive tuple
///      without a successfully bound descriptor hard-refuses.
///   5. Plain value transfer (empty inner calldata).
///   6. ERC-20 with verified metadata (token name/symbol/decimals).
///   7. ERC-20 shape-only (unverified token — bare hex decode).
///   8. Typed-call selector + verified ABI walk.
///   9. Blind-sign, only after known-call non-membership succeeds.
///
/// Ordering is load-bearing. In particular, the native CoW route must
/// retain priority over generic typed-call/descriptor rendering so a
/// setPreSignature UserOp renders the complete order intent. The handler's
/// downgrade-mitigation gate enforces this separately at refuse-to-sign
/// level. (2) is above (3) so a Safe
/// `execTransaction` carrying an ERC-7730 descriptor for an inner
/// call still renders the outer Safe banner first — the descriptor
/// would be for the inner call, which the Safe renderer dispatches
/// through its own inner-tx ladder.
///
/// Combination rule: when BOTH a v3 order and a Safe context verified
/// (Safe-wrapped CoW presign — the handler bound the order to the
/// SafeTx inner calldata with uid owner = the Safe), the render routes
/// through the Safe surface with the order as its inner pages. A bare
/// CoW render would hide the SafeTx's signed refund parameters, which
/// are a drain channel (see `safe_display.rs`).
///
/// # Refusal (fail-closed)
///
/// Returns `Err(())` when the dispatcher-level native-ETH value page is
/// mandatory (`tx.value != 0`) but cannot be spliced because the chosen
/// renderer already filled `MAX_PAGES`. Callers MUST map `Err(())` to a
/// refuse-to-sign — releasing a signature whose native `value` was never
/// displayed is exactly the C-1 ETH-drain class this gate exists to close.
#[allow(clippy::too_many_arguments)]
fn pick_sign_pages_impl(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc7730_set: Option<&crate::tx::erc7730::VerifiedProofSet<'_>>,
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    proofs: &mut DispatchPageProofs,
) -> Result<super::Pages, ()> {
    if !proofs.is_pristine() {
        return Err(());
    }
    if expected_nested.is_some() && erc7730_set.is_none() {
        return Err(());
    }
    if let Some(set) = erc7730_set {
        if erc7730 != Some(&set.outer.descriptor) {
            return Err(());
        }
    }
    // Gate the representation that the winning route actually publishes.
    // ERC-7730 renders its own wider exact envelope and returns a hard error
    // before any Pages value escapes. Every other winning route uses the
    // compact legacy painter. Keep route ownership and exactness in one
    // unconditional, double-evaluated FI gate: a skipped outer branch must
    // never become a way around the compact painter's preflight.
    let legacy_fee_exact = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(
            !legacy_fee_preflight_required(
                v3.is_some(),
                safe_v1.is_some(),
                safe_exec.is_some(),
                erc7730.is_some(),
            ) || super::primitives::legacy_fee_rows_are_exactly_renderable(
                &tx.max_fee_per_gas,
                &tx.max_priority_fee_per_gas,
                tx.gas_limit,
                tx.chain_id,
            ),
        )
    });
    crate::fi::scrub_sentinel_register();
    if legacy_fee_exact != crate::fi::OK_SENTINEL {
        return Err(());
    }
    if let Some(order) = v3 {
        let cow_amounts_exact = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(
                crate::tx::eip712::cowswap_display::amounts_are_exactly_renderable(
                    &order.canonical,
                    &order.sell,
                    &order.buy,
                ),
            )
        });
        crate::fi::scrub_sentinel_register();
        if cow_amounts_exact != crate::fi::OK_SENTINEL {
            return Err(());
        }
    }
    classify_intent_requirement(
        v3.is_some(),
        safe_v1.is_some(),
        safe_exec.is_some(),
        erc7730,
        expected_nested,
        inner_data,
        &mut proofs.erc7730_transcript,
    )?;
    // `pick_sign_pages_inner` returns `Err(())` when a Safe-surface render
    // refuses (page budget exceeded / page-accounting self-check failed);
    // propagate it so the handler maps it to a refuse-to-sign rather than
    // showing a buffer with a hidden signed value (audit 2026-06-27).
    let mut pages = pick_sign_pages_inner(
        tx,
        inner_data,
        device_signer,
        v3,
        safe_v1,
        safe_exec,
        erc7730,
        erc7730_set,
        expected_nested,
        erc20,
        selector,
        resolver,
        &mut proofs.erc7730_transcript,
    )?;
    proofs.erc7730_transcript.finish_route()?;
    // Dispatcher-level WYSIWYS invariant (audit C-1 / H-2 / M-8; hardened
    // 2026-06-18).
    //
    // The outer UserOp `value` is signed verbatim into
    // `executeWithOffchainCount(ownerIndex, count, target, value, data)`
    // and forwarded on chain via `target.call{value: value}(data)`, but
    // several renderers surface only token / inner-tx semantics and never
    // the native ETH. Rather than trust each renderer to opt in, EVERY
    // sign confirm funnels through here: when `value` is non-zero we splice
    // in a dedicated, loud value page right after the renderer's banner so
    // the user always sees the ETH the signature commits to.
    //
    // `enforce_native_value_page` is now FI-hardened (the skip-on-zero
    // decision is sentinel-gated, not a bare `if value.is_zero()`) and
    // FAILS CLOSED: if `value != 0` and the loud page cannot be spliced
    // (the renderer already filled `MAX_PAGES`), it returns `Err(())` and
    // we propagate it so the caller REFUSES to sign rather than release a
    // signature over ETH the user never saw. The helper lives in
    // `value_page.rs` so the host-test scaffold can mount and exercise the
    // real body (this dispatcher is `cfg(not(test))`).
    proofs.native_prior_len = pages.len;
    super::value_page::enforce_native_value_page(
        &mut pages,
        &tx.value,
        tx.chain_id,
        &mut proofs.native_cfi,
    )?;
    crate::fi::scrub_sentinel_register();
    let native_cfi_verdict = proofs
        .native_cfi
        .check_into_sentinel(super::value_page::NATIVE_VALUE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let native_page_verdict = super::value_page::native_value_page_proof(
        &pages,
        proofs.native_prior_len,
        &tx.value,
        tx.chain_id,
    );
    if native_cfi_verdict != crate::fi::OK_SENTINEL || native_page_verdict != crate::fi::OK_SENTINEL
    {
        return Err(());
    }

    // Dispatcher-level WYSIWYS invariant (audit 2026-06-19 — gas/fee pages).
    //
    // The five signed EntryPoint v0.6 fee fields (callGasLimit,
    // verificationGasLimit, preVerificationGas, maxFeePerGas,
    // maxPriorityFeePerGas) are committed to by the UserOp signature, and the
    // wallet pays the resulting EntryPoint prefund out of its own native ETH.
    // Most renderers emit the two standard gas pages inline (the same
    // "Max fee" / "Worst-case" pair value_transfer shows), but the Safe and
    // CoW surfaces historically did NOT — so a fee-bomb UserOp (huge
    // maxFeePerGas / gas limits, no paymaster) drained the wallet's ETH as
    // gas behind a benign Safe/CoW confirm with no fee page on screen.
    //
    // Rather than trust each of those renderers to opt in, splice the same
    // two pages here for exactly the flows that lack them. `needs_gas`
    // mirrors the branch precedence in `pick_sign_pages_inner`: any
    // v3 / safe trailer routes to a gas-less renderer; every other
    // outcome (erc7730 / value / erc20 / typed-call / blind-sign) already
    // shows gas, so splicing there would DOUBLE the pages. Fails CLOSED on a
    // full buffer (same refuse-to-sign contract as the value page).
    let needs_gas = legacy_fee_pages_required(v3.is_some(), safe_v1.is_some(), safe_exec.is_some());
    if needs_gas {
        proofs.legacy_fee_prior_len = pages.len;
        super::value_page::enforce_gas_pages(&mut pages, tx, &mut proofs.legacy_fee_cfi)?;
        crate::fi::scrub_sentinel_register();
        let legacy_fee_cfi_verdict = proofs
            .legacy_fee_cfi
            .check_into_sentinel(super::value_page::LEGACY_FEE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let legacy_fee_page_verdict =
            super::value_page::legacy_fee_pages_proof(&pages, proofs.legacy_fee_prior_len, tx);
        if legacy_fee_cfi_verdict != crate::fi::OK_SENTINEL
            || legacy_fee_page_verdict != crate::fi::OK_SENTINEL
        {
            return Err(());
        }
    }
    crate::fi::scrub_sentinel_register();
    let transcript_verdict = proofs.erc7730_transcript.proof(&pages);
    crate::fi::scrub_sentinel_register();
    if transcript_verdict != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(pages)
}

/// Render the authenticated contract twice into one fixed-capacity page buffer.
/// Only the second render is returned for display; the first survives solely as
/// a 40-byte transcript receipt. A volatile full-buffer poison and randomized
/// delay separate the fresh renderer/witness states.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn render_verified_erc7730_two_pass<'ir>(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    descriptor: Option<&crate::tx::erc7730::VerifiedDescriptor<'ir>>,
    set: Option<&crate::tx::erc7730::VerifiedProofSet<'ir>>,
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    device_signer: &[u8; 20],
    proof: &mut Erc7730TranscriptProof,
) -> Result<super::Pages, crate::tx::erc7730_render::RenderErr> {
    use crate::tx::erc7730_render::RenderErr;

    let mut pages = super::Pages::with_len(0);
    let first = match (set, descriptor) {
        (Some(set), Some(descriptor)) if descriptor == &set.outer.descriptor => {
            super::erc7730::render_contract_proof_set_pass_into(
                tx,
                inner_data,
                set,
                erc20,
                resolver,
                device_signer,
                expected_nested,
                &mut pages,
            )?
        }
        (None, Some(descriptor)) if expected_nested.is_none() => {
            super::erc7730::render_contract_pass_into(
                tx,
                inner_data,
                descriptor,
                erc20,
                resolver,
                device_signer,
                &mut pages,
            )?
        }
        _ => return Err(RenderErr::Reject("7730 evidence mismatch")),
    };
    proof
        .record_first_receipt(&first, &pages)
        .map_err(|_| RenderErr::Reject("7730 first transcript proof"))?;
    proof
        .poison_for_second_render(&mut pages)
        .map_err(|_| RenderErr::Reject("7730 transcript reset proof"))?;
    crate::fi::wait_random();

    let second = match (set, descriptor) {
        (Some(set), Some(descriptor)) if descriptor == &set.outer.descriptor => {
            super::erc7730::render_contract_proof_set_pass_into(
                tx,
                inner_data,
                set,
                erc20,
                resolver,
                device_signer,
                expected_nested,
                &mut pages,
            )?
        }
        (None, Some(descriptor)) if expected_nested.is_none() => {
            super::erc7730::render_contract_pass_into(
                tx,
                inner_data,
                descriptor,
                erc20,
                resolver,
                device_signer,
                &mut pages,
            )?
        }
        _ => return Err(RenderErr::Reject("7730 evidence mismatch")),
    };

    let mut immediate_verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique live local. A skipped verification call leaves the
    // materialized FAIL value in memory rather than a stale return register.
    unsafe {
        core::ptr::write_volatile(&mut immediate_verdict, crate::fi::FAIL_SENTINEL);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    proof.verify_second_render(&second, &pages, &mut immediate_verdict);
    // SAFETY: the local verdict remains live and uniquely owned; volatile
    // readback is part of the fault-detection boundary.
    let verdict_a = unsafe { core::ptr::read_volatile(&immediate_verdict) };
    crate::fi::wait_random();
    // SAFETY: same live local as above, read a second time after an independent
    // randomized delay.
    let verdict_b = unsafe { core::ptr::read_volatile(&immediate_verdict) };
    crate::fi::scrub_sentinel_register();
    if verdict_a != crate::fi::OK_SENTINEL || verdict_b != crate::fi::OK_SENTINEL {
        return Err(RenderErr::Reject("7730 second transcript mismatch"));
    }
    Ok(pages)
}

#[allow(clippy::too_many_arguments)]
fn pick_sign_pages_inner(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    device_signer: &[u8; 20],
    v3: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc7730: Option<&crate::tx::erc7730::VerifiedDescriptor<'_>>,
    erc7730_set: Option<&crate::tx::erc7730::VerifiedProofSet<'_>>,
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    selector: Option<&crate::selectors::SelectorMeta<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    transcript_proof: &mut Erc7730TranscriptProof,
) -> Result<super::Pages, ()> {
    // Handler verification already enforces this before dispatch. Repeat the
    // public-envelope bind locally so future or host-only call sites cannot
    // lend metadata from another chain to any renderer. Surface-specific
    // contract/tokenPath checks below remain mandatory as a separate axis.
    let erc20 = erc20.filter(|meta| meta.chain_id == tx.chain_id);

    if let Some(v3) = v3 {
        // Safe-wrapped CoW presign: when the v3 order was verified
        // against a Safe flow's inner calldata (the handler bound uid
        // owner == the Safe via `safe::cow_binding`), the Safe surface
        // must stay visible — its banner, address, nonce and above all
        // the gas-refund pages are signed facts a bare CoW render would
        // hide (the refund channel is a full-balance drain vector, see
        // `safe_display.rs`). The order renders as the Safe's inner-tx
        // pages instead. ERC-20 metadata can apply to a multiSend
        // RECORD (the Safe-UI flow batches `approve(sellToken)` next to
        // the presign), so the address-matched bundle is threaded
        // through; the single-call presign arm ignores it.
        if let Some(safe) = safe_v1 {
            let inner_meta = safe_inner_meta(
                erc20,
                safe.canonical[sphincs_tz_shared::SAFE_OFF_OPERATION],
                &safe_v1_inner_to(safe),
                safe.raw_data,
            );
            return super::safe_display::render_safe_v1_pages(safe, Some(v3), inner_meta, resolver);
        }
        if let Some(exec) = safe_exec {
            let inner_meta = safe_inner_meta(
                erc20,
                exec.decoded.operation,
                &exec.decoded.to,
                exec.decoded.data,
            );
            return super::safe_display::render_safe_exec_pages(
                exec,
                Some(v3),
                inner_meta,
                resolver,
            );
        }
        return Ok(crate::tx::eip712::cowswap_display::render_cowswap_pages(
            &v3.canonical,
            &v3.sell,
            &v3.buy,
        ));
    }
    if let Some(safe) = safe_v1 {
        // For Safe inner-tx ERC-20 rendering, only apply the outer
        // ERC-20 metadata bundle when its contract address matches the
        // inner-tx target — a Safe call carrying USDC metadata is
        // useful only if the inner `to` is in fact USDC — or, for a
        // multiSend batch, when one of the packed records targets the
        // token (the renderer re-matches per record before applying).
        let inner_meta = safe_inner_meta(
            erc20,
            safe.canonical[sphincs_tz_shared::SAFE_OFF_OPERATION],
            &safe_v1_inner_to(safe),
            safe.raw_data,
        );
        return super::safe_display::render_safe_v1_pages(safe, None, inner_meta, resolver);
    }
    if let Some(exec) = safe_exec {
        // Same address-match rule for the exec path, multiSend records
        // included. This pairs with the approveHash branch above so
        // both Safe surfaces handle ERC-20 attribution consistently.
        let inner_meta = safe_inner_meta(
            erc20,
            exec.decoded.operation,
            &exec.decoded.to,
            exec.decoded.data,
        );
        return super::safe_display::render_safe_exec_pages(exec, None, inner_meta, resolver);
    }
    if erc7730.is_some() {
        match render_verified_erc7730_two_pass(
            tx,
            inner_data,
            erc7730,
            erc7730_set,
            expected_nested,
            erc20,
            resolver,
            device_signer,
            transcript_proof,
        ) {
            Ok(pages) => return Ok(pages),
            Err(error) => return refuse_verified_erc7730(error),
        }
    }
    // A Merkle root authenticates a supplied descriptor but cannot, by itself,
    // reveal that a hostile companion omitted one. The firmware-pinned known-
    // call filter supplies that missing non-optional membership signal. Once a
    // registry-declared `(chain, target, selector)` is known, absence/malformed binding
    // is a hard refusal rather than permission to downgrade to ERC-20, typed-
    // call, or blind-sign pages. Higher-priority native Safe/CoW decoders have
    // already returned above and remain valid without an ERC-7730 trailer.
    {
        // Route the proof unconditionally. The old outer `if let` was itself a
        // one-instruction permission branch: skipping it bypassed every A/B
        // gate below. A missing target and short calldata are represented
        // canonically and proven just like any other tuple; Bloom false
        // positives only refuse, which is safe.
        let mut target = [0u8; 20];
        let mut target_present = 0u32;
        // SAFETY: unique local. Start from a materialized FAIL state so a
        // skipped `Some` route cannot inherit a permissive stack value.
        unsafe {
            core::ptr::write_volatile(&mut target_present, crate::fi::FAIL_SENTINEL);
        }
        if let Some(actual) = tx.to.as_ref() {
            target.copy_from_slice(actual);
            // SAFETY: unique live local; volatile publication makes a skipped
            // target-copy route observable in both final permission gates.
            unsafe {
                core::ptr::write_volatile(&mut target_present, crate::fi::OK_SENTINEL);
            }
        }
        let mut selector = [0u8; 4];
        let selector_len = core::cmp::min(inner_data.len(), selector.len());
        selector[..selector_len].copy_from_slice(&inner_data[..selector_len]);
        // Permission to fall through is the security-sensitive direction.
        // The verdict slot starts FAIL and the CFI counter belongs to this
        // caller but is bumped inside the non-inlined proof. Skipping the whole
        // call therefore cannot turn attacker-controlled argument registers
        // into an accidental OK return value.
        let mut unknown_verdict_slot = 0u32;
        // SAFETY: unique local. The volatile FAIL materialization is
        // load-bearing: an ordinary initialization is dead on the normal path
        // (the callee overwrites it) and LTO could erase it, leaving stale
        // stack data if a fault skips the call.
        unsafe {
            core::ptr::write_volatile(&mut unknown_verdict_slot, crate::fi::FAIL_SENTINEL);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut unknown_cfi = crate::fi::CfiCounter::new();
        crate::tx::erc7730::prove_unknown_contract_call(
            tx.chain_id,
            &target,
            &selector,
            &mut unknown_verdict_slot,
            &mut unknown_cfi,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // Gate A independently materializes both permission proofs. Gate B
        // repeats the volatile read and caller-CFI check after a randomized
        // gap, so a skipped reject branch still lands at another reject.
        // SAFETY: local was initialized above and remains live; the proof's
        // unique mutable borrow ended before this independent readback.
        let unknown_verdict_a = unsafe { core::ptr::read_volatile(&unknown_verdict_slot) };
        let unknown_cfi_verdict_a =
            unknown_cfi.check_into_sentinel(crate::tx::erc7730::CFI_KNOWN_EXPECTED);
        let route_a = match tx.to.as_ref() {
            Some(actual) => {
                // SAFETY: initialized above and independently materialized at
                // the gate that consumes it.
                let present = unsafe { core::ptr::read_volatile(&target_present) };
                present == crate::fi::OK_SENTINEL
                    && actual == &target
                    && selector[..selector_len] == inner_data[..selector_len]
            }
            None => {
                // Contract creation has no catalogue target. It still queries
                // the all-zero sentinel tuple so a Bloom collision refuses.
                target == [0u8; 20] && selector[..selector_len] == inner_data[..selector_len]
            }
        };
        let unknown_all_ok_a = unknown_verdict_a == crate::fi::OK_SENTINEL
            && unknown_cfi_verdict_a == crate::fi::OK_SENTINEL
            && route_a;
        crate::fi::scrub_sentinel_register();
        let unknown_gate_a =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_a));
        crate::fi::scrub_sentinel_register();
        if unknown_gate_a != crate::fi::OK_SENTINEL {
            secure_log!("erc7730 clear-sign refused: known call omitted descriptor");
            crate::ui::show_status("Sign refused", "7730 proof needed");
            return Err(());
        }
        crate::fi::wait_random();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: same live local, independently re-read after the randomized
        // gap instead of reusing gate A's cached evidence.
        let unknown_verdict_b = unsafe { core::ptr::read_volatile(&unknown_verdict_slot) };
        let unknown_cfi_verdict_b =
            unknown_cfi.check_into_sentinel(crate::tx::erc7730::CFI_KNOWN_EXPECTED);
        let route_b = match tx.to.as_ref() {
            Some(actual) => {
                // SAFETY: same initialized local, re-read after the gap.
                let present = unsafe { core::ptr::read_volatile(&target_present) };
                present == crate::fi::OK_SENTINEL
                    && actual == &target
                    && selector[..selector_len] == inner_data[..selector_len]
            }
            None => target == [0u8; 20] && selector[..selector_len] == inner_data[..selector_len],
        };
        let unknown_all_ok_b = unknown_verdict_b == crate::fi::OK_SENTINEL
            && unknown_cfi_verdict_b == crate::fi::OK_SENTINEL
            && route_b;
        crate::fi::scrub_sentinel_register();
        let unknown_gate_b =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(unknown_all_ok_b));
        crate::fi::scrub_sentinel_register();
        if unknown_gate_b != crate::fi::OK_SENTINEL {
            secure_log!("erc7730 clear-sign refused: known call omitted descriptor");
            crate::ui::show_status("Sign refused", "7730 proof needed");
            return Err(());
        }
    }
    if inner_data.is_empty() {
        return Ok(super::value_transfer::render_pages(tx, resolver));
    }
    match crate::erc20::calldata::parse_erc20_calldata(inner_data) {
        Some(call) => {
            // WYSIWYS per-flow address-match gate (audit 2026-06-28 —
            // `v1_ms` metadata mis-attribution).
            //
            // This is the DIRECT ERC-20 branch: control only reaches here
            // when NO Safe / CoW / v1 context was verified (every Safe
            // surface returned above through its own `safe_inner_meta`
            // re-match). On a direct call the wallet itself is `msg.sender`
            // and `tx.to` IS the token contract, so the ONLY legitimate
            // attribution is `meta.contract == tx.to`.
            //
            // `erc20` has only Merkle+chain authority here. Safe branches
            // returned above after matching verified Safe execution facts;
            // direct ERC-7730 returned after matching its signed tokenPath.
            // Neither grants authority to this direct ERC-20 branch. Re-check
            // the outer contract and fall back to the raw unknown-token view
            // on mismatch.
            let matched = erc20.filter(|meta| {
                super::value_page::direct_erc20_meta_matches(&meta.contract, tx.to.as_ref())
            });
            Ok(match matched {
                Some(meta) => {
                    let amount = match &call {
                        crate::erc20::calldata::Erc20Call::Transfer { amount, .. }
                        | crate::erc20::calldata::Erc20Call::TransferFrom { amount, .. }
                        | crate::erc20::calldata::Erc20Call::Approve { amount, .. } => amount,
                    };
                    let unlimited_approve =
                        matches!(&call, crate::erc20::calldata::Erc20Call::Approve { .. })
                            && crate::erc20::calldata::is_unlimited_amount(amount);
                    if !unlimited_approve
                        && !super::primitives::token_amount_is_exactly_renderable(amount, meta)
                    {
                        return Err(());
                    }
                    super::erc20_known::render_erc20_known_pages(tx, &call, meta, resolver)
                }
                None => super::erc20_unknown::render_erc20_unknown_pages(tx, &call, resolver),
            })
        }
        // The verified selector → text-sig mapping (if any) is only
        // consulted when nothing else has decoded the calldata. Phase 2
        // first tries to ABI-decode the calldata against the verified
        // type list; on any parse / shape failure (or any type the
        // first cut declines) we fall through to the Phase 1 BLIND
        // SIGN flow, which itself surfaces the FUNCTION page above
        // the warning header.
        None => {
            if let Some(meta) = selector {
                if let Some(pages) =
                    super::typed_call::try_render_typed_call(tx, inner_data, meta, resolver)
                {
                    return Ok(pages);
                }
            }
            Ok(super::blind_sign::render_blind_sign_pages(
                tx, inner_data, selector, resolver,
            ))
        }
    }
}

/// Apply the one permitted policy to a render error from a descriptor that has
/// already verified and bound to this request: hard refusal.  Keeping this as
/// one executable function lets host tests enumerate every [`RenderErr`]
/// variant without manufacturing a descriptor fixture for each diagnostic.
fn refuse_verified_erc7730(
    error: crate::tx::erc7730_render::RenderErr,
) -> Result<super::Pages, ()> {
    use crate::tx::erc7730_render::RenderErr;
    use pqsigner_erc7730::render::VerifiedDescriptorErrorPolicy;

    match error.verified_descriptor_policy() {
        VerifiedDescriptorErrorPolicy::HardRefuse => {}
    }

    match error {
        RenderErr::Reject(msg) => {
            // `msg` is a developer trace tag (e.g. "7730 nested blob
            // trailing") — not user-facing text, and several exceed the
            // 16-col row. Keep the tag in the debug log and refuse: once a
            // descriptor has verified and bound to this transaction, a
            // renderer failure is an integrity failure, not permission to
            // downgrade to a weaker typed/blind-sign interpretation.
            // Bare invocation — `secure_log!` is a `macro_rules!` in
            // main.rs without `#[macro_export]`, textually scoped: the
            // `crate::secure_log!` path form fails E0433 under
            // `debug-log` (only the cfg'd-out no-op arm is suggested).
            secure_log!("erc7730 clear-sign refused: {}", msg);
            let _ = msg;
            crate::ui::show_status("Sign refused", "clear-sign failed");
        }
        RenderErr::NoFormat => {
            secure_log!("erc7730 clear-sign refused: no format");
            crate::ui::show_status("Sign refused", "clear-sign format");
        }
        RenderErr::PageBudget => {
            secure_log!("erc7730 clear-sign refused: page budget");
            crate::ui::show_status("Sign refused", "clear-sign pages");
        }
    }
    Err(())
}

#[cfg(test)]
mod semantic_guard_tests {
    use super::{legacy_fee_preflight_required, refuse_verified_erc7730};
    use crate::tx::erc7730_render::RenderErr;

    #[test]
    fn every_verified_descriptor_render_error_is_fatal() {
        for error in [
            RenderErr::Reject("semantic guard"),
            RenderErr::NoFormat,
            RenderErr::PageBudget,
        ] {
            assert!(
                refuse_verified_erc7730(error).is_err(),
                "verified descriptor errors must never enter a weaker renderer"
            );
        }
    }

    #[test]
    fn fee_preflight_follows_the_winning_route() {
        assert!(
            !legacy_fee_preflight_required(false, false, false, true),
            "a direct authenticated ERC-7730 route owns its exact fee envelope"
        );
        assert!(legacy_fee_preflight_required(false, false, false, false));
        assert!(
            legacy_fee_preflight_required(true, false, false, true),
            "native CoW outranks ERC-7730 and uses the legacy suffix"
        );
        assert!(legacy_fee_preflight_required(false, true, false, true));
        assert!(legacy_fee_preflight_required(false, false, true, true));
    }
}

#[cfg(test)]
mod transcript_proof_tests {
    use super::*;

    fn sample_pages() -> super::super::Pages {
        let mut pages = super::super::Pages::with_len(3);
        pages.buf[0][0].copy_from_slice(b"** DEV BUILD ** ");
        pages.buf[0][1][..10].copy_from_slice(b"Unattested");
        pages.buf[1][0][..13].copy_from_slice(b"Static intent");
        for (row_index, row) in pages.buf[2].iter_mut().enumerate() {
            for (col_index, byte) in row.iter_mut().enumerate() {
                *byte = b'A'
                    + ((row_index * pqsigner_erc7730::display::DISPLAY_COLS + col_index) % 26)
                        as u8;
            }
        }
        pages
    }

    fn completed_proof(state: u32) -> (Erc7730TranscriptProof, super::super::Pages) {
        let mut first_pages = sample_pages();
        let first = pqsigner_erc7730::display::render::ContractTranscriptReceipt::from_pages(
            state,
            &first_pages,
        )
        .unwrap();
        let mut proof = Erc7730TranscriptProof::new();
        proof.fail_initialize();
        proof.expected_state = state;
        proof.cfi.bump(INTENT_CFI_REQUIREMENT_CLASSIFIED);
        proof.record_first_receipt(&first, &first_pages).unwrap();
        proof.poison_for_second_render(&mut first_pages).unwrap();

        let second_pages = sample_pages();
        let second = pqsigner_erc7730::display::render::ContractTranscriptReceipt::from_pages(
            state,
            &second_pages,
        )
        .unwrap();
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proof.verify_second_render(&second, &second_pages, &mut verdict);
        assert_eq!(verdict, crate::fi::OK_SENTINEL);
        (proof, second_pages)
    }

    #[test]
    fn distinct_no_erc7730_route_requires_its_own_cfi_completion() {
        let pages = sample_pages();
        let mut proof = Erc7730TranscriptProof::new();
        proof.fail_initialize();
        proof.expected_state = INTENT_REQUIREMENT_NONE;
        proof.cfi.bump(INTENT_CFI_REQUIREMENT_CLASSIFIED);
        assert_ne!(proof.proof(&pages), crate::fi::OK_SENTINEL);
        proof.finish_route().unwrap();
        assert_eq!(proof.proof(&pages), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn static_and_interpolated_transcripts_bind_every_page_byte() {
        for state in [
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC,
            pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED,
        ] {
            let (proof, mut pages) = completed_proof(state);
            assert_eq!(proof.proof(&pages), crate::fi::OK_SENTINEL);

            let protected = pages.len;
            for page in 0..protected {
                let original = pages.buf[page];
                for row in 0..pqsigner_erc7730::display::DISPLAY_ROWS {
                    for col in 0..pqsigner_erc7730::display::DISPLAY_COLS {
                        pages.buf[page] = original;
                        pages.buf[page][row][col] ^= 1;
                        assert_ne!(
                            proof.proof(&pages),
                            crate::fi::OK_SENTINEL,
                            "state={state:#x}, page={page}, row={row}, col={col}"
                        );
                    }
                }
                pages.buf[page] = original;
            }
        }
    }

    #[test]
    fn suffix_count_state_and_range_are_exact() {
        let (mut proof, mut pages) =
            completed_proof(pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC);
        let suffix = pages.push_blank().unwrap();
        pages.buf[suffix][0][..6].copy_from_slice(b"suffix");
        assert_eq!(proof.proof(&pages), crate::fi::OK_SENTINEL);

        pages.len -= 2;
        assert_ne!(proof.proof(&pages), crate::fi::OK_SENTINEL);
        pages.len += 2;
        proof.expected_state = pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED;
        assert_ne!(proof.proof(&pages), crate::fi::OK_SENTINEL);
        proof.expected_state = pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC;
        proof.shift_index(1).unwrap();
        assert_ne!(proof.proof(&pages), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn common_mode_first_pass_corruption_cannot_authorize_clean_second_render() {
        let state = pqsigner_erc7730::display::render::INTENT_PUBLICATION_STATIC;
        let mut first_pages = sample_pages();
        first_pages.buf[2][3][15] ^= 1;
        let first = pqsigner_erc7730::display::render::ContractTranscriptReceipt::from_pages(
            state,
            &first_pages,
        )
        .unwrap();
        let mut proof = Erc7730TranscriptProof::new();
        proof.fail_initialize();
        proof.expected_state = state;
        proof.cfi.bump(INTENT_CFI_REQUIREMENT_CLASSIFIED);
        proof.record_first_receipt(&first, &first_pages).unwrap();
        proof.poison_for_second_render(&mut first_pages).unwrap();
        assert!(first_pages.is_transcript_poisoned());

        let second_pages = sample_pages();
        let second = pqsigner_erc7730::display::render::ContractTranscriptReceipt::from_pages(
            state,
            &second_pages,
        )
        .unwrap();
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proof.verify_second_render(&second, &second_pages, &mut verdict);
        assert_eq!(verdict, crate::fi::FAIL_SENTINEL);
    }

    #[test]
    fn batch_prefix_shift_moves_the_full_transcript_exactly_once() {
        let (proof, inner) =
            completed_proof(pqsigner_erc7730::display::render::INTENT_PUBLICATION_INTERPOLATED);
        let mut carrier = DispatchPageProofs::new();
        carrier.erc7730_transcript = proof;
        carrier.native_prior_len = inner.len;

        let mut wrapped = super::super::Pages::with_len(inner.len + 1);
        wrapped.buf[0][0][..12].copy_from_slice(b"Batch member");
        for index in 0..inner.len {
            wrapped.buf[index + 1] = inner.buf[index];
        }
        assert_ne!(
            carrier.erc7730_transcript.proof(&wrapped),
            crate::fi::OK_SENTINEL
        );
        carrier.shift_indices(1).unwrap();
        assert_eq!(
            carrier.erc7730_transcript.proof(&wrapped),
            crate::fi::OK_SENTINEL
        );
        carrier.shift_indices(1).unwrap();
        assert_ne!(
            carrier.erc7730_transcript.proof(&wrapped),
            crate::fi::OK_SENTINEL
        );
    }
}

/// Inner `to` decoded from a verified `safe_v1` canonical.
/// The ERC-20 metadata the Safe painters receive from the dispatcher ladder:
/// chain-bound to the outer transaction, then address-matched to the
/// verified inner call / multiSend records. Shared with the pixel-UI screen
/// emitter (`px_lift`) so both painters see the same capability; the
/// renderer still re-matches per record before applying it.
pub(crate) fn safe_route_meta<'m>(
    tx_chain_id: u64,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    erc20: Option<&'m crate::erc20::bundle::Erc20Metadata<'m>>,
) -> Option<&'m crate::erc20::bundle::Erc20Metadata<'m>> {
    let erc20 = erc20.filter(|meta| meta.chain_id == tx_chain_id);
    if let Some(safe) = safe_v1 {
        return safe_inner_meta(
            erc20,
            safe.canonical[sphincs_tz_shared::SAFE_OFF_OPERATION],
            &safe_v1_inner_to(safe),
            safe.raw_data,
        );
    }
    if let Some(exec) = safe_exec {
        return safe_inner_meta(erc20, exec.decoded.operation, &exec.decoded.to, exec.decoded.data);
    }
    None
}

fn safe_v1_inner_to(safe: &crate::tx::eip712::safe::VerifiedSafeV1<'_>) -> [u8; 20] {
    let mut t = [0u8; 20];
    t.copy_from_slice(
        &safe.canonical[sphincs_tz_shared::SAFE_OFF_TO..sphincs_tz_shared::SAFE_OFF_TO + 20],
    );
    t
}

/// Address-match filter for ERC-20 metadata on the Safe surfaces: the bundle
/// applies when its contract is the verified inner `to`, or when one of the
/// records in a verified pinned `MultiSendCallOnly` delegatecall targets it.
/// The renderer still re-matches per record before applying the metadata.
fn safe_inner_meta<'m>(
    erc20: Option<&'m crate::erc20::bundle::Erc20Metadata<'m>>,
    operation: u8,
    inner_to: &[u8; 20],
    raw_data: &[u8],
) -> Option<&'m crate::erc20::bundle::Erc20Metadata<'m>> {
    erc20.filter(|m| {
        crate::tx::eip712::safe::erc20_metadata_matches_verified_safe_call(
            operation,
            inner_to,
            raw_data,
            &m.contract,
        )
    })
}
