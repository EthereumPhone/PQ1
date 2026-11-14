//! ERC-7730 clear-signing renderer — **re-export shim**.
//!
//! The renderer (dispatch → field iteration → `Pages` emission: the former
//! `mod.rs` + `formatters.rs` + `intent.rs` + `nested.rs` + `calldata_nested.rs`
//! in this directory) moved into `pqsigner_erc7730::display::render` so the full
//! per-`FormatOp` dispatch can be host-linked and fuzzed — see
//! `docs/erc7730-renderer-fuzzability.md` and
//! `fuzz/fuzz_targets/erc7730_render_dispatch.rs`. It renders over the shared
//! host `Pages` (`crate::tx::display::Pages`, re-exported from the same crate).
//!
//! Production exposes checked two-pass EIP-712 wrappers. The one-pass contract
//! primitive is visible only to its sibling dispatcher; raw EIP-712 primitives
//! stay private to this shim. Allocating conveniences remain test-only.

use pqsigner_erc7730::display::render::{
    render_erc7730_eip712_pages_into, render_erc7730_eip712_pages_v3_into,
    render_erc7730_pages_with_signer_into as render_contract_pass_into_raw,
    render_erc7730_proof_set_pages_with_signer_into as render_contract_proof_set_pass_into_raw,
    ContractTranscriptReceipt, INTENT_PUBLICATION_EIP712_STATIC,
};

#[cfg(test)]
#[allow(unused_imports)]
pub use pqsigner_erc7730::display::render::{
    render_erc7730_eip712_pages, render_erc7730_eip712_pages_v3, render_erc7730_pages,
    render_erc7730_pages_with_signer, render_erc7730_pages_with_signer_checked,
};

/// Dispatcher-owned contract pass. The raw host-crate `*_into` symbol is not
/// re-exported from the secure shim, so production callers cannot name a
/// one-pass contract renderer outside the checked dispatcher protocol.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn render_contract_pass_into<'ir>(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    descriptor: &'ir crate::tx::erc7730::VerifiedDescriptor<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
    device_signer: &[u8; 20],
    pages: &mut super::Pages,
) -> Result<ContractTranscriptReceipt, crate::tx::erc7730_render::RenderErr> {
    render_contract_pass_into_raw(
        tx,
        inner_data,
        descriptor,
        erc20,
        resolver,
        device_signer,
        pages,
    )
}

/// Dispatcher-owned proof-set contract pass. The expected nested binding was
/// independently derived and FI-proven by the secure handler; the renderer
/// re-derives and exact-matches it before publishing any page.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub(super) fn render_contract_proof_set_pass_into<'ir>(
    tx: &crate::tx::eip1559::Eip1559Tx,
    inner_data: &[u8],
    set: &crate::tx::erc7730::VerifiedProofSet<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
    device_signer: &[u8; 20],
    expected_nested: Option<&crate::tx::erc7730::NestedCallBinding>,
    pages: &mut super::Pages,
) -> Result<ContractTranscriptReceipt, crate::tx::erc7730_render::RenderErr> {
    render_contract_proof_set_pass_into_raw(
        tx,
        inner_data,
        set,
        erc20,
        resolver,
        device_signer,
        expected_nested,
        pages,
    )
}

const EIP712_TRANSCRIPT_CFI_FAIL_INITIALIZED: u32 = 0x31A6_D4E9;
const EIP712_TRANSCRIPT_CFI_FIRST_RECORDED: u32 = 0xC86B_2D17;
const EIP712_TRANSCRIPT_CFI_BUFFER_RESET: u32 = 0x5D92_E8C3;
const EIP712_TRANSCRIPT_CFI_SECOND_VERIFIED: u32 = 0xA26D_173C;
const EIP712_TRANSCRIPT_CFI_EXPECTED: u32 = crate::cfi_expected!(
    EIP712_TRANSCRIPT_CFI_FAIL_INITIALIZED,
    EIP712_TRANSCRIPT_CFI_FIRST_RECORDED,
    EIP712_TRANSCRIPT_CFI_BUFFER_RESET,
    EIP712_TRANSCRIPT_CFI_SECOND_VERIFIED,
);

/// Proof carried from the checked EIP-712 renderer to the immediate
/// pre-confirm boundary after the handler appends its ERC-8213 fingerprint.
pub(crate) struct Eip712TranscriptProof {
    receipt: ContractTranscriptReceipt,
    cfi: crate::fi::CfiCounter,
}

impl Eip712TranscriptProof {
    const fn new() -> Self {
        Self {
            receipt: ContractTranscriptReceipt::unpublished(),
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    #[inline(never)]
    fn fail_initialize(&mut self) {
        // SAFETY: unique mutable borrow. The volatile fail receipt survives a
        // skipped later publication under LTO.
        unsafe {
            core::ptr::write_volatile(&mut self.receipt, ContractTranscriptReceipt::unpublished());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(EIP712_TRANSCRIPT_CFI_FAIL_INITIALIZED);
    }

    #[inline(never)]
    fn record_first(
        &mut self,
        receipt: &ContractTranscriptReceipt,
        pages: &super::Pages,
    ) -> Result<(), ()> {
        let valid = receipt.state_code() == INTENT_PUBLICATION_EIP712_STATIC
            && receipt.range_matches(pages, 0);
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(valid))
            != crate::fi::OK_SENTINEL
        {
            return Err(());
        }
        // SAFETY: unique mutable borrow; a skipped publication retains the
        // fail receipt established above.
        unsafe { core::ptr::write_volatile(&mut self.receipt, *receipt) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(EIP712_TRANSCRIPT_CFI_FIRST_RECORDED);
        Ok(())
    }

    #[inline(never)]
    fn poison_for_second(&mut self, pages: &mut super::Pages) -> Result<(), ()> {
        pages.volatile_poison_and_reset();
        let poisoned = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(pages.is_transcript_poisoned())
        });
        if poisoned != crate::fi::OK_SENTINEL {
            return Err(());
        }
        self.cfi.bump(EIP712_TRANSCRIPT_CFI_BUFFER_RESET);
        Ok(())
    }

    #[inline(never)]
    fn verify_second(
        &mut self,
        second: &ContractTranscriptReceipt,
        pages: &super::Pages,
        verdict_out: &mut u32,
    ) {
        let valid = self.receipt.exact_match(second)
            && second.state_code() == INTENT_PUBLICATION_EIP712_STATIC
            && second.range_matches(pages, 0);
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(valid))
            != crate::fi::OK_SENTINEL
        {
            return;
        }
        self.cfi.bump(EIP712_TRANSCRIPT_CFI_SECOND_VERIFIED);
        let verdict = self.proof(pages);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: unique caller-owned slot, fail-initialized before this call.
        unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    }

    #[inline(never)]
    fn proof(&self, pages: &super::Pages) -> u32 {
        let cfi = self.cfi.check_into_sentinel(EIP712_TRANSCRIPT_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let content = self.receipt.state_code() == INTENT_PUBLICATION_EIP712_STATIC
            && self.receipt.range_matches(pages, 0);
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(cfi == crate::fi::OK_SENTINEL) && core::hint::black_box(content)
        })
    }

    /// Recheck the original renderer-owned range after all handler-owned
    /// suffixes and publish a verdict into the caller's fail-initialized slot.
    #[inline(never)]
    pub(crate) fn final_set_proof(&self, pages: &super::Pages, verdict_out: &mut u32) {
        let verdict = self.proof(pages);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: unique caller-owned output slot; the caller materializes FAIL
        // before invoking this final confirmation-boundary proof.
        unsafe { core::ptr::write_volatile(verdict_out, verdict) };
    }
}

#[derive(Clone, Copy)]
enum Eip712RenderMode<'a> {
    V2,
    V3(&'a [u8]),
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn render_pass<'ir>(
    mode: Eip712RenderMode<'_>,
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir crate::tx::erc7730::VerifiedDescriptor<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
    pages: &mut super::Pages,
) -> Result<ContractTranscriptReceipt, crate::tx::erc7730_render::RenderErr> {
    match mode {
        Eip712RenderMode::V2 => render_erc7730_eip712_pages_into(
            chain_id,
            verifying_contract,
            primary_type_hash,
            encoded_data,
            descriptor,
            erc20,
            resolver,
            pages,
        ),
        Eip712RenderMode::V3(nested_blob) => render_erc7730_eip712_pages_v3_into(
            chain_id,
            verifying_contract,
            primary_type_hash,
            encoded_data,
            nested_blob,
            descriptor,
            erc20,
            resolver,
            pages,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn render_checked_two_pass<'ir>(
    mode: Eip712RenderMode<'_>,
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir crate::tx::erc7730::VerifiedDescriptor<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<(super::Pages, Eip712TranscriptProof), crate::tx::erc7730_render::RenderErr> {
    use crate::tx::erc7730_render::RenderErr;

    let mut pages = super::Pages::with_len(0);
    let mut proof = Eip712TranscriptProof::new();
    proof.fail_initialize();
    let first = render_pass(
        mode,
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        descriptor,
        erc20,
        resolver,
        &mut pages,
    )?;
    proof
        .record_first(&first, &pages)
        .map_err(|_| RenderErr::Reject("7730 eip712 first transcript proof"))?;
    proof
        .poison_for_second(&mut pages)
        .map_err(|_| RenderErr::Reject("7730 eip712 transcript reset proof"))?;
    crate::fi::wait_random();
    let second = render_pass(
        mode,
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        descriptor,
        erc20,
        resolver,
        &mut pages,
    )?;

    let mut immediate_verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique live local. Skipping verification leaves materialized
    // failure rather than stale register authority.
    unsafe { core::ptr::write_volatile(&mut immediate_verdict, crate::fi::FAIL_SENTINEL) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    proof.verify_second(&second, &pages, &mut immediate_verdict);
    // SAFETY: same live local, independently read on each side of the delay.
    let verdict_a = unsafe { core::ptr::read_volatile(&immediate_verdict) };
    crate::fi::wait_random();
    // SAFETY: second volatile read of the same live local after random delay.
    let verdict_b = unsafe { core::ptr::read_volatile(&immediate_verdict) };
    crate::fi::scrub_sentinel_register();
    if verdict_a != crate::fi::OK_SENTINEL || verdict_b != crate::fi::OK_SENTINEL {
        return Err(RenderErr::Reject("7730 eip712 second transcript mismatch"));
    }
    Ok((pages, proof))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_erc7730_eip712_pages_checked<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    descriptor: &'ir crate::tx::erc7730::VerifiedDescriptor<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<(super::Pages, Eip712TranscriptProof), crate::tx::erc7730_render::RenderErr> {
    render_checked_two_pass(
        Eip712RenderMode::V2,
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        descriptor,
        erc20,
        resolver,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_erc7730_eip712_pages_v3_checked<'ir>(
    chain_id: u64,
    verifying_contract: &[u8; 20],
    primary_type_hash: &[u8; 32],
    encoded_data: &[u8],
    nested_blob: &[u8],
    descriptor: &'ir crate::tx::erc7730::VerifiedDescriptor<'ir>,
    erc20: crate::erc20::set::Erc20Scope<'_, '_>,
    resolver: &crate::names::NameResolver<'_>,
) -> Result<(super::Pages, Eip712TranscriptProof), crate::tx::erc7730_render::RenderErr> {
    render_checked_two_pass(
        Eip712RenderMode::V3(nested_blob),
        chain_id,
        verifying_contract,
        primary_type_hash,
        encoded_data,
        descriptor,
        erc20,
        resolver,
    )
}
