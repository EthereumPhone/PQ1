//! UserOperation deployment-mode trusted-display binding.
//!
//! `FLAG_INCLUDE_INIT_CODE` changes both the released response and the Type-2
//! signed preimage, and also authorizes a bootstrap-key factory signature.
//! The flag therefore cannot remain an invisible companion-controlled mode.
//! This module gives both single and batch handlers one exact consent page and
//! one fail-initialized receipt carried across the confirmation boundary.
//!
//! The final initCode contains the randomized C10 factory signature, so its
//! byte digest cannot exist before the user authorizes that signature.  The
//! pre-confirm page instead commits visibly to the exact factory, while the
//! receipt binds the deployment request, chain, account, sender, slot, and
//! Type-2 nonce.  After consent, [`deployment_output_binding_proof`] proves
//! that the emitted initCode starts with that factory and that the digest fed
//! into Type 2 is the digest of those exact emitted bytes.

use super::primitives::write_addr_full;
use super::Pages;
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};
use sha2::{Digest, Sha256};

type DeploymentPage = [[u8; DISPLAY_COLS]; DISPLAY_ROWS];

pub(crate) const DEPLOYMENT_MODE_PAGES: usize = 1;

const DEPLOYMENT_PAGE_CFI_STEP: u32 = 0xD310_7A61;
pub(crate) const DEPLOYMENT_PAGE_CFI_EXPECTED: u32 = crate::cfi_expected!(DEPLOYMENT_PAGE_CFI_STEP);

const DEPLOYMENT_CONFIRM_CFI_STEP: u32 = 0xD310_C0F1;
const DEPLOYMENT_CONFIRM_FAIL_DIGEST: [u8; 32] = [0xD3; 32];
const DEPLOYMENT_CONFIRM_DOMAIN: &[u8] = b"PQSigner/deployment-confirm/v1";

/// Exact public deployment context authorized by one trusted confirmation.
#[derive(Clone, Copy)]
pub(crate) struct DeploymentConfirmContext {
    requested: bool,
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    type2_nonce: [u8; 32],
    factory: [u8; 20],
}

impl DeploymentConfirmContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        requested: bool,
        chain_id: u64,
        account_index: u32,
        slot_index: u32,
        sender: [u8; 20],
        type2_nonce: [u8; 32],
        factory: [u8; 20],
    ) -> Self {
        Self {
            requested,
            chain_id,
            account_index,
            slot_index,
            sender,
            type2_nonce,
            factory,
        }
    }

    /// Whether the confirmation covers an `initCode` deployment.
    pub(crate) fn requested(&self) -> bool {
        self.requested
    }

    /// The factory the deployment page names.
    pub(crate) fn factory(&self) -> &[u8; 20] {
        &self.factory
    }

    fn receipt_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DEPLOYMENT_CONFIRM_DOMAIN);
        h.update([u8::from(self.requested)]);
        h.update(self.chain_id.to_be_bytes());
        h.update(self.account_index.to_be_bytes());
        h.update(self.slot_index.to_be_bytes());
        h.update(self.sender);
        h.update(self.type2_nonce);
        h.update(self.factory);
        h.finalize().into()
    }
}

/// Fail-initialized authority receipt carried from the affirmative UI branch
/// to both post-confirm signing boundaries.
pub(crate) struct DeploymentConfirmReceipt {
    confirmed: u32,
    context_digest: [u8; 32],
    cfi: crate::fi::CfiCounter,
}

impl DeploymentConfirmReceipt {
    pub(crate) const fn new() -> Self {
        Self {
            confirmed: 0,
            context_digest: DEPLOYMENT_CONFIRM_FAIL_DIGEST,
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        // SAFETY: every field is uniquely borrowed and has no destructor.
        unsafe {
            core::ptr::write_volatile(&mut self.confirmed, 0);
            core::ptr::write_volatile(&mut self.context_digest, DEPLOYMENT_CONFIRM_FAIL_DIGEST);
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Publish exactly one receipt after both the confirmed result and its
    /// affirmative FI sentinel have been checked by the caller.
    #[inline(never)]
    pub(crate) fn record_confirmed(
        &mut self,
        context: &DeploymentConfirmContext,
    ) -> Result<(), ()> {
        // SAFETY: unique live receipt; volatile state stays observable under
        // LTO independently of the CFI accumulator.
        let current = unsafe { core::ptr::read_volatile(&self.confirmed) };
        if current != 0 {
            return Err(());
        }
        let digest = context.receipt_digest();
        unsafe {
            core::ptr::write_volatile(&mut self.context_digest, digest);
            core::ptr::write_volatile(&mut self.confirmed, 1);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(DEPLOYMENT_CONFIRM_CFI_STEP);
        Ok(())
    }

    /// Reconstruct the expected context and prove exactly one affirmative
    /// publication.  Callers use spatially separate checks before the
    /// bootstrap factory signature and before the Type-2 signature.
    #[inline(never)]
    pub(crate) fn completion_proof(&self, context: &DeploymentConfirmContext) -> u32 {
        // SAFETY: immutable live receipt, sampled twice around a randomized
        // gap so one corrupt load cannot forge the authority state.
        let confirmed_a = unsafe { core::ptr::read_volatile(&self.confirmed) };
        let digest_a = unsafe { core::ptr::read_volatile(&self.context_digest) };
        crate::fi::wait_random();
        let confirmed_b = unsafe { core::ptr::read_volatile(&self.confirmed) };
        let digest_b = unsafe { core::ptr::read_volatile(&self.context_digest) };

        let expected = context.receipt_digest();
        let mut diff_a = 0u8;
        let mut diff_b = 0u8;
        for i in 0..expected.len() {
            diff_a |= digest_a[i] ^ expected[i];
            diff_b |= digest_b[i] ^ expected[i];
        }
        let expected_cfi =
            crate::fi::CfiCounter::INIT_VALUE.wrapping_add(DEPLOYMENT_CONFIRM_CFI_STEP);
        crate::fi::scrub_sentinel_register();
        let cfi_verdict = self.cfi.check_into_sentinel(expected_cfi);
        let all_ok = confirmed_a == 1
            && confirmed_b == 1
            && diff_a == 0
            && diff_b == 0
            && cfi_verdict == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(all_ok))
    }
}

/// Append the exact deployment/factory page, or publish an exact completed
/// skip when deployment was not requested.
#[inline(never)]
pub(crate) fn enforce_deployment_page(
    pages: &mut Pages,
    context: &DeploymentConfirmContext,
    cfi: &mut crate::fi::CfiCounter,
) -> Result<(), ()> {
    crate::fi::scrub_sentinel_register();
    let may_skip =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(!context.requested));
    if may_skip == crate::fi::OK_SENTINEL {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        cfi.bump(DEPLOYMENT_PAGE_CFI_STEP);
        return Ok(());
    }

    let page = build_deployment_page(&context.factory);
    let index = pages.push_blank()?;
    pages.buf[index] = page;
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(DEPLOYMENT_PAGE_CFI_STEP);
    Ok(())
}

/// Exact insertion/completed-skip proof immediately after publication.
#[inline(never)]
pub(crate) fn deployment_page_proof(
    pages: &Pages,
    prior_len: usize,
    context: &DeploymentConfirmContext,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        deployment_page_set_matches(pages, prior_len, context, true)
    })
}

/// Independent final-set proof immediately before confirmation.
#[inline(never)]
pub(crate) fn deployment_final_set_proof(
    pages: &Pages,
    expected_index: usize,
    context: &DeploymentConfirmContext,
) -> u32 {
    crate::fi::check_true_into_sentinel(|| {
        deployment_page_set_matches(pages, expected_index, context, true)
    })
}

/// Bind the post-confirm output and Type-2 initCode digest to the exact mode
/// and factory that crossed the trusted-display boundary.
#[inline(never)]
pub(crate) fn deployment_output_binding_proof(
    context: &DeploymentConfirmContext,
    emit_init_code: bool,
    init_code: &[u8],
    type2_init_code_digest: &[u8; 32],
    empty_digest: &[u8; 32],
) -> u32 {
    let mut computed = *empty_digest;
    if context.requested {
        computed = Sha256::digest(init_code).into();
    }
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(context.requested) {
            core::hint::black_box(emit_init_code)
                && init_code.len() >= context.factory.len()
                && bytes_equal(&init_code[..context.factory.len()], &context.factory)
                && bytes_equal(&computed, type2_init_code_digest)
        } else {
            core::hint::black_box(!emit_init_code)
                && bytes_equal(type2_init_code_digest, empty_digest)
                && init_code.iter().all(|byte| *byte == 0)
        }
    })
}

pub(crate) fn build_deployment_page(factory: &[u8; 20]) -> DeploymentPage {
    let mut page = [[b' '; DISPLAY_COLS]; DISPLAY_ROWS];
    page[0][..15].copy_from_slice(b"DEPLOY FACTORY:");
    let [_label, first, second, third] = &mut page;
    write_addr_full(first, second, third, factory);
    page
}

fn deployment_page_set_matches(
    pages: &Pages,
    expected_index: usize,
    context: &DeploymentConfirmContext,
    require_final_len: bool,
) -> bool {
    let expected = build_deployment_page(&context.factory);
    if context.requested {
        let Some(end) = expected_index.checked_add(DEPLOYMENT_MODE_PAGES) else {
            return false;
        };
        if end > pages.len || (require_final_len && pages.len != end) {
            return false;
        }
        pages
            .as_slice()
            .get(expected_index)
            .is_some_and(|page| page_exact(page, &expected))
            && page_occurrences(pages, &expected) == 1
    } else {
        (!require_final_len || pages.len == expected_index)
            && page_occurrences(pages, &expected) == 0
    }
}

fn page_occurrences(pages: &Pages, expected: &DeploymentPage) -> usize {
    pages
        .as_slice()
        .iter()
        .filter(|page| page_exact(page, expected))
        .count()
}

fn page_exact(actual: &DeploymentPage, expected: &DeploymentPage) -> bool {
    let mut diff = 0u8;
    for row in 0..DISPLAY_ROWS {
        for col in 0..DISPLAY_COLS {
            diff |= actual[row][col] ^ expected[row][col];
        }
    }
    diff == 0
}

fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..left.len() {
        diff |= left[i] ^ right[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const FACTORY: [u8; 20] = [0x42; 20];
    const EMPTY: [u8; 32] = [0xE0; 32];

    fn context(requested: bool) -> DeploymentConfirmContext {
        DeploymentConfirmContext::new(requested, 1, 7, 0, [0x11; 20], [0x22; 32], FACTORY)
    }

    #[test]
    fn requested_mode_appends_exact_factory_page_and_proves_final_set() {
        let ctx = context(true);
        let mut pages = Pages::empty_with_len(0);
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_deployment_page(&mut pages, &ctx, &mut cfi).unwrap();
        assert_eq!(pages.len, 1);
        assert_eq!(
            cfi.check_into_sentinel(DEPLOYMENT_PAGE_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            deployment_page_proof(&pages, 0, &ctx),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            deployment_final_set_proof(&pages, 0, &ctx),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(&pages.buf[0][0][..15], b"DEPLOY FACTORY:");
    }

    #[test]
    fn disabled_mode_proves_exact_completed_skip() {
        let ctx = context(false);
        let mut pages = Pages::empty_with_len(0);
        let mut cfi = crate::fi::CfiCounter::new();
        enforce_deployment_page(&mut pages, &ctx, &mut cfi).unwrap();
        assert_eq!(pages.len, 0);
        assert_eq!(
            deployment_page_proof(&pages, 0, &ctx),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            deployment_final_set_proof(&pages, 0, &ctx),
            crate::fi::OK_SENTINEL
        );
    }

    #[test]
    fn receipt_fails_closed_and_is_context_specific() {
        let ctx = context(true);
        let other = DeploymentConfirmContext::new(true, 2, 7, 0, [0x11; 20], [0x22; 32], FACTORY);
        let mut receipt = DeploymentConfirmReceipt::new();
        receipt.fail_initialize();
        assert_ne!(receipt.completion_proof(&ctx), crate::fi::OK_SENTINEL);
        receipt.record_confirmed(&ctx).unwrap();
        assert_eq!(receipt.completion_proof(&ctx), crate::fi::OK_SENTINEL);
        assert_ne!(receipt.completion_proof(&other), crate::fi::OK_SENTINEL);
        assert!(receipt.record_confirmed(&ctx).is_err());
    }

    #[test]
    fn output_proof_binds_mode_factory_and_exact_digest() {
        let ctx = context(true);
        let mut init_code = [0u8; 96];
        init_code[..20].copy_from_slice(&FACTORY);
        let digest: [u8; 32] = Sha256::digest(init_code).into();
        assert_eq!(
            deployment_output_binding_proof(&ctx, true, &init_code, &digest, &EMPTY),
            crate::fi::OK_SENTINEL
        );
        init_code[0] ^= 1;
        assert_ne!(
            deployment_output_binding_proof(&ctx, true, &init_code, &digest, &EMPTY),
            crate::fi::OK_SENTINEL
        );

        let disabled = context(false);
        let zeros = [0u8; 96];
        assert_eq!(
            deployment_output_binding_proof(&disabled, false, &zeros, &EMPTY, &EMPTY),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            deployment_output_binding_proof(&disabled, true, &zeros, &EMPTY, &EMPTY),
            crate::fi::OK_SENTINEL
        );
    }
}
