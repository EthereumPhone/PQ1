//! Standalone "ROTATE SLOT?" confirm page for `FLAG_REGISTER_SLOT`.
//!
//! When the companion sets `FLAG_REGISTER_SLOT`, the firmware emits a
//! Type 1 (`addOwnerBytes`) UserOp alongside the user's Type 2. That
//! Type 1 silently consumes one of the wallet's `MAX_BOOTSTRAP_USES`
//! bootstrap budget items on chain — so a hostile companion that always
//! sets the flag can drain the bootstrap reserve at twice the rate the
//! user thinks they're authorising.
//!
//! Closing the gap is a UI affair, not an invariant break: every Type 1
//! is already verified by the bootstrap C10 sig and bumps `bootstrapUses`
//! through the on-chain monotonic cap. We just need the trusted display
//! to surface the rotation as its own affirmative-consent step before
//! the inner-tx render runs.
//!
//! ## Consent receipt (sweep 2026-10-13 finding #1)
//!
//! The whole rotation dialog sits under one `if register_slot` branch in
//! each handler. A single fault that sends that branch the false way would
//! skip the dialog while later code (which re-reads the honest flag) still
//! derives the bootstrap key and releases a Type-1. [`RotationConfirmReceipt`]
//! closes that: it is fail-initialised before the dialog, published only in
//! the dialog's affirmative arm (or, when rotation was not requested, as an
//! explicit `requested = false` skip record), and its
//! [`RotationConfirmReceipt::completion_proof`] against the context built
//! from the real flag is checked twice before the bootstrap key is used. A
//! skipped dialog leaves either no record or a skip record whose digest
//! cannot match a `requested = true` context.
//!
//! ## Output binding (#353)
//!
//! Protocol 0x0203 returns the new slot's 64-byte owner bytes ahead of the
//! Type-1 wrapper. [`rotation_output_binding_proof`] proves, immediately
//! before release, that the emitted owner bytes are the new slot's key AND
//! that `addOwnerBytes(emitted)` hashes to the calldata digest the bootstrap
//! key actually signed — so a companion rebuilding the Type-1 UserOp from the
//! response submits exactly the signed preimage.

use super::Pages;
use crate::ui::DISPLAY_COLS;
use sha2::{Digest, Sha256};

const ROTATION_CONFIRM_CFI_STEP: u32 = 0x5107_C0F1;
const ROTATION_CONFIRM_FAIL_DIGEST: [u8; 32] = [0x5A; 32];
const ROTATION_CONFIRM_DOMAIN: &[u8] = b"PQSigner/rotation-confirm/v1";

/// Exact public rotation context authorised by one trusted confirmation.
///
/// Built from the handler's real (FI-rechecked) `register_slot` flag and the
/// exact Type-1 UserOp fields the bootstrap key will sign.
#[derive(Clone, Copy)]
pub(crate) struct RotationConfirmContext {
    requested: bool,
    chain_id: u64,
    account_index: u32,
    slot_index: u32,
    sender: [u8; 20],
    base_nonce: [u8; 32],
    gas: [[u8; 32]; 5],
}

impl RotationConfirmContext {
    /// `gas` = `[call_gas_limit, verification_gas_limit, pre_verification_gas,
    /// max_fee_per_gas, max_priority_fee_per_gas]`, as signed into Type 1.
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        requested: bool,
        chain_id: u64,
        account_index: u32,
        slot_index: u32,
        sender: [u8; 20],
        base_nonce: [u8; 32],
        gas: [[u8; 32]; 5],
    ) -> Self {
        Self {
            requested,
            chain_id,
            account_index,
            slot_index,
            sender,
            base_nonce,
            gas,
        }
    }

    /// Whether this context covers a requested rotation.
    pub(crate) fn requested(&self) -> bool {
        self.requested
    }

    /// The same context with `requested` forced to a literal `false`: the
    /// only shape a "rotation not requested" record may carry.
    const fn as_not_requested(&self) -> Self {
        let mut c = *self;
        c.requested = false;
        c
    }

    fn receipt_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ROTATION_CONFIRM_DOMAIN);
        h.update([u8::from(self.requested)]);
        h.update(self.chain_id.to_be_bytes());
        h.update(self.account_index.to_be_bytes());
        h.update(self.slot_index.to_be_bytes());
        h.update(self.sender);
        h.update(self.base_nonce);
        for word in &self.gas {
            h.update(word);
        }
        h.finalize().into()
    }
}

/// Fail-initialised authority receipt carried from the rotation dialog's
/// affirmative branch to both bootstrap-key boundaries.
pub(crate) struct RotationConfirmReceipt {
    recorded: u32,
    context_digest: [u8; 32],
    cfi: crate::fi::CfiCounter,
}

impl RotationConfirmReceipt {
    pub(crate) const fn new() -> Self {
        Self {
            recorded: 0,
            context_digest: ROTATION_CONFIRM_FAIL_DIGEST,
            cfi: crate::fi::CfiCounter::new(),
        }
    }

    #[inline(never)]
    pub(crate) fn fail_initialize(&mut self) {
        // SAFETY: every field is uniquely borrowed; the `Drop` impl only
        // re-runs this fail-state store.
        unsafe {
            core::ptr::write_volatile(&mut self.recorded, 0);
            core::ptr::write_volatile(&mut self.context_digest, ROTATION_CONFIRM_FAIL_DIGEST);
            core::ptr::write_volatile(&mut self.cfi, crate::fi::CfiCounter::new());
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Publish the receipt from the rotation dialog's affirmative arm, after
    /// the caller has checked both `Confirmed` and its FI sentinel.
    #[inline(never)]
    pub(crate) fn record_confirmed(&mut self, context: &RotationConfirmContext) -> Result<(), ()> {
        if !context.requested {
            return Err(());
        }
        self.publish(context.receipt_digest())
    }

    /// Publish the "rotation not requested" record. Its digest is always
    /// computed over a literal `requested = false` context, so it can never
    /// satisfy [`Self::completion_proof`] for a requested rotation — a fault
    /// that diverts a `register_slot == true` flow into this path fails
    /// closed at both bootstrap boundaries.
    #[inline(never)]
    pub(crate) fn record_not_requested(&mut self, context: &RotationConfirmContext) -> Result<(), ()> {
        self.publish(context.as_not_requested().receipt_digest())
    }

    fn publish(&mut self, digest: [u8; 32]) -> Result<(), ()> {
        // SAFETY: unique live receipt; volatile state stays observable under
        // LTO independently of the CFI accumulator.
        let current = unsafe { core::ptr::read_volatile(&self.recorded) };
        if current != 0 {
            return Err(());
        }
        unsafe {
            core::ptr::write_volatile(&mut self.context_digest, digest);
            core::ptr::write_volatile(&mut self.recorded, 1);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.cfi.bump(ROTATION_CONFIRM_CFI_STEP);
        Ok(())
    }

    /// Prove exactly one publication for exactly `context` (built from the
    /// handler's real `register_slot`). Callers check it before deriving the
    /// bootstrap key and again immediately before the bootstrap sign.
    #[inline(never)]
    pub(crate) fn completion_proof(&self, context: &RotationConfirmContext) -> u32 {
        let expected_cfi = crate::fi::CfiCounter::INIT_VALUE.wrapping_add(ROTATION_CONFIRM_CFI_STEP);
        let (ok_a, ok_b) = self.state_matches(1, &context.receipt_digest(), expected_cfi);
        Self::verdict(ok_a, ok_b)
    }

    /// Read-back immediately after [`Self::fail_initialize`]: the receipt
    /// must be in the fail state, so a skipped initialization cannot leave an
    /// earlier call's published state live on the reused stack slot.
    #[inline(never)]
    pub(crate) fn pristine_proof(&self) -> u32 {
        let (ok_a, ok_b) = self.state_matches(
            0,
            &ROTATION_CONFIRM_FAIL_DIGEST,
            crate::fi::CfiCounter::INIT_VALUE,
        );
        Self::verdict(ok_a, ok_b)
    }

    fn verdict(ok_a: bool, ok_b: bool) -> u32 {
        crate::fi::scrub_sentinel_register();
        crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(ok_a) && core::hint::black_box(ok_b)
        })
    }

    /// Sample the whole receipt twice around a randomized gap and reduce each
    /// sample independently against the expected publication state, digest
    /// and CFI accumulator. One corrupt load or one skipped compare in either
    /// reduction cannot forge both results.
    #[inline(never)]
    fn state_matches(&self, recorded: u32, digest: &[u8; 32], expected_cfi: u32) -> (bool, bool) {
        // SAFETY: immutable live receipt.
        let recorded_a = unsafe { core::ptr::read_volatile(&self.recorded) };
        let digest_a = unsafe { core::ptr::read_volatile(&self.context_digest) };
        crate::fi::scrub_sentinel_register();
        let cfi_a = self.cfi.check_into_sentinel(expected_cfi);
        crate::fi::wait_random();
        let recorded_b = unsafe { core::ptr::read_volatile(&self.recorded) };
        let digest_b = unsafe { core::ptr::read_volatile(&self.context_digest) };
        crate::fi::scrub_sentinel_register();
        let cfi_b = self.cfi.check_into_sentinel(expected_cfi);

        let mut diff_a = 0u8;
        for i in 0..digest.len() {
            diff_a |= digest_a[i] ^ digest[i];
        }
        let ok_a = core::hint::black_box(recorded_a) == recorded
            && core::hint::black_box(diff_a) == 0
            && core::hint::black_box(cfi_a) == crate::fi::OK_SENTINEL;
        let mut diff_b = 0u8;
        for i in 0..digest.len() {
            diff_b |= digest_b[i] ^ digest[i];
        }
        let ok_b = core::hint::black_box(recorded_b) == recorded
            && core::hint::black_box(diff_b) == 0
            && core::hint::black_box(cfi_b) == crate::fi::OK_SENTINEL;
        (ok_a, ok_b)
    }
}

impl Drop for RotationConfirmReceipt {
    /// Return the stack slot to the fail state on every handler exit, so a
    /// later call that reuses it never inherits a published receipt.
    fn drop(&mut self) {
        self.fail_initialize();
    }
}

/// Bind the released Type-1 section to the exact signed preimage (#353).
///
/// * Requested: `emit_type1` must be set, `owner_out` must equal the new
///   slot's `slot_owner_bytes` (the key the Type-2 is signed with), and
///   SHA-256 of `addOwnerBytes(owner_out)` must equal `signed_call_digest`,
///   the calldata digest folded into the bootstrap-signed sphincs digest.
/// * Not requested: `emit_type1` must be clear.
#[inline(never)]
pub(crate) fn rotation_output_binding_proof(
    context: &RotationConfirmContext,
    emit_type1: bool,
    owner_out: &[u8; 64],
    slot_owner_bytes: &[u8; 64],
    signed_call_digest: &[u8; 32],
) -> u32 {
    let rebuilt: [u8; 32] =
        Sha256::digest(pqsigner_aa::userop::add_owner_bytes_calldata(owner_out)).into();
    crate::fi::check_true_into_sentinel(|| {
        if core::hint::black_box(context.requested) {
            let mut diff = 0u8;
            for i in 0..64 {
                diff |= owner_out[i] ^ slot_owner_bytes[i];
            }
            for i in 0..32 {
                diff |= rebuilt[i] ^ signed_call_digest[i];
            }
            core::hint::black_box(emit_type1) && core::hint::black_box(diff) == 0
        } else {
            !core::hint::black_box(emit_type1)
        }
    })
}

/// Build the one-page "ROTATE SLOT?" confirm shown before the inner-tx
/// confirm whenever `FLAG_REGISTER_SLOT` is set.
///
/// Layout (16 cols × 4 rows):
///
/// ```text
///   row 0:                    (blank)
///   row 1:    ROTATE SLOT?
///   row 2:    Slot: N
///   row 3:    +bootstrap use
/// ```
///
/// `slot_index` is the firmware-side index supplied in the FLAG word
/// (always `>= 1` here — the handler refuses `register_slot && slot_index
/// == 0` upstream). Its on-chain `ownerIndex` is `slot_index + 1`, but
/// the firmware/UI/flash all key on the firmware-side index, so we keep
/// the displayed number aligned with that convention.
pub fn build_slot_rotation_pages(slot_index: u32) -> Pages {
    let mut out = Pages::empty_with_len(1);

    out.row_mut(0, 0).copy_from_slice(&[b' '; DISPLAY_COLS]);
    write_centered(out.row_mut(0, 1), b"ROTATE SLOT?");
    let mut buf = [b' '; DISPLAY_COLS];
    write_new_slot(&mut buf, slot_index);
    out.row_mut(0, 2).copy_from_slice(&buf);
    write_centered(out.row_mut(0, 3), b"+bootstrap use");

    out
}

fn write_centered(row: &mut [u8; DISPLAY_COLS], text: &[u8]) {
    *row = [b' '; DISPLAY_COLS];
    let len = core::cmp::min(text.len(), DISPLAY_COLS);
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&text[..len]);
}

fn write_new_slot(row: &mut [u8; DISPLAY_COLS], slot_index: u32) {
    // The six-byte prefix leaves ten columns, exactly enough for every
    // decimal `u32`.  In particular, every accepted 22-bit FLAG-word slot
    // index is rendered in full: distinct signed slot indices must never
    // collapse to the same trusted-display row.
    let mut buf = [b' '; DISPLAY_COLS];
    let prefix = b"Slot: ";
    buf[..prefix.len()].copy_from_slice(prefix);
    let len = prefix.len() + write_dec(&mut buf, prefix.len(), slot_index);
    *row = [b' '; DISPLAY_COLS];
    let start = (DISPLAY_COLS - len) / 2;
    row[start..start + len].copy_from_slice(&buf[..len]);
}

/// Write the complete decimal `u32` into the ten columns reserved after
/// `pos`.  The only caller passes `pos == 6`, so even `u32::MAX` occupies
/// exactly the remaining 10 columns and cannot be truncated.
fn write_dec(buf: &mut [u8; DISPLAY_COLS], pos: usize, value: u32) -> usize {
    if value == 0 {
        buf[pos] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = 0;
    let mut v = value;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for i in 0..n {
        buf[pos + i] = tmp[n - 1 - i];
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(requested: bool) -> RotationConfirmContext {
        RotationConfirmContext::new(requested, 8453, 0, 3, [0x11; 20], [0x22; 32], [[0x33; 32]; 5])
    }

    #[test]
    fn pristine_read_back_detects_a_live_published_state() {
        let mut fresh = RotationConfirmReceipt::new();
        fresh.fail_initialize();
        assert_eq!(fresh.pristine_proof(), crate::fi::OK_SENTINEL);

        // A published receipt left on a reused stack slot (initialization
        // skipped) must fail the read-back, whichever record it carries.
        let mut rotated = RotationConfirmReceipt::new();
        rotated.fail_initialize();
        rotated.record_confirmed(&ctx(true)).unwrap();
        assert_ne!(rotated.pristine_proof(), crate::fi::OK_SENTINEL);
        let mut skipped = RotationConfirmReceipt::new();
        skipped.fail_initialize();
        skipped.record_not_requested(&ctx(false)).unwrap();
        assert_ne!(skipped.pristine_proof(), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn drop_returns_the_slot_to_the_fail_state() {
        let c = ctx(true);
        let mut r = RotationConfirmReceipt::new();
        r.fail_initialize();
        r.record_confirmed(&c).unwrap();
        assert_eq!(r.completion_proof(&c), crate::fi::OK_SENTINEL);
        // SAFETY: `r` is dropped in place exactly once and then forgotten, so
        // its destructor never runs a second time; the type owns no heap
        // memory, so inspecting its bytes afterwards is sound.
        unsafe { core::ptr::drop_in_place(&mut r) };
        assert_eq!(r.pristine_proof(), crate::fi::OK_SENTINEL);
        assert_ne!(r.completion_proof(&c), crate::fi::OK_SENTINEL);
        core::mem::forget(r);
    }

    #[test]
    fn unrecorded_receipt_fails_closed() {
        let mut r = RotationConfirmReceipt::new();
        r.fail_initialize();
        assert_ne!(r.completion_proof(&ctx(true)), crate::fi::OK_SENTINEL);
        assert_ne!(r.completion_proof(&ctx(false)), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn confirmed_receipt_is_context_specific() {
        let c = ctx(true);
        let mut r = RotationConfirmReceipt::new();
        r.fail_initialize();
        r.record_confirmed(&c).unwrap();
        assert_eq!(r.completion_proof(&c), crate::fi::OK_SENTINEL);
        let mut gas = [[0x33; 32]; 5];
        gas[3][31] ^= 1;
        for other in [
            RotationConfirmContext::new(true, 8453, 0, 4, [0x11; 20], [0x22; 32], [[0x33; 32]; 5]),
            RotationConfirmContext::new(true, 1, 0, 3, [0x11; 20], [0x22; 32], [[0x33; 32]; 5]),
            RotationConfirmContext::new(true, 8453, 1, 3, [0x11; 20], [0x22; 32], [[0x33; 32]; 5]),
            RotationConfirmContext::new(true, 8453, 0, 3, [0x12; 20], [0x22; 32], [[0x33; 32]; 5]),
            RotationConfirmContext::new(true, 8453, 0, 3, [0x11; 20], [0x23; 32], [[0x33; 32]; 5]),
            RotationConfirmContext::new(true, 8453, 0, 3, [0x11; 20], [0x22; 32], gas),
            ctx(false),
        ] {
            assert_ne!(r.completion_proof(&other), crate::fi::OK_SENTINEL);
        }
        // Exactly one publication.
        assert!(r.record_confirmed(&c).is_err());
        assert!(r.record_not_requested(&c).is_err());
    }

    #[test]
    fn skip_record_cannot_authorise_a_requested_rotation() {
        // The FI scenario of sweep finding #1: the dialog branch is skipped
        // while the honest flag is still `true`, and control lands on the
        // not-requested record. The proof against the real context must fail.
        let requested = ctx(true);
        let mut r = RotationConfirmReceipt::new();
        r.fail_initialize();
        r.record_not_requested(&requested).unwrap();
        assert_ne!(r.completion_proof(&requested), crate::fi::OK_SENTINEL);
        // ...while the genuine disabled mode proves cleanly.
        let disabled = ctx(false);
        let mut r2 = RotationConfirmReceipt::new();
        r2.fail_initialize();
        r2.record_not_requested(&disabled).unwrap();
        assert_eq!(r2.completion_proof(&disabled), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn confirmed_record_refuses_a_not_requested_context() {
        let mut r = RotationConfirmReceipt::new();
        r.fail_initialize();
        assert!(r.record_confirmed(&ctx(false)).is_err());
        assert_ne!(r.completion_proof(&ctx(false)), crate::fi::OK_SENTINEL);
    }

    #[test]
    fn output_proof_binds_owner_bytes_to_signed_calldata() {
        let mut owner = [0u8; 64];
        for (i, b) in owner.iter_mut().enumerate() {
            *b = i as u8;
        }
        let signed: [u8; 32] =
            Sha256::digest(pqsigner_aa::userop::add_owner_bytes_calldata(&owner)).into();
        let on = ctx(true);
        assert_eq!(
            rotation_output_binding_proof(&on, true, &owner, &owner, &signed),
            crate::fi::OK_SENTINEL
        );
        // Type-1 not emitted although requested.
        assert_ne!(
            rotation_output_binding_proof(&on, false, &owner, &owner, &signed),
            crate::fi::OK_SENTINEL
        );
        // Emitted owner differs from the slot key.
        let mut wrong = owner;
        wrong[40] ^= 1;
        assert_ne!(
            rotation_output_binding_proof(&on, true, &wrong, &owner, &signed),
            crate::fi::OK_SENTINEL
        );
        // Emitted owner is the slot key but not what was signed.
        assert_ne!(
            rotation_output_binding_proof(&on, true, &wrong, &wrong, &signed),
            crate::fi::OK_SENTINEL
        );
        // Disabled mode: no Type-1 may be emitted.
        let off = ctx(false);
        assert_eq!(
            rotation_output_binding_proof(&off, false, &[0; 64], &owner, &[0; 32]),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            rotation_output_binding_proof(&off, true, &owner, &owner, &signed),
            crate::fi::OK_SENTINEL
        );
    }
}
