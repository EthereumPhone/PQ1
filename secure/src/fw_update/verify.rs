//! COMMIT-time verification: re-hash the written images and match
//! them against the manifest's signed hashes.
//!
//! This is our "defence in depth after flash". The signature check at
//! BEGIN proves the manifest came from the vendor; this check proves
//! the bytes we actually wrote match what the manifest said we should
//! write. A mismatch here means either flash corruption during stream
//! (brown-out, bit flip) or a companion-side bug that sent different
//! bytes than the manifest was signed over.

use core::ptr::read_volatile;

use fw_manifest::ManifestRef;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::fw_update::FwUpdateCtx;
use crate::hw::flash::{self, Slot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageCheckError {
    /// Running hash during streaming didn't match the hash computed
    /// by re-reading flash (i.e., a torn write the `write_quadword_verified`
    /// guard missed). Should never fire in practice; if it does, the
    /// flash hardware is misbehaving and the user should stop.
    StreamingHashMismatch,
    /// Post-streaming hash of `[slot_base, slot_base + secure_len)`
    /// doesn't match `manifest.secure_hash`.
    SecureMismatch,
    /// Same, for the NS half.
    NonsecureMismatch,
    /// Declared image length doesn't match how much the companion
    /// actually sent. BEGIN tracks expected_*_len and COMMIT checks
    /// that received_*_len == expected.
    LengthMismatch,
}

/// Re-read the inactive slot's bytes from flash and compare their
/// SHA-256 against both (a) the running hash computed during
/// streaming and (b) the manifest's signed hash. Both must agree.
pub fn verify_images(ctx: &FwUpdateCtx, m: &ManifestRef) -> Result<(), ImageCheckError> {
    if ctx.received_secure != m.secure_len() {
        return Err(ImageCheckError::LengthMismatch);
    }
    if ctx.received_nonsecure != m.nonsecure_len() {
        return Err(ImageCheckError::LengthMismatch);
    }

    let slot: Slot = ctx.inactive.into();

    // (a) running-hash check. Cheap: we already computed this as we
    // streamed chunks in.
    let streaming_secure = ctx.secure_hasher.clone_finalize();
    let streaming_ns = ctx.nonsecure_hasher.clone_finalize();

    // (b) fresh re-read from flash.
    let fresh_secure = hash_flash(flash::slot_secure_addr(slot), ctx.received_secure);
    let fresh_ns = hash_flash(flash::slot_ns_addr(slot), ctx.received_nonsecure);

    // ── FI-hardened binding (audit: FW-COMMIT single-fault bypass) ──
    //
    // These four 32-byte equalities are the SOLE cryptographic binding
    // between the bytes actually programmed into the inactive slot and
    // the vendor-SIGNED manifest hashes (whose signature BEGIN already
    // F-7-verified). A bare `if a != b { return Err }` reject is one
    // instruction-skip / branch-flip away from falling through to
    // `Ok(())` — at which point a non-matching (UNSIGNED, attacker)
    // image commits, lifting the whole device's firmware-signing
    // guarantee off a single fault. That asymmetry — BEGIN routes its
    // signature verdict through the F-2 Hamming-distant sentinel while
    // COMMIT did a bare `!=` — was the bug.
    //
    // Match BEGIN's bar: constant-time-compare each pair (no early-out
    // timing oracle on WHERE two hashes first differ) and gate the final
    // `Ok(())` on the AND of all four verdicts, re-derived inside
    // `fi::check_true_into_sentinel` (double-evaluated + Hamming-distant
    // sentinel) after a `wait_random()` desync. To reach `Ok` a glitch
    // must now defeat BOTH a per-check reject below AND two independent
    // re-evaluations of the compare inside the sentinel gate — ~2
    // coordinated faults, the F-5/F-7 residual the rest of the firmware
    // already lives at. Distinct error codes are retained for host
    // diagnostics; the SECURITY decision is the aggregate sentinel gate.
    let streaming_secure_ok = bool::from(streaming_secure[..].ct_eq(&fresh_secure[..]));
    let streaming_ns_ok = bool::from(streaming_ns[..].ct_eq(&fresh_ns[..]));
    let manifest_secure_ok = bool::from(fresh_secure[..].ct_eq(&m.secure_hash()[..]));
    let manifest_ns_ok = bool::from(fresh_ns[..].ct_eq(&m.nonsecure_hash()[..]));

    if !streaming_secure_ok || !streaming_ns_ok {
        return Err(ImageCheckError::StreamingHashMismatch);
    }
    if !manifest_secure_ok {
        return Err(ImageCheckError::SecureMismatch);
    }
    if !manifest_ns_ok {
        return Err(ImageCheckError::NonsecureMismatch);
    }

    // Aggregate fail-closed gate. The closure RE-RUNS every comparison
    // (it does not re-read the booleans above), and `check_true_into_sentinel`
    // evaluates it twice, so a single fault on any one earlier compare
    // cannot survive to `Ok`. `black_box` on each sub-verdict stops LLVM
    // from CSE-ing these back into the booleans above and collapsing the
    // redundancy (F-1).
    crate::fi::wait_random();
    let gate = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(bool::from(streaming_secure[..].ct_eq(&fresh_secure[..])))
            && core::hint::black_box(bool::from(streaming_ns[..].ct_eq(&fresh_ns[..])))
            && core::hint::black_box(bool::from(fresh_secure[..].ct_eq(&m.secure_hash()[..])))
            && core::hint::black_box(bool::from(fresh_ns[..].ct_eq(&m.nonsecure_hash()[..])))
    });
    if gate != crate::fi::OK_SENTINEL {
        return Err(ImageCheckError::SecureMismatch);
    }
    Ok(())
}

/// Stream-hash a flash region. Reads through a volatile pointer so the
/// compiler can't fold "we just wrote X, so X is the value" optimisations.
/// Also used by `ui::px::assets` to prove the NS-resident pixel-UI atlas.
pub(crate) fn hash_flash(base: u32, len: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 256];
    let mut off = 0u32;
    while off < len {
        let n = core::cmp::min(256, (len - off) as usize);
        // SAFETY: [base, base + len) was bounds-checked at BEGIN
        // against the slot capacity. Reading is always safe.
        unsafe {
            let src = (base + off) as *const u8;
            for i in 0..n {
                chunk[i] = read_volatile(src.add(i));
            }
        }
        hasher.update(&chunk[..n]);
        off += n as u32;
    }
    hasher.finalize().into()
}

/// Compute the 8-BIP-39-word fingerprint the user confirms before
/// COMMIT actually flips the active slot. Same derivation as
/// `measured_boot`: first 88 bits of SHA-256 → 8 × 11-bit indices.
pub fn measurement_words_for_inactive_slot(
    ctx: &FwUpdateCtx,
) -> ([u16; 8], [u8; 32]) {
    let slot: Slot = ctx.inactive.into();
    let hash = hash_flash(flash::slot_secure_addr(slot), ctx.received_secure);
    let words = sphincs_tz_bip39::hash_to_word_indices(&hash);
    (words, hash)
}
