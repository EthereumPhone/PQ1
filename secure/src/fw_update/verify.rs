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

use crate::fw_update::{FwUpdateCtx, SlotTag};
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

    if streaming_secure != fresh_secure {
        return Err(ImageCheckError::StreamingHashMismatch);
    }
    if streaming_ns != fresh_ns {
        return Err(ImageCheckError::StreamingHashMismatch);
    }
    if &fresh_secure != m.secure_hash() {
        return Err(ImageCheckError::SecureMismatch);
    }
    if &fresh_ns != m.nonsecure_hash() {
        return Err(ImageCheckError::NonsecureMismatch);
    }
    Ok(())
}

/// Stream-hash a flash region. Reads through a volatile pointer so the
/// compiler can't fold "we just wrote X, so X is the value" optimisations.
fn hash_flash(base: u32, len: u32) -> [u8; 32] {
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
