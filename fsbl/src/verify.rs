//! Slot-image hash verification.
//!
//! The manifest's `secure_hash` and `nonsecure_hash` cover the exact
//! bytes FSBL re-hashes from flash at boot. We stream-hash directly
//! from the memory-mapped flash — no RAM copy — using the SHA-256
//! software path (`sha2::Sha256`) since FSBL's HASH-peripheral setup
//! is optional. On a real board with HASH enabled this is ~10 ms for
//! the secure half; in pure software at 16 MHz it's ~200 ms. Both
//! are acceptable for boot.

use fw_manifest::ManifestRef;
use sha2::{Digest, Sha256};

use crate::fi;
use crate::slot::{slot_ns_addr, slot_secure_addr, Slot};

/// Verify the secure + nonsecure images for `slot` hash to the
/// manifest's stored values. Returns the secure-image SHA-256 on
/// success so the caller can drive the on-OLED firmware fingerprint
/// from the same trusted bytes FSBL just verified — without re-hashing.
///
/// Returns `None` on length-bound failure or hash mismatch.
pub fn verify_images(slot: Slot, m: &ManifestRef) -> Option<[u8; 32]> {
    let secure_base = slot_secure_addr(slot);
    let ns_base = slot_ns_addr(slot);
    let secure_len = m.secure_len() as usize;
    let ns_len = m.nonsecure_len() as usize;

    #[cfg(feature = "stage-marker")]
    crate::marker::record(crate::marker::Stage::ImgEntered, secure_len as u32);

    // Sanity: reject obviously-bogus lengths before hashing. A length
    // exceeding slot capacity is a signed-but-malformed manifest and
    // should never pass the verify step. Returning None here is
    // defence-in-depth; a lying manifest couldn't pass the signature
    // check in the first place.
    if secure_len > crate::slot::SLOT_SECURE_CAPACITY as usize {
        return None;
    }
    if ns_len > crate::slot::SLOT_NS_CAPACITY as usize {
        return None;
    }

    #[cfg(feature = "stage-marker")]
    crate::marker::record(crate::marker::Stage::ImgLensOk, ns_len as u32);

    let actual_secure = hash_flash_region(secure_base, secure_len);
    #[cfg(feature = "stage-marker")]
    crate::marker::record(
        crate::marker::Stage::ImgSecureHashed,
        u32::from_le_bytes([actual_secure[0], actual_secure[1], actual_secure[2], actual_secure[3]]),
    );
    let actual_ns = hash_flash_region(ns_base, ns_len);
    #[cfg(feature = "stage-marker")]
    crate::marker::record(
        crate::marker::Stage::ImgNsHashed,
        u32::from_le_bytes([actual_ns[0], actual_ns[1], actual_ns[2], actual_ns[3]]),
    );

    // F15 hardening: these two 32-byte image-hash equalities are the SOLE
    // boot-time binding between the bytes in flash and the vendor-SIGNED
    // manifest hashes (whose signature `filter_valid` already sentinel-verified).
    // Pre-F15 each was a bare `if &a != b { return None }` — one instruction-
    // skip / branch-flip from falling through to `Some(..)` and BOOTING an
    // UNSIGNED (attacker-substituted) image, even though the signature gate
    // needs ~2 faults. This mirrors the secure-world COMMIT-time `verify_images`
    // (secure/src/fw_update/verify.rs): gate the success path on an aggregate
    // verdict re-evaluated inside `check_true_into_sentinel` (double-eval +
    // Hamming-distant sentinel after a wait-random desync), with `black_box`
    // stopping LLVM from CSE-ing the redundant compares back into the early
    // rejects. The compared hashes are PUBLIC, so a plain `==` (not constant-
    // time) leaks nothing and keeps the FSBL footprint lean (no `subtle` dep).
    let secure_ok = actual_secure == *m.secure_hash();
    let ns_ok = actual_ns == *m.nonsecure_hash();

    #[cfg(feature = "stage-marker")]
    {
        crate::marker::record(crate::marker::Stage::ImgSecureCmp, u32::from(secure_ok));
        crate::marker::record(crate::marker::Stage::ImgNsCmp, u32::from(ns_ok));
    }
    if !secure_ok {
        return None;
    }
    if !ns_ok {
        return None;
    }
    let gate = fi::check_true_into_sentinel(|| {
        core::hint::black_box(actual_secure == *m.secure_hash())
            && core::hint::black_box(actual_ns == *m.nonsecure_hash())
    });
    if gate != fi::OK_SENTINEL {
        return None;
    }
    Some(actual_secure)
}

/// SHA-256 of `len` bytes starting at `base`. Reads through a volatile
/// pointer so the compiler doesn't optimize the loop based on
/// assumed-identical reads.
fn hash_flash_region(base: usize, len: usize) -> [u8; 32] {
    // We stream 256-byte chunks into the hasher to keep the stack
    // usage small. The `sha2::Sha256::update` path takes a slice, so
    // we need a local buffer — 256 B on a 16 KB stack is fine.
    const CHUNK: usize = 256;

    let mut hasher = Sha256::new();
    let mut chunk = [0u8; CHUNK];
    let mut off = 0usize;
    while off < len {
        let n = core::cmp::min(CHUNK, len - off);
        let src = (base + off) as *const u8;
        for (i, byte) in chunk[..n].iter_mut().enumerate() {
            // SAFETY: flash is memory-mapped and readable throughout
            // `[base, base + len)`. `verify_images` has already
            // checked `len <= slot_capacity`, and `off + i < len` by
            // the outer and inner loop bounds, so `src.add(i)` stays
            // inside the chip's flash window.
            *byte = unsafe { core::ptr::read_volatile(src.add(i)) };
        }
        hasher.update(&chunk[..n]);
        off += n;
    }
    hasher.finalize().into()
}
