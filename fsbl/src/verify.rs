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

use crate::slot::{slot_ns_addr, slot_secure_addr, Slot};

/// Verify the secure + nonsecure images for `slot` hash to the
/// manifest's stored values.
pub fn verify_images(slot: Slot, m: &ManifestRef) -> bool {
    let secure_base = slot_secure_addr(slot);
    let ns_base = slot_ns_addr(slot);
    let secure_len = m.secure_len() as usize;
    let ns_len = m.nonsecure_len() as usize;

    // Sanity: reject obviously-bogus lengths before hashing. A length
    // exceeding slot capacity is a signed-but-malformed manifest and
    // should never pass the verify step. Returning false here is
    // defence-in-depth; a lying manifest couldn't pass the signature
    // check in the first place.
    if secure_len > crate::slot::SLOT_SECURE_CAPACITY as usize {
        return false;
    }
    if ns_len > crate::slot::SLOT_NS_CAPACITY as usize {
        return false;
    }

    let actual_secure = hash_flash_region(secure_base, secure_len);
    if &actual_secure != m.secure_hash() {
        return false;
    }
    let actual_ns = hash_flash_region(ns_base, ns_len);
    if &actual_ns != m.nonsecure_hash() {
        return false;
    }
    true
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
