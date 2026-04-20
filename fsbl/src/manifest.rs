//! Manifest I/O for the FSBL.
//!
//! Reads the 8 KB manifest page directly from flash and wraps it in
//! a [`fw_manifest::ManifestRef`]. Does NOT copy the bytes; the
//! returned reference borrows the memory-mapped flash region. This is
//! safe because:
//!
//! 1. Flash is read-only during FSBL execution (we never program flash
//!    from FSBL in the normal path — the only write is the boot-state
//!    page update, which is a separate address).
//! 2. The FSBL never hands the `ManifestRef` out to untrusted code.
//!
//! The manifest's SHA-256 fields point at 464 KB + 512 KB images, so
//! verifying them dominates runtime. We stream-hash those images
//! directly from flash in `verify.rs` — no RAM copy needed.

use core::ptr::read_volatile;
use fw_manifest::{ManifestRef, MANIFEST_SIZE};

use crate::slot::{manifest_addr, Slot};

/// Read a manifest from flash into a stack-allocated 8 KB buffer.
///
/// We copy instead of using the memory-mapped region directly because
/// `ManifestRef` needs a `&[u8; MANIFEST_SIZE]` reference with a
/// normal (aligned) Rust pointer. The flash address *is* a normal
/// pointer, but borrow-checker ergonomics are simpler with an owned
/// buffer. 8 KB on the stack is well within the 16 KB FSBL RAM budget.
pub fn read(slot: Slot) -> [u8; MANIFEST_SIZE] {
    let addr = manifest_addr(slot);
    let mut buf = [0u8; MANIFEST_SIZE];
    // SAFETY: `addr` is a fixed, known-valid flash address in the
    // secure bank 1. Reading from it always succeeds on STM32U585.
    unsafe {
        let src = addr as *const u8;
        for i in 0..MANIFEST_SIZE {
            buf[i] = read_volatile(src.add(i));
        }
    }
    buf
}

/// Convenience: read + wrap in a `ManifestRef`. The returned reference
/// borrows the caller's buffer.
pub fn as_ref(buf: &[u8; MANIFEST_SIZE]) -> ManifestRef<'_> {
    ManifestRef::new(buf)
}
