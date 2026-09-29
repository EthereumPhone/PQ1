//! SHA-256 backend selection for the FSBL.
//!
//! Default (`sha2`) is the software implementation. Under `hw-sha256` every
//! call routes through the three `pqsigner_sha256_*` symbols that
//! [`crate::hash`] provides from the STM32U585 HASH peripheral.
//!
//! WHY THIS EXISTS. `sha2::sha256::compress256` is **7,202 B — 23.4% of the
//! FSBL image**, and it only leaves the binary if EVERY consumer in the cone
//! stops referencing it: this crate's [`crate::verify`], `fw-manifest`, and
//! `sphincs-c10`. Switching one or two of them saves nothing.
//!
//! The shape deliberately mirrors `sphincs_c10::hash`'s private shim rather
//! than inventing a second contract; that one is `pub(crate)` there, so it
//! cannot simply be imported.

#[cfg(not(feature = "hw-sha256"))]
pub use sha2::{Digest, Sha256};

#[cfg(feature = "hw-sha256")]
extern "C" {
    fn pqsigner_sha256_init();
    fn pqsigner_sha256_update(ptr: *const u8, len: usize);
    fn pqsigner_sha256_final(out: *mut u8);
}

/// The subset of `sha2::Digest` the FSBL uses.
#[cfg(feature = "hw-sha256")]
pub trait Digest: Sized {
    fn new() -> Self;
    fn update(&mut self, data: impl AsRef<[u8]>);
    fn finalize(self) -> [u8; 32];
}

/// Typestate marker — the engine itself is global and single-session.
#[cfg(feature = "hw-sha256")]
pub struct Sha256;

#[cfg(feature = "hw-sha256")]
impl Digest for Sha256 {
    fn new() -> Self {
        // SAFETY: FFI to the hook `crate::hash` defines in this same binary.
        // No arguments, no return; it initialises the global engine.
        unsafe { pqsigner_sha256_init() };
        Self
    }
    fn update(&mut self, data: impl AsRef<[u8]>) {
        let b = data.as_ref();
        // SAFETY: `b.as_ptr()` is valid for `b.len()` bytes for the duration
        // of the call (the borrow outlives it); the hook only reads.
        unsafe { pqsigner_sha256_update(b.as_ptr(), b.len()) };
    }
    fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: `out` is 32 bytes on this frame, live past the call; the
        // hook writes exactly the digest size.
        unsafe { pqsigner_sha256_final(out.as_mut_ptr()) };
        out
    }
}
