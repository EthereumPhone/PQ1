//! TEMPORARY MEASUREMENT STUB — not a hash. Replaced by the real STM32U585
//! HASH driver in the next step.
//!
//! It exists only to produce a linkable image whose size isolates "what does
//! removing `sha2` save" from "what does the driver cost". Any image built
//! with this is a SIZE PROBE and must never be flashed.
#![allow(clippy::missing_safety_doc)]

// HARD FENCE. This file does not compute SHA-256. An image built with it
// would "verify" every firmware slot against a garbage digest, i.e. accept
// anything. It exists only so the `hw-sha256` size delta could be MEASURED
// (30,720 -> 22,152 B) before the real STM32U585 HASH driver is written.
//
// Building it requires naming it explicitly. `hw-sha256` on its own is a
// compile error until the real driver lands, which is the correct state:
// the feature is declared, wired through `fw-manifest` and `sphincs-c10`,
// and refuses to produce a bootable image.
#[cfg(not(feature = "sha-stub-measure-only"))]
compile_error!(
    "fsbl/src/hash.rs is a MEASUREMENT STUB, not SHA-256. The real HASH \
     driver is not wired yet. Enable `sha-stub-measure-only` only to \
     reproduce the size measurement; never flash the result."
);

static mut ACC: u32 = 0;

#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_init() {
    unsafe { ACC = 1 };
}

#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_update(ptr: *const u8, len: usize) {
    let mut a = unsafe { ACC };
    for i in 0..len {
        // SAFETY: caller contract — `[ptr, ptr+len)` is readable.
        a = a.wrapping_mul(31).wrapping_add(u32::from(unsafe { *ptr.add(i) }));
    }
    unsafe { ACC = a };
}

#[no_mangle]
pub unsafe extern "C" fn pqsigner_sha256_final(out: *mut u8) {
    let a = unsafe { ACC };
    for i in 0..32 {
        // SAFETY: caller contract — `out` is valid for 32 bytes.
        unsafe { *out.add(i) = (a >> ((i % 4) * 8)) as u8 };
    }
}
