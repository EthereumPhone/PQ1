//! Fault-sweep target ELF for `tools/sca/fault_sweep_c10_sign.py`. Mirrors
//! the production `secure::crypto::c10_sign_verified_with_progress`
//! (the FI-hardened signing primitive post-F-1/F-2/F-5) bit-for-bit:
//! `sphincs_c10::SigningKey::sign` (real) → `fi::wait_random()` →
//! `sphincs_c10::verify` (real) → `fi::check_true_into_sentinel`
//! re-checks the verify result with `core::hint::black_box(v)` defeating
//! LLVM CSE → caller compares to `OK_SENTINEL`. If the gate accepts, the
//! signature bytes are written to `out_sig_ptr`; otherwise nothing is
//! written and the function returns 0.
//!
//! Vendor / signing keypair is derived deterministically from a fixed
//! sk_seed / pk_seed so the harness can produce a baseline signature in
//! Python (by re-running the unfaulted path) and bytewise-compare against
//! every faulted run. Any `Ok` return whose `sig != baseline_sig` is a
//! BYPASS — a single fault that released a sig the production gate should
//! have rejected.
//!
//! Build:  cargo build --release --target thumbv8m.main-none-eabi
//!         (or: make -C tools/sca build-c10-sign)
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;
use sphincs_c10::params::{N, SIGNATURE_LEN};

// ---------------------------------------------------------------------------
// FI helpers — production `secure/src/fi.rs` verbatim. `rng::byte()`
// stubbed to a small constant (same pattern as fi_target, fw_verify_target,
// ns_ptr_target).
// ---------------------------------------------------------------------------

pub mod rng {
    #[inline(never)]
    pub fn byte() -> u8 {
        5
    }
}

#[path = "../../../../secure/src/fi.rs"]
mod fi;

// ---------------------------------------------------------------------------
// Fixed keypair — deterministic, bit-stable across builds. The harness
// re-derives the same keypair off-line for sig/key validation.
// ---------------------------------------------------------------------------

const SK_SEED: [u8; 32] = [0x42u8; 32];
const PK_SEED: [u8; N] = [0x77u8; N];
// Pre-computed by build.rs from (SK_SEED, PK_SEED) so the runtime path uses
// SigningKey::from_parts (cheap struct fill) instead of keygen — saves
// ~2.5M emulation instructions per fault iteration in the sweep.
const PK_ROOT: [u8; N] = *include_bytes!(concat!(env!("OUT_DIR"), "/pk_root.bin"));

// ---------------------------------------------------------------------------
// Plain (unhardened) one-shot sign — for reference / contrast. Just calls
// `sphincs_c10::SigningKey::sign` and writes the bytes. No verify gate.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_c10_sign_plain(
    msg_hash_ptr: *const u8,
    out_sig_ptr: *mut u8,
) -> u32 {
    let sk = sphincs_c10::SigningKey::from_parts(SK_SEED, PK_SEED, PK_ROOT);
    // SAFETY: harness maps 32 B / SIGNATURE_LEN B at these addresses.
    let msg: &[u8; 32] = unsafe { &*(msg_hash_ptr as *const [u8; 32]) };
    let sig = sk.sign(msg, None);
    unsafe {
        for (i, &b) in sig.iter().enumerate() {
            core::ptr::write_volatile(out_sig_ptr.add(i), b);
        }
    }
    1
}

// ---------------------------------------------------------------------------
// PRODUCTION-MIRROR sign+verify gate (F-1/F-2/F-5 fixed).
// Bit-equivalent to `secure::crypto::c10_sign_verified_with_progress`.
// Returns 1 on Ok (sig written), 0 on Err (nothing written, gate rejected).
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_c10_sign_verified(
    msg_hash_ptr: *const u8,
    out_sig_ptr: *mut u8,
) -> u32 {
    let sk = sphincs_c10::SigningKey::from_parts(SK_SEED, PK_SEED, PK_ROOT);
    let msg: &[u8; 32] = unsafe { &*(msg_hash_ptr as *const [u8; 32]) };
    let sig = sk.sign(msg, None);
    fi::wait_random();
    let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg, &sig);
    if fi::check_true_into_sentinel(|| core::hint::black_box(v)) != fi::OK_SENTINEL {
        return 0;
    }
    unsafe {
        for (i, &b) in sig.iter().enumerate() {
            core::ptr::write_volatile(out_sig_ptr.add(i), b);
        }
    }
    1
}

// ---------------------------------------------------------------------------
// Raw `sphincs_c10::verify` — exposed so the harness can validate signatures
// produced by faulted runs without a Python SPHINCS+ verifier. Bit-equivalent
// to `c10v_target::sca_c10_verify_real`.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_c10_verify_real(
    pk_seed: *const u8,
    pk_root: *const u8,
    msg_hash: *const u8,
    sig: *const u8,
) -> u32 {
    let pk_seed: &[u8; N] = unsafe { &*(pk_seed as *const [u8; N]) };
    let pk_root: &[u8; N] = unsafe { &*(pk_root as *const [u8; N]) };
    let msg_hash: &[u8; 32] = unsafe { &*(msg_hash as *const [u8; 32]) };
    let sig: &[u8; SIGNATURE_LEN] = unsafe { &*(sig as *const [u8; SIGNATURE_LEN]) };
    u32::from(sphincs_c10::verify(pk_seed, pk_root, msg_hash, sig))
}

// ---------------------------------------------------------------------------
// Keep-statics + entry stub (defeats `--gc-sections` + LLVM dead-code).
// ---------------------------------------------------------------------------

#[used]
static _KEEP_PLAIN: extern "C" fn(*const u8, *mut u8) -> u32 = sca_c10_sign_plain;
#[used]
static _KEEP_GATED: extern "C" fn(*const u8, *mut u8) -> u32 = sca_c10_sign_verified;
#[used]
static _KEEP_VERIFY: extern "C" fn(*const u8, *const u8, *const u8, *const u8) -> u32 =
    sca_c10_verify_real;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_PLAIN);
    core::hint::black_box(&_KEEP_GATED);
    core::hint::black_box(&_KEEP_VERIFY);
    loop {
        cortex_m::asm::nop();
    }
}
