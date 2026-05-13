//! Fault-sweep target ELF for `tools/sca/fault_sweep_ns_ptr.py`: thin
//! `#[no_mangle]` wrappers around the *real*
//! `secure::nsc::ptr_validate::validate_ns_{read,write}_ptr` (`#[path]`-
//! included). The harness invokes them with attacker-controlled `(ptr, len)`
//! pairs covering (a) a clearly-NS-valid baseline (should return 1), (b) a
//! pointer into secure RAM (should return 0 — the classic TrustZone bypass
//! target), (c) a pointer aliasing the shared command mailbox (also 0), (d)
//! a NULL pointer (also 0), and (e) `ptr + len` overflow (also 0). Sweeps
//! every single-fault model and reports any case where a bad scenario flips
//! to "validate accepted" — that's a single-fault TrustZone boundary
//! breach.
//!
//! The mirror also exposes a hardened pair
//! (`sca_ns_validate_{read,write}_fi`) that wraps the same predicate in
//! `fi::check_true_into_sentinel` — useful for evaluating the candidate
//! hardening side-by-side if F-8 / F-9 turn up bypasses.
//!
//! Build:  cargo build --release --target thumbv8m.main-none-eabi
//!         (or: make -C tools/sca build-ns-ptr)
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

// ---------------------------------------------------------------------------
// FI helpers — production `secure/src/fi.rs` verbatim. `rng::byte()` stubbed
// to a small constant (the wait-loop invariant is sweep-equivalent regardless
// of the value).
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
// The real NS-pointer validators. `pub(super)` items in the production file
// become visible at this crate's root (the file's parent), so the wrappers
// below can call them directly.
// ---------------------------------------------------------------------------

#[path = "../../../../secure/src/nsc/ptr_validate.rs"]
mod ptr_validate;

// ---------------------------------------------------------------------------
// Plain (unhardened) wrappers — what production currently runs at every
// gateway entry (via `NsPtr::validate_{read,write}`).
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_ns_validate_read(ptr: u32, len: u32) -> u32 {
    if ptr_validate::validate_ns_read_ptr(ptr, len as usize) {
        1
    } else {
        0
    }
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_ns_validate_write(ptr: u32, len: u32) -> u32 {
    if ptr_validate::validate_ns_write_ptr(ptr, len as usize) {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Hardened wrappers — `fi::check_true_into_sentinel` around the same
// predicate. Returns `OK_SENTINEL` (0xA5A5_A5A5) for accept, `FAIL_SENTINEL`
// (0x5A5A_5A5A) for reject. Caller compares to OK_SENTINEL rather than `!= 0`.
// Bit-equivalent to what the F-7 fix applies to verify_signature; here
// purely for evaluating "would the same pattern protect ptr_validate?".
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_ns_validate_read_fi(ptr: u32, len: u32) -> u32 {
    fi::check_true_into_sentinel(|| ptr_validate::validate_ns_read_ptr(ptr, len as usize))
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_ns_validate_write_fi(ptr: u32, len: u32) -> u32 {
    fi::check_true_into_sentinel(|| ptr_validate::validate_ns_write_ptr(ptr, len as usize))
}

// ---------------------------------------------------------------------------
// Keep-statics so cortex-m-rt's link.x doesn't `--gc-sections` away the
// `#[no_mangle]` exports.
// ---------------------------------------------------------------------------

#[used]
static _KEEP_R: extern "C" fn(u32, u32) -> u32 = sca_ns_validate_read;
#[used]
static _KEEP_W: extern "C" fn(u32, u32) -> u32 = sca_ns_validate_write;
#[used]
static _KEEP_R_FI: extern "C" fn(u32, u32) -> u32 = sca_ns_validate_read_fi;
#[used]
static _KEEP_W_FI: extern "C" fn(u32, u32) -> u32 = sca_ns_validate_write_fi;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_R);
    core::hint::black_box(&_KEEP_W);
    core::hint::black_box(&_KEEP_R_FI);
    core::hint::black_box(&_KEEP_W_FI);
    loop {
        cortex_m::asm::nop();
    }
}
