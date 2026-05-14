//! Fault-sweep target for `tools/sca/fault_sweep_cap.py` — mirrors the
//! off-chain gap + combined-cap enforcement gates in
//! `secure/src/nsc/cmd_sign_offchain.rs:202-223`. These two checks bound
//! how many SPHINCS+C10 signatures a single slot key produces on a single
//! chain: a fault that bypasses either gate erodes the structural
//! 65,536-signatures-per-slot-per-chain invariant that bounds the
//! SPHINCS+ subset-resilience margin AND the FORS-leaf-index F-9 leakage
//! exposure.
//!
//! Production checks (verbatim from cmd_sign_offchain.rs):
//!
//! ```ignore
//! let gap = local_offchain.saturating_sub(last_userop);
//! if gap >= MAX_OFFCHAIN_GAP {           // = 100
//!     return NscStatus::OffchainGapExceeded as u32;
//! }
//! let new_count = match local_offchain.checked_add(1) {
//!     Some(v) => v,
//!     None => return NscStatus::OffchainCapExceeded as u32,
//! };
//! if new_count > MAX_SLOT_USES {         // = 65_536
//!     return NscStatus::OffchainCapExceeded as u32;
//! }
//! // ... proceed to sign ...
//! ```
//!
//! Entry-points:
//!   - `sca_cap_check_plain` — the predicates verbatim, returning u32:
//!       0 → accept (both pass), proceed to sign
//!       1 → gap rejected
//!       2 → cap rejected (overflow OR > MAX_SLOT_USES)
//!   - `sca_cap_check_fi` — same predicates, but each gate is wrapped in
//!     `fi::check_true_into_sentinel` so a single skip/stuck-at can't flip
//!     a reject into an accept. Same return values + the sentinel-encoded
//!     accept path. Bit-equivalent to what the production code WOULD look
//!     like after F-7/F-8-style hardening.
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

const MAX_OFFCHAIN_GAP: u64 = 100;
const MAX_SLOT_USES: u64 = 65_536;

// ---------------------------------------------------------------------------
// FI helpers — re-export from pqsigner-fi. The secure-side fi.rs uses these
// + a TRNG closure; here the analog is a fixed RNG (FSBL-style, deterministic
// 0x42 — the wait-random invariant still catches mid-loop glitches; only
// attacker retiming benefits from real randomness).
// ---------------------------------------------------------------------------

#[inline(never)]
fn wait_random() {
    pqsigner_fi::wait_random_loop(|| 0x42);
}

#[inline(never)]
fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}

// ---------------------------------------------------------------------------
// Plain (unhardened) mirror — what production currently runs.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_cap_check_plain(local_offchain: u64, last_userop: u64) -> u32 {
    let gap = local_offchain.saturating_sub(last_userop);
    if gap >= MAX_OFFCHAIN_GAP {
        return 1; // OffchainGapExceeded
    }
    let new_count = match local_offchain.checked_add(1) {
        Some(v) => v,
        None => return 2, // OffchainCapExceeded (overflow)
    };
    if new_count > MAX_SLOT_USES {
        return 2; // OffchainCapExceeded
    }
    0 // accept — proceed to sign
}

// ---------------------------------------------------------------------------
// FI-hardened mirror — verify-twice + double sentinel check, same pattern as
// the F-8 fix in NsPtr::validate_*. Single-wrap (as the F-7 fix had) is
// empirically NOT enough: the caller's `!= OK_SENTINEL { reject }` cmp+branch
// is itself a one-skip route. Verifying TWICE with wait_random between, and
// checking each verdict independently, raises the bar to ~2 coordinated faults
// per gate — same residual as F-5 for the rest of the firmware.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_cap_check_fi(local_offchain: u64, last_userop: u64) -> u32 {
    let gap = local_offchain.saturating_sub(last_userop);

    // Gate 1, first verification.
    let g1 = check_true_into_sentinel(|| gap < MAX_OFFCHAIN_GAP);
    if g1 != pqsigner_fi::OK_SENTINEL {
        return 1;
    }
    wait_random();
    // Gate 1, second independent verification.
    let g2 = check_true_into_sentinel(|| gap < MAX_OFFCHAIN_GAP);
    if g2 != pqsigner_fi::OK_SENTINEL {
        return 1;
    }

    let new_count = match local_offchain.checked_add(1) {
        Some(v) => v,
        None => return 2,
    };

    // Gate 2, first verification.
    let c1 = check_true_into_sentinel(|| new_count <= MAX_SLOT_USES);
    if c1 != pqsigner_fi::OK_SENTINEL {
        return 2;
    }
    wait_random();
    // Gate 2, second independent verification.
    let c2 = check_true_into_sentinel(|| new_count <= MAX_SLOT_USES);
    if c2 != pqsigner_fi::OK_SENTINEL {
        return 2;
    }

    0
}

// ---------------------------------------------------------------------------
// F-10 PRODUCTION call-site mirror. The actual F-10 fix lives in
// `secure/src/nsc/cmd_sign_offchain.rs` and uses input-register
// redundancy (double-read the inputs with wait_random between, halt on
// mismatch) + a post-derivation recheck. This entry-point mirrors that
// shape so the sweep can show that it closes the residuals the
// gate-only `sca_cap_check_fi` leaves open.
//
// Status codes (matched to NscStatus):
//   0  → accept (proceed to sign)
//   1  → OffchainGapExceeded (correct reject)
//   2  → OffchainCapExceeded (correct reject)
//   3  → InternalError (glitch detected → fail-closed)
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_cap_check_callsite_fi(local_offchain: u64, last_userop: u64) -> u32 {
    // Input-register redundancy: re-read each value with wait_random
    // between, halt on mismatch. (In production, each "read" is a real
    // `offchain_count_read` call that re-scans flash from scratch.)
    let lu_a = core::hint::black_box(last_userop);
    wait_random();
    let lu_b = core::hint::black_box(last_userop);
    if lu_a != lu_b {
        return 3;
    }
    let lo_a = core::hint::black_box(local_offchain);
    wait_random();
    let lo_b = core::hint::black_box(local_offchain);
    if lo_a != lo_b {
        return 3;
    }
    let local = lo_a;
    let last = lu_a;

    let gap = local.saturating_sub(last);
    if gap >= MAX_OFFCHAIN_GAP {
        return 1;
    }
    let new_count = match local.checked_add(1) {
        Some(v) => v,
        None => return 2,
    };
    if new_count > MAX_SLOT_USES {
        return 2;
    }

    // F-10 belt-and-braces: recheck the gates with re-read inputs.
    wait_random();
    let local_r = core::hint::black_box(local_offchain);
    let last_r = core::hint::black_box(last_userop);
    let gap_r = local_r.saturating_sub(last_r);
    let new_r = match local_r.checked_add(1) {
        Some(v) => v,
        None => return 3,
    };
    if gap_r >= MAX_OFFCHAIN_GAP {
        return 3;
    }
    if new_r > MAX_SLOT_USES {
        return 3;
    }
    if gap_r != gap || new_r != new_count {
        return 3;
    }

    0
}

#[used]
static _KEEP_PLAIN: extern "C" fn(u64, u64) -> u32 = sca_cap_check_plain;
#[used]
static _KEEP_FI: extern "C" fn(u64, u64) -> u32 = sca_cap_check_fi;
#[used]
static _KEEP_CALLSITE: extern "C" fn(u64, u64) -> u32 = sca_cap_check_callsite_fi;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_PLAIN);
    core::hint::black_box(&_KEEP_FI);
    core::hint::black_box(&_KEEP_CALLSITE);
    loop {
        cortex_m::asm::nop();
    }
}
