//! Re-export shim over [`pqsigner_hw::hash`], plus this world's HASH-fault
//! posture.
//!
//! The driver moved to the `pqsigner-hw` workspace crate on 2026-09-28 so the
//! FSBL uses the same code rather than a second copy (#758 option (d)):
//! `sha2::compress256` is 7,202 B of a 32 KiB FSBL image that had 2,048 B
//! free. A duplicated 400-line driver for the peripheral that MEASURES the
//! firmware is precisely the two-drifting-copies defect this tree keeps
//! finding.
//!
//! What stays here is the part that is genuinely world-specific: what to do
//! when the engine wedges.

pub use pqsigner_hw::hash::{
    init_clock, pqsigner_sha256_final, pqsigner_sha256_init, pqsigner_sha256_update,
};

/// **H-1 (Trezor-port) — a wedged HASH engine must fail LOUD, not silently
/// return a stale digest.**
///
/// The STM32U5 HASH peripheral exposes NO hardware fault flag (`HASH_SR`
/// carries only DINIS/DCIS/BUSY), so a stuck engine can only be observed as a
/// completion-wait that never finishes. The old timeout paths just `return`ed,
/// leaving the caller's `out` buffer untouched (stale prior digest / stack
/// garbage). `sphincs-c10` would then consume that non-digest, and because the
/// same engine feeds sign_a, sign_b AND the verify-before-release, all three
/// could ingest the same bad value — silently defeating the FI double-compute.
///
/// We route the fault to the SAME posture as the `HardFault` handler
/// (`main.rs`, rr-1): wipe every in-SRAM secret cache, barrier, then
/// `sys_reset()`. A hash that timed out mid-signature has no safe
/// continuation, and parking with `wfe` (as the boot KAT does, where no secret
/// exists yet) would strand `master_secret` + the cached slot key live in SRAM
/// through the idle window — exactly the exposure rr-1 closes. A reset
/// re-zeroes `.bss` and the FSBL re-verifies the active slot before any secret
/// is reconstructed from the PIN.
///
/// (If the engine is wedged at *boot* — inside the self-test's `init` →
/// `wait_ready` — this reset-loops instead of halting; a HASH engine that
/// cannot leave BUSY at cold boot is a dead device either way, and a reset
/// retry is the right response to a possibly-transient stall.)
///
/// The FSBL supplies its own version of this symbol: it holds no secrets yet,
/// so it halts instead of resetting, and resetting would loop it forever.
#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    crate::nsc::zeroize_sensitive_state();
    crate::fi::zeroize_barrier();
    cortex_m::peripheral::SCB::sys_reset()
}
