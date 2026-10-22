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

/// Software half of the dev crosscheck (`hw-sha256-crosscheck`): the driver
/// mirrors every digest here and faults on a difference. It lives in this
/// world because `sha2` is already a dependency here, so the shared driver
/// crate takes no new edge and `Cargo.lock` does not move. SOAK EVIDENCE
/// ONLY — a second, unzeroized copy of every preimage, compared in variable
/// time; fenced out of production in `nsc/mod.rs`.
#[cfg(feature = "hw-sha256-crosscheck")]
mod xcheck {
    use sha2::{Digest, Sha256};

    static mut SW: Option<Sha256> = None;

    fn sw() -> &'static mut Option<Sha256> {
        // SAFETY: category 5 — called only from the hash hooks, which are
        // serialised by their FFI contract on a single-threaded world; each
        // caller drops this borrow before returning.
        unsafe { &mut *core::ptr::addr_of_mut!(SW) }
    }

    #[no_mangle]
    pub extern "C" fn pqsigner_xcheck_begin() {
        *sw() = Some(Sha256::new());
    }

    /// # Safety
    /// `ptr..ptr + len` is a live byte slice for the call (the driver passes
    /// its own `update` arguments through).
    #[no_mangle]
    pub unsafe extern "C" fn pqsigner_xcheck_feed(ptr: *const u8, len: usize) {
        // SAFETY: category 3 — the caller's contract above.
        let data = unsafe { core::slice::from_raw_parts(ptr, len) };
        if let Some(h) = sw().as_mut() {
            h.update(data);
        }
    }

    /// # Safety
    /// `digest` names 32 readable bytes (the driver's `final` output).
    #[no_mangle]
    pub unsafe extern "C" fn pqsigner_xcheck_same(digest: *const u8) -> bool {
        // SAFETY: category 3 — the caller's contract above.
        let hw = unsafe { &*digest.cast::<[u8; 32]>() };
        sw().take().is_some_and(|h| h.finalize()[..] == hw[..])
    }
}
