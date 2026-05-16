//! `CMD_TZIC_STATUS` — read the GTZC1 TZIC illegal-access counter.
//!
//! Returns the running count of NS→SECURE access violations since
//! boot. Each illegal access (NS read/write of a peripheral marked
//! SECURE in `TZSC_SECCFGRx`) raises NVIC IRQ 8, which lands in
//! `hw::tzic::on_violation` and bumps the counter.
//!
//! Test-only gateway command: lets the `gtzc-test` NS-side driver
//! probe each protected NS-alias address and assert that GTZC1 +
//! TZIC enforcement is wired up correctly. No secret state is
//! touched; the counter is plain `u32` bookkeeping.

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Body reads a
/// SECURE-world static through `read_volatile`; no NS pointer derefs.
pub(super) unsafe fn run() -> u32 {
    crate::hw::tzic::violation_count()
}
