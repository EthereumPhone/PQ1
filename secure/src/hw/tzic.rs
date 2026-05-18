//! GTZC1 TZIC — TrustZone Illegal-access Controller.
//!
//! When NS attempts to access a peripheral marked SECURE in
//! `TZSC_SECCFGRx`, the AHB bridge gates the access (read returns 0,
//! write is ignored). If the matching `TZIC_IERx` bit is set, the
//! controller raises NVIC IRQ 8 (`GTZC_IRQn` on STM32U585). Without
//! TZIC, an illegal access is silent — this module is the *measurement
//! instrument* that proves GTZC enforcement is working.
//!
//! Bit positions in `IERx` / `SRx` / `FCRx` match `TZSC_SECCFGRx` 1:1
//! for the same peripheral, so the same masks `sau::stm32` builds for
//! SECCFGR are reused as IER masks.
//!
//! Production behaviour (today, slice-1 of the GTZC hardening): log
//! the offender via `secure_log!` and increment a counter. The
//! follow-up commit replaces the body of [`on_violation`] with a
//! lockout-wipe + reboot once TAMP has been moved off log-only — see
//! `docs/production-todo.md` §"GTZC1 TZSC ... validation".

use crate::hw::mmio::{Reg32, RoReg32};

/// NVIC interrupt number for GTZC1 illegal-access on STM32U585.
/// Confirmed against CMSIS `stm32u585xx.h` (`GTZC_IRQn = 8`).
pub const GTZC_IRQN: u32 = 8;

const TZIC_BASE: u32 = 0x5003_2800;

struct Regs {
    ier1: Reg32,
    ier2: Reg32,
    ier3: Reg32,
    ier4: Reg32,
    sr1: RoReg32,
    sr2: RoReg32,
    sr3: RoReg32,
    sr4: RoReg32,
    fcr1: Reg32,
    fcr2: Reg32,
    fcr3: Reg32,
    fcr4: Reg32,
    nvic_iser0: Reg32,
    nvic_icpr0: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned STM32U585 MMIO
// register owned exclusively by this driver. TZIC + NVIC ISER0/ICPR0
// are touched from the single-threaded boot path and from the GTZC IRQ
// handler — those are mutually exclusive (the IRQ is unmasked after
// `configure()` returns).
const REG: Regs = unsafe {
    Regs {
        ier1: Reg32::new(TZIC_BASE + 0x00),
        ier2: Reg32::new(TZIC_BASE + 0x04),
        ier3: Reg32::new(TZIC_BASE + 0x08),
        ier4: Reg32::new(TZIC_BASE + 0x0C),
        sr1: RoReg32::new(TZIC_BASE + 0x10),
        sr2: RoReg32::new(TZIC_BASE + 0x14),
        sr3: RoReg32::new(TZIC_BASE + 0x18),
        sr4: RoReg32::new(TZIC_BASE + 0x1C),
        fcr1: Reg32::new(TZIC_BASE + 0x20),
        fcr2: Reg32::new(TZIC_BASE + 0x24),
        fcr3: Reg32::new(TZIC_BASE + 0x28),
        fcr4: Reg32::new(TZIC_BASE + 0x2C),
        nvic_iser0: Reg32::new(0xE000_E100),
        nvic_icpr0: Reg32::new(0xE000_E280),
    }
};

/// Running count of illegal-access events seen since boot. Read from
/// the gateway via [`violation_count`] for the validation test.
///
/// Single-threaded secure world + the IRQ is the only writer; readers
/// from thread mode see a monotonically increasing value.
static mut VIOLATION_COUNT: u32 = 0;

/// Last-seen SR snapshot per bank (so the test harness can identify
/// which peripheral triggered the most recent IRQ even after FCR has
/// cleared the live SR).
static mut LAST_SR: [u32; 4] = [0; 4];

/// Test-only: enable the AHB2 clocks for AES, PKA, SAES so the
/// `gtzc-test` validation driver can exercise GTZC enforcement on
/// all three. Without their clocks running, those peripherals are
/// not present on the bus matrix: NS reads RAZ via the default-
/// no-responder path and TZIC never fires, indistinguishable from
/// a successful block. HASH and RNG are already clocked by boot
/// init (HASH self-test + TRNG init), so this only adds the three
/// that the production firmware never enables.
///
/// Gated on `e2e-test`. Production firmware leaves these clocks
/// off by design — wasted power + unnecessary attack surface for
/// peripherals nothing in the secure world currently drives.
///
/// RCC_AHB2ENR1 bit positions per CMSIS `stm32u585xx.h`:
/// AES=16, PKA=19, SAES=20.
#[cfg(feature = "e2e-test")]
pub fn enable_test_target_clocks() {
    // RCC is on AHB3 at `0x5602_0C00`; AHB2ENR1 is offset `0x8C`.
    // SAFETY: real 4-byte-aligned MMIO register, owned by the
    // single-threaded boot path.
    let rcc_ahb2enr1 = unsafe { Reg32::new(0x5602_0C00 + 0x8C) };
    rcc_ahb2enr1.set_bits((1 << 16) | (1 << 19) | (1 << 20));
    cortex_m::asm::dsb();
}

/// Enable illegal-access IRQ for the peripherals marked SECURE in
/// `seccfgr{1,2,3,4}`. Caller passes the same masks `sau::stm32`
/// just wrote to TZSC — bit positions are identical between the two
/// register banks.
pub fn configure(seccfgr1: u32, seccfgr2: u32, seccfgr3: u32, seccfgr4: u32) {
    REG.ier1.write(seccfgr1);
    REG.ier2.write(seccfgr2);
    REG.ier3.write(seccfgr3);
    REG.ier4.write(seccfgr4);

    // Clear any latent SR flags from before IER was unmasked. FCR is
    // write-1-to-clear.
    REG.fcr1.write(0xFFFF_FFFF);
    REG.fcr2.write(0xFFFF_FFFF);
    REG.fcr3.write(0xFFFF_FFFF);
    REG.fcr4.write(0xFFFF_FFFF);
    cortex_m::asm::dsb();

    // Unmask GTZC IRQ in NVIC. Clear pending first to avoid taking a
    // spurious IRQ from a latent pending bit set during reset.
    REG.nvic_icpr0.write(1 << GTZC_IRQN);
    REG.nvic_iser0.write(1 << GTZC_IRQN);
}

/// GTZC1 illegal-access IRQ handler. Read all four SRs, snapshot
/// them, write-1-to-clear via FCR, bump the counter. Under
/// `tzic-wipe`, also fire the production escalation (zeroize +
/// arm + reset). Must be dispatched from `DefaultHandler` on
/// `irqn == GTZC_IRQN`.
///
/// Intentionally **no `secure_log!` from this body** — semihosting
/// `BKPT 0xAB` from IRQ context can re-trigger a fault (the
/// semihosting host-side stub is dispatched in a way that's
/// sensitive to ICI/IT state and banked-MSP/PSP, and an aborted
/// BKPT inside an IRQ handler chains to SecureFault on STM32U5).
/// The counter + LAST_SR snapshot is read out by NS via
/// `nsc_tzic_status`; that path is thread-mode and logs cleanly.
///
/// # Safety
/// Only call from exception context for IRQ 8.
pub unsafe fn on_violation() {
    let s1 = REG.sr1.read();
    let s2 = REG.sr2.read();
    let s3 = REG.sr3.read();
    let s4 = REG.sr4.read();

    // Snapshot for thread-mode readback. Single-threaded secure
    // world; the IRQ pre-empts thread mode but doesn't re-enter
    // itself, so this is a series of plain stores.
    unsafe {
        let last = core::ptr::addr_of_mut!(LAST_SR);
        (*last)[0] = s1;
        (*last)[1] = s2;
        (*last)[2] = s3;
        (*last)[3] = s4;
        let n = core::ptr::read_volatile(core::ptr::addr_of!(VIOLATION_COUNT));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(VIOLATION_COUNT), n.wrapping_add(1));
    }

    // Write-1-to-clear all SR flags so the IRQ line de-asserts.
    // Writing FCR for a bank that had SR=0 is a no-op.
    REG.fcr1.write(s1);
    REG.fcr2.write(s2);
    REG.fcr3.write(s3);
    REG.fcr4.write(s4);
    cortex_m::asm::dsb();

    // Production escalation: a single illegal NS→S access is a
    // tamper-class event. Wipe the SRAM secrets immediately
    // (latency-critical — residual-power side channels), arm the
    // flash wipe flag so the next boot finishes the full SE
    // factory_reset + page-124 erase, then reset. The next boot's
    // wipe-resume path in `main.rs:909` drives the slow part of
    // the wipe (SE I2C work, ~seconds) under thread mode.
    //
    // Gated OFF by default while the IRQ wiring soaks; the
    // `gtzc-enforcement-hw` validation test requires it off so
    // it can trip 7 violations and read the counter back.
    #[cfg(feature = "tzic-wipe")]
    unsafe {
        trigger_tzic_wipe();
    }
}

/// Production wipe sequence triggered from the TZIC IRQ. Never
/// returns — calls `SCB::sys_reset` after staging.
///
/// Order matters: SRAM zeroize first (microseconds — racing
/// residual-power side channels), then flash arm (single
/// 1→0 quadword bit-clear on page 125 QW1 — atomic at the
/// quadword granularity), then reset.
///
/// Does NOT call `ui::show_status` — UI access from IRQ context
/// would touch I2C/SPI drivers whose state machines are not
/// re-entrant against thread-mode use, and one failure mode
/// caught during slice 1 bring-up was IRQ-context semihosting
/// chaining to SecureFault. The "WIPING — do not power off"
/// status text shows on the next boot's wipe-resume path
/// (`main.rs:937`).
///
/// # Safety
/// Caller is in IRQ context; `crate::SE` and `state::SecureState`
/// are accessed under the single-threaded secure-world invariant
/// (IRQ pre-empts thread mode but doesn't re-enter itself, and
/// we never return to thread mode).
#[cfg(feature = "tzic-wipe")]
unsafe fn trigger_tzic_wipe() -> ! {
    // 1. Zero every secret in SRAM. Microseconds — drains the
    //    cache before any residual-power side channel can read
    //    it. Same primitive `cmd_request_unlock::trigger_lockout_wipe`
    //    uses.
    crate::nsc::zeroize_sensitive_state();

    // 2. Arm the persistent wipe-in-progress flag (page 125 QW1).
    //    On next boot, `main.rs:909-945` reads `is_wipe_armed()`
    //    and calls `factory_reset_admin` to wipe both SEs +
    //    erase page 124. The flag is cleared as part of that
    //    routine.
    //
    //    SAFETY: arm_wipe_flag is a single QW write to the
    //    dedicated flag slot; idempotent if already armed.
    //    Failure here is non-fatal — we still reset; worst case
    //    the SEs aren't wiped on the next boot but SRAM is
    //    gone and the chip is unprovisioned.
    let _ = unsafe { crate::hw::flash::arm_wipe_flag() };

    // 3. Reset. cortex-m's SCB::sys_reset writes the VECTKEY +
    //    SYSRESETREQ pattern to AIRCR and loops on NOP until the
    //    reset takes effect. Under `probe-rs run` the reset is
    //    intercepted by vector-catch — that surfaces as an
    //    "Exception" report but is the expected success state
    //    (the chip *did* reset; probe-rs just caught it before
    //    re-execution). On a stand-alone power-up the chip
    //    reboots normally and the boot-time wipe-resume path
    //    drives the SE wipe.
    cortex_m::peripheral::SCB::sys_reset();
}

/// Total illegal-access events since boot. Stable read from thread
/// mode (the IRQ is the only writer; it pre-empts thread mode but
/// `wrapping_add` is one store).
pub fn violation_count() -> u32 {
    // SAFETY: single-threaded secure world; read of a `u32` is atomic
    // on Cortex-M33. `read_volatile` to keep the compiler from
    // hoisting it past the IRQ-fence implied by the caller's logic.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VIOLATION_COUNT)) }
}

/// Last-seen SR snapshot per bank. Index 0..3 corresponds to SR1..SR4.
pub fn last_sr() -> [u32; 4] {
    // SAFETY: see [`violation_count`].
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LAST_SR)) }
}

/// Identify the first peripheral set in a SECCFGR1/IER1/SR1 mask.
/// Currently unused (the IRQ handler no longer logs from IRQ context;
/// see [`on_violation`]). Kept around for the future thread-mode
/// `[S][TZIC]` polling path that will replace the in-IRQ log.
#[allow(dead_code)]
fn label_bank1(sr: u32) -> &'static str {
    // SECCFGR1 / IER1 (APB1) — bit positions per CMSIS
    // `GTZC_CFGR1_*_Pos`. We only enable I2C1 (bit 13) and I2C2
    // (bit 14) on this branch; cover those plus a couple of
    // common neighbours so a stray illegal access elsewhere is
    // still legible.
    if sr & (1 << 13) != 0 { return "I2C1"; }
    if sr & (1 << 14) != 0 { return "I2C2"; }
    "(APB1)"
}

/// Same as [`label_bank1`] but for SECCFGR3/IER3/SR3 (AHB2).
#[allow(dead_code)]
fn label_bank3(sr: u32) -> &'static str {
    // SECCFGR3 / IER3 (AHB2) — bit positions per CMSIS
    // `GTZC_CFGR3_*_Pos`.
    if sr & (1 << 10) != 0 { return "OTG"; }
    if sr & (1 << 11) != 0 { return "AES"; }
    if sr & (1 << 12) != 0 { return "HASH"; }
    if sr & (1 << 13) != 0 { return "RNG"; }
    if sr & (1 << 14) != 0 { return "PKA"; }
    if sr & (1 << 15) != 0 { return "SAES"; }
    "(AHB2)"
}
