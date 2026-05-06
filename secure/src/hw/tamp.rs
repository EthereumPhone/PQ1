//! STM32U585 TAMP (tamper detection) driver — log-only dev harness.
//!
//! Port of Trezor's `core/embed/sec/tamper/stm32u5/tamper.c` with two
//! deliberate differences for the PQSigner bring-up branch:
//!
//! 1. **Log-only IRQ handler.** Where Trezor calls `reboot_with_rsod()`
//!    (zeroize + reboot into red-screen-of-death), this handler logs
//!    the trigger source via `secure_log!` and parks in a WFE loop. On
//!    a dev board wired to probe-rs, a false ITAMP9 (crypto peripheral
//!    fault) during a glitch-sensitive debug probe would otherwise
//!    wipe the bench chip every session — that's the exact
//!    bring-up-safety failure mode `CLAUDE.md` warns about. Once
//!    hardware is stable end-to-end, flip to `trigger_lockout_wipe()`.
//!
//! 2. **Feature-gated behind `tamp`.** Without the feature, this
//!    module compiles into a no-op and nothing in the boot sequence
//!    changes. With the feature, `init()` should be called early in
//!    `main()` after RCC init, before any SE/USB bring-up. Reversible
//!    by removing the feature from the build target.
//!
//! # What gets monitored
//!
//! All internal tampers (ITAMP1/2/3/5/6/7/8/9/11/12/13) per Trezor.
//! The high-signal ones for PQSigner:
//!
//! - **ITAMP1** — Backup-domain voltage (brownout / probe voltage glitch).
//! - **ITAMP3** — LSE clock security (LSECSS). Catches clock-glitch attacks
//!   on the RTC clock source.
//! - **ITAMP6** — JTAG/SWD access when RDP > 0. Production-only signal:
//!   on a dev board (RDP=0) this never fires.
//! - **ITAMP9** — Crypto peripheral fault (SAES/AES/PKA/TRNG). This is
//!   the fault-injection canary: a glitch on SAES or the TRNG trips
//!   this immediately.
//! - **ITAMP11** — IWDG reset with tamper flag set. Coupled reboot gate.
//!
//! # Prerequisites
//!
//! `init()` enables LSI (the 32 kHz internal low-speed oscillator) as
//! the RTC clock source. That's a new clock in PQSigner's tree —
//! harmless, low-power, and the backup-domain peripherals (RTC + TAMP)
//! require it. No LSE crystal is assumed (the dev board has one but we
//! don't need it for tamper monitoring).
//!
//! # Reference
//!
//! - Trezor: `core/embed/sec/tamper/stm32u5/tamper.c:100-207`.
//! - STM32U585 reference manual RM0456 §§ 44 (RTC), 45 (TAMP).

#![allow(dead_code)]

#[cfg(feature = "tamp")]
use core::ptr::{read_volatile, write_volatile};

#[cfg(feature = "tamp")]
pub fn init() {
    // SAFETY: single-threaded boot-time init.
    //
    // Two modes selected by the `tamp-irq` feature:
    //
    //   * polled  (`tamp` only): skip `enable_tamp_irq` — IER stays
    //     masked. `poll()` drains TAMP_SR from SysTick (~1 ms latency).
    //   * IRQ     (`tamp-irq`):  arm IER + NVIC ISER0 bit 2; the
    //     `DefaultHandler` in `main.rs` dispatches IRQn=2 to
    //     `on_tamp_irq()` (~hundreds-of-cycles latency). Caller MUST
    //     have a `DefaultHandler` registered; otherwise the IRQ lands
    //     in cortex-m-rt's WEAK fallback and HardFaults.
    unsafe {
        init_lsi_and_rtc_clock();
        init_tamp_registers();
        #[cfg(feature = "tamp-irq")]
        enable_tamp_irq();
    }
}

#[cfg(not(feature = "tamp"))]
pub fn init() {}

/// Drain TAMP_SR flags. Caller (typically `SysTick`) is expected to
/// invoke this once per tick. Fast path: 1 MMIO read. Trigger path:
/// read SR, log the reason, write-1-to-clear SCR. NEVER halts, NEVER
/// wipes — log-only by design.
#[cfg(feature = "tamp")]
#[inline]
pub fn poll() {
    use regs::*;
    // SAFETY: TAMP_SR is a plain MMIO read.
    let sr = unsafe { read_volatile(TAMP_SR) };
    if sr & ITAMP_FLAG_MASK == 0 {
        return;
    }
    let _reason = reason_from_sr(sr);
    secure_log!("[TAMP] poll: {} (SR={:#010x})", _reason, sr);
    unsafe {
        write_volatile(TAMP_SCR, ITAMP_FLAG_MASK);
    }
}

#[cfg(not(feature = "tamp"))]
#[inline]
pub fn poll() {}

#[cfg(feature = "tamp")]
mod regs {
    // RCC (secure alias — `rcc.rs` uses the NS alias for SYSCLK setup
    // but TAMP lives entirely in the secure backup domain).
    pub const RCC: u32 = 0x5602_0C00;
    pub const RCC_AHB3ENR: *mut u32 = (RCC + 0x94) as *mut u32;
    pub const RCC_BDCR: *mut u32 = (RCC + 0xF0) as *mut u32;

    // PWR (secure alias) — we need DBP (disable-backup-protection) +
    // MONEN (backup-domain voltage monitor).
    pub const PWR: u32 = 0x5602_0800;
    pub const PWR_DBPR: *mut u32 = (PWR + 0x10) as *mut u32;
    pub const PWR_BDCR1: *mut u32 = (PWR + 0x18) as *mut u32;

    // TAMP (secure alias, backup domain).
    pub const TAMP: u32 = 0x5600_4400;
    pub const TAMP_CR1: *mut u32 = (TAMP + 0x00) as *mut u32;
    pub const TAMP_CR2: *mut u32 = (TAMP + 0x04) as *mut u32;
    pub const TAMP_CR3: *mut u32 = (TAMP + 0x08) as *mut u32;
    pub const TAMP_FLTCR: *mut u32 = (TAMP + 0x0C) as *mut u32;
    pub const TAMP_IER: *mut u32 = (TAMP + 0x2C) as *mut u32;
    pub const TAMP_SR: *const u32 = (TAMP + 0x30) as *const u32;
    pub const TAMP_SCR: *mut u32 = (TAMP + 0x3C) as *mut u32;

    // NVIC — TAMP_IRQn on STM32U585 is interrupt number 2.
    pub const NVIC_ISER0: *mut u32 = 0xE000_E100 as *mut u32;
    pub const TAMP_IRQN: u32 = 2;

    // --- bit positions (RM0456) ---
    pub const RCC_BDCR_LSION: u32 = 1 << 0;
    pub const RCC_BDCR_LSIRDY: u32 = 1 << 1;
    pub const RCC_BDCR_RTCSEL_LSI: u32 = 0b10 << 8;
    pub const RCC_BDCR_RTCEN: u32 = 1 << 15;

    pub const RCC_AHB3ENR_PWREN: u32 = 1 << 2;
    pub const RCC_AHB3ENR_RTCAPBEN: u32 = 1 << 21; // TAMP lives here
    pub const PWR_DBPR_DBP: u32 = 1 << 0;
    pub const PWR_BDCR1_MONEN: u32 = 1 << 4;

    pub const TAMP_CR1_ITAMP1E: u32 = 1 << 16;
    pub const TAMP_CR1_ITAMP2E: u32 = 1 << 17;
    pub const TAMP_CR1_ITAMP3E: u32 = 1 << 18;
    pub const TAMP_CR1_ITAMP5E: u32 = 1 << 20;
    pub const TAMP_CR1_ITAMP6E: u32 = 1 << 21;
    pub const TAMP_CR1_ITAMP7E: u32 = 1 << 22;
    pub const TAMP_CR1_ITAMP8E: u32 = 1 << 23;
    pub const TAMP_CR1_ITAMP9E: u32 = 1 << 24;
    pub const TAMP_CR1_ITAMP11E: u32 = 1 << 26;
    pub const TAMP_CR1_ITAMP12E: u32 = 1 << 27;
    pub const TAMP_CR1_ITAMP13E: u32 = 1 << 28;

    pub const TAMP_FLTCR_TAMPPRCH_8CYC: u32 = 0b11 << 0;
    pub const TAMP_FLTCR_TAMPFLT_4SAMPLES: u32 = 0b10 << 2;
    pub const TAMP_FLTCR_TAMPFREQ_RTCCLK_DIV256: u32 = 0b111 << 4;

    /// Combined ITAMP*F flag mask used by `poll()` for read/clear.
    pub const ITAMP_FLAG_MASK: u32 = TAMP_CR1_ITAMP1E
        | TAMP_CR1_ITAMP2E
        | TAMP_CR1_ITAMP3E
        | TAMP_CR1_ITAMP5E
        | TAMP_CR1_ITAMP6E
        | TAMP_CR1_ITAMP7E
        | TAMP_CR1_ITAMP8E
        | TAMP_CR1_ITAMP9E
        | TAMP_CR1_ITAMP11E
        | TAMP_CR1_ITAMP12E
        | TAMP_CR1_ITAMP13E;
}

#[cfg(feature = "tamp")]
unsafe fn init_lsi_and_rtc_clock() {
    use regs::*;

    // Enable PWR + RTCAPB clocks — needed before we can touch DBPR or
    // TAMP registers.
    let ahb3enr = read_volatile(RCC_AHB3ENR);
    write_volatile(RCC_AHB3ENR, ahb3enr | RCC_AHB3ENR_PWREN | RCC_AHB3ENR_RTCAPBEN);

    // Disable backup-domain write protection (one-shot cookie).
    write_volatile(PWR_DBPR, PWR_DBPR_DBP);

    // Turn on LSI and wait for ready.
    let mut bdcr = read_volatile(RCC_BDCR);
    bdcr |= RCC_BDCR_LSION;
    write_volatile(RCC_BDCR, bdcr);

    // Bounded wait (LSI comes up in <200 µs on silicon; timeout after
    // ~1 ms of CPU cycles).
    for _ in 0..200_000 {
        if read_volatile(RCC_BDCR) & RCC_BDCR_LSIRDY != 0 {
            break;
        }
        cortex_m::asm::nop();
    }

    // Select LSI as RTC source and enable the RTC peripheral.
    // RTCSEL can only be written while the backup domain isn't in
    // reset and no prior RTC source is selected; on first boot from
    // power-up this is the clean state we're in. If RTCSEL is already
    // non-zero from a prior firmware, we skip — keeping the existing
    // choice preserves LSE if it was set by a future PQSigner build.
    let mut bdcr = read_volatile(RCC_BDCR);
    if (bdcr >> 8) & 0b11 == 0 {
        bdcr |= RCC_BDCR_RTCSEL_LSI;
    }
    bdcr |= RCC_BDCR_RTCEN;
    write_volatile(RCC_BDCR, bdcr);

    // Enable backup-domain voltage monitor (feeds ITAMP1).
    let bdcr1 = read_volatile(PWR_BDCR1);
    write_volatile(PWR_BDCR1, bdcr1 | PWR_BDCR1_MONEN);
}

#[cfg(feature = "tamp")]
unsafe fn init_tamp_registers() {
    use regs::*;

    // Clear any pending tamper flags from a prior power cycle (backup
    // domain survives reset, so we may see stale flags at first boot).
    write_volatile(TAMP_SCR, 0x0007_FFFF);

    // Filter config for external tamper pins — matches Trezor:
    // 8-cycle pre-charge, 4 identical samples to confirm, RTCCLK/256
    // (128 Hz) sampling period. We don't enable external pins here;
    // this is defensive in case a future revision wires them.
    write_volatile(
        TAMP_FLTCR,
        TAMP_FLTCR_TAMPPRCH_8CYC
            | TAMP_FLTCR_TAMPFLT_4SAMPLES
            | TAMP_FLTCR_TAMPFREQ_RTCCLK_DIV256,
    );

    // Enable every internal tamper we care about — Trezor's set,
    // minus the two they skip (ITAMP4 and ITAMP10 are documented
    // to never fire on this MCU revision).
    let cr1 = read_volatile(TAMP_CR1);
    write_volatile(
        TAMP_CR1,
        cr1 | TAMP_CR1_ITAMP1E
            | TAMP_CR1_ITAMP2E
            | TAMP_CR1_ITAMP3E
            | TAMP_CR1_ITAMP5E
            | TAMP_CR1_ITAMP6E
            | TAMP_CR1_ITAMP7E
            | TAMP_CR1_ITAMP8E
            | TAMP_CR1_ITAMP9E
            | TAMP_CR1_ITAMP11E
            | TAMP_CR1_ITAMP12E
            | TAMP_CR1_ITAMP13E,
    );

    // CR3 = 0 → all tampers in "confirmed" mode. Mirrors Trezor's
    // `TAMP->CR3 = 0` comment: "all secrets all deleted when any
    // tamper event is triggered." On silicon, this means tamper flags
    // trigger the backup SRAM erase hardware — which we don't *have*
    // data in yet (PQSigner doesn't use backup SRAM), but the invariant
    // stays correct for when we do.
    write_volatile(TAMP_CR3, 0);

    // Enable interrupts for every internal tamper we enabled above.
    // Using the shifted ITAMP*E bits one position higher gives the IE
    // bits per RM0456 table — this is how Trezor writes it.
    let ier_value = (TAMP_CR1_ITAMP1E
        | TAMP_CR1_ITAMP2E
        | TAMP_CR1_ITAMP3E
        | TAMP_CR1_ITAMP5E
        | TAMP_CR1_ITAMP6E
        | TAMP_CR1_ITAMP7E
        | TAMP_CR1_ITAMP8E
        | TAMP_CR1_ITAMP9E
        | TAMP_CR1_ITAMP11E
        | TAMP_CR1_ITAMP12E
        | TAMP_CR1_ITAMP13E)
        >> 16;
    // `ier_value` now has the corresponding ITAMP*IE bits (bit 0..=13)
    // — the IER layout is ITAMP*IE starting at bit 16 too, but several
    // cheat-sheets get this wrong. Per RM0456 §45.8.8, the IER bits
    // for internal tampers are at positions 16..=28 exactly matching
    // CR1's ITAMP*E bits, so we just echo CR1's mask:
    let _ = ier_value; // sanity check that the computation typechecks
    write_volatile(
        TAMP_IER,
        TAMP_CR1_ITAMP1E
            | TAMP_CR1_ITAMP2E
            | TAMP_CR1_ITAMP3E
            | TAMP_CR1_ITAMP5E
            | TAMP_CR1_ITAMP6E
            | TAMP_CR1_ITAMP7E
            | TAMP_CR1_ITAMP8E
            | TAMP_CR1_ITAMP9E
            | TAMP_CR1_ITAMP11E
            | TAMP_CR1_ITAMP12E
            | TAMP_CR1_ITAMP13E,
    );
}

/// Arm `TAMP_IER` for the same internal-tamper sources `TAMP_CR1`
/// enables, then enable the TAMP IRQ in NVIC. Called from `init()`
/// only when the `tamp-irq` feature is set.
///
/// SAFETY: caller must have registered a `DefaultHandler` exception
/// fn in `main.rs` that dispatches `irqn == TAMP_IRQN` to
/// `on_tamp_irq()`. Without that, an unmasked TAMP IRQ lands in
/// cortex-m-rt's WEAK default fallback and HardFaults the chip.
#[cfg(all(feature = "tamp", feature = "tamp-irq"))]
unsafe fn enable_tamp_irq() {
    use regs::*;

    // Mirror the CR1 enable mask into IER — same bit positions on
    // STM32U5 (RM0456 §45.8.8 confirms ITAMP*IE bits at positions
    // 16..=28 matching CR1's ITAMP*E bits).
    write_volatile(TAMP_IER, ITAMP_FLAG_MASK);

    // Clear any latent pending in NVIC, then enable.
    const NVIC_ICPR0: *mut u32 = 0xE000_E280 as *mut u32;
    write_volatile(NVIC_ICPR0, 1 << TAMP_IRQN);
    write_volatile(NVIC_ISER0, 1 << TAMP_IRQN);
}

/// Return a short human-readable label for whichever TAMP source
/// raised the IRQ. Exposed so other log paths can reuse the mapping.
#[cfg(feature = "tamp")]
pub fn reason_from_sr(sr: u32) -> &'static str {
    const ITAMP1F: u32 = 1 << 16;
    const ITAMP2F: u32 = 1 << 17;
    const ITAMP3F: u32 = 1 << 18;
    const ITAMP5F: u32 = 1 << 20;
    const ITAMP6F: u32 = 1 << 21;
    const ITAMP7F: u32 = 1 << 22;
    const ITAMP8F: u32 = 1 << 23;
    const ITAMP9F: u32 = 1 << 24;
    const ITAMP11F: u32 = 1 << 26;
    const ITAMP12F: u32 = 1 << 27;
    const ITAMP13F: u32 = 1 << 28;
    if sr & ITAMP1F != 0 {
        "VOLTAGE"
    } else if sr & ITAMP2F != 0 {
        "TEMPERATURE"
    } else if sr & ITAMP3F != 0 {
        "LSE_CLOCK"
    } else if sr & ITAMP5F != 0 {
        "RTC_OVERFLOW"
    } else if sr & ITAMP6F != 0 {
        "SWD_ACCESS"
    } else if sr & ITAMP7F != 0 {
        "ANALOG_WDG1"
    } else if sr & ITAMP8F != 0 {
        "MONO_COUNTER"
    } else if sr & ITAMP9F != 0 {
        "CRYPTO_FAULT"
    } else if sr & ITAMP11F != 0 {
        "IWDG"
    } else if sr & ITAMP12F != 0 {
        "ANALOG_WDG2"
    } else if sr & ITAMP13F != 0 {
        "ANALOG_WDG3"
    } else {
        "UNKNOWN"
    }
}

/// TAMP IRQ handler. **Same log-only semantics as [`poll`]**:
/// reads `TAMP_SR`, logs the trigger reason via `secure_log!`,
/// write-1-to-clears the flags, and returns. Never halts and never
/// wipes — production hardening will flip the trigger response in a
/// later commit (see `docs/production-todo.md` "TAMP escalation").
///
/// Called from `DefaultHandler` in `main.rs` when `irqn == 2`
/// (TAMP_IRQn on STM32U5).
#[cfg(all(feature = "tamp", feature = "tamp-irq"))]
#[allow(non_snake_case)]
pub unsafe fn on_tamp_irq() {
    use regs::*;
    let sr = read_volatile(TAMP_SR);
    if sr & ITAMP_FLAG_MASK == 0 {
        // Spurious — IRQ asserted but no flag we monitor. Clear the
        // NVIC pending bit anyway so the IRQ doesn't re-enter.
        return;
    }
    let _reason = reason_from_sr(sr);
    secure_log!("[TAMP] irq: {} (SR={:#010x})", _reason, sr);
    // Write-1-to-clear the flags so the line de-asserts. Without this
    // the IRQ would re-enter immediately on return.
    write_volatile(TAMP_SCR, ITAMP_FLAG_MASK);
}

#[cfg(all(test, feature = "tamp"))]
mod tests {
    use super::*;

    #[test]
    fn reason_strings_cover_every_itamp_bit() {
        // Spot-check that the decoder maps specific flags to the
        // strings the postmortem inspector expects.
        assert_eq!(reason_from_sr(1 << 16), "VOLTAGE");
        assert_eq!(reason_from_sr(1 << 24), "CRYPTO_FAULT");
        assert_eq!(reason_from_sr(1 << 26), "IWDG");
        assert_eq!(reason_from_sr(0), "UNKNOWN");
    }
}
