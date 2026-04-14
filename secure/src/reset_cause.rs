//! Reset-cause classification via RCC_CSR.
//!
//! Read once at the very top of boot, before any peripheral init, so we
//! can dispatch on *why* the chip came up. Distinguishes cold boot from
//! software reset, watchdog bite, low-power illegal exit, and option-byte
//! reload. Used by the brownout-hardening design (see
//! `docs/brownout-hardening.md`) — abnormal causes (Watchdog / LowPower /
//! Unknown) trigger defensive SRAM zeroization before the unlock path
//! runs.
//!
//! STM32U5 register layout per RM0456 §11 (RCC).
//! Verify the first time a real board boots this code: the classified
//! cause is logged via `debug-log` semihosting as `[S] Reset cause: ...`.

use core::ptr::{read_volatile, write_volatile};

// Mirror the address convention from hw/rcc.rs: RCC is on the AHB3 bus,
// non-secure alias at 0x4602_0C00 (works from secure code on U5).
const RCC: u32 = 0x4602_0C00;
const RCC_CSR: *mut u32 = (RCC + 0xF4) as *mut u32;

// RCC_CSR sticky reset flags. Bit layout empirically verified on
// STM32U585 hardware (see boot log with `se050-admin-wipe-e2e`): a
// `probe-rs run` SYSRESETREQ boot produces CSR=0x14004400 (bits 26 +
// 28 set), confirming PINRSTF=26 + SFTRSTF=28. The earlier guess with
// all bits shifted one position lower misclassified SW resets as
// watchdogs — don't silently re-shift without re-validating.
const RMVF: u32 = 1 << 23;
const OBLRSTF: u32 = 1 << 25;
const PINRSTF: u32 = 1 << 26;
const BORRSTF: u32 = 1 << 27;
const SFTRSTF: u32 = 1 << 28;
const IWDGRSTF: u32 = 1 << 29;
const WWDGRSTF: u32 = 1 << 30;
const LPWRRSTF: u32 = 1 << 31;

const ANY_RESET_FLAG: u32 =
    OBLRSTF | PINRSTF | BORRSTF | SFTRSTF | IWDGRSTF | WWDGRSTF | LPWRRSTF;

/// Classification of the most recent reset.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResetCause {
    /// Power-on / brown-out. Expected on first plug-in or after battery
    /// swap. `BORRSTF | PINRSTF` with nothing else.
    Cold,
    /// Software-initiated reset (`SCB_AIRCR.SYSRESETREQ`). Our own
    /// wipe-complete path, `probe-rs reset`, etc.
    Software,
    /// Independent or window watchdog. Always suspicious — firmware was
    /// wedged for long enough to let the timer bite.
    Watchdog,
    /// Illegal low-power transition (e.g. Stop/Standby entered improperly).
    LowPower,
    /// Option-byte reload (`OBL_LAUNCH`). Expected when applying BOR /
    /// SRAM2_RST / other option-byte changes via STM32_Programmer_CLI.
    OptionByte,
    /// No flags set, or an unrecognised combination. Treat conservatively.
    Unknown,
}

impl ResetCause {
    /// True for any cause that suggests secrets might linger in SRAM.
    ///
    /// Cold boots are safe because SRAM has been without Vdd long enough
    /// to not hold useful data (and any cold-boot data belongs to an
    /// older firmware version that predates our invariants anyway). The
    /// software-reset path is also safe because it's always initiated
    /// from code that zeroizes first.
    ///
    /// Watchdog / LowPower / Unknown are suspicious: the firmware
    /// crashed or got wedged without running its zeroization path.
    pub fn is_abnormal(self) -> bool {
        matches!(
            self,
            ResetCause::Watchdog | ResetCause::LowPower | ResetCause::Unknown
        )
    }

    /// Short tag for semihosting logs.
    pub fn tag(self) -> &'static str {
        match self {
            ResetCause::Cold => "cold",
            ResetCause::Software => "software",
            ResetCause::Watchdog => "watchdog",
            ResetCause::LowPower => "low-power",
            ResetCause::OptionByte => "option-byte",
            ResetCause::Unknown => "unknown",
        }
    }
}

/// Read `RCC_CSR`, classify the cause, then clear the sticky flags so
/// the next reset reports fresh state.
///
/// Must be called at most once per boot, before anything else touches
/// RCC_CSR. Safe-ish to call multiple times (returns Unknown after the
/// first call since RMVF has cleared the flags).
///
/// # Safety
/// Unsafe because it does raw MMIO. Caller must ensure this runs exactly
/// once, early in boot, on the STM32 target (not QEMU).
#[cfg(feature = "stm32u585")]
pub unsafe fn classify_and_clear() -> (ResetCause, u32) {
    let csr = read_volatile(RCC_CSR);

    // Clear sticky flags. Write RMVF=1, then 0 so the next reset's flags
    // aren't masked by our own clear.
    write_volatile(RCC_CSR, csr | RMVF);
    write_volatile(RCC_CSR, csr & !RMVF);

    (classify_bits(csr), csr)
}

#[cfg(not(feature = "stm32u585"))]
pub unsafe fn classify_and_clear() -> (ResetCause, u32) {
    // QEMU / mock: no real reset-cause machinery. Pretend every boot is
    // cold — matches the observable QEMU behaviour (full reset between runs).
    (ResetCause::Cold, 0)
}

/// Pure classification: takes the raw RCC_CSR value, returns the cause.
/// Factored out for testability.
fn classify_bits(csr: u32) -> ResetCause {
    let flags = csr & ANY_RESET_FLAG;

    if flags == 0 {
        return ResetCause::Unknown;
    }

    // Priority: more specific causes take precedence over PINRSTF (which
    // is set on essentially every reset). We want "IWDG + PINRSTF" to
    // classify as Watchdog, not Unknown.
    if csr & OBLRSTF != 0 {
        return ResetCause::OptionByte;
    }
    if csr & (IWDGRSTF | WWDGRSTF) != 0 {
        return ResetCause::Watchdog;
    }
    if csr & LPWRRSTF != 0 {
        return ResetCause::LowPower;
    }
    if csr & SFTRSTF != 0 {
        return ResetCause::Software;
    }
    if csr & BORRSTF != 0 {
        // BOR + PIN with nothing else = clean power-on.
        return ResetCause::Cold;
    }

    // Only PINRSTF set with no other cause — shouldn't normally happen
    // (the chip asserts BORRSTF on every power-on), but if we see it,
    // treat as Unknown.
    ResetCause::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_is_bor_plus_pin_only() {
        assert_eq!(classify_bits(BORRSTF | PINRSTF), ResetCause::Cold);
    }

    #[test]
    fn software_reset() {
        assert_eq!(classify_bits(SFTRSTF | PINRSTF), ResetCause::Software);
    }

    #[test]
    fn watchdog_iwdg() {
        assert_eq!(classify_bits(IWDGRSTF | PINRSTF), ResetCause::Watchdog);
    }

    #[test]
    fn watchdog_wwdg() {
        assert_eq!(classify_bits(WWDGRSTF | PINRSTF), ResetCause::Watchdog);
    }

    #[test]
    fn low_power() {
        assert_eq!(classify_bits(LPWRRSTF | PINRSTF), ResetCause::LowPower);
    }

    #[test]
    fn option_byte_reload() {
        assert_eq!(
            classify_bits(OBLRSTF | PINRSTF | BORRSTF),
            ResetCause::OptionByte
        );
    }

    #[test]
    fn no_flags_is_unknown() {
        assert_eq!(classify_bits(0), ResetCause::Unknown);
    }

    #[test]
    fn watchdog_beats_bor_if_both_set() {
        // Shouldn't happen in practice but tests priority logic.
        assert_eq!(
            classify_bits(IWDGRSTF | BORRSTF | PINRSTF),
            ResetCause::Watchdog
        );
    }

    #[test]
    fn abnormal_flags() {
        assert!(ResetCause::Watchdog.is_abnormal());
        assert!(ResetCause::LowPower.is_abnormal());
        assert!(ResetCause::Unknown.is_abnormal());
        assert!(!ResetCause::Cold.is_abnormal());
        assert!(!ResetCause::Software.is_abnormal());
        assert!(!ResetCause::OptionByte.is_abnormal());
    }
}
