//! Pure TAMP status-register decode, split out of `hw/tamp.rs` so it can be
//! tested.
//!
//! WHY THIS FILE EXISTS (#723). `main.rs` declares `#[cfg(not(test))] mod hw;`,
//! so the entire `hw` tree is absent from every host test build — no feature
//! flag reaches it. `reason_from_sr` therefore had exactly one test, and that
//! test had never executed. It was also a spot-check of four flags under the
//! name `reason_strings_cover_every_itamp_bit`, for a decoder with eleven.
//!
//! This is a pure `u32 -> &'static str` with no MMIO, so the fix is to put it
//! somewhere the host build can reach and mount it from both sides:
//! `hw/tamp.rs` re-exports it for the firmware, and
//! `hw_platform_under_test/mod.rs` `#[path]`-mounts it for the tests.
//!
//! **Deliberately carries no `#![cfg(...)]` header.** The parent `hw/tamp.rs`
//! is gated on `all(stm32u585, tamp)`; inheriting that gate here would make
//! the mounted copy compile to nothing host-side and silently re-create the
//! very hole this file closes.
//!
//! WHY NOT A SOURCE-TEXT PIN. `reason_from_sr` is an if-chain, and its
//! meaning lives in the ORDER of the arms. Pinning the text of one arm says
//! nothing about its position, so a reordering passes a text-pinned suite
//! unchanged — demonstrated on `reset_cause::classify_bits` in 74d949e9,
//! where a swap silently disabled the abnormal-reset secret scrub while every
//! mirror test stayed green. Text pinning is complete for a constant and
//! unsound for a branch chain.

/// Internal-tamper status flags in `TAMP_SR` (RM0456 §50.6.6). `pub` so the
/// exhaustive decode tests can name them rather than re-deriving bit numbers.
pub const ITAMP1F: u32 = 1 << 16;
pub const ITAMP2F: u32 = 1 << 17;
pub const ITAMP3F: u32 = 1 << 18;
pub const ITAMP5F: u32 = 1 << 20;
pub const ITAMP6F: u32 = 1 << 21;
pub const ITAMP7F: u32 = 1 << 22;
pub const ITAMP8F: u32 = 1 << 23;
pub const ITAMP9F: u32 = 1 << 24;
pub const ITAMP11F: u32 = 1 << 26;
pub const ITAMP12F: u32 = 1 << 27;
pub const ITAMP13F: u32 = 1 << 28;

/// Every decodable flag, highest priority first — the same order the if-chain
/// below tests them in. Tests walk this to assert the chain rather than
/// re-listing bit numbers, so adding a flag to one and not the other shows up.
pub const DECODE_ORDER: [(u32, &str); 11] = [
    (ITAMP1F, "VOLTAGE"),
    (ITAMP2F, "TEMPERATURE"),
    (ITAMP3F, "LSE_CLOCK"),
    (ITAMP5F, "RTC_OVERFLOW"),
    (ITAMP6F, "SWD_ACCESS"),
    (ITAMP7F, "ANALOG_WDG1"),
    (ITAMP8F, "MONO_COUNTER"),
    (ITAMP9F, "CRYPTO_FAULT"),
    (ITAMP11F, "IWDG"),
    (ITAMP12F, "ANALOG_WDG2"),
    (ITAMP13F, "ANALOG_WDG3"),
];

/// Return a short human-readable label for whichever TAMP source raised the
/// IRQ. Exposed so other log paths can reuse the mapping.
///
/// Body moved verbatim from `hw/tamp.rs`; no decode changed.
pub fn reason_from_sr(sr: u32) -> &'static str {
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
