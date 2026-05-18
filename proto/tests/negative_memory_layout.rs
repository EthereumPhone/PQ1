//! Negative tests on the NS-memory region constants the secure world
//! uses to validate non-secure pointers.
//!
//! **What's being attacked.** A future contributor "tidies up" the
//! addresses so SRAM and Flash regions touch, or expands a region into
//! the shared-mailbox window. The secure-world pointer validator
//! depends on **disjoint** regions to refuse NS pointers that aim into
//! S-RAM or device-memory MMIO (CLAUDE.md non-negotiable invariant #4:
//! "All secrets only in TrustZone secure world"). If two NS regions
//! overlap, validation can give a false positive for an attacker-chosen
//! pointer.
//!
//! The numeric values themselves are platform-specific (mps2-an505
//! by default; STM32U585 under `stm32u585`), so these tests pin the
//! *structural* properties that the platform values must satisfy.

use pqsigner_proto::*;

#[test]
fn negative_ns_sram_region_non_empty_and_well_ordered() {
    assert!(
        NS_SRAM_BASE < NS_SRAM_END,
        "NS_SRAM region is empty or inverted: base={NS_SRAM_BASE:#x} end={NS_SRAM_END:#x}"
    );
}

#[test]
fn negative_ns_flash_region_non_empty_and_well_ordered() {
    assert!(
        NS_FLASH_BASE < NS_FLASH_END,
        "NS_FLASH region is empty or inverted: base={NS_FLASH_BASE:#x} end={NS_FLASH_END:#x}"
    );
}

#[test]
fn negative_shared_mailbox_region_non_empty_and_well_ordered() {
    assert!(
        SHARED_MAILBOX_BASE < SHARED_MAILBOX_END,
        "SHARED_MAILBOX region is empty or inverted"
    );
}

#[test]
fn negative_ns_sram_and_ns_flash_do_not_overlap() {
    // SRAM and Flash live at distinct address ranges on both targets.
    // Overlap here would mean an NS pointer that validates as "in SRAM"
    // could ALSO be in Flash, and the secure-world reader couldn't
    // tell which memory it was about to dereference.
    let disjoint =
        NS_SRAM_END <= NS_FLASH_BASE || NS_FLASH_END <= NS_SRAM_BASE;
    assert!(
        disjoint,
        "NS_SRAM [{NS_SRAM_BASE:#x},{NS_SRAM_END:#x}) overlaps NS_FLASH [{NS_FLASH_BASE:#x},{NS_FLASH_END:#x}) — the pointer validator cannot disambiguate the target memory"
    );
}

#[test]
fn negative_shared_mailbox_inside_ns_sram() {
    // The mailbox is documented as living at the *end* of NS SRAM.
    // If it drifted outside, NS-world writes through the mailbox would
    // either land in S-RAM (catastrophic) or in unmapped space (faults).
    assert!(
        SHARED_MAILBOX_BASE >= NS_SRAM_BASE && SHARED_MAILBOX_END <= NS_SRAM_END,
        "SHARED_MAILBOX [{SHARED_MAILBOX_BASE:#x},{SHARED_MAILBOX_END:#x}) is not contained in NS_SRAM [{NS_SRAM_BASE:#x},{NS_SRAM_END:#x})"
    );
}

#[test]
fn negative_shared_mailbox_is_exactly_24_bytes() {
    // 3 × u64 args per gateway call. A drift in size silently truncates
    // or aliases the arg vector.
    assert_eq!(
        SHARED_MAILBOX_END - SHARED_MAILBOX_BASE,
        0x18,
        "SHARED_MAILBOX size drifted from 24 bytes — gateway arg vector layout broken"
    );
}

// ───────────────────────────────────────────────────────────────────────
// Platform-specific bound checks
//
// Under the `stm32u585` feature the addresses must be in the
// STM32U585's SRAM2 (0x2003_xxxx) and Flash bank 2 NS alias
// (0x081x_xxxx). Under the default (mps2-an505) feature they are in
// the QEMU AN505 NS aliases (0x280x_xxxx for SSRAM-1, 0x002x_xxxx for
// SSRAM-0).
// ───────────────────────────────────────────────────────────────────────

#[test]
#[cfg(not(feature = "stm32u585"))]
fn negative_default_target_addresses_are_in_mps2_an505_aliases() {
    assert!(NS_SRAM_BASE >= 0x2800_0000 && NS_SRAM_END <= 0x2830_0000);
    assert!(NS_FLASH_BASE >= 0x0010_0000 && NS_FLASH_END <= 0x0080_0000);
}

#[test]
#[cfg(feature = "stm32u585")]
fn negative_stm32u585_addresses_are_in_silicon_aliases() {
    // SRAM2 NS alias at 0x2003_xxxx; Flash bank 2 NS alias at 0x081x_xxxx.
    assert!(NS_SRAM_BASE >= 0x2003_0000 && NS_SRAM_END <= 0x2004_0000);
    assert!(NS_FLASH_BASE >= 0x0810_0000 && NS_FLASH_END <= 0x0820_0000);
}
